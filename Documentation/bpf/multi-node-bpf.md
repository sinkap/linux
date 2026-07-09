# BPF over non-coherent shared memory

This document describes how a BPF program can produce data (ring buffer
records, arena contents) into memory that is shared with a peer which does
**not** participate in hardware cache coherency with the producer -- for
example two processors on an accelerator/IPU that can each address the same
DRAM window through the fabric but do not snoop each other's caches.

Two questions have to be answered explicitly on such memory, because the
peer's MMU and the peer's cache are both out of the producer's reach:

  - *Authorization* -- which physical memory may a BPF map use? A raw
    physical address from userspace would be /dev/mem-grade power.
  - *Coherency* -- when do the producer's writes actually become visible
    to the peer, given that neither side snoops the other?

## Authorization: dma-buf backed maps

A `BPF_MAP_TYPE_RINGBUF` or `BPF_MAP_TYPE_ARENA` map created with the
`BPF_F_DMABUF` flag is backed by a dma-buf instead of anonymous kernel
pages. `map_extra` carries the dma-buf **fd**:

```
dmabuf_fd = <allocate from a dma-heap / device driver>
map_fd    = bpf(BPF_MAP_CREATE, {map_type: BPF_MAP_TYPE_RINGBUF,
                                 map_flags: BPF_F_DMABUF,
                                 map_extra: dmabuf_fd, ...})
```

The kernel imports the buffer (attach + map_attachment), which pins it for
the map's lifetime, and uses the exporter's pages to back the map. There is
never a physical address in the API: the exporter -- a carveout dma-heap or
the device driver that owns the window -- controls who may obtain the fd
via its own file permissions, and is responsible for the physically
contiguous, peer-addressable placement the cross-node contract needs. The
map's private bookkeeping (waitqueue, spinlock, page array) stays in
normal kernel memory and is never placed in the shared window.

### Keeping the buffer alive across agent restarts

The agent that creates these maps is typically restartable: on upgrade or
crash it re-execs and re-attaches to bpffs-pinned programs and maps. The
dma-buf fd (and any eventfd used to notify the peer) lives outside bpffs
and would be torn down when the agent's last fd closes, even though the
pinned maps survive.

`BPF_LINK_TYPE_FD` closes that gap: it wraps a foreign fd in a BPF link
that can itself be pinned in bpffs, so the file outlives the agent.

```
link_fd = bpf(BPF_LINK_CREATE, {target_fd: dmabuf_fd,
                                attach_type: BPF_DEPENDENT_FD})
bpf(BPF_OBJ_PIN, "/sys/fs/bpf/agent/window", link_fd)
```

Only **leaf** file types may be pinned this way -- types whose outward
references cannot loop back to hold the link's own fd, which would create
an unreclaimable reference cycle (the kernel has no general file-graph GC).
The permitted kinds live in a small in-kernel registry; eventfd and dma-buf
are the built-in entries, and a driver can opt its own file type in with
`bpf_fd_link_register_kind(&fops, "name")` (paired with
`bpf_fd_link_unregister_kind()` at driver exit). See `kernel/bpf/syscall.c`.

## Ring buffer coherency protocol

The producer's mapping of the window is cacheable, so writes park in its
cache until explicitly written back ("cleaned") to DRAM; conversely a load
may return a stale cached line unless it is "invalidated" first. The kernel
ring buffer producer path therefore maintains caches at the exact points
the protocol requires (`kernel/bpf/ringbuf.c`, `kernel/bpf/cache_maint.h`):

1. **Create** -- the zeroed positions and data are cleaned to DRAM.
2. **Reserve** -- the record header is written with the BUSY bit and
   cleaned *before* `producer_pos` is published, so that once
   `producer_pos` becomes visible the peer sees BUSY, never stale bytes.
3. **Commit** -- the payload is cleaned while the header still carries
   BUSY, then the final header is written and cleaned, then `producer_pos`
   is cleaned. The peer can never observe a completed header whose data has
   not reached DRAM.
4. `consumer_pos` is invalidated before it is read, since the peer updates
   it behind the producer's back.

The window layout (all offsets relative to the dma-buf start):

| dma-buf offset | contents        | producer access | peer access     |
|----------------|-----------------|-----------------|-----------------|
| page 0         | `consumer_pos`  | read (+inval)   | read/write      |
| page 1         | `producer_pos`  | write (+clean)  | read            |
| page 2+        | data (records)  | write (+clean)  | read            |

The peer runs the standard BPF ring buffer consumer algorithm: read
`producer_pos` with acquire semantics, walk records from its own
`consumer_pos`, stop at a BUSY header, skip DISCARDed records, advance by
`round_up(len + 8, 8)`, and store `consumer_pos` with release semantics. A
peer that maps the window write-combine (uncacheable) needs no maintenance
of its own; that is the simplest correct consumer and also sidesteps the
arm64 limitation that EL0 cannot execute `DC IVAC`.

`BPF_F_RB_OVERWRITE` is rejected together with `BPF_F_DMABUF`: overwrite
mode is not part of the cleaning protocol.

## Arena cache maintenance

An arena is a free-form shared region: only the program knows its record
boundaries, so blanket ring-buffer-style maintenance does not apply.
Instead the maintenance is per-access and program-directed, expressed as
two map flags the JIT honours when it emits arena load/store instructions:

  - `BPF_F_ARENA_CLEAN` -- after a store, clean the line to the point of
    coherency so the peer can observe it.
  - `BPF_F_ARENA_INVAL` -- before a load, invalidate the line so the CPU
    refetches the peer's write instead of a stale cached copy.

Emitting the maintenance inline in the JIT keeps it on the exact addresses
the program touches, with no map-wide barriers and no helper call. Because
it must be emitted by the JIT, an arena with these flags can only be
created where the JIT supports it: `bpf_jit_supports_arena_cache_maint()`
defaults to false, arena creation returns `-EOPNOTSUPP` otherwise, and an
arch opts in only once its JIT emits the ops (x86_64 and arm64 today).

An arena created with `BPF_F_ARENA_INVAL` is a read-only consumer window
onto the peer's memory; a store racing an invalidate has no well-defined
result, so the verifier rejects writes to such an arena at load time.

A dma-buf arena is fully pre-populated at creation.
`bpf_arena_alloc_pages()`/`free_pages()` act as pure range allocation over
the window -- no pages are allocated or freed, mappings are never torn
down, and allocated ranges are **not** zeroed, so the window's existing
contents are preserved. A program with a fixed layout can
`bpf_arena_reserve_pages()` its regions so the allocator never hands them
out.

## MMIO access from BPF

A datapath frequently needs to touch a device register directly -- ring a
peer's doorbell, poll a mailbox -- without a syscall round trip. The
`bpf_mmio_map()` / `bpf_mmio_read*()` / `bpf_mmio_write*()` kfuncs provide
that. A physical address from a BPF program would be /dev/mem-grade power,
so `bpf_mmio_map()` does not take one -- it takes an **fd**:

```
r = bpf_mmio_map(fd, offset, size);   /* fd authorizes the aperture */
bpf_mmio_writel(r, doorbell_off, val);
bpf_mmio_release(r);
```

The fd is resolved through a **provider** -- the subsystem that owns the
aperture. For a PCI device BAR that is vfio-pci: it hands an fd to an
authorized process (VFIO's existing per-fd ownership), registers the fd's
file_operations, and supplies a resolver that translates `(file, offset,
size)` into a physical range while applying its own access control and
sub-range rules (e.g. keeping the BAR's MSI-X table hidden):

```c
#include <linux/bpf_mmio.h>

static const struct bpf_mmio_provider my_prov = {
        .fops    = &my_region_fops,
        .name    = "vfio-pci",
        .resolve = my_resolve,
};
bpf_mmio_register_provider(&my_prov);
...
bpf_mmio_unregister_provider(&my_prov);
```

Access is thus scoped to *holding the fd*, not to a global allowlist: the
provider's per-fd ownership and range restrictions are preserved end to
end. This is the same principle the dma-buf backed maps use for memory --
authorize by fd, never by physical address. With no provider registered
every `bpf_mmio_map()` fails, so the kfuncs expose nothing until a provider
opts in; bpf core never references a provider itself.

## Notification

There is no doorbell in the ring buffer itself: `poll()` on a dma-buf
backed ring buffer returns `EPOLLERR` and the wakeup irq_work is node-local.
Deployments signal the peer out of band -- typically an eventfd kicked
through a mailbox or NIC -- which is exactly the fd that `BPF_LINK_TYPE_FD`
keeps alive across agent restarts.

## Testing without the fabric

Everything here is exercisable on a single machine, and the selftest
`tools/testing/selftests/bpf/prog_tests/multinode_dmabuf.c` does so:

1. Allocate a buffer from `/dev/dma_heap/system`, create the map with
   `BPF_F_DMABUF` and the fd in `map_extra`.
2. Produce through the BPF map and consume through a second mapping of the
   same dma-buf.
3. For arenas, store through a `BPF_F_ARENA_CLEAN` mapping and read back
   through a `BPF_F_ARENA_INVAL` mapping; on x86 the invalidate is
   implemented with `clflush` (write-back-and-invalidate), and the protocol
   is arranged so the writeback-vs-discard difference is unobservable.

## Limitations

- The dma-buf's pages are charged to the map's memcg and reported in
  `mem_usage` as if the map allocated them, over-reporting the footprint of
  a dma-buf backed map. Cosmetic; correct attribution would require
  teaching the accounting paths that the pages are borrowed.
- The producer-side import does not call `dma_buf_begin_cpu_access()`;
  harmless for a coherent carveout heap but part of the importer contract.
- Running the ring buffer *consumer* inside a BPF program
  (`BPF_MAP_TYPE_USER_RINGBUF` + `BPF_F_DMABUF`) is not yet supported: it
  needs a page-backed window on the consumer and the symmetric
  consumer-side maintenance (invalidate before every producer-data read,
  clean after `consumer_pos`).
