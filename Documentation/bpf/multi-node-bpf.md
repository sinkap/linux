# Multi-node BPF telemetry over non-coherent shared memory

This document describes the design on this branch for producing BPF
telemetry (ringbuf records, arena data) on one node and consuming it on
another node that shares physical memory with the producer **without
cache coherency** — e.g. two processors on an IPU that can address the
same DRAM window through the fabric but do not snoop each other's
caches.

Porting code from the earlier raw-physical-address prototype? See
`multi-node-bpf-migration.md` in the repository root.

## Architecture

```
 producer node                              consumer node
 ─────────────                              ─────────────
 BPF program                                userspace consumer
   │ bpf_ringbuf_reserve/submit               │ mmap (write-combine)
   ▼                                          ▼
 dma-buf backed BPF map  ──── shared DRAM ── xnode_shmem driver
 (BPF_F_DMABUF)               window          (drivers/misc/xnode_shmem.c)
   │                            ▲
   └── dma-buf fd ──────────────┘
       (exporter: carveout dma-heap / device driver)
```

Both sides address the same physical window. Neither side's page-table
permissions constrain the other side — the fabric path bypasses the
MMU of the peer — so the *authorization* question ("who may use this
memory") and the *coherency* question ("when do writes become
visible") are both handled explicitly.

## Authorization: dma-buf fds, not physical addresses

Maps never take a raw physical address from userspace. When
`BPF_F_DMABUF` is set on a `BPF_MAP_TYPE_RINGBUF` or
`BPF_MAP_TYPE_ARENA` map, `map_extra` carries a **dma-buf fd**. The
exporter (a carveout dma-heap or the device driver that owns the
window) controls access via its file permissions, and the kernel
imports the buffer (attach + map_attachment), which pins it for the
map's lifetime. Physically contiguous placement — which the cross-node
contract requires — is the exporter's responsibility.

Restrictions checked at map creation:

- `-EOPNOTSUPP` if the architecture has no cache maintenance support
  (`kernel/bpf/cache_maint.h`: arm64 and x86-64 today) or the kernel
  lacks `CONFIG_DMA_SHARED_BUFFER`.
- `BPF_F_RB_OVERWRITE` is rejected: `overwrite_pos` is not part of the
  cleaning protocol yet.

Maintenance is symmetric and driven by `BPF_F_DMABUF`: a kernel-producer
`BPF_MAP_TYPE_RINGBUF` cleans (writes back) the record and `producer_pos`
on submit; a kernel-consumer `BPF_MAP_TYPE_USER_RINGBUF` invalidates
`producer_pos` and the record on consume and cleans `consumer_pos` after
advancing. Both directions are supported.

### Keeping resources alive: fd links

`BPF_LINK_TYPE_FD` (`attach_type BPF_DEPENDENT_FD`) wraps an external
fd in a BPF link so it can be pinned in bpffs, letting the buffer and
its notification fd outlive the agent that created them:

```
dmabuf_fd = <allocate from heap / driver>
link_fd   = bpf(BPF_LINK_CREATE, {target_fd: dmabuf_fd,
                                  attach_type: BPF_DEPENDENT_FD})
bpf(BPF_OBJ_PIN, "/sys/fs/bpf/agent/window", link_fd)
```

Only **leaf file types** may be pinned (currently eventfd and
dma-buf). Files that can themselves hold references to other files
(io_uring, unix sockets) would allow unreclaimable reference cycles
and are rejected.

## Window layout (ringbuf)

All offsets are relative to the start of the dma-buf. The kernel's
private ringbuf state (waitqueue, spinlock, page array) lives in
normally allocated memory and is **never** placed in the window.

| dma-buf offset | contents        | producer access | consumer access |
|----------------|-----------------|-----------------|-----------------|
| page 0         | `consumer_pos`  | read (+inval)   | read/write      |
| page 1         | `producer_pos`  | write (+clean)  | read            |
| page 2+        | data (records)  | write (+clean)  | read            |

An arena window has no imposed layout: the whole dma-buf is the
arena, and the program defines its contents.

## Coherency protocol

The producer's mappings are cacheable; writes park in its cache until
explicitly cleaned (written back) to DRAM. The consumer maps the
window **write-combine (uncacheable)**, so it needs no maintenance at
all — every load observes DRAM, every `consumer_pos` store reaches
DRAM. This also sidesteps an arm64 limitation: userspace (EL0) cannot
execute `DC IVAC`, so a *cacheable* consumer mapping could never
invalidate stale lines.

Producer-side maintenance (`kernel/bpf/ringbuf.c`):

1. **Create**: the zeroed positions and data are cleaned to DRAM.
2. **Reserve**: the record header is written with the BUSY bit and
   cleaned *before* `producer_pos` is published — once any commit (or a
   cache eviction) makes `producer_pos` visible, the consumer must see
   BUSY rather than stale bytes for still-open records.
3. **Commit**: the payload is cleaned *while the header still carries
   BUSY*, then the final header is written and cleaned, then
   `producer_pos` is cleaned. The consumer can therefore never observe
   a completed header whose data has not reached DRAM.
4. `consumer_pos` is invalidated before every read, since the consumer
   updates it behind the producer's back.

The consumer applies the standard BPF ringbuf algorithm (see
`tools/xnode_shmem/consumer.c`): read `producer_pos` with acquire
semantics, walk records from its own `consumer_pos`, stop at a header
with the BUSY bit, skip DISCARDed records, advance by
`round_up(len + 8, 8)` and store `consumer_pos` with release
semantics.

For arenas the program is the producer and only it knows record
boundaries, so it cleans explicitly with the
`bpf_arena_cache_clean(map, ptr, size)` kfunc after writing.

Note on x86 (testing): "invalidate" is implemented with `clflush`,
which writes dirty lines back before invalidating. The protocol is
laid out so the producer never dirties lines the consumer owns, making
the writeback-vs-discard difference unobservable.

## Arena allocation semantics

A dma-buf arena is fully pre-populated at creation.
`bpf_arena_alloc_pages()`/`bpf_arena_free_pages()` work as pure range
allocation over the window: no pages are allocated or freed, mappings
are never torn down, and — unlike normal arenas — **allocated ranges
are not zeroed** (the window's previous contents are preserved).
Programs with a fixed layout can `bpf_arena_reserve_pages()` their
regions so the allocator never hands them out.

## Consumer node: the xnode_shmem driver

Raw `/dev/mem` access on the consumer node is both too broad (all of
physical memory) and subtly broken (a cacheable mapping cannot be
invalidated from EL0). `drivers/misc/xnode_shmem.c` replaces it:

- Binds to the window via a `memory-region` phandle to a
  reserved-memory node (compatible `xnode,shmem-window`), or via
  `base=`/`size=` module parameters for DT-less bring-up:

  ```dts
  reserved-memory {
          window: telemetry@8f000000 {
                  reg = <0x0 0x8f000000 0x0 0x1000000>;
                  no-map;
          };
  };
  telemetry-window {
          compatible = "xnode,shmem-window";
          memory-region = <&window>;
  };
  ```

- Exposes `/dev/xnode_shmem`. `XNODE_SHMEM_GET_INFO` returns the
  window base and size.
- `mmap` offsets are window-relative. A writable mapping is only
  permitted for page 0 (`consumer_pos`); everything else is enforced
  read-only (including `VM_MAYWRITE`, so `mprotect()` cannot upgrade).
  This restores the permission discipline that the BPF map's own mmap
  enforces on the producer node.
- Access control is the device node's permissions.

### Mapping modes

`XNODE_SHMEM_SET_MODE` selects, per fd, how subsequent mappings (and
exported dma-bufs) are cached:

- **`XNODE_SHMEM_WC`** (default): write-combine / uncacheable. Loads
  always observe DRAM and `consumer_pos` stores reach DRAM, so no
  cache maintenance is ever needed. Simplest and correct; the right
  default for a telemetry consumer that is not read-bandwidth-bound.

- **`XNODE_SHMEM_CACHED`**: cacheable mappings for higher read
  throughput on large records. The consumer must then bracket its
  accesses with `XNODE_SHMEM_SYNC` — `INVAL` a range before reading
  producer data, `CLEAN` the `consumer_pos` range after writing it.
  The kernel performs the maintenance on a write-back kernel mapping
  of the window; because arm64 D-caches are PIPT this reaches the
  physical lines cached through the userspace mapping too. (This is
  also why the driver, not EL0, must issue it: `DC IVAC` is
  privileged.) Rejected with `-EOPNOTSUPP` on architectures without
  maintenance support.

### Re-exporting as a dma-buf

`XNODE_SHMEM_EXPORT_DMABUF` returns a dma-buf fd for the window
(honouring the fd's WC/CACHED mode), so the consumer node speaks the
same abstraction as the producer:

- A consumer-side **device** (e.g. a NIC forwarding telemetry) can
  attach and DMA from it. The window is `no-map` and has no `struct
  page`s, so `map_dma_buf` uses `dma_map_resource()` to hand the
  importing device a DMA address for the physical range.
- **Userspace** can `mmap` it through the dma-buf, under the same
  page-0-only-writable discipline.
- `dma_buf_begin/end_cpu_access` drive the same invalidate/clean
  maintenance in CACHED mode.

Because the export is not `struct page` backed, it is **not**
importable into a BPF map (`bpf_dmabuf_backing_get()` requires pages).
Running the ringbuf consumer in BPF rather than userspace therefore
requires a page-backed window (e.g. a `shared-dma-pool reusable` CMA
region, not `no-map`) on the consumer. Given that, a
`BPF_MAP_TYPE_USER_RINGBUF` map over the window drained with
`bpf_user_ringbuf_drain()` gets the consumer-side coherency for free:
the drain path invalidates `producer_pos`, the header, and the record
before reading them and cleans `consumer_pos` after advancing.

The demo consumer (`tools/xnode_shmem/consumer.c`) shows the full
flow, including double-mapping the data pages so wrapped records read
contiguously.

## Notification

There is no doorbell in the ringbuf itself: `poll()` on a dma-buf
backed ringbuf returns `EPOLLERR`, and the kernel's wakeup irq_work is
local. Deployments signal the consumer out-of-band (eventfd kicked via
the NIC/mailbox — the eventfd is exactly what `BPF_LINK_TYPE_FD` keeps
alive); the demo consumer simply polls.

## Testing without the fabric

Everything above is testable on a single x86-64 machine:

1. Allocate a buffer from a dma-heap (`/dev/dma_heap/system`) or
   `udmabuf`, create the map with `BPF_F_DMABUF` and the fd in
   `map_extra`.
2. Load `xnode_shmem base=<phys> size=<bytes>` pointing at a
   `memmap=`-carved region backing the exporter, or simply consume
   through a second mapping of the dma-buf.
3. The x86 `clflush` backend of `cache_maint.h` exercises the same
   protocol paths as arm64.

## MMIO kfunc allowlist

`bpf_mmio_map(phys, size)` lets a BPF program map an MMIO aperture, but
a raw physical address from a program is /dev/mem-grade access. It is
therefore gated by a driver-registered allowlist:

```c
#include <linux/bpf_mmio.h>

/* in the device driver that owns the aperture */
bpf_mmio_register_region(bar_phys, bar_size);
...
bpf_mmio_unregister_region(bar_phys, bar_size);
```

`bpf_mmio_map()` refuses any range not fully contained in a registered
region. The allowlist is **fail-closed**: with nothing registered,
every `bpf_mmio_map()` call fails, so a kernel that ships these kfuncs
but whose drivers register no window exposes no MMIO. The accessors
live in their own kfunc set (`mmio_kfunc_set`) registered for the same
program types as the generic helpers, so their exposure can be trimmed
independently of the allowlist.

## Accounting note (memcg / mem_usage)

The dma-buf's pages are charged to the map's memcg and reported in
`mem_usage` as though the map allocated them, even though the exporter
owns them. This over-reports memory for dma-buf backed maps. It is
cosmetic — no page is double-freed — but a map's reported footprint
includes memory it does not own. Left as-is: correct attribution would
require teaching the accounting paths that the pages are borrowed.

## Known gaps

- The producer-side dma-buf import does not call
  `dma_buf_begin_cpu_access()`; harmless for a coherent carveout heap,
  but part of the importer contract.
- The importer collects `struct page`s from the exporter's sg_table,
  which upstream dma-buf discourages; fine for carveout heaps.
