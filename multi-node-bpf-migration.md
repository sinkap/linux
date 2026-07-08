# Migrating from the multi-node BPF prototype

The original prototype (the 5 `multi-node-bpf` patches) authorized shared
memory by **raw physical address** and had a few unsafe/broken corners.
The current design authorizes by **dma-buf fd** and reworks the ringbuf
layout, arena cache maintenance, MMIO access, and fd links. This is a
breaking change to the UAPI. Below is what to change, by area.

## 1. Map flags: `*_RESERVED` → `BPF_F_DMABUF`

The two per-map flags collapsed into one.

| Prototype | Now |
|-----------|-----|
| `BPF_F_RINGBUF_RESERVED` (bit 20) | `BPF_F_DMABUF` (bit 20) |
| `BPF_F_ARENA_RESERVED` (bit 21)   | `BPF_F_DMABUF` (bit 20) |

```c
/* before */
attr.map_flags = BPF_F_RINGBUF_RESERVED;      /* or BPF_F_ARENA_RESERVED */
/* after */
attr.map_flags = BPF_F_DMABUF;
```

New arena-only flags occupy bits 21/22 (`BPF_F_ARENA_CLEAN`,
`BPF_F_ARENA_INVAL`) — see §4.

## 2. `map_extra`: physical address → dma-buf fd

`map_extra` no longer carries a physical base address. It carries a
**dma-buf fd**. Allocate the buffer from an exporter that owns the shared
window (a carveout dma-heap or your device driver) and pass its fd.

```c
/* before */
attr.map_extra = 0x8f000000;                  /* physical base */

/* after */
int dmabuf = /* allocate from /dev/dma_heap/<carveout> */;
attr.map_extra = dmabuf;                       /* the fd */
```

Requirements now enforced at map creation:

- `CONFIG_DMA_SHARED_BUFFER` must be enabled (`-EOPNOTSUPP` otherwise).
- The arch must have cache maintenance support
  (`-EOPNOTSUPP` otherwise; arm64 and x86-64 today).
- The `CAP_SYS_ADMIN` / raw-`pfn_valid` checks are gone — access is now
  controlled by the exporter's file permissions on the fd. Physically
  contiguous placement is the exporter's responsibility.

The exporter must be **page-backed** for a BPF map to import it (a
carveout dma-heap or system heap; a `no-map` region has no `struct
page`s and cannot back a map — it is only for the consumer-side
`xnode_shmem` driver, §6).

## 3. Ringbuf: window layout changed

The prototype placed the entire `struct bpf_ringbuf`, including its
kernel-private part, in the reserved region — so a remote consumer read
kernel pointers and had to skip `RINGBUF_PGOFF` pages to reach
`consumer_pos`. Now the kernel-private state stays in normal memory and
**only the position/data pages come from the dma-buf**:

| dma-buf offset | contents       |
|----------------|----------------|
| page 0         | `consumer_pos` |
| page 1         | `producer_pos` |
| page 2+        | data (records) |

A remote consumer must update its offsets:

```c
/* before: relative to the physical base */
consumer_pos = base + RINGBUF_PGOFF * PAGE;

/* after: relative to the dma-buf */
consumer_pos = dmabuf_map + 0;
producer_pos = dmabuf_map + PAGE;
data         = dmabuf_map + 2 * PAGE;
```

Other ringbuf changes:

- `BPF_MAP_TYPE_USER_RINGBUF + BPF_F_DMABUF` is now **supported** (kernel
  consumer; it invalidates on `bpf_user_ringbuf_drain`). The prototype
  had no such path.
- `BPF_F_RB_OVERWRITE + BPF_F_DMABUF` is **rejected** (`-EINVAL`) — the
  overwrite position is not part of the maintenance protocol.
- Cache maintenance is automatic in the kernel producer/consumer helpers;
  no caller change.

## 4. Arena: no maintenance was done; now use the flags

The prototype's `BPF_F_ARENA_RESERVED` did **no** cache maintenance, so a
producer's writes were never guaranteed to reach the non-coherent
reader. Fix by adding, alongside `BPF_F_DMABUF`:

- `BPF_F_ARENA_CLEAN` — the JIT emits a clean (write-back) after each
  arena store, for a producer.
- `BPF_F_ARENA_INVAL` — the JIT emits an invalidate before each arena
  load, for an in-BPF consumer.

```c
attr.map_flags = BPF_F_DMABUF | BPF_F_MMAPABLE | BPF_F_ARENA_CLEAN;
```

No program change and no kfunc call — the maintenance is inserted by the
JIT around the program's own arena accesses. (An interim
`bpf_arena_cache_clean()` kfunc that briefly existed on this branch has
been removed; delete any calls to it.) The clean/invalidate carry no
ordering — use `store_release`/`load_acquire` at the producer/consumer
handoff.

Two behaviours to be aware of:

- `bpf_arena_alloc_pages()`/`bpf_arena_free_pages()` now work on dma-buf
  arenas (range-tree bookkeeping over the pre-mapped window); the
  prototype disabled them. **Allocated ranges are not zeroed.**
- The verifier requires an arena's `user_vm_start` to be set before a
  program can reference it. A dma-buf arena's `map_extra` is the fd, so
  **`mmap()` the arena (4 GiB-aligned) before loading** the program:

  ```c
  mmap((void *)0x4000000000ULL, size, PROT_READ | PROT_WRITE,
       MAP_SHARED | MAP_FIXED, arena_fd, 0);   /* then load */
  ```

## 5. MMIO kfuncs: now gated by a driver allowlist

`bpf_mmio_map(phys, size)` is **fail-closed**: it refuses any range not
registered by a driver via `bpf_mmio_register_region()`. The prototype
mapped any physical address.

- A driver that owns the aperture must register it (the `xnode_shmem`
  driver does this when loaded with `expose_mmio=1`).
- `bpf_mmio_map()` is now `KF_SLEEPABLE` — call it from a sleepable
  program.
- `bpf_mmio_readq`/`writeq` exist only on 64-bit arches.

The accessor calls (`bpf_mmio_readl`/`writel`/…) are otherwise unchanged.

## 6. Consumer node: use `xnode_shmem`, not `/dev/mem`

The reading node should stop mapping the window through raw `/dev/mem`
and go through a driver that owns the window and hands out controlled
mappings: write-combine (or cached + a range-sync ioctl), the
page-0-only-writable ringbuf discipline, and access control by device
permissions rather than raw physical access.

`drivers/misc/xnode_shmem.c` (`/dev/xnode_shmem`) provides exactly that,
**but it is a reference/example driver and is not expected to be
upstreamed as-is.** In a real deployment the device that owns the shared
window — the IPU/NIC driver — is the natural home for this: it is
already the dma-buf *exporter* on the producer side (§2), so it should
also expose the consumer-side mapping + sync interface and, if needed,
register the window with the `bpf_mmio` allowlist (§5). `xnode_shmem`
exists to make the mechanism testable and to document the required
interface (`GET_INFO`, the mmap discipline, `SET_MODE`/`SYNC`,
`EXPORT_DMABUF`); port that interface into your device driver rather
than shipping `xnode_shmem`. See the driver section in
`multi-node-bpf.md`.

## 7. fd links: only leaf file types

`BPF_LINK_TYPE_FD` (`attach_type BPF_DEPENDENT_FD`) now accepts only
**eventfd** and **dma-buf** fds; pinning any other fd type returns
`-EPERM` (reference-cycle safety). If you pinned other fd types, that no
longer works. Link info now reports the kind/inode
(`bpf_link_info.fd`).

## Quick checklist

- [ ] Replace `BPF_F_{RINGBUF,ARENA}_RESERVED` with `BPF_F_DMABUF`.
- [ ] Allocate a page-backed dma-buf; put its fd in `map_extra`.
- [ ] Recompute the remote ringbuf consumer's offsets (page 0 =
      `consumer_pos`).
- [ ] Add `BPF_F_ARENA_CLEAN`/`INVAL` to arena maps; drop any
      `bpf_arena_cache_clean()` calls; `mmap()` the arena before load.
- [ ] Register MMIO windows with `bpf_mmio_register_region()` before
      using `bpf_mmio_map()`.
- [ ] Switch the consumer node from `/dev/mem` to `/dev/xnode_shmem`.
- [ ] Ensure any pinned fd links are eventfd or dma-buf only.
