# multinode functional test

End-to-end test for the dma-buf backed BPF ringbuf/arena and the
`Documentation/bpf/multi-node-bpf.md`.

`multinode_test` is a single self-contained binary (hand-assembled BPF
program, raw `bpf()` syscalls, no libbpf) so it links statically and
runs in a minimal initramfs. It exercises three things:

- **ringbuf**: allocate a page-backed dma-buf from the system dma-heap,
  create a `BPF_F_DMABUF` ringbuf over it, load an XDP producer that
  writes sequenced records, and consume 1000 records through a second
  mapping of the dma-buf — enough to wrap the data region several
  times. Validates the layout contract, the BUSY-bit protocol and
  in-order delivery.
- **arena**: create a `BPF_F_DMABUF` arena and confirm its pages alias
  the dma-buf's pages. The mapping is placed 4 GiB-aligned because
  arenas address pages by the low 32 bits of the user address.
  discipline, and `SET_MODE`/`SYNC` in cached mode.

## What it does and does not prove

A single SMP guest is cache-coherent, so the cache-maintenance calls
run but their *effect* is invisible: this validates functional
correctness (layout, dma-buf import, protocol, arena page identity,
driver ioctls and permissions), **not** the non-coherency benefit,
which needs real non-coherent hardware or a fabric model.

## Build and run

`run.sh` builds and boots the test for one or both architectures and
reports a combined result. Point it at pre-built kbuild dirs (each
built with `make O=<dir> ... {bzImage|Image} headers_install`):

```sh
# both architectures (default):
tools/testing/multinode/run.sh --x86 <kbuild> --arm64 <kbuild-arm64>

# a single architecture:
tools/testing/multinode/run.sh --arch x86_64 --x86 <kbuild>
tools/testing/multinode/run.sh --arch arm64  --arm64 <kbuild-arm64>
```

`--arch` selects `x86_64`, `arm64` or `both` (default). arm64 is
cross-built with `CROSS_CXX` (default `aarch64-linux-gnu-g++`). The
kernel needs `BPF_SYSCALL`, `BPF_JIT`, `DMA_SHARED_BUFFER`,
`DMABUF_HEAPS_SYSTEM`, initramfs support (see
`multinode.config`).

### How each arch is booted

`run.sh` calls `run_qemu.sh` per arch (which can also be used directly:
`ARCH=<arch> run_qemu.sh <kernel-image> <test-binary>`):

  with `memmap=` and passes `base=`/`size=` to the builtin driver; the
  window base must be below guest RAM.
- **arm64** (`qemu-system-aarch64 -M virt`) exercises the real
  `dc civac`/`dc ivac` maintenance. `virt` has no `memmap=`, so the
  runner reserves the window by dumping the machine DTB, splicing in a
  `reserved-memory` node and passing it back with `-dtb` (needs

All three sub-tests pass on both x86_64 and arm64.

## Not covered yet

- A BPF program writing to the arena (needs arena-address codegen);
  the arena test validates page identity via userspace mmap only.
- `bpf_arena_cache_clean()` and the consumer-in-BPF path
  (`USER_RINGBUF + BPF_F_DMABUF`).
- ARM: no aarch64 userspace toolchain here. The kernel side builds for
  arm64; running there needs an aarch64 rootfs and
  `qemu-system-aarch64`, and would exercise the real `dc civac`/`ivac`
  maintenance instead of x86 `clflush`.
