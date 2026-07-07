# multinode libbpf selftest

Covers the parts of the multi-node work that need real, clang-compiled
BPF programs — things the self-contained `multinode_test` (raw `bpf()`
syscalls) can't reach:

- **arena JIT clean** (`BPF_F_ARENA_CLEAN`): `arena_writer` stores to a
  dma-buf arena; the test dumps the JITed image and confirms a `clflush`
  (`0F AE /7`) was emitted after the store, then runs it (a malformed
  `clflush` would `#UD`).
- **dma-buf ringbuf producer**: `rb_producer` reserves/submits a record
  into a `BPF_F_DMABUF` ringbuf (kernel cleans on submit); the test reads
  the record back from a second dma-buf mapping.
- **dma-buf user-ringbuf drain**: `urb_drain` calls
  `bpf_user_ringbuf_drain` on a `USER_RINGBUF + BPF_F_DMABUF` map (kernel
  is the consumer, invalidates on consume); the test injects a record
  through the dma-buf and checks the callback saw it.

All three BPF programs live in `multinode.bpf.c`; `multinode_bpf.c` is
the loader/verifier.

## dma-buf map gotchas

- libbpf doesn't create dma-buf maps (`map_extra` is a dma-buf fd, not a
  user VM start). Each map is created here by hand and handed to the
  program with `bpf_map__reuse_fd()`.
- The verifier rejects a program that references an arena whose
  `user_vm_start` is 0 ("arena's user address must be set via map_extra
  or mmap()"). A dma-buf arena starts there, so the loader **mmap()s it
  (4 GiB-aligned) before loading**. Any dma-buf-arena user must do the
  same.

## Build and run (x86_64)

```sh
make KBUILD=<kbuild dir> LIBBPF=<libbpf.a>     # needs vmlinux (BTF) + headers
./run.sh <kbuild>/arch/x86/boot/bzImage
```

`make` generates `vmlinux.h` from `<kbuild>/vmlinux` via `bpftool`,
builds the BPF object with clang, and links the loader static against
libbpf + libelf + libz + libzstd. arm64 needs an aarch64 static
libbpf/libelf, not wired up here yet.

## Note on what this proves

A single QEMU guest is cache-coherent, so the clean/invalidate calls run
but have no observable effect. These tests confirm the code paths are
reached and correct (JIT emits the clflush, the producer/consumer flows
work, no crashes) — not the non-coherency benefit, which needs real
hardware.
