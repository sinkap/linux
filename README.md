# Loadable BPF Verifier — `lsf` branch

This branch turns the BPF verifier into a loadable kernel module so a
verifier bug fix can be deployed by `modprobe`-ing a replacement
instead of rebuilding and rebooting the kernel.  See
`Documentation/bpf/verifier_module.rst` for the full design; this
README is a quick orientation and a recipe for building and testing.

## What's on this branch

Eight commits on top of `bpf-next/master`:

```
27345f0 bpf: take bpf_get_btf_vmlinux out of the dispatcher
6228eb7 bpf: complete the verifier-as-module boundary
0f7f634 bpf: namespaced exports + dispatcher impl helpers for verifier-as-module
e0364d7 bpf: add test module + selftest + docs for the verifier dispatcher
0cf94f8 bpf: add ABI versioning to the verifier dispatcher
ff83ade bpf: route bpf_check() through a pluggable dispatcher
70434c3 bpf: split verifier-internal types into kernel/bpf/verifier_internal.h
50cece1 bpf: document the verifier's public entry points
```

## Architecture in one paragraph

`bpf_check()` and `bpf_check_attach_target()` are now thin
RCU-protected dispatchers in `kernel/bpf/verifier_dispatch.c` that
route every call through `struct bpf_verifier_impl *active_verifier`.
The verifier proper (`verifier.c`, `liveness.c`, `states.c`,
`backtrack.c`, `cfg.c`, `check_btf.c`, `const_fold.c`, `fixups.c`)
ships either built into vmlinux or as `bpf_verifier.ko`, controlled by
`CONFIG_BPF_VERIFIER_REPLACEABLE` (`=y` default, `=m` for the loadable
build).  237 BPF-subsystem symbols the verifier set calls into are
exported with `EXPORT_SYMBOL_NS_GPL(name, "BPF_VERIFIER_INTERNAL")`;
seven helpers the verifier set provides back to vmlinux are routed
through function pointers in `struct bpf_verifier_impl`.  Module load
publishes a new impl via `register_bpf_verifier()`; module unload
calls `unregister_bpf_verifier()`, which `synchronize_rcu()` + drains
in-flight verifications before returning.  An ABI version field
(`BPF_VERIFIER_ABI_MAJOR/MINOR`) gates whether a given module can
load against the running kernel.

Public boundary lives in `include/linux/bpf_verifier.h`.  Anything
verifier-internal lives in `kernel/bpf/verifier_internal.h` (private
header, not in `include/`).

## Build

The branch defaults to the existing behavior — verifier built into
vmlinux:

```
make olddefconfig
make -j$(nproc)
```

For the loadable variant:

```
scripts/config -m BPF_VERIFIER_REPLACEABLE
make olddefconfig
make -j$(nproc)
make -j$(nproc) modules
ls kernel/bpf/bpf_verifier.ko
```

The `.ko` is ~7.4 MB and carries its own BTF section; the kernel boots
with a stub verifier active and `bpf(BPF_PROG_LOAD)` returns `-ENOENT`
until the module is loaded.

## Test

There are two distinct things to exercise: the dispatcher mechanism
(does the swap/drain/ABI-rejection work?) and the loadable verifier
itself (does a real BPF program load through it?).

### 1. Dispatcher mechanism (`CONFIG_BPF_VERIFIER_REPLACE_TEST=m`)

Builds a small test module that registers a stub `bpf_verifier_impl`
returning `-ENOSYS`.  Used to validate dispatcher swap, drain, and
ABI rejection without needing the full loadable verifier.

```
scripts/config -m BPF_VERIFIER_REPLACE_TEST
make olddefconfig
make -j$(nproc) modules
# In a VM:
sh tools/testing/selftests/bpf/test_verifier_dispatch.sh
```

Expected output:

```
TEST: dispatch swap to stub ... PASS
TEST: ABI rejection ... PASS
```

### 2. Loadable verifier (`CONFIG_BPF_VERIFIER_REPLACEABLE=m`)

Boot the kernel built with `=m`, then:

```
# Baseline: dispatcher stub is active, BPF programs cannot load.
dmesg | grep "bpf_check.*before any verifier"
# (should show: "bpf_check() called before any verifier implementation registered")

# Load the real verifier module.
modprobe bpf_verifier
# or, if not in modules.dep:
insmod kernel/bpf/bpf_verifier.ko

dmesg | tail
# Expect: "bpf: verifier 'builtin-mod' active"

# Confirm it shows up as a module BTF entry:
bpftool btf show | grep bpf_verifier
# Expect: "<id>: name [bpf_verifier]  size <N>B"

# Load a real BPF program through the loaded verifier:
echo 'BEGIN { printf("hello\n"); exit(); }' > /tmp/p.bt
bpftrace /tmp/p.bt
# Expect:
#   Attached 1 probe
#   hello

# Unload and confirm the dispatcher reverts to the stub.
rmmod bpf_verifier
dmesg | tail
# Expect: "bpf: verifier 'builtin-mod' inactive (now: 'stub')"

# Verify BPF loads now fail again until the module is reloaded.
bpftrace /tmp/p.bt
# Expect: a failure, since bpf_check() is back to the stub.
```

### ABI rejection sanity check

```
modprobe bpf_verifier_replace_test abi_major=99
# Expect: insmod fails, dmesg shows
#   "bpf: rejecting verifier 'test-replace' with ABI 99.0 (kernel expects 1.x)"
```

## Stacking + unlimited reloads

The dispatcher is a real stack of registered impls, not a single
replacement slot.  Implications:

- **Unlimited reloads.**  `rmmod bpf_verifier` + `modprobe bpf_verifier`
  works any number of times.  Each cycle runs a real verification
  through a fresh instance of the module.
- **Stacking.**  Loading a second verifier on top of an already-loaded
  one (e.g. a hotfix module on top of the main one) succeeds; the
  newer one becomes active, the older one stays in the stack as the
  fallback.  `bpftool` confirms with two module BTF entries.
- **Out-of-order rmmod is refused by the kernel.**  Each registration
  takes `try_module_get()` on the impl below it, so attempting to
  `rmmod` the bottom of the stack while the top is still loaded fails
  with *"Module bpf_verifier is in use"* — no use-after-free, no
  kernel trace.  The user must `rmmod` from the top down.

```
$ insmod bpf_verifier.ko          # stack: [stub, bpf_verifier]
$ insmod bpf_verifier_v2.ko       # stack: [stub, bpf_verifier, bpf_verifier_v2]
$ rmmod bpf_verifier              # refused: "Module bpf_verifier is in use"
$ rmmod bpf_verifier_v2           # ok    -> stack: [stub, bpf_verifier]
$ rmmod bpf_verifier              # ok    -> stack: [stub]
```

## Other limitations

- No per-cgroup or per-task verifier selection.  No multi-version
  coexistence with different verifiers serving different programs.
  No JIT/maps/helpers/syscall.c modularization.  These are deliberate
  non-goals for v1 — see the design doc.
- `bpf_log` and `bpf_verifier_log_write` are still plain
  `EXPORT_SYMBOL_GPL` (pre-existing exports we deliberately didn't
  touch).  The rest of the log API is namespace-gated to
  `BPF_VERIFIER_INTERNAL`.  Easy follow-up to convert the two for
  consistency.

## Where to read next

- `Documentation/bpf/verifier_module.rst` — design and ABI details.
- `kernel/bpf/verifier_dispatch.c` — the dispatcher itself, ~250 lines.
- `kernel/bpf/verifier_internal.h` — the private boundary.
- `include/linux/bpf_verifier.h` — the public boundary
  (`struct bpf_verifier_impl`, `register_bpf_verifier()`, ABI macros).
