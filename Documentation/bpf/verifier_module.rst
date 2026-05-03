.. SPDX-License-Identifier: GPL-2.0-only

============================
Replaceable BPF Verifier
============================

The BPF verifier (``kernel/bpf/verifier.c`` and its closely-coupled
helpers) is the highest-churn file in the BPF subsystem -- around 35
commits per release, ~16% of all BPF kernel changes.  Bugs in the
verifier therefore land routinely, and historically the only ways to
ship a fix were a kernel rebuild + reboot, or a kernel live patch
(KLP) with all its constraints (no struct layout changes, no new
outbound calls, ...).

This document describes the in-tree boundary that lets a fixed BPF
verifier be deployed as a loadable kernel module instead, without
rebooting.

Architecture
============

::

    Userspace
        bpf(BPF_PROG_LOAD, ...)
            v
    +--------------------------------------------------+
    | vmlinux (always present)                         |
    |                                                  |
    |  kernel/bpf/syscall.c -> bpf_check()             |
    |                                                  |
    |  kernel/bpf/verifier_dispatch.c                  |
    |    bpf_check()  --rcu_dereference(active)-+      |
    |    bpf_check_attach_target()             |       |
    |                                          v       |
    |    register_bpf_verifier(impl)                   |
    |    unregister_bpf_verifier(impl)                 |
    |                                                  |
    |  Built-in verifier impl                          |
    |    kernel/bpf/{verifier,liveness,states,...}.c   |
    |    Registered via subsys_initcall.               |
    |                                                  |
    +-------------------+------------------------------+
                        |  dispatch
                        v
    +--------------------------------------------------+
    | Loaded verifier module (optional)                |
    |   register_bpf_verifier() at module_init         |
    |   unregister_bpf_verifier() at module_exit       |
    +--------------------------------------------------+

The dispatcher in ``kernel/bpf/verifier_dispatch.c`` owns a single
slot.  At boot, a stub implementation that returns ``-ENOENT`` from
every entry point sits in the slot; the built-in verifier replaces it
via ``subsys_initcall`` registration.  A loadable module then replaces
the built-in via ``register_bpf_verifier()``; ``unregister_bpf_verifier()``
restores the built-in.

All dispatch is RCU-protected and refcounted: every call to
``bpf_check()`` or ``bpf_check_attach_target()`` takes a
``try_module_get()`` reference on ``impl->owner`` and bumps an
in-flight counter.  ``unregister_bpf_verifier()`` swaps the active
pointer, ``synchronize_rcu()``, then waits on the in-flight counter
before returning, so an unloading module is safe to free immediately
afterwards.

The public API
==============

``include/linux/bpf_verifier.h`` declares::

    struct bpf_verifier_impl {
            int (*check)(struct bpf_prog **prog, union bpf_attr *attr,
                         bpfptr_t uattr, __u32 uattr_size);
            int (*check_attach_target)(struct bpf_verifier_log *log,
                                       const struct bpf_prog *prog,
                                       const struct bpf_prog *tgt_prog,
                                       u32 btf_id,
                                       struct bpf_attach_target_info *tgt_info);
            struct module *owner;
            const char *name;
            u32 abi_version;
    };

    int  register_bpf_verifier(struct bpf_verifier_impl *impl);
    void unregister_bpf_verifier(struct bpf_verifier_impl *impl);

Both functions are ``EXPORT_SYMBOL_GPL``.  v1 supports a single
non-built-in registration at a time -- a second
``register_bpf_verifier()`` while a module is already active returns
``-EBUSY``.

ABI versioning
==============

A loaded module and the running kernel agree implicitly on struct
layouts only when they were built from compatible headers.
``BPF_VERIFIER_ABI_MAJOR`` / ``BPF_VERIFIER_ABI_MINOR`` make this
explicit:

* **MAJOR** is bumped on any layout change to a type that crosses
  the boundary -- ``bpf_reg_state``, ``bpf_verifier_log``,
  ``bpf_verifier_env``, ``bpf_insn_aux_data``, ``bpf_func_state``,
  ``bpf_verifier_state``, ``bpf_subprog_info``, ``bpf_retval_range`` --
  or on a signature change in ``struct bpf_verifier_impl``.

* **MINOR** is bumped on additive changes that older modules can
  ignore (e.g. a new optional callback appended to
  ``struct bpf_verifier_impl``).

A module advertises the ABI it was built against in
``impl->abi_version``.  ``register_bpf_verifier()`` rejects MAJOR
mismatches with ``-ENOEXEC`` and a one-line ``dmesg``.

Public boundary
===============

The boundary is enforced at the header level: ``include/linux/bpf_verifier.h``
holds only what the rest of the kernel and a loadable verifier module
both rely on.  Verifier internals -- search state, backtracking
working buffers, SCC bookkeeping, kfunc-call metadata, the cross-file
declarations between ``verifier.c`` and its neighbours -- live in the
private ``kernel/bpf/verifier_internal.h``, which is not in
``include/`` and is included only by the verifier set itself plus
``kernel/bpf/log.c`` (which walks verifier state for diagnostics).

Types that cross the boundary are documented as part of the ABI in
``include/linux/bpf_verifier.h``.  A handful of these
(``bpf_func_state``, ``bpf_verifier_state``, ``bpf_subprog_info``,
``bpf_retval_range``) stay public not only for the verifier module
itself but also because in-tree consumers --
``drivers/net/ethernet/netronome/nfp/bpf/verifier.c`` for NFP BPF
offload, ``include/linux/bpf_lsm.h`` for ``bpf_lsm_get_retval_range``
-- depend on them directly.

What v1 does and doesn't deliver
================================

**v1 (this series) delivers:**

* The dispatcher, registration API, refcount + drain semantics, and
  ABI versioning.
* A header split that names exactly which types and functions are
  part of the verifier ABI.
* A test module (``CONFIG_BPF_VERIFIER_REPLACE_TEST``) that
  registers a stub implementation.  Loading it makes
  ``bpf(BPF_PROG_LOAD)`` return ``-ENOSYS``; unloading it restores
  the built-in.  Used to validate the dispatch and drain paths
  end-to-end.

**v1 does NOT yet deliver a fully loadable replacement verifier**,
but it does most of the preparatory work:

* 237 verifier-callable symbols across ``kernel/bpf/``,
  ``kernel/trace/``, ``kernel/events/``, ``arch/x86/``, ``net/core/``,
  ``net/netfilter/``, ``fs/``, ``mm/``, ``lib/`` and ``drivers/media/``
  are exported with ``EXPORT_SYMBOL_NS_GPL(name, "BPF_VERIFIER_INTERNAL")``.
  A future verifier module declares ``MODULE_IMPORT_NS("BPF_VERIFIER_INTERNAL")``
  to resolve them.

* ``struct bpf_verifier_impl`` carries function pointers for the
  seven helpers the verifier set defines but vmlinux callers (the
  JIT path in ``core.c``, BTF code in ``btf.c``/``syscall.c``/``inode.c``)
  invoke during a verifier-driven flow:
  ``get_btf_vmlinux``, ``patch_insn_data``, ``dup_insn_aux_data``,
  ``restore_insn_aux_data``, ``get_kfunc_addr``,
  ``free_kfunc_btf_tab``, ``prog_has_kfunc_call``.  The dispatcher
  exposes these as ordinary ``EXPORT_SYMBOL_NS_GPL`` wrappers; intra-
  verifier callers go straight to the ``_impl`` versions via macro
  redirection in ``kernel/bpf/verifier_internal.h`` (zero overhead in
  the built-in path).

* The Kconfig symbol ``BPF_VERIFIER_REPLACEABLE`` is a tristate; with
  ``=y`` (the default) the verifier set is built into vmlinux as
  today.

What still blocks ``CONFIG_BPF_VERIFIER_REPLACEABLE=m``:

* A handful of global *data* symbols defined in the verifier set are
  read from vmlinux files: ``btf_vmlinux`` (read by ``btf.c`` and
  ``bpf_struct_ops.c``), ``bpf_global_percpu_ma`` (read by
  ``helpers.c``).  These need to be moved to vmlinux-resident files
  (likely ``btf.c`` and ``memalloc.c``).

* A few cross-boundary functions still live in the verifier set:
  ``map_set_for_each_callback_args`` (referenced from map_ops vtables
  in ``arraymap.c`` etc.), ``bpf_prog_ctx_arg_info_init`` (called
  from ``bpf_iter.c``).  Same treatment: move to vmlinux or add to
  the impl table.

These are concrete, mechanical, and bounded.  Once they're done, the
``=m`` build links cleanly and the ``.ko`` is loadable.

The non-goals carry over from the design doc:

* No per-cgroup or per-task verifier selection.
* No multi-version coexistence -- only one verifier active at a time.
* No JIT, BTF, helpers, maps, or syscall.c modularization.
* No artifact base-class split.

Shipping a verifier hotfix (future workflow)
============================================

Once the boundary exports are in place, the workflow for shipping a
verifier bug fix without rebooting is:

1. Apply the verifier patch to a copy of the kernel source matching
   the running kernel's ``BPF_VERIFIER_ABI_MAJOR``.
2. Build the verifier module (``CONFIG_BPF_VERIFIER_REPLACEABLE=m``,
   in a future patch).
3. ``modprobe`` the resulting ``bpf_verifier.ko``.  The dispatcher
   atomically swaps to the new implementation; in-flight
   ``bpf_check()`` calls finish on the old code, new ones land on
   the fixed one.
4. To roll back, ``modprobe -r bpf_verifier``.  The built-in resumes.

Programs verified before the swap remain loaded and running --
verification is one-shot at load time, so swapping the verifier
doesn't affect already-attached programs.
