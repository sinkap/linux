// SPDX-License-Identifier: GPL-2.0-only
/* BPF verifier dispatcher.
 *
 * The verifier proper (kernel/bpf/verifier.c and friends) is a pluggable
 * implementation of struct bpf_verifier_impl.  This file owns the
 * single-slot dispatch table and the public bpf_check() /
 * bpf_check_attach_target() entry points that the rest of the kernel
 * (kernel/bpf/syscall.c, kernel/bpf/trampoline.c) calls.
 *
 * Goals:
 *  - Boot-time safety: the built-in verifier registers via
 *    subsys_initcall.  Verification requests that arrive before that
 *    initcall has run -- which in practice cannot happen, since BPF
 *    syscalls only become reachable from userspace -- get a clear
 *    -ENOENT back from a stub implementation rather than NULL-deref.
 *  - Module-replace semantics: a loaded verifier module overrides the
 *    built-in via register_bpf_verifier(); module unload calls
 *    unregister_bpf_verifier() which restores the previous (built-in)
 *    impl and drains any in-flight verification before returning.
 *  - Refcount safety: every dispatched call holds try_module_get() on
 *    impl->owner, so module unload cannot race with running
 *    verifications.
 *
 * v1 supports a single non-built-in registration at a time -- enough
 * for the "ship a verifier hotfix as a module" use case.
 */

#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/wait.h>

static int stub_check(struct bpf_prog **prog, union bpf_attr *attr,
		      bpfptr_t uattr, __u32 uattr_size)
{
	pr_warn_once("bpf: bpf_check() called before any verifier implementation registered\n");
	return -ENOENT;
}

static int stub_check_attach_target(struct bpf_verifier_log *log,
				    const struct bpf_prog *prog,
				    const struct bpf_prog *tgt_prog,
				    u32 btf_id,
				    struct bpf_attach_target_info *tgt_info)
{
	return -ENOENT;
}

static struct btf *stub_get_btf_vmlinux(void)
{
	return NULL;
}

static struct bpf_prog *stub_patch_insn_data(struct bpf_verifier_env *env,
					     u32 off,
					     const struct bpf_insn *patch,
					     u32 len)
{
	return NULL;
}

static struct bpf_insn_aux_data *stub_dup_insn_aux_data(struct bpf_verifier_env *env)
{
	return NULL;
}

static void stub_restore_insn_aux_data(struct bpf_verifier_env *env,
				       struct bpf_insn_aux_data *orig)
{
}

static int stub_get_kfunc_addr(const struct bpf_prog *prog, u32 func_id,
			       u16 btf_fd_idx, u8 **func_addr)
{
	return -ENOENT;
}

static void stub_free_kfunc_btf_tab(struct bpf_kfunc_btf_tab *tab)
{
}

static bool stub_prog_has_kfunc_call(const struct bpf_prog *prog)
{
	return false;
}

/* Pre-registration fallback.  Active until the built-in verifier
 * registers itself via subsys_initcall.  Owner is NULL so dispatch
 * takes no try_module_get() reference.
 */
static struct bpf_verifier_impl stub_verifier_impl = {
	.check			= stub_check,
	.check_attach_target	= stub_check_attach_target,
	.get_btf_vmlinux	= stub_get_btf_vmlinux,
	.patch_insn_data	= stub_patch_insn_data,
	.dup_insn_aux_data	= stub_dup_insn_aux_data,
	.restore_insn_aux_data	= stub_restore_insn_aux_data,
	.get_kfunc_addr		= stub_get_kfunc_addr,
	.free_kfunc_btf_tab	= stub_free_kfunc_btf_tab,
	.prog_has_kfunc_call	= stub_prog_has_kfunc_call,
	.owner			= NULL,
	.name			= "stub",
	.abi_version		= BPF_VERIFIER_ABI_VERSION,
};

static struct bpf_verifier_impl __rcu *active_verifier =
	RCU_INITIALIZER(&stub_verifier_impl);

/* Saved fallback: when a module registers, we record the previously
 * active impl here so unregister_bpf_verifier() can restore it.  v1
 * allows a single replacement, so this is a single slot rather than a
 * stack.
 */
static struct bpf_verifier_impl *fallback_verifier;

static DEFINE_MUTEX(verifier_register_mutex);

/* Counts dispatched calls (i.e. those that have already taken a ref on
 * impl->owner and are between RCU read-side and impl->check return).
 * Used by unregister_bpf_verifier() to drain before returning.
 */
static atomic_t verifier_in_flight = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(verifier_drain_wq);

static struct bpf_verifier_impl *get_active_verifier(void)
{
	struct bpf_verifier_impl *impl;

	rcu_read_lock();
	impl = rcu_dereference(active_verifier);
	if (impl->owner && !try_module_get(impl->owner)) {
		/* Module is on its way out; the unregister path will
		 * publish the fallback any moment now.  Caller will
		 * retry (-EAGAIN) and pick up the fallback.
		 */
		rcu_read_unlock();
		return ERR_PTR(-EAGAIN);
	}
	atomic_inc(&verifier_in_flight);
	rcu_read_unlock();
	return impl;
}

static void put_active_verifier(struct bpf_verifier_impl *impl)
{
	if (impl->owner)
		module_put(impl->owner);
	if (atomic_dec_and_test(&verifier_in_flight))
		wake_up(&verifier_drain_wq);
}

int bpf_check(struct bpf_prog **prog, union bpf_attr *attr,
	      bpfptr_t uattr, __u32 uattr_size)
{
	struct bpf_verifier_impl *impl;
	int ret;

	impl = get_active_verifier();
	if (IS_ERR(impl))
		return PTR_ERR(impl);

	ret = impl->check(prog, attr, uattr, uattr_size);

	put_active_verifier(impl);
	return ret;
}

int bpf_check_attach_target(struct bpf_verifier_log *log,
			    const struct bpf_prog *prog,
			    const struct bpf_prog *tgt_prog,
			    u32 btf_id,
			    struct bpf_attach_target_info *tgt_info)
{
	struct bpf_verifier_impl *impl;
	int ret;

	impl = get_active_verifier();
	if (IS_ERR(impl))
		return PTR_ERR(impl);

	ret = impl->check_attach_target(log, prog, tgt_prog, btf_id, tgt_info);

	put_active_verifier(impl);
	return ret;
}

int register_bpf_verifier(struct bpf_verifier_impl *impl)
{
	struct bpf_verifier_impl *cur;
	u32 impl_major, kernel_major;

	if (!impl || !impl->check || !impl->check_attach_target)
		return -EINVAL;

	impl_major = BPF_VERIFIER_ABI_GET_MAJOR(impl->abi_version);
	kernel_major = BPF_VERIFIER_ABI_GET_MAJOR(BPF_VERIFIER_ABI_VERSION);
	if (impl_major != kernel_major) {
		pr_err("bpf: rejecting verifier '%s' with ABI %u.%u (kernel expects %u.x)\n",
		       impl->name ?: "(unnamed)",
		       impl_major,
		       BPF_VERIFIER_ABI_GET_MINOR(impl->abi_version),
		       kernel_major);
		return -ENOEXEC;
	}

	mutex_lock(&verifier_register_mutex);
	cur = rcu_dereference_protected(active_verifier,
					lockdep_is_held(&verifier_register_mutex));
	if (cur == &stub_verifier_impl) {
		/* First registration -- the built-in coming up via
		 * subsys_initcall.  No fallback to remember; the stub
		 * is just a NULL-deref guard, not something we want to
		 * fall back to when a module unregisters.
		 */
	} else if (fallback_verifier) {
		/* A non-built-in is already active; v1 only supports a
		 * single replacement layer.
		 */
		mutex_unlock(&verifier_register_mutex);
		return -EBUSY;
	} else {
		fallback_verifier = cur;
	}
	rcu_assign_pointer(active_verifier, impl);
	mutex_unlock(&verifier_register_mutex);

	/* Wait for any in-flight readers to observe the new impl before
	 * returning -- not strictly required for correctness (readers
	 * holding the old impl keep an owner ref via try_module_get and
	 * release it normally) but gives a tighter "registered" semantic.
	 */
	synchronize_rcu();

	pr_info("bpf: verifier '%s' active%s%s%s\n",
		impl->name ?: "(unnamed)",
		fallback_verifier ? " (replacing '" : "",
		fallback_verifier ? (fallback_verifier->name ?: "(unnamed)") : "",
		fallback_verifier ? "')" : "");
	return 0;
}
EXPORT_SYMBOL_GPL(register_bpf_verifier);

void unregister_bpf_verifier(struct bpf_verifier_impl *impl)
{
	struct bpf_verifier_impl *cur, *next;

	if (WARN_ON_ONCE(!impl))
		return;

	mutex_lock(&verifier_register_mutex);
	cur = rcu_dereference_protected(active_verifier,
					lockdep_is_held(&verifier_register_mutex));
	if (WARN(cur != impl,
		 "bpf: unregister of inactive verifier '%s' (active is '%s')\n",
		 impl->name ?: "(unnamed)", cur->name ?: "(unnamed)")) {
		mutex_unlock(&verifier_register_mutex);
		return;
	}
	next = fallback_verifier ?: &stub_verifier_impl;
	fallback_verifier = NULL;
	rcu_assign_pointer(active_verifier, next);
	mutex_unlock(&verifier_register_mutex);

	/* After synchronize_rcu(), no new caller can observe @impl via
	 * the dispatcher.  Any caller that observed it before the swap
	 * already incremented verifier_in_flight inside an RCU read-side
	 * critical section; wait for them to drain so the caller (or
	 * their module) can be freed safely.
	 */
	synchronize_rcu();
	wait_event(verifier_drain_wq, atomic_read(&verifier_in_flight) == 0);

	pr_info("bpf: verifier '%s' inactive (now: '%s')\n",
		impl->name ?: "(unnamed)",
		next->name ?: "(unnamed)");
}
EXPORT_SYMBOL_GPL(unregister_bpf_verifier);

/* Helper wrappers.  Vmlinux callers use these; they route through the
 * active impl.  Module callers can use them too -- but the verifier
 * module typically calls its own internal versions directly, so these
 * wrappers carry no per-call refcount overhead beyond an RCU read.
 *
 * These deliberately do NOT take try_module_get()/in_flight refs:
 * every legitimate caller is reached only via env != NULL, which can
 * only be true if the caller is itself running inside a bpf_check()
 * dispatched call -- which already holds the module ref.
 */

struct btf *bpf_get_btf_vmlinux(void)
{
	struct btf *ret;

	rcu_read_lock();
	ret = rcu_dereference(active_verifier)->get_btf_vmlinux();
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_NS_GPL(bpf_get_btf_vmlinux, "BPF_VERIFIER_INTERNAL");

struct bpf_prog *bpf_patch_insn_data(struct bpf_verifier_env *env, u32 off,
				     const struct bpf_insn *patch, u32 len)
{
	return rcu_dereference_check(active_verifier, 1)
		->patch_insn_data(env, off, patch, len);
}
EXPORT_SYMBOL_NS_GPL(bpf_patch_insn_data, "BPF_VERIFIER_INTERNAL");

struct bpf_insn_aux_data *bpf_dup_insn_aux_data(struct bpf_verifier_env *env)
{
	return rcu_dereference_check(active_verifier, 1)->dup_insn_aux_data(env);
}
EXPORT_SYMBOL_NS_GPL(bpf_dup_insn_aux_data, "BPF_VERIFIER_INTERNAL");

void bpf_restore_insn_aux_data(struct bpf_verifier_env *env,
			       struct bpf_insn_aux_data *orig)
{
	rcu_dereference_check(active_verifier, 1)
		->restore_insn_aux_data(env, orig);
}
EXPORT_SYMBOL_NS_GPL(bpf_restore_insn_aux_data, "BPF_VERIFIER_INTERNAL");

int bpf_get_kfunc_addr(const struct bpf_prog *prog, u32 func_id,
		       u16 btf_fd_idx, u8 **func_addr)
{
	int ret;

	rcu_read_lock();
	ret = rcu_dereference(active_verifier)
		->get_kfunc_addr(prog, func_id, btf_fd_idx, func_addr);
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_NS_GPL(bpf_get_kfunc_addr, "BPF_VERIFIER_INTERNAL");

void bpf_free_kfunc_btf_tab(struct bpf_kfunc_btf_tab *tab)
{
	rcu_read_lock();
	rcu_dereference(active_verifier)->free_kfunc_btf_tab(tab);
	rcu_read_unlock();
}
EXPORT_SYMBOL_NS_GPL(bpf_free_kfunc_btf_tab, "BPF_VERIFIER_INTERNAL");

bool bpf_prog_has_kfunc_call(const struct bpf_prog *prog)
{
	bool ret;

	rcu_read_lock();
	ret = rcu_dereference(active_verifier)->prog_has_kfunc_call(prog);
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_NS_GPL(bpf_prog_has_kfunc_call, "BPF_VERIFIER_INTERNAL");
