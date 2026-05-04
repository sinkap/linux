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

static int stub_map_set_for_each_callback_args(struct bpf_verifier_env *env,
					       struct bpf_func_state *caller,
					       struct bpf_func_state *callee)
{
	return -ENOENT;
}

/* Pre-registration fallback.  Active until the built-in verifier
 * registers itself via subsys_initcall.  Owner is NULL so dispatch
 * takes no try_module_get() reference.
 */
static struct bpf_verifier_impl stub_verifier_impl = {
	.check			= stub_check,
	.check_attach_target	= stub_check_attach_target,
	.patch_insn_data	= stub_patch_insn_data,
	.dup_insn_aux_data	= stub_dup_insn_aux_data,
	.restore_insn_aux_data	= stub_restore_insn_aux_data,
	.get_kfunc_addr		= stub_get_kfunc_addr,
	.free_kfunc_btf_tab	= stub_free_kfunc_btf_tab,
	.prog_has_kfunc_call	= stub_prog_has_kfunc_call,
	.map_set_for_each_callback_args = stub_map_set_for_each_callback_args,
	.owner			= NULL,
	.name			= "stub",
	.abi_version		= BPF_VERIFIER_ABI_VERSION,
};

static struct bpf_verifier_impl __rcu *active_verifier =
	RCU_INITIALIZER(&stub_verifier_impl);

/* Stack of registered verifier impls, oldest at the head, top-of-stack
 * (the currently active impl) at the tail.  active_verifier always
 * points at the tail.  The stub is the implicit bottom -- never on the
 * list.  Each non-stub registration pins the impl beneath it via
 * try_module_get(), so out-of-order rmmod is refused by the module
 * subsystem.
 */
struct bpf_verifier_stack_node {
	struct list_head list;
	struct bpf_verifier_impl *impl;
};
static LIST_HEAD(verifier_stack);

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
	struct bpf_verifier_stack_node *node;
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

	node = kzalloc_obj(*node, GFP_KERNEL);
	if (!node)
		return -ENOMEM;
	node->impl = impl;

	mutex_lock(&verifier_register_mutex);
	cur = rcu_dereference_protected(active_verifier,
					lockdep_is_held(&verifier_register_mutex));
	/* Pin the impl we're stacking on top of so its module can't be
	 * removed while we sit above it.  When @cur is the static stub
	 * (owner == NULL), try_module_get() is a no-op.
	 */
	if (cur->owner && !try_module_get(cur->owner)) {
		mutex_unlock(&verifier_register_mutex);
		kfree(node);
		return -ENOENT;
	}
	list_add_tail(&node->list, &verifier_stack);
	rcu_assign_pointer(active_verifier, impl);
	mutex_unlock(&verifier_register_mutex);

	/* Wait for any in-flight readers to observe the new impl before
	 * returning -- not strictly required for correctness (readers
	 * holding the old impl keep an owner ref via try_module_get and
	 * release it normally) but gives a tighter "registered" semantic.
	 */
	synchronize_rcu();

	pr_info("bpf: verifier '%s' active (replacing '%s')\n",
		impl->name ?: "(unnamed)",
		cur->name ?: "(unnamed)");
	return 0;
}
EXPORT_SYMBOL_GPL(register_bpf_verifier);

void unregister_bpf_verifier(struct bpf_verifier_impl *impl)
{
	struct bpf_verifier_stack_node *top;
	struct bpf_verifier_impl *cur, *next, *below;

	if (WARN_ON_ONCE(!impl))
		return;

	mutex_lock(&verifier_register_mutex);
	cur = rcu_dereference_protected(active_verifier,
					lockdep_is_held(&verifier_register_mutex));
	if (WARN(cur != impl,
		 "bpf: unregister of non-top verifier '%s' (top is '%s'); module refs should have prevented this\n",
		 impl->name ?: "(unnamed)", cur->name ?: "(unnamed)")) {
		mutex_unlock(&verifier_register_mutex);
		return;
	}
	top = list_last_entry(&verifier_stack, struct bpf_verifier_stack_node, list);
	list_del(&top->list);
	if (list_empty(&verifier_stack)) {
		next = &stub_verifier_impl;
		below = &stub_verifier_impl;
	} else {
		next = list_last_entry(&verifier_stack,
				       struct bpf_verifier_stack_node,
				       list)->impl;
		below = next;
	}
	rcu_assign_pointer(active_verifier, next);
	mutex_unlock(&verifier_register_mutex);

	/* After synchronize_rcu(), no new caller can observe @impl via
	 * the dispatcher.  Drain any caller that observed it before the
	 * swap.
	 */
	synchronize_rcu();
	wait_event(verifier_drain_wq, atomic_read(&verifier_in_flight) == 0);

	/* Drop the module ref we took in register_bpf_verifier on the
	 * impl we were stacked on top of.  After this, the now-revealed
	 * impl below us can be unloaded if no further user pins it.
	 */
	if (below->owner)
		module_put(below->owner);

	kfree(top);

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

int map_set_for_each_callback_args(struct bpf_verifier_env *env,
				   struct bpf_func_state *caller,
				   struct bpf_func_state *callee)
{
	return rcu_dereference_check(active_verifier, 1)
		->map_set_for_each_callback_args(env, caller, callee);
}
EXPORT_SYMBOL_NS_GPL(map_set_for_each_callback_args, "BPF_VERIFIER_INTERNAL");
