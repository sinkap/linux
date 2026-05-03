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

/* Pre-registration fallback.  Active until the built-in verifier
 * registers itself via subsys_initcall.  Owner is NULL so dispatch
 * takes no try_module_get() reference.
 */
static struct bpf_verifier_impl stub_verifier_impl = {
	.check			= stub_check,
	.check_attach_target	= stub_check_attach_target,
	.owner			= NULL,
	.name			= "stub",
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

	if (!impl || !impl->check || !impl->check_attach_target)
		return -EINVAL;

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
