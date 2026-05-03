// SPDX-License-Identifier: GPL-2.0-only
/* Test module for the BPF verifier dispatcher.
 *
 * Registers a stub bpf_verifier_impl whose check() always fails.  Used
 * to validate the dispatch swap, drain and ABI-rejection paths in
 * kernel/bpf/verifier_dispatch.c without needing the (much larger)
 * loadable replacement verifier itself.
 *
 * Module parameters:
 *   abi_major: override ABI major version baked into this module's
 *              bpf_verifier_impl.  Defaults to the kernel's current
 *              BPF_VERIFIER_ABI_MAJOR; set to a different value to
 *              exercise the dispatcher's ABI rejection path
 *              (modprobe should fail with -ENOEXEC).
 *
 * Usage:
 *   # Replace the built-in verifier with the failing stub:
 *   modprobe bpf_verifier_replace_test
 *   # Any bpf(BPF_PROG_LOAD) now returns -ENOSYS.  Restore:
 *   modprobe -r bpf_verifier_replace_test
 *
 *   # ABI rejection:
 *   modprobe bpf_verifier_replace_test abi_major=99
 *   # -> modprobe fails, dmesg shows "bpf: rejecting verifier ..."
 */

#include <linux/atomic.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

static unsigned int abi_major = BPF_VERIFIER_ABI_MAJOR;
module_param(abi_major, uint, 0);
MODULE_PARM_DESC(abi_major,
		 "ABI major version to advertise (default: kernel's BPF_VERIFIER_ABI_MAJOR)");

static atomic_t check_calls = ATOMIC_INIT(0);
static atomic_t attach_calls = ATOMIC_INIT(0);

static int test_check(struct bpf_prog **prog, union bpf_attr *attr,
		      bpfptr_t uattr, __u32 uattr_size)
{
	atomic_inc(&check_calls);
	return -ENOSYS;
}

static int test_check_attach_target(struct bpf_verifier_log *log,
				    const struct bpf_prog *prog,
				    const struct bpf_prog *tgt_prog,
				    u32 btf_id,
				    struct bpf_attach_target_info *tgt_info)
{
	atomic_inc(&attach_calls);
	return -ENOSYS;
}

static struct bpf_verifier_impl test_impl = {
	.check			= test_check,
	.check_attach_target	= test_check_attach_target,
	.owner			= THIS_MODULE,
	.name			= "test-replace",
	/* .abi_version filled in at module_init so the abi_major
	 * module parameter can override it.
	 */
};

static int __init test_verifier_replace_init(void)
{
	int ret;

	test_impl.abi_version = ((u32)abi_major << 16) | BPF_VERIFIER_ABI_MINOR;
	ret = register_bpf_verifier(&test_impl);
	if (ret) {
		pr_err("bpf_verifier_replace_test: register failed: %d\n", ret);
		return ret;
	}
	pr_info("bpf_verifier_replace_test: active; bpf_check() will return -ENOSYS\n");
	return 0;
}

static void __exit test_verifier_replace_exit(void)
{
	unregister_bpf_verifier(&test_impl);
	pr_info("bpf_verifier_replace_test: removed; check_calls=%d attach_calls=%d\n",
		atomic_read(&check_calls), atomic_read(&attach_calls));
}

module_init(test_verifier_replace_init);
module_exit(test_verifier_replace_exit);

MODULE_AUTHOR("KP Singh <kpsingh@kernel.org>");
MODULE_DESCRIPTION("Test module for the BPF verifier dispatcher");
MODULE_LICENSE("GPL");
