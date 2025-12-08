// SPDX-License-Identifier: GPL-2.0-only
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/dm-verity-loadpin.h>
#include <linux/btf_ids.h>
#include <linux/bpf.h>
#include <linux/btf.h>

#include "dm.h"
#include "dm-core.h
#include "dm-verity.h"

__bpf_kfunc_start_defs();

/*
 * Kfunc: Iterates all targets in the DM table.
 * If ANY target is 'verity' and matches the binary 'digest', returns 0.
 */
__bpf_kfunc int bpf_verify_dm_verity_digest(struct file *file,
					    u8 *trusted_digest,
					    u32 trusted_digest_len)
{
	struct inode *inode;
	struct mapped_device *md;
	struct dm_table *table;
	struct dm_target *ti;
	int srcu_idx;
	int verity_mode;
	u8 *kernel_digest = NULL;
	unsigned int kernel_digest_len;
	int ret = -EPERM;

	/* Basic sanity checks */
	if (!file || !trusted_digest || trusted_digest_len == 0)
		return -EINVAL;

	inode = file_inode(file);
	if (!inode || !inode->i_sb || !inode->i_sb->s_bdev)
		return -EINVAL;

	md = dm_get_md(inode->i_sb->s_bdev->bd_dev);
	if (!md)
		return -ENXIO;

	table = dm_get_live_table(md, &srcu_idx);
	if (!table)
		goto out_md;

	if (table->num_targets != 1)
		goto out_table;

	ti = &table->targets[0];

	if (!dm_is_verity_target(ti))
		goto out_table;

	verity_mode = dm_verity_get_mode(ti);
	if (verity_mode != DM_VERITY_MODE_EIO &&
	    verity_mode != DM_VERITY_MODE_RESTART &&
	    verity_mode != DM_VERITY_MODE_PANIC) {
		goto out_table;
	}

	if (dm_verity_get_root_digest(ti, &kernel_digest, &kernel_digest_len))
		goto out_table;

	if (kernel_digest_len == trusted_digest_len &&
	    !memcmp(kernel_digest, trusted_digest, trusted_digest_len))
		ret = 0;

	kfree(kernel_digest);

out_table:
	dm_put_live_table(md, srcu_idx);
out_md:
	dm_put(md);
	return ret;
}

__bpf_kfunc_end_defs();

/* Register symbols for BPF */
BTF_KFUNCS_START(dm_verity_kfunc_set)
BTF_ID_FLAGS(func, bpf_verify_dm_verity_digest, KF_SLEEPABLE|KF_TRUSTED_ARGS)
BTF_KFUNCS_END(dm_verity_kfunc_set)

static const struct btf_kfunc_id_set dm_verity_kfunc_ops = {
	.owner = THIS_MODULE,
	.set = &dm_verity_kfunc_set,
};

static int __init register_dm_verity_kfunc(void)
{
	pr_err("calleeddd >>>>\n");
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_LSM,
					 &dm_verity_kfunc_ops);
}

late_initcall(register_dm_verity_kfunc);
