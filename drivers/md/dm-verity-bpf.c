// SPDX-License-Identifier: GPL-2.0-only
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/dm-verity-loadpin.h>
#include <linux/btf_ids.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/slab.h> // Added for kfree/kmem functions, often necessary.
#include <linux/minmax.h> // Added for min_t

#include "dm.h"
#include "dm-core.h"
#include "dm-verity.h"

#define DM_VERITY_SHA256_SIZE 32

__bpf_kfunc_start_defs();

/**
 * bpf_get_dm_verity_digest - Retrieve the root hash of a dm-verity device.
 * @file: File handle referencing a file on the dm-verity device.
 * @digest_p: BPF dynamic pointer where the raw 32-byte SHA256 digest will be written.
 *
 * This BPF kfunc obtains the root digest (hash) of the dm-verity device backing
 * the given file's filesystem and writes the raw bytes into the BPF dynamic pointer.
 * The caller (BPF program) must ensure @digest_p points to a buffer of at least
 * DM_VERITY_SHA256_SIZE (32) bytes.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
__bpf_kfunc int bpf_get_dm_verity_digest(struct file *file,
					 struct bpf_dynptr *digest_p)
{
	struct bpf_dynptr_kern *digest_ptr = (struct bpf_dynptr_kern *)digest_p;
	const struct inode *inode;
	u32 dynptr_sz = __bpf_dynptr_size(digest_ptr);
	u8 *arg; // Pointer to the raw dynptr data
	struct mapped_device *md;
	struct dm_table *table;
	struct dm_target *ti;
	int srcu_idx;
	int verity_mode;
	u8 *kernel_digest = NULL;
	unsigned int kernel_digest_len;
	int ret = -EPERM;
	size_t copy_len;

	if (!file)
		return -EINVAL;

	if (dynptr_sz != DM_VERITY_SHA256_SIZE)
		return -EINVAL;

	arg = __bpf_dynptr_data_rw(digest_ptr, dynptr_sz);
	if (!arg)
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

	if (table->num_targets != 1) {
		ret = -ENODEV;
		goto out_table;
	}

	ti = &table->targets[0];

	if (!dm_is_verity_target(ti)) {
		ret = -ENODEV;
		goto out_table;
	}

	verity_mode = dm_verity_get_mode(ti);
	if (verity_mode != DM_VERITY_MODE_EIO &&
	    verity_mode != DM_VERITY_MODE_RESTART &&
	    verity_mode != DM_VERITY_MODE_PANIC) {
		ret = -EPERM;
		goto out_table;
	}

	if (dm_verity_get_root_digest(ti, &kernel_digest, &kernel_digest_len)) {
		ret = -EIO;
		goto out_table;
	}

	if (kernel_digest_len != DM_VERITY_SHA256_SIZE) {
		ret = -EOPNOTSUPP;
		goto out_kfree;
	}

	copy_len = min_t(size_t, dynptr_sz, DM_VERITY_SHA256_SIZE);

	memcpy(arg, kernel_digest, copy_len);

	if (dynptr_sz > copy_len)
		memset(arg + copy_len, 0, dynptr_sz - copy_len);

	ret = 0;

out_kfree:
	kfree(kernel_digest);
out_table:
	dm_put_live_table(md, srcu_idx);
out_md:
	dm_put(md);
	return ret;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(dm_verity_kfunc_set)
BTF_ID_FLAGS(func, bpf_get_dm_verity_digest, KF_SLEEPABLE | KF_TRUSTED_ARGS)
BTF_KFUNCS_END(dm_verity_kfunc_set)

static const struct btf_kfunc_id_set dm_verity_kfunc_ops = {
	.owner = THIS_MODULE,
	.set = &dm_verity_kfunc_set,
};

static int __init register_dm_verity_kfunc(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_LSM,
					 &dm_verity_kfunc_ops);
}

late_initcall(register_dm_verity_kfunc);