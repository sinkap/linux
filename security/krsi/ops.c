/*
 * Kernel Runtime Security Instrumentation (KRSI) LSM
 *
 * Author: KP Singh <kpsingh@google.com>
 *
 * Copyright (C) 2019 Google Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 */

#include <linux/err.h>
#include <linux/types.h>
#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/security.h>
#include <linux/krsi.h>
#include <linux/binfmts.h>
#include <linux/highmem.h>

#include "include/krsi_init.h"
#include "include/krsi_fs.h"

extern struct krsi_hook krsi_hooks_list[];

static struct dentry *get_dentry_from_fd(int fd)
{
	struct fd f = fdget(fd);
	struct dentry *dentry;

	if (!f.file)
		return ERR_PTR(-EBADF);

	if (!is_valid_hook_file(f.file)) {
		fdput(f);
		return ERR_PTR(-EINVAL);
	}

	dentry = file_dentry(f.file);
	fdput(f);
	return dentry;
}

int krsi_prog_attach(const union bpf_attr *attr, struct bpf_prog *prog) {
	struct dentry *dentry;
	struct bpf_prog_array __rcu *old_array;
	struct bpf_prog_array *new_array;
	struct krsi_fsdata *fs_data;
	int ret = 0;

	dentry = get_dentry_from_fd(attr->target_fd);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	fs_data = dentry->d_fsdata;
	mutex_lock(&fs_data->mutex);
	old_array = fs_data->progs;

	ret = bpf_prog_array_copy(old_array, NULL, prog, &new_array);
	if (ret < 0) {
		ret = -ENOMEM;
		goto unlock;
	}

	rcu_assign_pointer(fs_data->progs, new_array);
	bpf_prog_array_free(old_array);

unlock:
	mutex_unlock(&fs_data->mutex);
	return ret;
}

const struct bpf_prog_ops krsi_prog_ops = {
};

static bool krsi_prog_is_valid_access(int off, int size,
					 enum bpf_access_type type,
					 const struct bpf_prog *prog,
					 struct bpf_insn_access_aux *info)
{
	if (off < 0 || off >= sizeof(struct linux_binprm))
		return false;
	if (type != BPF_READ)
		return false;
	if (off % size != 0)
		return false;
	return true;
	/*
	 * Assertion for 32 bit to make sure last 8 byte access
	 * (BPF_DW) to the last 4 byte member is disallowed.
	 */
	if (off + size > sizeof(struct linux_binprm))
		return false;

	return true;
}

static struct page *get_arg_page(struct linux_binprm *bprm, unsigned long pos)
{
	struct page *page;
	int ret;
	unsigned int gup_flags = FOLL_FORCE;

	/*
	 * We are doing an exec().  'current' is the process
	 * doing the exec and bprm->mm is the new process's mm.
	 */
	ret = get_user_pages_remote(current, bprm->mm, pos, 1, gup_flags,
			&page, NULL, NULL);
	if (ret <= 0)
		return NULL;

	return page;
}

static int bprm_dump_env(struct linux_binprm *bprm, char *buffer)
{
	int i = 0;
	unsigned long offset;
	char *kaddr;
	struct page *page;
	unsigned long p = bprm->p;
	int argc = bprm->argc;
	int envc = bprm->envc;

	if (!bprm->envc)
	        return 0;


	do {
	        offset = p & ~PAGE_MASK;
	        page = get_arg_page(bprm, p);
	        if (!page)
			return -EFAULT;
		kaddr = kmap_atomic(page);

	        for (; offset < PAGE_SIZE; offset++, p++) {
	                char c = kaddr[offset];
	                if (c) {
	                        if (argc)
	                                continue;
	                        if (envc) {
	                                buffer[i++] = c;
	                                if (unlikely(i) > PAGE_SIZE)
						return -ENAMETOOLONG;
	                                continue;
	                        }
	                }
	                if (argc) {
	                        argc--;
	                        continue;
	                }
	                if (envc) {
	                        buffer[i++] = c;
	                        if (unlikely(i) > PAGE_SIZE)
					return -ENAMETOOLONG;
	                        envc--;
	                        continue;
	                }
	        }
	        kunmap_atomic(kaddr);
	        put_page(page);
	} while (offset == PAGE_SIZE && envc != 0);

	return i - 1;

}

BPF_CALL_3(krsi_get_bprm_envs, struct linux_binprm *, bprm, void *, dest,
	   u32, size)
{
	int len;
	char *buffer;

	buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buffer)
	        return -ENOMEM;

	len = bprm_dump_env(bprm, buffer);
	if (len < 0) {
		goto out;
	}
	memcpy(dest, buffer, len);

out:
	kfree(buffer);
	return len;
}

static const struct bpf_func_proto krsi_get_bprm_envs_proto = {
	.func		= krsi_get_bprm_envs,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg3_type	= ARG_CONST_SIZE_OR_ZERO,
};

BPF_CALL_5(krsi_event_output, void *, log,
	   struct bpf_map *, map, u64, flags, void *, data, u64, size)
{
	if (unlikely(flags & ~(BPF_F_INDEX_MASK)))
		return -EINVAL;

	return bpf_event_output(map, flags, data, size, NULL, 0, NULL);
}

static const struct bpf_func_proto krsi_event_output_proto =  {
	.func		= krsi_event_output,
	.gpl_only       = true,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type      = ARG_CONST_MAP_PTR,
	.arg3_type      = ARG_ANYTHING,
	.arg4_type      = ARG_PTR_TO_MEM,
	.arg5_type      = ARG_CONST_SIZE_OR_ZERO,
};


static const struct bpf_func_proto *
krsi_prog_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_krsi_get_bprm_envs:
		return &krsi_get_bprm_envs_proto;
	case BPF_FUNC_perf_event_output:
		return &krsi_event_output_proto;
	default:
		return NULL;
	}
}

const struct bpf_verifier_ops krsi_verifier_ops = {
	.get_func_proto  = krsi_prog_func_proto,
	.is_valid_access = krsi_prog_is_valid_access,
};
