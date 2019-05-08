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
#include <linux/init.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/security.h>
#include <linux/krsi.h>

#include "include/krsi_fs.h"
#include "include/krsi_init.h"

extern struct krsi_hook krsi_hooks_list[];

static struct dentry *krsi_dir;

static const struct file_operations krsi_hook_ops = {
	.llseek = generic_file_llseek,
};

int krsi_fs_initialized;

bool is_valid_hook_file(struct file *f) {
	return f->f_op == &krsi_hook_ops;
}

static struct krsi_fsdata *krsi_fsdata_alloc(void)
{
	struct krsi_fsdata *fs_data;
	struct bpf_prog_array __rcu     *progs;

	fs_data = kmalloc(sizeof (struct krsi_fsdata), GFP_KERNEL);
	if (!fs_data)
		return ERR_PTR(-ENOMEM);

	mutex_init(&fs_data->mutex);
	progs = bpf_prog_array_alloc(0, GFP_KERNEL);
	if (!progs)
		goto error;

	fs_data->progs = progs;
	return fs_data;

error:
	kfree(fs_data);
	return ERR_PTR(-ENOMEM);

}

static void krsi_fsdata_free(struct krsi_fsdata *fs_data)
{
	struct bpf_prog_array_item *item;

	if (IS_ERR_OR_NULL(fs_data))
		return;

	if (fs_data->progs) {
		item = rcu_dereference(fs_data->progs)->items;
		while (item->prog) {
			bpf_prog_put(item->prog);
			item++;
		}
		bpf_prog_array_free(fs_data->progs);
	}

	kfree(fs_data);
	return;
}

static void krsi_free_hook(struct krsi_hook *h) {
	if (IS_ERR_OR_NULL(h))
		return;

	/*
	 * bpm_lsm_fsdata_free and securityfs_remove handle
	 * errorneous or unallocated data.
	 */
	krsi_fsdata_free(h->h_fsdata);
	securityfs_remove(h->h_dentry);
	h->h_dentry = NULL;
	h->h_fsdata = NULL;
	return;
}

static int krsi_init_hook(struct krsi_hook *h, struct dentry *parent)
{
	struct krsi_fsdata *fs_data;
	struct dentry *h_dentry;
	int ret;

	h_dentry = securityfs_create_file(h->name, 0660, parent,
			NULL, &krsi_hook_ops);

	if (IS_ERR(h_dentry))
		return PTR_ERR(h_dentry);

	fs_data = krsi_fsdata_alloc();
	if (IS_ERR(fs_data)) {
		ret = PTR_ERR(fs_data);
		goto error;
	}

	h_dentry->d_fsdata = (void *)fs_data;
	h->h_dentry = h_dentry;
	h->h_fsdata = fs_data;
	return 0;

error:
	securityfs_remove(h_dentry);
	return ret;
}

static int __init krsi_fs_init(void)
{

	int h, error;
	struct krsi_hook *hook;

	krsi_dir = securityfs_create_dir(KRSI_SFS_NAME, NULL);
	if (IS_ERR(krsi_dir)) {
		int ret = PTR_ERR(krsi_dir);

		if (ret != -ENODEV)
			pr_err("Unable to create krsi sysfs dir: %d\n",
			       ret);
		krsi_dir = NULL;
		return ret;
	}

	/*
	 * If there is an error in initializing a hook, the initialization
	 * logic makes sure that it has been freed, but this means that
	 * cleanup should be called for all the other hooks. The cleanup
	 * logic handles uninitialized data.
	 */
	krsi_for_each_hook(h, hook) {
		error = krsi_init_hook(hook, krsi_dir);
		if (error < 0)
			goto error;
	}

	krsi_fs_initialized = 1;
	return 0;
error:
	krsi_for_each_hook(h, hook)
		krsi_free_hook(hook);
	securityfs_remove(krsi_dir);
	return error;
}

late_initcall(krsi_fs_init);
