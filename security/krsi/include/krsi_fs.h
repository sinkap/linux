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
#ifndef _KRSI_FS_H
#define _KRSI_FS_H

#include <linux/bpf.h>
#include <linux/fs.h>
#include <linux/types.h>


/*
 * The FS data to attach the BPF programs to a given LSM hook. This is stored in the
 * dentry of the per-hook file created in securityfs.
 */
struct krsi_fsdata {
	struct mutex mutex;
	struct bpf_prog_array __rcu	*progs;
};

struct bpf_lsm_hook;

bool is_valid_hook_file(struct file *f);

/*
 * The name of the directory created in /sys/kernel/security (securityfs).
 */
#define KRSI_SFS_NAME "krsi"


#endif /* _KRSI_FS_H */
