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
#ifndef _KRSI_INIT_H
#define _KRSI_INIT_H

#include "krsi_fs.h"

enum krsi_hook_type {
	__MAX_KRSI_HOOK_TYPE,
};

extern int krsi_fs_initialized;

/*
 * The LSM creates one file per hook.
 */
struct krsi_hook {
	/*
	 * The name of the security hook, a file with this name will be created
	 * in the securityfs.
	 */
	const char *name;
	/*
	 * The type of the LSM hook, the LSM uses this to index the list of the
	 * hooks to run the eBPF programs that may have been attached.
	 */
	enum krsi_hook_type h_type;
	/*
	 * The dentry of the file created in securityfs, the the program is stored
	 * in the krsi_fsdata as private fsdata in the the dentry.
	 */
	struct dentry *h_dentry;
	/*
	 * A reference to the fsdata, also stored in the dentry.
	 */
	struct krsi_fsdata *h_fsdata;
};

#define KRSI_RUN_PROGS(TYPE, CTX, RET) \
	if (!krsi_fs_initialized) \
		RET = 0; \
	else { \
		RET = BPF_PROG_RUN_ARRAY( \
			krsi_hooks_list[TYPE].h_fsdata->progs, \
			CTX, BPF_PROG_RUN); \
	}

#define krsi_for_each_hook(h, hook) \
	for (h = 0, hook = &krsi_hooks_list[0]; \
	     h < __MAX_KRSI_HOOK_TYPE; \
	     h++, hook = &krsi_hooks_list[h])

#endif /* _KRSI_INIT_H */
