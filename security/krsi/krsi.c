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

#include <linux/lsm_hooks.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/filter.h>
#include <linux/bpf.h>

#include "include/krsi_init.h"

struct krsi_hook krsi_hooks_list[] = {
	#define KRSI_HOOK_INIT(TYPE, NAME, IMPL) \
		[TYPE] = { .h_type = TYPE, .name = #NAME },
	#include "include/hooks.h"
	#undef KRSI_HOOK_INIT
};

static struct security_hook_list krsi_hooks[] __lsm_ro_after_init = {
	#define KRSI_HOOK_INIT(TYPE, NAME, IMPL) LSM_HOOK_INIT(NAME, IMPL),
	#include "include/hooks.h"
	#undef KRSI_HOOK_INIT
};

static int __init krsi_init(void)
{
	security_add_hooks(krsi_hooks, ARRAY_SIZE(krsi_hooks), "krsi");
	pr_info("eBPF and LSM are friends now.\n");
	return 0;
}

DEFINE_LSM(krsi) = {
	.name = "krsi",
	.init = krsi_init,
};
