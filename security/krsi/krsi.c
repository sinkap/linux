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

static int __init krsi_init(void)
{
	pr_info("eBPF and LSM are friends now.\n");
	return 0;
}

DEFINE_LSM(krsi) = {
	.name = "krsi",
	.init = krsi_init,
};
