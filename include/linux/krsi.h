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
#ifndef _KRSI_H
#define _KRSI_H

#include <uapi/linux/bpf.h>

#ifdef CONFIG_SECURITY_KRSI
int krsi_prog_attach(const union bpf_attr *attr, struct bpf_prog *prog);
#else
static inline int krsi_prog_attach(const union bpf_attr *attr,
				      struct bpf_prog *prog)
{
	return -EINVAL;
}
#endif /* CONFIG_SECURITY_KRSI */

#endif /* _KRSI_H */
