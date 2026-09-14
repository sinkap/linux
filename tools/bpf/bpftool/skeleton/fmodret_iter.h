/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */

#ifndef __FMODRET_ITER_H
#define __FMODRET_ITER_H

enum fmodret_iter_flags {
	FMODRET_ITER_F_SLEEPABLE = 1U << 5,
};

struct fmodret_iter_entry {
	__u32 btf_obj_id;
	__u32 btf_id;
	__u32 flags;
};

#endif /* __FMODRET_ITER_H */
