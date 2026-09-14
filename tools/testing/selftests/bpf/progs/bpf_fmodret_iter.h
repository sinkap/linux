/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BPF_FMODRET_ITER_H
#define __BPF_FMODRET_ITER_H

struct bpf_fmodret_iter_entry {
	__u32 btf_obj_id;
	__u32 btf_id;
	__u32 flags;
};

#endif /* __BPF_FMODRET_ITER_H */
