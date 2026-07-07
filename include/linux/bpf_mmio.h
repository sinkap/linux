/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BPF_MMIO_H
#define _LINUX_BPF_MMIO_H

#include <linux/types.h>

/*
 * Allowlist for the bpf_mmio_map() kfunc.
 *
 * BPF programs pass a raw physical address to bpf_mmio_map(); on its
 * own that is /dev/mem-grade access. A driver that wants to expose a
 * specific MMIO aperture to BPF registers its physical range here, and
 * bpf_mmio_map() refuses anything not fully contained in a registered
 * range. The allowlist is fail-closed: with no registered range, every
 * bpf_mmio_map() call fails.
 */
#ifdef CONFIG_BPF_SYSCALL
int bpf_mmio_register_region(phys_addr_t base, size_t size);
void bpf_mmio_unregister_region(phys_addr_t base, size_t size);
#else
static inline int bpf_mmio_register_region(phys_addr_t base, size_t size)
{
	return -EOPNOTSUPP;
}
static inline void bpf_mmio_unregister_region(phys_addr_t base, size_t size) {}
#endif

#endif /* _LINUX_BPF_MMIO_H */
