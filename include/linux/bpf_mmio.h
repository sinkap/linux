/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BPF_MMIO_H
#define _LINUX_BPF_MMIO_H

#include <linux/types.h>

struct file;
struct file_operations;

/*
 * MMIO provider interface for the bpf_mmio_map() kfunc.
 *
 * bpf_mmio_map() takes an fd, not a physical address: a program proves it is
 * authorized to touch an aperture by holding an fd that some subsystem (the
 * "provider", e.g. vfio-pci for a device BAR) handed it. The provider
 * registers the file_operations of those fds and a resolver that translates
 * (file, offset, size) into a CPU-physical MMIO range, enforcing its own
 * access control and range restrictions in the process.
 *
 * This keeps the /dev/mem-grade decision -- which physical memory may be
 * touched, and by whom -- with the subsystem that owns the device, and scopes
 * access to holding the fd rather than to a global allowlist. With no provider
 * registered, bpf_mmio_map() fails for every fd.
 */
struct bpf_mmio_provider {
	const struct file_operations *fops;	/* fd type this provider owns */
	const char *name;
	/*
	 * Validate [offset, offset+size) against the region named by @file and
	 * the caller's authorization, and return its CPU-physical base in
	 * *@phys. Return 0 on success or a negative errno.
	 */
	int (*resolve)(struct file *file, u64 offset, size_t size,
		       phys_addr_t *phys);
};

#ifdef CONFIG_BPF_SYSCALL
int bpf_mmio_register_provider(const struct bpf_mmio_provider *prov);
void bpf_mmio_unregister_provider(const struct bpf_mmio_provider *prov);
#else
static inline int bpf_mmio_register_provider(const struct bpf_mmio_provider *prov)
{
	return -EOPNOTSUPP;
}
static inline void bpf_mmio_unregister_provider(const struct bpf_mmio_provider *prov) {}
#endif

#endif /* _LINUX_BPF_MMIO_H */
