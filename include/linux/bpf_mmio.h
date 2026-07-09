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

/*
 * Physical-range allowlist for the bpf_mmio_map_region() kfunc -- the second
 * way to name an aperture, for a *fixed* region owned by a trusted in-kernel
 * driver (e.g. a doorbell/mailbox) rather than a per-fd grant. The driver
 * registers the range; bpf_mmio_map_region() refuses anything not fully inside
 * a registered range, and takes no fd so it can be mapped from any context.
 * Fail-closed: with nothing registered, it maps nothing.
 */
#ifdef CONFIG_BPF_SYSCALL
int bpf_mmio_register_provider(const struct bpf_mmio_provider *prov);
void bpf_mmio_unregister_provider(const struct bpf_mmio_provider *prov);
int bpf_mmio_register_region(phys_addr_t base, size_t size);
void bpf_mmio_unregister_region(phys_addr_t base, size_t size);
#else
static inline int bpf_mmio_register_provider(const struct bpf_mmio_provider *prov)
{
	return -EOPNOTSUPP;
}
static inline void bpf_mmio_unregister_provider(const struct bpf_mmio_provider *prov) {}
static inline int bpf_mmio_register_region(phys_addr_t base, size_t size)
{
	return -EOPNOTSUPP;
}
static inline void bpf_mmio_unregister_region(phys_addr_t base, size_t size) {}
#endif

#endif /* _LINUX_BPF_MMIO_H */
