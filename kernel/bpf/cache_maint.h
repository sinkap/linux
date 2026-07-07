/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BPF_CACHE_MAINT_H
#define _BPF_CACHE_MAINT_H

#include <linux/types.h>

/*
 * Cache maintenance for BPF maps backed by reserved physical memory
 * that is shared with a non-coherent observer (e.g. another node
 * reading/writing DRAM directly through the fabric).
 *
 * bpf_nc_cache_clean: write dirty lines back to the point of
 * coherency so a non-coherent reader observes them.
 *
 * bpf_nc_cache_inval: discard locally cached (possibly stale) lines
 * so the next read observes a non-coherent writer's update. x86 has
 * no pure invalidate; clflush writes dirty lines back first. Callers
 * must therefore only invalidate lines they never dirty locally, so
 * that the writeback-vs-discard difference cannot be observed.
 *
 * Both include the barriers needed to order the maintenance against
 * surrounding accesses (dsb on arm64, mb() in clflush_cache_range).
 */
#if defined(CONFIG_ARM64)
#include <asm/cacheflush.h>

static inline bool bpf_nc_cache_maint_available(void)
{
	return true;
}

static inline void bpf_nc_cache_clean(void *addr, size_t len)
{
	dcache_clean_poc((unsigned long)addr, (unsigned long)addr + len);
}

static inline void bpf_nc_cache_inval(void *addr, size_t len)
{
	dcache_inval_poc((unsigned long)addr, (unsigned long)addr + len);
}

#elif defined(CONFIG_X86_64)
#include <asm/cacheflush.h>

static inline bool bpf_nc_cache_maint_available(void)
{
	return true;
}

static inline void bpf_nc_cache_clean(void *addr, size_t len)
{
	clflush_cache_range(addr, len);
}

static inline void bpf_nc_cache_inval(void *addr, size_t len)
{
	clflush_cache_range(addr, len);
}

#else

static inline bool bpf_nc_cache_maint_available(void)
{
	return false;
}

static inline void bpf_nc_cache_clean(void *addr, size_t len) {}
static inline void bpf_nc_cache_inval(void *addr, size_t len) {}

#endif

#endif /* _BPF_CACHE_MAINT_H */
