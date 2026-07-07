/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_XNODE_SHMEM_H
#define _UAPI_LINUX_XNODE_SHMEM_H

#include <linux/types.h>
#include <linux/ioctl.h>

/*
 * Cross-node shared memory window.
 *
 * Layout of a window used as a BPF ringbuf (see
 * Documentation/bpf/multi-node-bpf.md):
 *
 *   page 0:  consumer_pos (the only page this node may write)
 *   page 1:  producer_pos
 *   page 2+: data
 */
struct xnode_shmem_info {
	__u64 base;	/* physical base of the window */
	__u64 size;	/* size in bytes */
	__u64 rsvd[2];
};

/* Mapping cacheability, selected per-fd before mmap()/EXPORT_DMABUF. */
enum {
	XNODE_SHMEM_WC		= 0,	/* write-combine, no sync needed (default) */
	XNODE_SHMEM_CACHED	= 1,	/* cacheable, requires SYNC/CPU-access sync */
};

/* Cache maintenance for a range, only meaningful in CACHED mode. */
struct xnode_shmem_sync {
	__u64 offset;	/* window-relative, page-aligned not required */
	__u64 size;
	__u32 flags;
	__u32 pad;
};

#define XNODE_SHMEM_SYNC_INVAL	(1U << 0)	/* discard stale lines before a read */
#define XNODE_SHMEM_SYNC_CLEAN	(1U << 1)	/* write dirty lines back after a write */

/* Export the window as a dma-buf (requires CONFIG_DMA_SHARED_BUFFER). */
struct xnode_shmem_dmabuf {
	__u32 flags;	/* XNODE_SHMEM_WC or XNODE_SHMEM_CACHED */
	__s32 fd;	/* out: the new dma-buf fd */
	__u64 pad;
};

#define XNODE_SHMEM_GET_INFO	_IOR('x', 0x01, struct xnode_shmem_info)
#define XNODE_SHMEM_SET_MODE	_IOW('x', 0x02, __u32)
#define XNODE_SHMEM_SYNC	_IOW('x', 0x03, struct xnode_shmem_sync)
#define XNODE_SHMEM_EXPORT_DMABUF _IOWR('x', 0x04, struct xnode_shmem_dmabuf)

#endif /* _UAPI_LINUX_XNODE_SHMEM_H */
