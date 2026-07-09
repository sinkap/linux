/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_IPU_DMA_H
#define _UAPI_LINUX_IPU_DMA_H

#include <linux/types.h>
#include <linux/ioctl.h>

/*
 * IPU DMA binding: import a dma-buf for DMA by the IPU offload engine and
 * keep the resulting IOVA mapping alive.
 *
 * IPU_DMA_BIND imports @dmabuf_fd on the IPU's DMA device, programs the
 * engine, and returns @binding_fd: an fd that *owns* the mapping. The
 * binding holds its own reference on the dma-buf, so the binding alone keeps
 * both the memory and the IOVAs alive. Release the mapping by closing (or
 * unpinning) @binding_fd; the IOVAs stay valid for exactly as long as that
 * fd is open.
 */

/* IPU_DMA_BIND.flags: access direction of the IPU DMA */
#define IPU_DMA_F_READ		(1U << 0)	/* IPU reads the buffer  */
#define IPU_DMA_F_WRITE		(1U << 1)	/* IPU writes the buffer */
#define IPU_DMA_F_BIDIR		(IPU_DMA_F_READ | IPU_DMA_F_WRITE)

struct ipu_dma_bind {
	__s32	dmabuf_fd;	/* in:  dma-buf to import                     */
	__u32	flags;		/* in:  IPU_DMA_F_*                           */
	__s32	binding_fd;	/* out: fd owning the mapping (close to free) */
	__u32	nr_iovas;	/* out: number of IOVA segments               */
};

struct ipu_dma_iova {
	__u64	iova;		/* device address of this segment */
	__u64	len;		/* length of this segment         */
};

struct ipu_dma_get_iovas {
	__u32	nr;		/* in:  capacity of iovas[]; out: count returned */
	__u32	pad;
	__u64	iovas_ptr;	/* in:  __u64 cast of struct ipu_dma_iova *      */
};

#define IPU_DMA_BIND		_IOWR('I', 0x01, struct ipu_dma_bind)
#define IPU_DMA_GET_IOVAS	_IOWR('I', 0x02, struct ipu_dma_get_iovas)

#endif /* _UAPI_LINUX_IPU_DMA_H */
