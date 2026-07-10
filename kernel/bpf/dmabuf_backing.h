/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BPF_DMABUF_BACKING_H
#define _BPF_DMABUF_BACKING_H

#include <linux/types.h>
#include <linux/errno.h>

struct dma_buf;
struct dma_buf_attachment;
struct sg_table;
struct page;

/*
 * A dma-buf imported as the page backing of a BPF map (reserved
 * ringbuf/arena). The dma-buf fd — not a raw physical address — is what
 * authorizes use of the memory: the exporter (typically a carveout
 * dma-heap or the IPU driver) owns the physical range, access is
 * controlled by the exporter's file permissions, and the attachment
 * keeps the pages pinned for the lifetime of the map.
 */
struct bpf_dmabuf_backing {
	struct dma_buf *dmabuf;
	struct dma_buf_attachment *attach;
	struct sg_table *sgt;
	struct page **pages;
	unsigned long nr_pages;
};

#ifdef CONFIG_DMA_SHARED_BUFFER
int bpf_dmabuf_backing_get(int fd, unsigned long nr_pages,
			   struct bpf_dmabuf_backing *b);
void bpf_dmabuf_backing_put(struct bpf_dmabuf_backing *b);
#else
static inline int bpf_dmabuf_backing_get(int fd, unsigned long nr_pages,
					 struct bpf_dmabuf_backing *b)
{
	return -EOPNOTSUPP;
}

static inline void bpf_dmabuf_backing_put(struct bpf_dmabuf_backing *b) {}
#endif

#endif /* _BPF_DMABUF_BACKING_H */
