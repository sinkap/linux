// SPDX-License-Identifier: GPL-2.0
/*
 * dma-buf import for BPF maps backed by reserved/shared physical memory.
 *
 * Instead of accepting a raw physical address from userspace (which is
 * /dev/mem-grade access and bypasses STRICT_DEVMEM/lockdown), reserved
 * ringbufs and arenas take a dma-buf fd. Whoever can obtain the fd from
 * the exporter may use the memory; the kernel never trusts a
 * user-supplied address.
 */
#include <linux/dma-buf.h>
#include <linux/dma-mapping.h>
#include <linux/device.h>
#include <linux/scatterlist.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/mutex.h>

#include "dmabuf_backing.h"

/* dma_buf_attach() requires an importer device. BPF only needs CPU
 * access through the backing pages, but attach + map_attachment is the
 * sanctioned way to get at them while keeping the buffer pinned. One
 * lazily created device serves all imports.
 */
static struct device *bpf_dmabuf_idev;
static DEFINE_MUTEX(bpf_dmabuf_fdev_lock);

static struct device *bpf_dmabuf_importer_dev(void)
{
	mutex_lock(&bpf_dmabuf_fdev_lock);
	if (!bpf_dmabuf_idev) {
		struct device *dev;

		dev = root_device_register("bpf_dmabuf");
		if (IS_ERR(dev)) {
			dev = NULL;
		} else if (dma_coerce_mask_and_coherent(dev, DMA_BIT_MASK(64))) {
			root_device_unregister(dev);
			dev = NULL;
		}
		bpf_dmabuf_idev = dev;
	}
	mutex_unlock(&bpf_dmabuf_fdev_lock);

	return bpf_dmabuf_idev;
}

/*
 * Import @fd and collect at least @nr_pages backing pages. On success
 * the buffer stays attached (pages pinned) until
 * bpf_dmabuf_backing_put().
 */
int bpf_dmabuf_backing_get(int fd, unsigned long nr_pages,
			   struct bpf_dmabuf_backing *b)
{
	struct sg_page_iter piter;
	struct device *dev;
	unsigned long i = 0;
	int err;

	dev = bpf_dmabuf_importer_dev();
	if (!dev)
		return -ENODEV;

	b->dmabuf = dma_buf_get(fd);
	if (IS_ERR(b->dmabuf)) {
		err = PTR_ERR(b->dmabuf);
		b->dmabuf = NULL;
		return err;
	}

	err = -EINVAL;
	if (b->dmabuf->size < (u64)nr_pages << PAGE_SHIFT)
		goto err_put;

	b->attach = dma_buf_attach(b->dmabuf, dev);
	if (IS_ERR(b->attach)) {
		err = PTR_ERR(b->attach);
		goto err_put;
	}

	b->sgt = dma_buf_map_attachment_unlocked(b->attach, DMA_BIDIRECTIONAL);
	if (IS_ERR(b->sgt)) {
		err = PTR_ERR(b->sgt);
		goto err_detach;
	}

	b->pages = kvcalloc(nr_pages, sizeof(*b->pages), GFP_KERNEL);
	if (!b->pages) {
		err = -ENOMEM;
		goto err_unmap;
	}

	/* Exporters of non-page-backed memory (true MMIO) cannot back a
	 * BPF map: the ringbuf/arena code vmaps and user-mmaps individual
	 * struct pages.
	 */
	err = -EINVAL;
	for_each_sgtable_page(b->sgt, &piter, 0) {
		struct page *page = sg_page_iter_page(&piter);

		/* Accept ordinary RAM pages and ZONE_DEVICE pages (e.g. a
		 * host-memory region shared into a guest as a device); reject
		 * only true MMIO with no struct page.
		 */
		if (!page ||
		    (!pfn_valid(page_to_pfn(page)) && !is_zone_device_page(page)))
			goto err_free;
		b->pages[i++] = page;
		if (i == nr_pages)
			break;
	}
	if (i < nr_pages)
		goto err_free;

	b->nr_pages = nr_pages;
	return 0;

err_free:
	kvfree(b->pages);
	b->pages = NULL;
err_unmap:
	dma_buf_unmap_attachment_unlocked(b->attach, b->sgt, DMA_BIDIRECTIONAL);
err_detach:
	dma_buf_detach(b->dmabuf, b->attach);
err_put:
	dma_buf_put(b->dmabuf);
	b->dmabuf = NULL;
	return err;
}

void bpf_dmabuf_backing_put(struct bpf_dmabuf_backing *b)
{
	if (!b->dmabuf)
		return;

	kvfree(b->pages);
	dma_buf_unmap_attachment_unlocked(b->attach, b->sgt, DMA_BIDIRECTIONAL);
	dma_buf_detach(b->dmabuf, b->attach);
	dma_buf_put(b->dmabuf);
	memset(b, 0, sizeof(*b));
}
