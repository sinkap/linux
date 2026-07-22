// SPDX-License-Identifier: GPL-2.0
/*
 * DMA-BUF carveout heap exporter
 *
 * Exposes an *exclusively* reserved memory region (a /reserved-memory node
 * that is neither `reusable` (CMA) nor `no-map`) as its own dma-heap. Unlike
 * the CMA heap the region is memblock_reserve()d out of the page allocator,
 * so it is never used for movable fallback -- allocations cannot fail with
 * -EBUSY under memory pressure, and the region is not zeroed/reused behind a
 * long-lived buffer. The region keeps its struct pages, so the resulting
 * dma-buf is page-backed and can back a BPF map (BPF_F_DMABUF).
 *
 * A region opts in with an `export;` boolean property. shared-dma-pool
 * (CMA / coherent pool) and restricted-dma-pool (swiotlb) regions are handled
 * by their own allocators and are skipped.
 */

#define pr_fmt(fmt) "carveout_heap: " fmt

#include <linux/dma-buf.h>
#include <linux/dma-heap.h>
#include <linux/dma-mapping.h>
#include <linux/genalloc.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_reserved_mem.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>

struct carveout_heap {
	struct dma_heap *heap;
	struct gen_pool *pool;
};

struct carveout_buffer {
	struct carveout_heap *heap;
	struct mutex lock;
	struct list_head attachments;
	phys_addr_t base;
	size_t len;
	unsigned int nr_pages;
	struct page **pages;
};

struct carveout_attachment {
	struct device *dev;
	struct sg_table table;
	struct list_head list;
	bool mapped;
};

static int carveout_attach(struct dma_buf *dmabuf,
			   struct dma_buf_attachment *attachment)
{
	struct carveout_buffer *b = dmabuf->priv;
	struct carveout_attachment *a;
	int ret;

	a = kzalloc(sizeof(*a), GFP_KERNEL);
	if (!a)
		return -ENOMEM;

	/*
	 * A carveout is physically contiguous, so an unbounded table would
	 * coalesce into one segment spanning the whole buffer -- longer than
	 * the attaching device's advertised max DMA segment size (64K for
	 * devices that never set dma_parms). That violates the DMA API
	 * (dma-debug flags it) and can fail on IOMMU paths that enforce the
	 * limit; split segments to what the device claims to support.
	 */
	ret = sg_alloc_table_from_pages_segment(&a->table, b->pages,
						b->nr_pages, 0, b->len,
						dma_get_max_seg_size(attachment->dev),
						GFP_KERNEL);
	if (ret) {
		kfree(a);
		return ret;
	}

	a->dev = attachment->dev;
	INIT_LIST_HEAD(&a->list);
	attachment->priv = a;

	mutex_lock(&b->lock);
	list_add(&a->list, &b->attachments);
	mutex_unlock(&b->lock);

	return 0;
}

static void carveout_detach(struct dma_buf *dmabuf,
			    struct dma_buf_attachment *attachment)
{
	struct carveout_buffer *b = dmabuf->priv;
	struct carveout_attachment *a = attachment->priv;

	mutex_lock(&b->lock);
	list_del(&a->list);
	mutex_unlock(&b->lock);

	sg_free_table(&a->table);
	kfree(a);
}

static struct sg_table *carveout_map(struct dma_buf_attachment *attachment,
				     enum dma_data_direction dir)
{
	struct carveout_attachment *a = attachment->priv;
	int ret;

	/* Propagate the real errno: -EIO/-ENXIO/-EINVAL from a
	 * misconfigured IOMMU must stay distinguishable from -ENOMEM.
	 */
	ret = dma_map_sgtable(attachment->dev, &a->table, dir, 0);
	if (ret)
		return ERR_PTR(ret);
	a->mapped = true;
	return &a->table;
}

static void carveout_unmap(struct dma_buf_attachment *attachment,
			   struct sg_table *table, enum dma_data_direction dir)
{
	struct carveout_attachment *a = attachment->priv;

	a->mapped = false;
	dma_unmap_sgtable(attachment->dev, table, dir, 0);
}

static int carveout_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct carveout_buffer *b = dmabuf->priv;
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long pfn = PHYS_PFN(b->base) + vma->vm_pgoff;

	if ((vma->vm_flags & (VM_SHARED | VM_MAYSHARE)) == 0)
		return -EINVAL;
	if (vma->vm_pgoff + (size >> PAGE_SHIFT) > b->nr_pages)
		return -EINVAL;

	vm_flags_set(vma, VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP);
	return remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot);
}

static void carveout_release(struct dma_buf *dmabuf)
{
	struct carveout_buffer *b = dmabuf->priv;

	gen_pool_free(b->heap->pool, b->base, b->len);
	kfree(b->pages);
	kfree(b);
}

static const struct dma_buf_ops carveout_buf_ops = {
	.attach		= carveout_attach,
	.detach		= carveout_detach,
	.map_dma_buf	= carveout_map,
	.unmap_dma_buf	= carveout_unmap,
	.mmap		= carveout_mmap,
	.release	= carveout_release,
};

static struct dma_buf *carveout_allocate(struct dma_heap *heap,
					 unsigned long len, u32 fd_flags,
					 u64 heap_flags)
{
	struct carveout_heap *ch = dma_heap_get_drvdata(heap);
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	size_t size = PAGE_ALIGN(len);
	struct carveout_buffer *b;
	struct dma_buf *dmabuf;
	unsigned long paddr;
	unsigned int i;
	int ret;

	b = kzalloc(sizeof(*b), GFP_KERNEL);
	if (!b)
		return ERR_PTR(-ENOMEM);
	INIT_LIST_HEAD(&b->attachments);
	mutex_init(&b->lock);

	paddr = gen_pool_alloc(ch->pool, size);
	if (!paddr) {
		ret = -ENOMEM;
		goto err_free;
	}
	b->heap = ch;
	b->base = paddr;
	b->len = size;
	b->nr_pages = size >> PAGE_SHIFT;

	b->pages = kmalloc_array(b->nr_pages, sizeof(*b->pages), GFP_KERNEL);
	if (!b->pages) {
		ret = -ENOMEM;
		goto err_pool;
	}
	for (i = 0; i < b->nr_pages; i++)
		b->pages[i] = pfn_to_page(PHYS_PFN(paddr) + i);

	exp_info.exp_name = dma_heap_get_name(heap);
	exp_info.ops = &carveout_buf_ops;
	exp_info.size = size;
	exp_info.flags = fd_flags;
	exp_info.priv = b;

	dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR(dmabuf)) {
		ret = PTR_ERR(dmabuf);
		goto err_pages;
	}
	return dmabuf;

err_pages:
	kfree(b->pages);
err_pool:
	gen_pool_free(ch->pool, paddr, size);
err_free:
	kfree(b);
	return ERR_PTR(ret);
}

static const struct dma_heap_ops carveout_heap_ops = {
	.allocate = carveout_allocate,
};

/*
 * Expose [base, base+size) as an exclusive carveout dma-heap named @name.
 * The region must be reserved RAM with valid struct pages (a DT
 * reserved-memory node without `no-map`, or a reserve_mem= region) so the
 * resulting dma-buf is page-backed and can back a BPF map.
 */
static int __init carveout_heap_add(const char *name, phys_addr_t base,
				    phys_addr_t size)
{
	struct dma_heap_export_info exp_info = {};
	struct carveout_heap *ch;
	int ret;

	/*
	 * An unaligned base would make gen_pool hand out unaligned paddrs
	 * whose PHYS_PFN() truncates into memory before the region; an
	 * unaligned size would leave a partial tail page in the pool.
	 */
	if (!size || !PAGE_ALIGNED(base) || !PAGE_ALIGNED(size)) {
		pr_err("%s: base %pa / size %pa must be non-zero and page-aligned\n",
		       name, &base, &size);
		return -EINVAL;
	}

	ch = kzalloc(sizeof(*ch), GFP_KERNEL);
	if (!ch)
		return -ENOMEM;

	ch->pool = gen_pool_create(PAGE_SHIFT, NUMA_NO_NODE);
	if (!ch->pool) {
		ret = -ENOMEM;
		goto err_free;
	}
	ret = gen_pool_add(ch->pool, base, size, NUMA_NO_NODE);
	if (ret)
		goto err_pool;

	exp_info.name = name;
	exp_info.ops = &carveout_heap_ops;
	exp_info.priv = ch;

	ch->heap = dma_heap_add(&exp_info);
	if (IS_ERR(ch->heap)) {
		ret = PTR_ERR(ch->heap);
		goto err_pool;
	}

	pr_info("%s: %zu MiB at %pa\n", name, (size_t)size / SZ_1M, &base);
	return 0;

err_pool:
	gen_pool_destroy(ch->pool);
err_free:
	kfree(ch);
	return ret;
}

static int __init carveout_heap_of_setup(struct device_node *node)
{
	const struct reserved_mem *rmem;

	rmem = of_reserved_mem_lookup(node);
	if (!rmem)
		return -EINVAL;
	return carveout_heap_add(node->full_name, rmem->base, rmem->size);
}

/*
 * Regions reserved via the arch-generic reserve_mem= command line
 * (e.g. on x86, which has no /reserved-memory device tree): opt in by
 * naming them in carveout_heap.export=<name>[,<name>...]. reserve_mem
 * keeps the region as reserved RAM with struct pages, matching a DT
 * reserved-memory node without `no-map`.
 */
static char *carveout_export;
module_param_named(export, carveout_export, charp, 0444);
MODULE_PARM_DESC(export,
		 "comma-separated reserve_mem region names to expose as carveout heaps");

static void __init carveout_heap_reserve_mem_setup(void)
{
	char *list, *p, *name;

	if (!carveout_export)
		return;
	list = kstrdup(carveout_export, GFP_KERNEL);
	if (!list)
		return;
	p = list;
	while ((name = strsep(&p, ","))) {
		phys_addr_t start, size;

		if (!*name)
			continue;
		if (!reserve_mem_find_by_name(name, &start, &size)) {
			pr_warn("%s: no reserve_mem region by that name\n", name);
			continue;
		}
		if (carveout_heap_add(name, start, size))
			pr_warn("%s: failed to add carveout heap\n", name);
	}
	kfree(list);
}

static int __init carveout_heap_init(void)
{
	struct device_node *rmem_node, *node;

	/* Device-tree path: /reserved-memory nodes that opt in with export. */
	rmem_node = of_find_node_by_path("/reserved-memory");
	if (rmem_node) {
		for_each_child_of_node(rmem_node, node) {
			/* Handled by their own allocators. */
			if (of_device_is_compatible(node, "shared-dma-pool") ||
			    of_device_is_compatible(node, "restricted-dma-pool"))
				continue;
			if (!of_property_read_bool(node, "export"))
				continue;
			if (carveout_heap_of_setup(node))
				pr_warn("%pOFn: failed to add carveout heap\n",
					node);
		}
		of_node_put(rmem_node);
	}

	/* Arch-generic path: reserve_mem= regions named in carveout_heap.export. */
	carveout_heap_reserve_mem_setup();
	return 0;
}
module_init(carveout_heap_init);
MODULE_DESCRIPTION("DMA-BUF Carveout Heap");
MODULE_LICENSE("GPL");
MODULE_IMPORT_NS("DMA_BUF");
