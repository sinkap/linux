// SPDX-License-Identifier: GPL-2.0
/*
 * Cross-node shared memory window driver.
 *
 * Exposes a reserved physical window that is shared with another,
 * non-cache-coherent node (the producer) to userspace consumers on
 * this node, replacing raw /dev/mem access:
 *
 * - The BPF ringbuf permission discipline is enforced: a writable
 *   mapping is only allowed for page 0 (consumer_pos). producer_pos
 *   and the data pages can only be mapped read-only.
 *
 * - Access control is the device node's file permissions instead of
 *   /dev/mem-grade access to all of physical memory.
 *
 * Two access modes, selected per-fd with XNODE_SHMEM_SET_MODE:
 *
 * - WC (default): write-combine (uncacheable) mappings. Loads always
 *   observe DRAM and consumer_pos stores reach DRAM, so the consumer
 *   needs no cache maintenance — which EL0 could not perform anyway
 *   (DC IVAC is privileged on arm64). Simplest and correct.
 *
 * - CACHED: cacheable mappings for higher read bandwidth on large
 *   records. The consumer must then bracket accesses with
 *   XNODE_SHMEM_SYNC (invalidate before reading producer data, clean
 *   after writing consumer_pos). Maintenance is issued by the kernel
 *   on a WB kernel mapping of the window; arm64 D-caches are PIPT, so
 *   this reaches the physical lines that the userspace cacheable
 *   mapping caches too.
 *
 * The window can also be re-exported as a dma-buf
 * (XNODE_SHMEM_EXPORT_DMABUF) so consumer-side devices (a NIC) and
 * userspace consume it through the same abstraction as the producer;
 * CPU-access sync hooks into the same maintenance.
 *
 * The window is described by a reserved-memory node referenced via the
 * device's "memory-region" property. For DT-less bring-up and testing,
 * base= and size= module parameters create the device directly.
 */

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/kref.h>
#include <linux/of.h>
#include <linux/of_reserved_mem.h>
#include <linux/uaccess.h>
#include <linux/dma-buf.h>
#include <linux/dma-mapping.h>
#include <linux/scatterlist.h>
#include <linux/bpf_mmio.h>
#include <uapi/linux/xnode_shmem.h>

/*
 * Optionally expose the window to the bpf_mmio_map() kfunc allowlist,
 * so BPF programs on this node can access it as MMIO (e.g. to poke
 * device registers in the same reserved window). Off by default.
 */
static bool expose_mmio;
module_param(expose_mmio, bool, 0444);
MODULE_PARM_DESC(expose_mmio, "register the window with the bpf_mmio allowlist");

/*
 * Cache maintenance on the window's WB kernel mapping. Mirrors
 * kernel/bpf/cache_maint.h; kept local so the driver has no
 * dependency on BPF internals.
 */
#if defined(CONFIG_ARM64)
#include <asm/cacheflush.h>
#define XNODE_MAINT 1
static void xnode_clean(void *a, size_t n)
{
	dcache_clean_poc((unsigned long)a, (unsigned long)a + n);
}
static void xnode_inval(void *a, size_t n)
{
	dcache_inval_poc((unsigned long)a, (unsigned long)a + n);
}
#elif defined(CONFIG_X86_64)
#include <asm/cacheflush.h>
#define XNODE_MAINT 1
static void xnode_clean(void *a, size_t n) { clflush_cache_range(a, n); }
static void xnode_inval(void *a, size_t n) { clflush_cache_range(a, n); }
#else
#define XNODE_MAINT 0
static void xnode_clean(void *a, size_t n) {}
static void xnode_inval(void *a, size_t n) {}
#endif

struct xnode_shmem {
	phys_addr_t base;
	size_t size;
	struct miscdevice misc;
	struct mutex kmap_lock;
	void *kva;		/* lazy WB kernel mapping for maintenance */
	/*
	 * Open files cache a pointer to this struct, but the platform device
	 * can be unbound (which does not wait for open fds and, unlike rmmod,
	 * is not blocked by the THIS_MODULE open reference) while fds are
	 * still open. Refcount so the struct outlives both the device and any
	 * open file, whichever goes away last.
	 */
	struct kref ref;
};

/* per-open state */
struct xnode_shmem_file {
	struct xnode_shmem *xs;
	bool cached;
};

/* Lazily create the WB kernel mapping used for cache maintenance. */
static void *xnode_kva(struct xnode_shmem *xs)
{
	void *kva;

	mutex_lock(&xs->kmap_lock);
	if (!xs->kva)
		xs->kva = memremap(xs->base, xs->size, MEMREMAP_WB);
	kva = xs->kva;
	mutex_unlock(&xs->kmap_lock);
	return kva;
}

/*
 * Shared mmap policy: bounds-check, enforce that only page 0
 * (consumer_pos) is writable, and pick the pgprot for the mode.
 */
static int xnode_mmap_common(struct xnode_shmem *xs, struct vm_area_struct *vma,
			     bool cached)
{
	size_t len = vma->vm_end - vma->vm_start;
	u64 off = (u64)vma->vm_pgoff << PAGE_SHIFT;

	if (off + len < off || off + len > xs->size)
		return -EINVAL;

	if (vma->vm_flags & VM_WRITE) {
		if (vma->vm_pgoff != 0 || len != PAGE_SIZE)
			return -EPERM;
	} else {
		/* forbid a later mprotect(PROT_WRITE) upgrade */
		vm_flags_clear(vma, VM_MAYWRITE);
	}

	if (!cached)
		vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

	return remap_pfn_range(vma, vma->vm_start,
			       (xs->base + off) >> PAGE_SHIFT, len,
			       vma->vm_page_prot);
}

static int xnode_shmem_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct xnode_shmem_file *f = file->private_data;

	return xnode_mmap_common(f->xs, vma, f->cached);
}

static int xnode_do_sync(struct xnode_shmem *xs, struct xnode_shmem_sync *s)
{
	void *kva;

	if (!XNODE_MAINT)
		return -EOPNOTSUPP;
	if (s->offset + s->size < s->offset || s->offset + s->size > xs->size)
		return -EINVAL;
	if (!(s->flags & (XNODE_SHMEM_SYNC_INVAL | XNODE_SHMEM_SYNC_CLEAN)))
		return -EINVAL;

	kva = xnode_kva(xs);
	if (!kva)
		return -ENOMEM;

	/* Clean before invalidate if both are asked for, so a
	 * just-written consumer_pos in the same range is not discarded.
	 */
	if (s->flags & XNODE_SHMEM_SYNC_CLEAN)
		xnode_clean(kva + s->offset, s->size);
	if (s->flags & XNODE_SHMEM_SYNC_INVAL)
		xnode_inval(kva + s->offset, s->size);
	return 0;
}

/* ---- dma-buf export ---- */

struct xnode_dmabuf {
	phys_addr_t base;
	size_t size;
	void *kva;		/* WB mapping for CPU-access sync, or NULL */
	bool cached;
};

static struct sg_table *xnode_dmabuf_map(struct dma_buf_attachment *attach,
					 enum dma_data_direction dir)
{
	struct xnode_dmabuf *d = attach->dmabuf->priv;
	struct sg_table *sgt;
	dma_addr_t dma;
	int err;

	sgt = kzalloc(sizeof(*sgt), GFP_KERNEL);
	if (!sgt)
		return ERR_PTR(-ENOMEM);
	err = sg_alloc_table(sgt, 1, GFP_KERNEL);
	if (err) {
		kfree(sgt);
		return ERR_PTR(err);
	}

	/* No struct pages (no-map reserved memory): map the physical
	 * resource for the importing device instead.
	 */
	dma = dma_map_resource(attach->dev, d->base, d->size, dir, 0);
	if (dma_mapping_error(attach->dev, dma)) {
		sg_free_table(sgt);
		kfree(sgt);
		return ERR_PTR(-EIO);
	}
	sg_dma_address(sgt->sgl) = dma;
	sg_dma_len(sgt->sgl) = d->size;
	return sgt;
}

static void xnode_dmabuf_unmap(struct dma_buf_attachment *attach,
			       struct sg_table *sgt,
			       enum dma_data_direction dir)
{
	dma_unmap_resource(attach->dev, sg_dma_address(sgt->sgl),
			   sg_dma_len(sgt->sgl), dir, 0);
	sg_free_table(sgt);
	kfree(sgt);
}

static int xnode_dmabuf_mmap(struct dma_buf *dmabuf,
			     struct vm_area_struct *vma)
{
	struct xnode_dmabuf *d = dmabuf->priv;
	struct xnode_shmem xs = { .base = d->base, .size = d->size };

	return xnode_mmap_common(&xs, vma, d->cached);
}

static int xnode_dmabuf_begin(struct dma_buf *dmabuf,
			      enum dma_data_direction dir)
{
	struct xnode_dmabuf *d = dmabuf->priv;

	/* About to read on the CPU what a device/remote wrote: drop stale
	 * lines. Whole-buffer, since the op carries no range.
	 */
	if (d->cached && d->kva &&
	    (dir == DMA_FROM_DEVICE || dir == DMA_BIDIRECTIONAL))
		xnode_inval(d->kva, d->size);
	return 0;
}

static int xnode_dmabuf_end(struct dma_buf *dmabuf,
			    enum dma_data_direction dir)
{
	struct xnode_dmabuf *d = dmabuf->priv;

	if (d->cached && d->kva &&
	    (dir == DMA_TO_DEVICE || dir == DMA_BIDIRECTIONAL))
		xnode_clean(d->kva, d->size);
	return 0;
}

static void xnode_dmabuf_release(struct dma_buf *dmabuf)
{
	struct xnode_dmabuf *d = dmabuf->priv;

	if (d->kva)
		memunmap(d->kva);
	kfree(d);
}

static const struct dma_buf_ops xnode_dmabuf_ops = {
	.map_dma_buf	= xnode_dmabuf_map,
	.unmap_dma_buf	= xnode_dmabuf_unmap,
	.mmap		= xnode_dmabuf_mmap,
	.begin_cpu_access = xnode_dmabuf_begin,
	.end_cpu_access	= xnode_dmabuf_end,
	.release	= xnode_dmabuf_release,
};

static int xnode_export_dmabuf(struct xnode_shmem *xs,
			       struct xnode_shmem_dmabuf *arg)
{
	DEFINE_DMA_BUF_EXPORT_INFO(exp);
	struct xnode_dmabuf *d;
	struct dma_buf *dmabuf;
	int fd;

	if (arg->flags & ~XNODE_SHMEM_CACHED)
		return -EINVAL;
	if ((arg->flags & XNODE_SHMEM_CACHED) && !XNODE_MAINT)
		return -EOPNOTSUPP;

	d = kzalloc(sizeof(*d), GFP_KERNEL);
	if (!d)
		return -ENOMEM;
	d->base = xs->base;
	d->size = xs->size;
	d->cached = arg->flags & XNODE_SHMEM_CACHED;

	/* Own WB mapping so CPU-access sync is independent of the
	 * device's lifetime.
	 */
	if (d->cached) {
		d->kva = memremap(d->base, d->size, MEMREMAP_WB);
		if (!d->kva) {
			kfree(d);
			return -ENOMEM;
		}
	}

	exp.ops = &xnode_dmabuf_ops;
	exp.size = xs->size;
	exp.flags = O_RDWR;
	exp.priv = d;
	exp.exp_name = "xnode_shmem";

	dmabuf = dma_buf_export(&exp);
	if (IS_ERR(dmabuf)) {
		if (d->kva)
			memunmap(d->kva);
		kfree(d);
		return PTR_ERR(dmabuf);
	}

	fd = dma_buf_fd(dmabuf, O_CLOEXEC);
	if (fd < 0) {
		dma_buf_put(dmabuf);	/* runs release, frees d */
		return fd;
	}
	arg->fd = fd;
	return 0;
}

static long xnode_shmem_ioctl(struct file *file, unsigned int cmd,
			      unsigned long arg)
{
	struct xnode_shmem_file *f = file->private_data;
	struct xnode_shmem *xs = f->xs;
	void __user *uarg = (void __user *)arg;

	switch (cmd) {
	case XNODE_SHMEM_GET_INFO: {
		struct xnode_shmem_info info = {
			.base = xs->base,
			.size = xs->size,
		};

		return copy_to_user(uarg, &info, sizeof(info)) ? -EFAULT : 0;
	}
	case XNODE_SHMEM_SET_MODE: {
		u32 mode;

		if (copy_from_user(&mode, uarg, sizeof(mode)))
			return -EFAULT;
		if (mode == XNODE_SHMEM_CACHED && !XNODE_MAINT)
			return -EOPNOTSUPP;
		if (mode != XNODE_SHMEM_WC && mode != XNODE_SHMEM_CACHED)
			return -EINVAL;
		f->cached = (mode == XNODE_SHMEM_CACHED);
		return 0;
	}
	case XNODE_SHMEM_SYNC: {
		struct xnode_shmem_sync s;

		if (copy_from_user(&s, uarg, sizeof(s)))
			return -EFAULT;
		/* Reject non-zero reserved field so it stays available. */
		if (s.pad)
			return -EINVAL;
		return xnode_do_sync(xs, &s);
	}
	case XNODE_SHMEM_EXPORT_DMABUF: {
		struct xnode_shmem_dmabuf dbuf;
		int err;

		if (!IS_ENABLED(CONFIG_DMA_SHARED_BUFFER))
			return -EOPNOTSUPP;
		if (copy_from_user(&dbuf, uarg, sizeof(dbuf)))
			return -EFAULT;
		if (dbuf.pad)
			return -EINVAL;
		err = xnode_export_dmabuf(xs, &dbuf);
		if (err)
			return err;
		return copy_to_user(uarg, &dbuf, sizeof(dbuf)) ? -EFAULT : 0;
	}
	default:
		return -ENOTTY;
	}
}

static void xnode_shmem_free(struct kref *ref)
{
	struct xnode_shmem *xs = container_of(ref, struct xnode_shmem, ref);

	if (xs->kva)
		memunmap(xs->kva);
	mutex_destroy(&xs->kmap_lock);
	kfree(xs);
}

static int xnode_shmem_open(struct inode *inode, struct file *file)
{
	struct miscdevice *misc = file->private_data;
	struct xnode_shmem *xs = container_of(misc, struct xnode_shmem, misc);
	struct xnode_shmem_file *f;

	f = kzalloc(sizeof(*f), GFP_KERNEL);
	if (!f)
		return -ENOMEM;
	/* Keep xs alive for as long as this fd is open, even across an
	 * unbind of the underlying device.
	 */
	kref_get(&xs->ref);
	f->xs = xs;
	file->private_data = f;
	return 0;
}

static int xnode_shmem_release(struct inode *inode, struct file *file)
{
	struct xnode_shmem_file *f = file->private_data;

	kref_put(&f->xs->ref, xnode_shmem_free);
	kfree(f);
	return 0;
}

static const struct file_operations xnode_shmem_fops = {
	.owner		= THIS_MODULE,
	.open		= xnode_shmem_open,
	.release	= xnode_shmem_release,
	.mmap		= xnode_shmem_mmap,
	.unlocked_ioctl	= xnode_shmem_ioctl,
	/* All ioctl args are pointer-free and identically laid out on 32/64
	 * bit, so the generic pointer conversion is sufficient.
	 */
	.compat_ioctl	= compat_ptr_ioctl,
};

static int xnode_shmem_register(struct device *parent, phys_addr_t base,
				size_t size, struct xnode_shmem **out)
{
	struct xnode_shmem *xs;
	int err;

	if (!size || (base | size) & ~PAGE_MASK)
		return -EINVAL;

	xs = kzalloc(sizeof(*xs), GFP_KERNEL);
	if (!xs)
		return -ENOMEM;

	xs->base = base;
	xs->size = size;
	mutex_init(&xs->kmap_lock);
	kref_init(&xs->ref);		/* the "registered" reference */
	xs->misc.minor = MISC_DYNAMIC_MINOR;
	xs->misc.name = "xnode_shmem";
	xs->misc.fops = &xnode_shmem_fops;
	xs->misc.parent = parent;

	err = misc_register(&xs->misc);
	if (err) {
		kref_put(&xs->ref, xnode_shmem_free);
		return err;
	}

	if (expose_mmio)
		bpf_mmio_register_region(base, size);

	*out = xs;
	return 0;
}

static void xnode_shmem_unregister(struct xnode_shmem *xs)
{
	if (expose_mmio)
		bpf_mmio_unregister_region(xs->base, xs->size);
	/* After this returns no new open can find xs; open fds keep their
	 * own reference. Drop the registered reference — xnode_shmem_free()
	 * runs (memunmap + free) once the last open fd is also gone.
	 */
	misc_deregister(&xs->misc);
	kref_put(&xs->ref, xnode_shmem_free);
}

static int xnode_shmem_probe(struct platform_device *pdev)
{
	struct reserved_mem *rmem;
	struct device_node *np;
	struct xnode_shmem *xs;
	int err;

	np = of_parse_phandle(pdev->dev.of_node, "memory-region", 0);
	if (!np)
		return -EINVAL;
	rmem = of_reserved_mem_lookup(np);
	of_node_put(np);
	if (!rmem)
		return -EINVAL;

	err = xnode_shmem_register(&pdev->dev, rmem->base, rmem->size, &xs);
	if (err)
		return err;

	platform_set_drvdata(pdev, xs);
	dev_info(&pdev->dev, "window %pa+%zx\n", &xs->base, xs->size);
	return 0;
}

static void xnode_shmem_remove(struct platform_device *pdev)
{
	xnode_shmem_unregister(platform_get_drvdata(pdev));
}

static const struct of_device_id xnode_shmem_of_match[] = {
	{ .compatible = "xnode,shmem-window" },
	{ }
};
MODULE_DEVICE_TABLE(of, xnode_shmem_of_match);

static struct platform_driver xnode_shmem_driver = {
	.probe = xnode_shmem_probe,
	.remove = xnode_shmem_remove,
	.driver = {
		.name = "xnode_shmem",
		.of_match_table = xnode_shmem_of_match,
	},
};

/* DT-less bring-up/testing: base=/size= create the device directly */
static u64 base_param;
module_param_named(base, base_param, ullong, 0444);
MODULE_PARM_DESC(base, "physical base of the window (DT-less testing)");
static u64 size_param;
module_param_named(size, size_param, ullong, 0444);
MODULE_PARM_DESC(size, "size of the window in bytes (DT-less testing)");

static struct xnode_shmem *param_xs;

static int __init xnode_shmem_init(void)
{
	int err;

	err = platform_driver_register(&xnode_shmem_driver);
	if (err)
		return err;

	if (base_param && size_param) {
		err = xnode_shmem_register(NULL, base_param, size_param,
					   &param_xs);
		if (err) {
			platform_driver_unregister(&xnode_shmem_driver);
			return err;
		}
	}
	return 0;
}
module_init(xnode_shmem_init);

static void __exit xnode_shmem_exit(void)
{
	if (param_xs)
		xnode_shmem_unregister(param_xs);
	platform_driver_unregister(&xnode_shmem_driver);
}
module_exit(xnode_shmem_exit);

MODULE_DESCRIPTION("Cross-node shared memory window");
MODULE_LICENSE("GPL");
