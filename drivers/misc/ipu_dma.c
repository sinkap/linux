// SPDX-License-Identifier: GPL-2.0-only
/*
 * IPU DMA binding: import a dma-buf for DMA by an IPU offload engine and keep
 * the resulting IOVA mapping alive independently of the process that created
 * it.
 *
 * The IOVA mapping (the dma_buf_attachment + its mapped sg_table) is a
 * refcounted object owned by an anon-inode fd handed back from IPU_DMA_BIND.
 * The binding takes its own reference on the dma-buf, so the binding alone
 * keeps both the memory and the IOVAs alive. Closing (or unpinning) the
 * binding fd releases the mapping.
 *
 * This is a hardware-less skeleton: ipu_program_ring()/ipu_quiesce_ring() are
 * stubs where a real driver would touch its descriptor ring, and the "IPU DMA
 * device" is a synthetic platform device standing in for the offload engine's
 * DMA-capable struct device.
 */
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/kref.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/file.h>
#include <linux/miscdevice.h>
#include <linux/anon_inodes.h>
#include <linux/platform_device.h>
#include <linux/dma-buf.h>
#include <linux/dma-mapping.h>
#include <linux/scatterlist.h>

#include <uapi/linux/ipu_dma.h>

struct ipu_device {
	struct miscdevice	misc;
	struct device		*dma_dev;	/* the IPU's DMA-capable device */
	struct mutex		lock;		/* protects bindings           */
	struct list_head	bindings;
};

struct ipu_dma_binding {
	struct kref			ref;
	struct ipu_device		*ipu;
	struct dma_buf			*dmabuf;
	struct dma_buf_attachment	*attach;
	struct sg_table			*sgt;
	enum dma_data_direction		dir;
	struct list_head		node;		/* on ipu->bindings */
};

/* ---- hardware stubs -------------------------------------------------- */

static int ipu_program_ring(struct ipu_device *ipu, struct sg_table *sgt,
			    enum dma_data_direction dir)
{
	struct scatterlist *sg;
	unsigned int i;

	/* A real driver walks the mapped sg_table and writes (iova, len) into
	 * its descriptor ring here.
	 */
	for_each_sgtable_dma_sg(sgt, sg, i)
		dev_dbg(ipu->dma_dev, "ipu desc: iova %pad len %u\n",
			&sg_dma_address(sg), sg_dma_len(sg));
	return 0;
}

static void ipu_quiesce_ring(struct ipu_device *ipu, struct ipu_dma_binding *b)
{
	/* A real driver stops the engine touching these IOVAs and waits for
	 * in-flight DMA to drain *before* the mapping is unmapped. kref keeps
	 * the struct alive but does not fence the hardware -- that must happen
	 * here.
	 */
}

/* ---- binding lifetime ------------------------------------------------ */

static void ipu_binding_free(struct kref *ref)
{
	struct ipu_dma_binding *b =
		container_of(ref, struct ipu_dma_binding, ref);

	mutex_lock(&b->ipu->lock);
	list_del(&b->node);
	mutex_unlock(&b->ipu->lock);

	dma_buf_unmap_attachment_unlocked(b->attach, b->sgt, b->dir);
	dma_buf_detach(b->dmabuf, b->attach);
	dma_buf_put(b->dmabuf);
	kfree(b);
}

static int ipu_binding_release(struct inode *inode, struct file *file)
{
	struct ipu_dma_binding *b = file->private_data;

	/* Fence the hardware before the mapping can go away. */
	ipu_quiesce_ring(b->ipu, b);
	kref_put(&b->ref, ipu_binding_free);
	return 0;
}

static long ipu_binding_get_iovas(struct ipu_dma_binding *b,
				  void __user *uarg)
{
	struct ipu_dma_get_iovas req;
	struct ipu_dma_iova __user *out;
	struct scatterlist *sg;
	unsigned int i, n = 0;

	if (copy_from_user(&req, uarg, sizeof(req)))
		return -EFAULT;
	if (req.pad)
		return -EINVAL;
	out = u64_to_user_ptr(req.iovas_ptr);

	for_each_sgtable_dma_sg(b->sgt, sg, i) {
		struct ipu_dma_iova seg = {
			.iova = sg_dma_address(sg),
			.len  = sg_dma_len(sg),
		};

		if (n < req.nr) {
			if (copy_to_user(&out[n], &seg, sizeof(seg)))
				return -EFAULT;
		}
		n++;
	}

	req.nr = n;			/* full count, even if truncated */
	return copy_to_user(uarg, &req, sizeof(req)) ? -EFAULT : 0;
}

static long ipu_binding_ioctl(struct file *file, unsigned int cmd,
			      unsigned long arg)
{
	struct ipu_dma_binding *b = file->private_data;

	switch (cmd) {
	case IPU_DMA_GET_IOVAS:
		return ipu_binding_get_iovas(b, (void __user *)arg);
	default:
		return -ENOTTY;
	}
}

/*
 * These fops identify the binding fd. A real deployment can make this fd
 * pinnable in bpffs by registering it with the fd-link mechanism (see the
 * bpf_fd_link_register_kind() follow-up); nothing here depends on bpf.
 */
const struct file_operations ipu_dma_binding_fops = {
	.owner		= THIS_MODULE,
	.release	= ipu_binding_release,
	.unlocked_ioctl	= ipu_binding_ioctl,
	.compat_ioctl	= compat_ptr_ioctl,
};
EXPORT_SYMBOL_GPL(ipu_dma_binding_fops);

static enum dma_data_direction ipu_dir(u32 flags)
{
	switch (flags & IPU_DMA_F_BIDIR) {
	case IPU_DMA_F_READ:	return DMA_TO_DEVICE;
	case IPU_DMA_F_WRITE:	return DMA_FROM_DEVICE;
	default:		return DMA_BIDIRECTIONAL;
	}
}

/* ---- bind ------------------------------------------------------------ */

static long ipu_dma_bind(struct ipu_device *ipu, void __user *uarg)
{
	struct ipu_dma_bind req;
	struct ipu_dma_binding *b;
	struct file *file;
	int fd, err;

	if (copy_from_user(&req, uarg, sizeof(req)))
		return -EFAULT;
	if (req.flags & ~IPU_DMA_F_BIDIR)
		return -EINVAL;

	b = kzalloc(sizeof(*b), GFP_KERNEL);
	if (!b)
		return -ENOMEM;
	kref_init(&b->ref);
	b->ipu = ipu;
	b->dir = ipu_dir(req.flags);

	b->dmabuf = dma_buf_get(req.dmabuf_fd);
	if (IS_ERR(b->dmabuf)) {
		err = PTR_ERR(b->dmabuf);
		goto err_free;
	}

	b->attach = dma_buf_attach(b->dmabuf, ipu->dma_dev);
	if (IS_ERR(b->attach)) {
		err = PTR_ERR(b->attach);
		goto err_put;
	}

	b->sgt = dma_buf_map_attachment_unlocked(b->attach, b->dir);
	if (IS_ERR(b->sgt)) {
		err = PTR_ERR(b->sgt);
		goto err_detach;
	}

	err = ipu_program_ring(ipu, b->sgt, b->dir);
	if (err)
		goto err_unmap;

	mutex_lock(&ipu->lock);
	list_add(&b->node, &ipu->bindings);
	mutex_unlock(&ipu->lock);

	/* Build the fd + file, but publish to userspace before fd_install():
	 * until fd_install() the file is private, so a copy_to_user() failure
	 * unwinds with a plain fput() (whose release frees @b).
	 */
	fd = get_unused_fd_flags(O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		err = fd;
		goto err_unlist;
	}
	file = anon_inode_getfile("[ipu-dma]", &ipu_dma_binding_fops, b, O_RDWR);
	if (IS_ERR(file)) {
		put_unused_fd(fd);
		err = PTR_ERR(file);
		goto err_unlist;
	}

	req.binding_fd = fd;
	req.nr_iovas   = b->sgt->nents;
	if (copy_to_user(uarg, &req, sizeof(req))) {
		put_unused_fd(fd);
		fput(file);	/* release frees @b (list_del + unmap + put) */
		return -EFAULT;
	}

	fd_install(fd, file);	/* the fd now owns @b */
	return 0;

err_unlist:
	mutex_lock(&ipu->lock);
	list_del(&b->node);
	mutex_unlock(&ipu->lock);
err_unmap:
	dma_buf_unmap_attachment_unlocked(b->attach, b->sgt, b->dir);
err_detach:
	dma_buf_detach(b->dmabuf, b->attach);
err_put:
	dma_buf_put(b->dmabuf);
err_free:
	kfree(b);
	return err;
}

static long ipu_dev_ioctl(struct file *file, unsigned int cmd,
			  unsigned long arg)
{
	struct ipu_device *ipu =
		container_of(file->private_data, struct ipu_device, misc);

	switch (cmd) {
	case IPU_DMA_BIND:
		return ipu_dma_bind(ipu, (void __user *)arg);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations ipu_dev_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= ipu_dev_ioctl,
	.compat_ioctl	= compat_ptr_ioctl,
	.llseek		= noop_llseek,
};

/* ---- module ---------------------------------------------------------- */

static struct ipu_device *ipu_singleton;
static struct platform_device *ipu_pdev;

static int __init ipu_dma_init(void)
{
	struct ipu_device *ipu;
	int err;

	/* Stand-in for the offload engine's DMA-capable device. */
	ipu_pdev = platform_device_register_simple("ipu_dma_engine", -1,
						   NULL, 0);
	if (IS_ERR(ipu_pdev))
		return PTR_ERR(ipu_pdev);
	err = dma_coerce_mask_and_coherent(&ipu_pdev->dev, DMA_BIT_MASK(64));
	if (err)
		goto err_pdev;

	ipu = kzalloc(sizeof(*ipu), GFP_KERNEL);
	if (!ipu) {
		err = -ENOMEM;
		goto err_pdev;
	}
	ipu->dma_dev = &ipu_pdev->dev;
	mutex_init(&ipu->lock);
	INIT_LIST_HEAD(&ipu->bindings);
	ipu->misc.minor = MISC_DYNAMIC_MINOR;
	ipu->misc.name  = "ipu_dma";
	ipu->misc.fops  = &ipu_dev_fops;

	err = misc_register(&ipu->misc);
	if (err)
		goto err_free;

	ipu_singleton = ipu;
	return 0;

err_free:
	kfree(ipu);
err_pdev:
	platform_device_unregister(ipu_pdev);
	return err;
}

static void __exit ipu_dma_exit(void)
{
	/* Open binding fds hold a module reference, so no bindings can be
	 * outstanding here.
	 */
	misc_deregister(&ipu_singleton->misc);
	kfree(ipu_singleton);
	platform_device_unregister(ipu_pdev);
}

module_init(ipu_dma_init);
module_exit(ipu_dma_exit);

MODULE_DESCRIPTION("IPU DMA dma-buf binding (IOVA lifetime holder)");
MODULE_LICENSE("GPL");
