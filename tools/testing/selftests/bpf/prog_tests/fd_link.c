// SPDX-License-Identifier: GPL-2.0
/*
 * Test BPF_LINK_TYPE_FD (attach_type BPF_DEPENDENT_FD): pinning external
 * fds via bpf_link so they can live in bpffs.
 *
 * - an eventfd and a dma-buf (leaf file types) can be pinned; link info
 *   reports the kind and the backing inode, fdinfo shows the kind
 * - a non-whitelisted fd (a pipe: can hold references) is rejected with
 *   -EPERM (reference-cycle safety)
 */
#include <test_progs.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include <linux/udmabuf.h>

static int link_create_fd(int target)
{
	union bpf_attr attr = {};

	attr.link_create.target_fd = target;
	attr.link_create.attach_type = BPF_DEPENDENT_FD;
	return syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));
}

static int get_link_info(int link, struct bpf_link_info *info)
{
	__u32 len = sizeof(*info);

	memset(info, 0, sizeof(*info));
	return bpf_link_get_info_by_fd(link, info, &len);
}

static bool fdinfo_contains(int fd, const char *needle)
{
	char path[64], buf[512];
	ssize_t n;
	int f;

	snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
	f = open(path, O_RDONLY);
	if (f < 0)
		return false;
	n = read(f, buf, sizeof(buf) - 1);
	close(f);
	if (n <= 0)
		return false;
	buf[n] = 0;
	return strstr(buf, needle) != NULL;
}

static void subtest_eventfd(void)
{
	struct bpf_link_info info;
	int ev, link;

	ev = eventfd(0, EFD_CLOEXEC);
	if (!ASSERT_OK_FD(ev, "eventfd"))
		return;

	link = link_create_fd(ev);
	if (!ASSERT_OK_FD(link, "link over eventfd"))
		goto out;

	if (ASSERT_OK(get_link_info(link, &info), "link info")) {
		ASSERT_EQ(info.type, BPF_LINK_TYPE_FD, "link type");
		ASSERT_EQ(info.fd.kind, BPF_FD_LINK_KIND_EVENTFD, "kind eventfd");
		ASSERT_NEQ(info.fd.ino, 0, "backing inode reported");
	}
	ASSERT_TRUE(fdinfo_contains(link, "fd_kind:\teventfd"),
		    "fdinfo shows fd_kind");
	close(link);
out:
	close(ev);
}

static void subtest_dmabuf(void)
{
	struct udmabuf_create create;
	struct bpf_link_info info;
	int memfd, dev, dmabuf, link;

	memfd = memfd_create("fd_link_buf", MFD_ALLOW_SEALING);
	if (!ASSERT_OK_FD(memfd, "memfd_create"))
		return;
	if (!ASSERT_OK(ftruncate(memfd, getpagesize()), "ftruncate"))
		goto close_memfd;
	if (!ASSERT_OK(fcntl(memfd, F_ADD_SEALS, F_SEAL_SHRINK), "seal"))
		goto close_memfd;

	dev = open("/dev/udmabuf", O_RDONLY);
	if (dev < 0) {
		test__skip();	/* no udmabuf support */
		goto close_memfd;
	}
	memset(&create, 0, sizeof(create));
	create.memfd = memfd;
	create.flags = UDMABUF_FLAGS_CLOEXEC;
	create.size = getpagesize();
	dmabuf = ioctl(dev, UDMABUF_CREATE, &create);
	close(dev);
	if (!ASSERT_OK_FD(dmabuf, "udmabuf create"))
		goto close_memfd;

	link = link_create_fd(dmabuf);
	if (ASSERT_OK_FD(link, "link over dma-buf")) {
		if (ASSERT_OK(get_link_info(link, &info), "link info"))
			ASSERT_EQ(info.fd.kind, BPF_FD_LINK_KIND_DMABUF,
				  "kind dmabuf");
		close(link);
	}
	close(dmabuf);
close_memfd:
	close(memfd);
}

static void subtest_rejected(void)
{
	int pfd[2], link;

	if (!ASSERT_OK(pipe(pfd), "pipe"))
		return;

	link = link_create_fd(pfd[0]);
	if (!ASSERT_ERR(link, "non-leaf fd rejected"))
		close(link);
	ASSERT_EQ(errno, EPERM, "rejected with EPERM");
	close(pfd[0]);
	close(pfd[1]);
}

void test_fd_link(void)
{
	if (test__start_subtest("eventfd"))
		subtest_eventfd();
	if (test__start_subtest("dmabuf"))
		subtest_dmabuf();
	if (test__start_subtest("rejected"))
		subtest_rejected();
}
