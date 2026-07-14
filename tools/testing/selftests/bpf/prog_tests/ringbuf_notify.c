// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <poll.h>
#include "bpf_testmod/bpf_testmod.h"
#include "ringbuf_notify.skel.h"

#define DOORBELL_DEV "/dev/bpf_testmod_doorbell"

/* Create the ring buffer with notify_fd and splice it into the skeleton
 * (declarative maps cannot carry a notify_fd).
 */
static struct ringbuf_notify *open_load_with_notify(int notify_fd)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts, .notify_fd = notify_fd);
	struct ringbuf_notify *skel;
	int map_fd, err;

	skel = ringbuf_notify__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return NULL;

	map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, "ringbuf_notify", 0, 0,
				4096, &opts);
	if (!ASSERT_GE(map_fd, 0, "map_create_notify"))
		goto err_out;

	err = bpf_map__reuse_fd(skel->maps.ringbuf, map_fd);
	close(map_fd); /* skeleton holds a dup */
	if (!ASSERT_OK(err, "reuse_fd"))
		goto err_out;

	if (!ASSERT_OK(ringbuf_notify__load(skel), "skel_load"))
		goto err_out;
	return skel;

err_out:
	ringbuf_notify__destroy(skel);
	return NULL;
}

static int produce(struct ringbuf_notify *skel, int n)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	int i, err;

	for (i = 0; i < n; i++) {
		err = bpf_prog_test_run_opts(
			bpf_program__fd(skel->progs.produce), &topts);
		if (!ASSERT_OK(err, "test_run") ||
		    !ASSERT_OK(topts.retval, "produce_retval"))
			return -1;
	}
	return 0;
}

/* The wakeup is deferred through irq_work; poll with a timeout instead
 * of racing it.
 */
static int wait_eventfd(int efd, __u64 *count)
{
	struct pollfd pfd = { .fd = efd, .events = POLLIN };

	if (!ASSERT_EQ(poll(&pfd, 1, 5000), 1, "eventfd_poll"))
		return -1;
	if (!ASSERT_EQ(read(efd, count, sizeof(*count)), sizeof(*count),
		       "eventfd_read"))
		return -1;
	return 0;
}

static void subtest_eventfd(void)
{
	struct ringbuf_notify *skel;
	__u64 count = 0;
	int efd;

	efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (!ASSERT_GE(efd, 0, "eventfd"))
		return;

	skel = open_load_with_notify(efd);
	if (!skel)
		goto out_efd;

	if (produce(skel, 3))
		goto out;
	if (wait_eventfd(efd, &count))
		goto out;
	/* commits may coalesce in one irq_work run, but at least one
	 * signal must arrive, and never more than one per record
	 */
	ASSERT_GE(count, 1, "signal_count_min");
	ASSERT_LE(count, 3, "signal_count_max");

	/* the eventfd read re-armed it; a further record signals again */
	if (produce(skel, 1))
		goto out;
	if (wait_eventfd(efd, &count))
		goto out;
	ASSERT_GE(count, 1, "signal_rearm");

out:
	ringbuf_notify__destroy(skel);
out_efd:
	close(efd);
}

static void subtest_doorbell(void)
{
	struct ringbuf_notify *skel = NULL;
	__u64 rings = 0;
	int efd, db, i;

	db = open(DOORBELL_DEV, O_RDWR | O_CLOEXEC);
	if (!ASSERT_GE(db, 0, "doorbell_open"))
		return;

	efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (!ASSERT_GE(efd, 0, "eventfd"))
		goto out_db;

	if (!ASSERT_OK(ioctl(db, BPF_TESTMOD_DB_IOC_BIND, efd), "db_bind"))
		goto out_efd;
	/* second bind must fail */
	ASSERT_ERR(ioctl(db, BPF_TESTMOD_DB_IOC_BIND, efd), "db_rebind");

	skel = open_load_with_notify(efd);
	if (!skel)
		goto out_efd;

	if (produce(skel, 3))
		goto out;

	/* the driver consumes the eventfd inline in eventfd_signal() and
	 * counts the rings; poll the register instead of the eventfd
	 */
	for (i = 0; i < 5000; i++) {
		if (!ASSERT_OK(ioctl(db, BPF_TESTMOD_DB_IOC_RINGS, &rings),
			       "db_rings"))
			goto out;
		if (rings >= 1)
			break;
		usleep(1000);
	}
	ASSERT_GE(rings, 1, "doorbell_rang");
	ASSERT_LE(rings, 3, "doorbell_max");

	/* the driver stole the signal: the eventfd itself must be empty */
	ASSERT_ERR(read(efd, &rings, sizeof(rings)), "eventfd_drained");

out:
	ringbuf_notify__destroy(skel);
out_efd:
	close(efd);
out_db:
	close(db);
}

static void subtest_bad_attrs(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	int fd, efd, memfd;

	efd = eventfd(0, EFD_CLOEXEC);
	if (!ASSERT_GE(efd, 0, "eventfd"))
		return;

	/* notify_fd on a non-ringbuf map type */
	opts.notify_fd = efd;
	fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, NULL, 4, 4, 1, &opts);
	ASSERT_EQ(fd, -EINVAL, "notify_fd_array");

	/* notify_fd that is not an eventfd */
	memfd = memfd_create("not_an_eventfd", 0);
	if (!ASSERT_GE(memfd, 0, "memfd"))
		goto out;
	opts.notify_fd = memfd;
	fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, 4096, &opts);
	ASSERT_EQ(fd, -EINVAL, "notify_fd_not_eventfd");
	close(memfd);

	/* notify_fd that is not an open fd */
	opts.notify_fd = 1 << 20;
	fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, 4096, &opts);
	ASSERT_EQ(fd, -EBADF, "notify_fd_bad");

out:
	close(efd);
}

void test_ringbuf_notify(void)
{
	if (test__start_subtest("eventfd"))
		subtest_eventfd();
	if (test__start_subtest("doorbell"))
		subtest_doorbell();
	if (test__start_subtest("bad_attrs"))
		subtest_bad_attrs();
}
