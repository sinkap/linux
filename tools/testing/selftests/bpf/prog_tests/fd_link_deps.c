// SPDX-License-Identifier: GPL-2.0
/*
 * Test fd-link anchors and BPF_LINK_GET_DEP_FD.
 *
 * - anchor_map: an fd-link { eventfd, anchor: array map } keeps the map
 *   alive after its fd closes; both sides are reacquirable and identical
 * - restart: only the fd-link is pinned; everything is closed; the pin is
 *   reopened, both sides unwrapped and verified; unpinning releases the map
 * - chain: an fd-link anchored to another fd-link, walked back via
 *   GET_DEP_FD(ANCHOR) then (EXTERNAL)
 * - bad: invalid selectors and a bare link with no anchor
 */
#include <test_progs.h>
#include <sys/eventfd.h>

#define PIN_PATH "/sys/fs/bpf/fd_link_deps_test"

static int link_create_anchored(int target, int anchor)
{
	union bpf_attr attr = {};

	attr.link_create.target_fd = target;
	attr.link_create.prog_fd = anchor;	/* anchor: link, prog, or map */
	attr.link_create.attach_type = BPF_DEPENDENT_FD;
	return syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));
}

static int map_id_of(int map_fd)
{
	struct bpf_map_info info = {};
	__u32 len = sizeof(info);

	if (bpf_map_get_info_by_fd(map_fd, &info, &len))
		return -1;
	return info.id;
}

/* eventfd round trip: signal via one fd, observe via another */
static bool efd_works(int wr, int rd)
{
	__u64 v = 1, out = 0;

	if (write(wr, &v, sizeof(v)) != sizeof(v))
		return false;
	return read(rd, &out, sizeof(out)) == sizeof(out) && out >= 1;
}

static void subtest_anchor_map(void)
{
	int efd, arr, link, ranchor, rext, id;
	struct bpf_link_info info;
	__u32 len = sizeof(info);

	efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (!ASSERT_OK_FD(efd, "eventfd"))
		return;
	arr = bpf_map_create(BPF_MAP_TYPE_ARRAY, "anchor_arr", 4, 8, 4, NULL);
	if (!ASSERT_OK_FD(arr, "array create"))
		goto out_efd;
	id = map_id_of(arr);

	link = link_create_anchored(efd, arr);
	if (!ASSERT_OK_FD(link, "anchored link create"))
		goto out_arr;

	/* info reports the anchor */
	memset(&info, 0, sizeof(info));
	if (ASSERT_OK(bpf_link_get_info_by_fd(link, &info, &len), "link info")) {
		ASSERT_EQ(info.fd.anchor_kind, BPF_FD_LINK_ANCHOR_MAP, "anchor kind");
		ASSERT_EQ(info.fd.anchor_id, id, "anchor id");
	}

	/* the link keeps the map alive without the map fd */
	close(arr);
	arr = -1;
	ranchor = bpf_link_get_dep_fd(link, BPF_FD_LINK_DEP_ANCHOR);
	if (ASSERT_OK_FD(ranchor, "reacquire anchor")) {
		ASSERT_EQ(map_id_of(ranchor), id, "same map");
		close(ranchor);
	}

	/* the external side is the same eventfd */
	rext = bpf_link_get_dep_fd(link, BPF_FD_LINK_DEP_EXTERNAL);
	if (ASSERT_OK_FD(rext, "reacquire external")) {
		ASSERT_TRUE(efd_works(efd, rext), "same eventfd");
		close(rext);
	}

	close(link);
out_arr:
	if (arr >= 0)
		close(arr);
out_efd:
	close(efd);
}

static void subtest_restart(void)
{
	int efd, arr, link, id, pin, rext, ranchor;

	efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	arr = bpf_map_create(BPF_MAP_TYPE_ARRAY, "restart_arr", 4, 8, 4, NULL);
	if (!ASSERT_OK_FD(efd, "eventfd") || !ASSERT_OK_FD(arr, "array"))
		goto out;
	id = map_id_of(arr);

	link = link_create_anchored(efd, arr);
	if (!ASSERT_OK_FD(link, "link"))
		goto out;
	if (!ASSERT_OK(bpf_obj_pin(link, PIN_PATH), "pin"))
		goto out_link;

	/* "loader exits": every fd goes away; only the pin remains */
	close(link);
	close(arr);
	close(efd);
	link = arr = efd = -1;

	/* map must still exist, held by the pinned link's anchor */
	arr = bpf_map_get_fd_by_id(id);
	ASSERT_OK_FD(arr, "map alive via pin");

	/* "restart": reopen the pin, unwrap both sides */
	pin = bpf_obj_get(PIN_PATH);
	if (!ASSERT_OK_FD(pin, "reopen pin"))
		goto out_unlink;
	ranchor = bpf_link_get_dep_fd(pin, BPF_FD_LINK_DEP_ANCHOR);
	rext = bpf_link_get_dep_fd(pin, BPF_FD_LINK_DEP_EXTERNAL);
	if (ASSERT_OK_FD(ranchor, "anchor back"))
		ASSERT_EQ(map_id_of(ranchor), id, "same map after restart");
	if (ASSERT_OK_FD(rext, "external back"))
		ASSERT_TRUE(efd_works(rext, rext), "eventfd works after restart");

	/* teardown: drop everything incl. the pin; the map must go away */
	if (rext >= 0)
		close(rext);
	if (ranchor >= 0)
		close(ranchor);
	close(pin);
	if (arr >= 0)
		close(arr);
	arr = -1;
	ASSERT_OK(unlink(PIN_PATH), "unpin");
	arr = bpf_map_get_fd_by_id(id);
	ASSERT_EQ(arr, -ENOENT, "map released after unpin");
	arr = -1;
	goto out;

out_unlink:
	unlink(PIN_PATH);
out_link:
	if (link >= 0)
		close(link);
out:
	if (arr >= 0)
		close(arr);
	if (efd >= 0)
		close(efd);
	if (link >= 0)
		close(link);
}

static void subtest_chain(void)
{
	int efd0, efd1, l0, l1, mid, rext, arr;

	arr = bpf_map_create(BPF_MAP_TYPE_ARRAY, "chain_anchor", 4, 4, 1, NULL);
	efd0 = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	efd1 = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (!ASSERT_OK_FD(arr, "anchor map") ||
	    !ASSERT_OK_FD(efd0, "efd0") || !ASSERT_OK_FD(efd1, "efd1"))
		return;

	l0 = link_create_anchored(efd0, arr);	/* chain bottom: a map */
	l1 = link_create_anchored(efd1, l0);	/* anchored to another fd-link */
	if (!ASSERT_OK_FD(l0, "l0") || !ASSERT_OK_FD(l1, "l1"))
		goto out;

	/* walk: l1 -> anchor (l0) -> external (efd0) */
	mid = bpf_link_get_dep_fd(l1, BPF_FD_LINK_DEP_ANCHOR);
	if (!ASSERT_OK_FD(mid, "anchor is l0"))
		goto out;
	rext = bpf_link_get_dep_fd(mid, BPF_FD_LINK_DEP_EXTERNAL);
	if (ASSERT_OK_FD(rext, "l0 external")) {
		ASSERT_TRUE(efd_works(efd0, rext), "walked to efd0");
		close(rext);
	}
	close(mid);
out:
	if (l1 >= 0)
		close(l1);
	if (l0 >= 0)
		close(l0);
	close(efd1);
	close(efd0);
	close(arr);
}

static void subtest_bad(void)
{
	int efd, l, r, arr;

	efd = eventfd(0, EFD_CLOEXEC);
	if (!ASSERT_OK_FD(efd, "eventfd"))
		return;

	/* an fd link must name its dependent object */
	l = link_create_anchored(efd, 0);
	ASSERT_ERR(l, "anchorless link rejected");
	if (l >= 0)
		close(l);

	arr = bpf_map_create(BPF_MAP_TYPE_ARRAY, "bad_anchor", 4, 4, 1, NULL);
	if (!ASSERT_OK_FD(arr, "anchor map"))
		goto out;
	l = link_create_anchored(efd, arr);
	close(arr);
	if (!ASSERT_OK_FD(l, "anchored link"))
		goto out;

	/* invalid selector */
	r = bpf_link_get_dep_fd(l, 0);
	ASSERT_EQ(r, -EINVAL, "which 0 rejected");
	r = bpf_link_get_dep_fd(l, 99);
	ASSERT_EQ(r, -EINVAL, "which 99 rejected");
	/* anchoring to a garbage fd fails at create */
	r = link_create_anchored(efd, efd);	/* an eventfd is not a bpf object */
	ASSERT_ERR(r, "bad anchor rejected");

	close(l);
out:
	close(efd);
}

void test_fd_link_deps(void)
{
	if (test__start_subtest("anchor_map"))
		subtest_anchor_map();
	if (test__start_subtest("restart"))
		subtest_restart();
	if (test__start_subtest("chain"))
		subtest_chain();
	if (test__start_subtest("bad"))
		subtest_bad();
}
