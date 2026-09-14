// SPDX-License-Identifier: GPL-2.0

#include <errno.h>
#include <linux/btf.h>
#include <test_progs.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>

#include "bpf_fmodret_iter.skel.h"
#include "bpf_fmodret_iter_fail.skel.h"
#include "progs/bpf_fmodret_iter.h"

static int read_one_byte_at_a_time(int fd, void **data, size_t *data_len)
{
	unsigned char *buf = NULL;
	size_t capacity = 0;
	size_t len = 0;
	unsigned char byte;
	ssize_t ret;
	void *tmp;

	while (true) {
		ret = read(fd, &byte, sizeof(byte));
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret <= 0)
			break;

		if (len == capacity) {
			capacity = capacity ? capacity * 2 : 256;
			tmp = realloc(buf, capacity);
			if (!tmp) {
				free(buf);
				return -ENOMEM;
			}
			buf = tmp;
		}
		buf[len++] = byte;
	}

	if (ret < 0) {
		ret = -errno;
		free(buf);
		return ret;
	}

	*data = buf;
	*data_len = len;
	return 0;
}

static const struct bpf_fmodret_iter_entry *
find_entry(const struct bpf_fmodret_iter_entry *entries, size_t count,
	   __u32 btf_obj_id, __u32 btf_id)
{
	size_t left = 0;
	size_t right = count;

	while (left < right) {
		size_t mid = left + (right - left) / 2;

		if (entries[mid].btf_obj_id < btf_obj_id ||
		    (entries[mid].btf_obj_id == btf_obj_id &&
		     entries[mid].btf_id < btf_id))
			left = mid + 1;
		else
			right = mid;
	}

	if (left == count || entries[left].btf_obj_id != btf_obj_id ||
	    entries[left].btf_id != btf_id)
		return NULL;
	return &entries[left];
}

static int find_btf_obj_id(const char *target_name)
{
	struct bpf_btf_info info;
	char name[64];
	__u32 id = 0;
	__u32 len;
	int err, fd;

	while (true) {
		err = bpf_btf_get_next_id(id, &id);
		if (err)
			return -errno;

		fd = bpf_btf_get_fd_by_id(id);
		if (fd < 0) {
			if (errno == ENOENT)
				continue;
			return -errno;
		}

		memset(&info, 0, sizeof(info));
		memset(name, 0, sizeof(name));
		info.name = ptr_to_u64(name);
		info.name_len = sizeof(name);
		len = sizeof(info);
		err = bpf_btf_get_info_by_fd(fd, &info, &len);
		if (err)
			err = -errno;
		close(fd);
		if (err)
			return err;
		if (info.kernel_btf && !strcmp(name, target_name))
			return id;
	}
}

static void check_function(const struct btf *btf,
			   const struct bpf_fmodret_iter_entry *entries,
			   size_t count, __u32 btf_obj_id, const char *name)
{
	const struct bpf_fmodret_iter_entry *entry;
	int btf_id;

	btf_id = btf__find_by_name_kind(btf, name, BTF_KIND_FUNC);
	if (!ASSERT_GT(btf_id, 0, name))
		return;

	entry = find_entry(entries, count, btf_obj_id, btf_id);
	ASSERT_NEQ(entry, NULL, name);
}

static void run_bpf_fmodret_iter(void)
{
	const struct bpf_fmodret_iter_entry *entries;
	struct bpf_fmodret_iter *skel = NULL;
	struct bpf_link *link = NULL;
	struct btf *btf = NULL;
	struct btf *owner_btf = NULL;
	void *data = NULL;
	size_t data_len = 0;
	size_t count, i;
	__u32 owner_id = 0;
	int vmlinux_btf_id;
	int iter_fd = -1;
	int err;

	btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(btf, "btf__load_vmlinux_btf"))
		goto cleanup;
	vmlinux_btf_id = find_btf_obj_id("vmlinux");
	if (!ASSERT_GT(vmlinux_btf_id, 0, "find_vmlinux_btf_obj_id"))
		goto cleanup;

	skel = bpf_fmodret_iter__open_and_load();
	if (!ASSERT_OK_PTR(skel, "bpf_fmodret_iter__open_and_load"))
		goto cleanup;

	link = bpf_program__attach_iter(skel->progs.dump_bpf_fmodret, NULL);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_iter"))
		goto cleanup;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (!ASSERT_GE(iter_fd, 0, "bpf_iter_create"))
		goto cleanup;

	err = read_one_byte_at_a_time(iter_fd, &data, &data_len);
	if (!ASSERT_OK(err, "read_one_byte_at_a_time"))
		goto cleanup;
	if (!data_len) {
		test__skip();
		goto cleanup;
	}
	if (!ASSERT_EQ(data_len % sizeof(*entries), 0,
		       "iterator_output_size"))
		goto cleanup;

	entries = data;
	count = data_len / sizeof(*entries);

	ASSERT_EQ(skel->bss->num_entries, count, "num_entries");
	ASSERT_EQ(skel->bss->num_terminal, 1, "num_terminal");

	for (i = 0; i < count; i++) {
		const struct btf_type *type;

		if (!ASSERT_GT(entries[i].btf_obj_id, 0, "valid_btf_obj_id"))
			break;
		if (!ASSERT_GT(entries[i].btf_id, 0, "valid_btf_id"))
			break;
		if (i) {
			if (!ASSERT_LE(entries[i - 1].btf_obj_id,
				       entries[i].btf_obj_id,
				       "sorted_btf_obj_ids"))
				break;
			if (entries[i - 1].btf_obj_id == entries[i].btf_obj_id &&
			    !ASSERT_LT(entries[i - 1].btf_id, entries[i].btf_id,
				       "sorted_unique_btf_ids"))
				break;
		}

		if (owner_id != entries[i].btf_obj_id) {
			if (owner_btf != btf)
				btf__free(owner_btf);
			owner_id = entries[i].btf_obj_id;
			if (owner_id == vmlinux_btf_id)
				owner_btf = btf;
			else
				owner_btf = btf__load_from_kernel_by_id_split(owner_id, btf);
			if (!ASSERT_OK_PTR(owner_btf, "load_owner_btf")) {
				owner_btf = NULL;
				break;
			}
		}

		type = btf__type_by_id(owner_btf, entries[i].btf_id);
		if (!ASSERT_NEQ(type, NULL, "btf__type_by_id") ||
		    !ASSERT_EQ(BTF_INFO_KIND(type->info), BTF_KIND_FUNC,
			       "btf_kind_func"))
			break;
	}

	check_function(btf, entries, count, vmlinux_btf_id,
		       "genl_family_rcv_msg_doit");
	if (env.has_testmod) {
		int testmod_btf_id;
		bool found = false;

		testmod_btf_id = find_btf_obj_id("bpf_testmod");
		if (ASSERT_GT(testmod_btf_id, 0, "find_testmod_btf_obj_id")) {
			for (i = 0; i < count; i++) {
				if (entries[i].btf_obj_id == testmod_btf_id) {
					found = true;
					break;
				}
			}
			ASSERT_TRUE(found, "testmod_fmodret_entries");
		}
	}

cleanup:
	if (owner_btf != btf)
		btf__free(owner_btf);
	if (iter_fd >= 0)
		close(iter_fd);
	bpf_link__destroy(link);
	bpf_fmodret_iter__destroy(skel);
	btf__free(btf);
	free(data);
}

void test_bpf_fmodret_iter(void)
{
	if (test__start_subtest("enumerate"))
		run_bpf_fmodret_iter();
	if (test__start_subtest("verifier"))
		RUN_TESTS(bpf_fmodret_iter_fail);
}
