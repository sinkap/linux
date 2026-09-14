// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "main.h"
#include "skeleton/fmodret_iter.h"

#define BTF_NAME_LEN 64

struct fmodret_owner {
	__u32 btf_obj_id;
	struct btf *btf;
	char *name;
	bool owns_btf;
};

struct fmodret_resolved_entry {
	const char *name;
	const char *owner;
};

#ifdef BPFTOOL_WITHOUT_SKELETONS

static int do_list(int argc, char **argv)
{
	if (argc)
		return BAD_ARG();

	p_err("bpftool was built without BPF skeleton support");
	return -EOPNOTSUPP;
}

#else /* BPFTOOL_WITHOUT_SKELETONS */

#include "fmodret_iter.skel.h"

static int read_iterator(int fd, struct fmodret_iter_entry **entries,
			 size_t *entry_cnt)
{
	unsigned char *buf = NULL;
	size_t capacity = 0;
	size_t len = 0;
	ssize_t ret;
	void *tmp;
	int err;

	while (true) {
		if (len == capacity) {
			size_t new_capacity = capacity ? capacity * 2 : 4096;

			if (new_capacity < capacity) {
				err = -EOVERFLOW;
				goto err_free;
			}
			tmp = realloc(buf, new_capacity);
			if (!tmp) {
				err = -ENOMEM;
				goto err_free;
			}
			buf = tmp;
			capacity = new_capacity;
		}

		ret = read(fd, buf + len, capacity - len);
		if (ret < 0 && (errno == EAGAIN || errno == EINTR))
			continue;
		if (ret < 0) {
			err = -errno;
			goto err_free;
		}
		if (!ret)
			break;
		len += ret;
	}

	if (len % sizeof(**entries)) {
		err = -EINVAL;
		goto err_free;
	}

	*entries = (void *)buf;
	*entry_cnt = len / sizeof(**entries);
	return 0;

err_free:
	free(buf);
	return err;
}

static int read_btf_name(__u32 btf_obj_id, char **name)
{
	struct bpf_btf_info info = {};
	char buf[BTF_NAME_LEN] = {};
	__u32 info_len = sizeof(info);
	int fd, err;

	fd = bpf_btf_get_fd_by_id(btf_obj_id);
	if (fd < 0)
		return -errno;

	info.name = ptr_to_u64(buf);
	info.name_len = sizeof(buf);
	err = bpf_btf_get_info_by_fd(fd, &info, &info_len);
	if (err)
		err = -errno;
	close(fd);
	if (err)
		return err;
	if (!info.kernel_btf)
		return -EINVAL;

	*name = strdup(buf);
	return *name ? 0 : -ENOMEM;
}

static void free_owners(struct fmodret_owner *owners, size_t owner_cnt)
{
	size_t i;

	for (i = 0; i < owner_cnt; i++) {
		if (owners[i].owns_btf)
			btf__free(owners[i].btf);
		free(owners[i].name);
	}
	free(owners);
}

static struct fmodret_owner *
find_owner(struct fmodret_owner *owners, size_t owner_cnt, __u32 btf_obj_id)
{
	size_t i;

	for (i = 0; i < owner_cnt; i++) {
		if (owners[i].btf_obj_id == btf_obj_id)
			return &owners[i];
	}
	return NULL;
}

static struct btf *load_module_btf(__u32 btf_obj_id, struct btf *vmlinux_btf)
{
	return btf__load_from_kernel_by_id_split(btf_obj_id, vmlinux_btf);
}

static int resolve_entries(struct btf *vmlinux_btf,
			   const struct fmodret_iter_entry *entries,
			   size_t entry_cnt,
			   struct fmodret_resolved_entry **resolved_entries,
			   struct fmodret_owner **resolved_owners,
			   size_t *resolved_owner_cnt)
{
	struct fmodret_resolved_entry *resolved = NULL;
	struct fmodret_owner *owners = NULL;
	size_t owner_cnt = 0;
	size_t i;
	int err;

	if (entry_cnt) {
		resolved = calloc(entry_cnt, sizeof(*resolved));
		owners = calloc(entry_cnt, sizeof(*owners));
		if (!resolved || !owners) {
			err = -ENOMEM;
			goto err_free;
		}
	}

	for (i = 0; i < entry_cnt; i++) {
		struct fmodret_owner *owner;
		const struct btf_type *type;
		const char *name;

		owner = find_owner(owners, owner_cnt, entries[i].btf_obj_id);
		if (!owner) {
			owner = &owners[owner_cnt++];
			owner->btf_obj_id = entries[i].btf_obj_id;
			err = read_btf_name(owner->btf_obj_id, &owner->name);
			if (err) {
				p_err("failed to read name of BTF object %u: %s",
				      owner->btf_obj_id, strerror(-err));
				goto err_free;
			}

			if (!strcmp(owner->name, "vmlinux")) {
				owner->btf = vmlinux_btf;
			} else {
				owner->btf = load_module_btf(owner->btf_obj_id,
							     vmlinux_btf);
				if (!owner->btf) {
					err = errno ? -errno : -EINVAL;
					p_err("failed to load BTF object %u (%s): %s",
					      owner->btf_obj_id, owner->name,
					      strerror(-err));
					goto err_free;
				}
				owner->owns_btf = true;
			}
		}

		type = btf__type_by_id(owner->btf, entries[i].btf_id);
		if (!type || !btf_is_func(type)) {
			p_err("BTF ID %u:%u is not a function",
			      entries[i].btf_obj_id, entries[i].btf_id);
			err = -EINVAL;
			goto err_free;
		}
		name = btf__name_by_offset(owner->btf, type->name_off);
		if (!name) {
			p_err("failed to resolve name for BTF ID %u:%u",
			      entries[i].btf_obj_id, entries[i].btf_id);
			err = -EINVAL;
			goto err_free;
		}
		resolved[i].name = name;
		resolved[i].owner = owner->name;
	}

	*resolved_entries = resolved;
	*resolved_owners = owners;
	*resolved_owner_cnt = owner_cnt;
	return 0;

err_free:
	free_owners(owners, owner_cnt);
	free(resolved);
	return err;
}

static void show_entry_plain(const struct fmodret_iter_entry *entry,
			     const struct fmodret_resolved_entry *resolved)
{
	__u32 unknown_flags = entry->flags & ~FMODRET_ITER_F_SLEEPABLE;

	printf("%u:%u  %s (%s)", entry->btf_obj_id, entry->btf_id,
	       resolved->name, resolved->owner);
	if (entry->flags & FMODRET_ITER_F_SLEEPABLE)
		printf(" sleepable");
	if (unknown_flags)
		printf(" flags=0x%x", unknown_flags);
	printf("\n");
}

static void show_entry_json(const struct fmodret_iter_entry *entry,
			    const struct fmodret_resolved_entry *resolved)
{
	jsonw_start_object(json_wtr);
	jsonw_uint_field(json_wtr, "btf_obj_id", entry->btf_obj_id);
	jsonw_uint_field(json_wtr, "btf_id", entry->btf_id);
	jsonw_string_field(json_wtr, "name", resolved->name);
	jsonw_string_field(json_wtr, "owner", resolved->owner);
	jsonw_uint_field(json_wtr, "flags", entry->flags);
	jsonw_bool_field(json_wtr, "sleepable",
			 entry->flags & FMODRET_ITER_F_SLEEPABLE);
	jsonw_end_object(json_wtr);
}

static int do_list(int argc, char **argv)
{
	struct fmodret_iter_entry *entries = NULL;
	struct fmodret_resolved_entry *resolved = NULL;
	struct fmodret_owner *owners = NULL;
	struct fmodret_iter_bpf *skel = NULL;
	struct btf *btf = NULL;
	size_t owner_cnt = 0;
	size_t entry_cnt = 0;
	int iter_fd = -1;
	size_t i;
	int err;

	if (argc)
		return BAD_ARG();

	set_max_rlimit();
	skel = fmodret_iter_bpf__open_and_load();
	if (!skel) {
		err = errno ? -errno : -EINVAL;
		p_err("failed to load fmod_ret iterator: %s", strerror(-err));
		goto out;
	}

	err = fmodret_iter_bpf__attach(skel);
	if (err) {
		p_err("failed to attach fmod_ret iterator: %s", strerror(-err));
		goto out;
	}

	iter_fd = bpf_iter_create(bpf_link__fd(skel->links.iter));
	if (iter_fd < 0) {
		err = -errno;
		p_err("failed to create fmod_ret iterator session: %s",
		      strerror(-err));
		goto out;
	}

	err = read_iterator(iter_fd, &entries, &entry_cnt);
	if (err) {
		p_err("failed to read fmod_ret iterator output: %s",
		      strerror(-err));
		goto out;
	}

	btf = btf__load_vmlinux_btf();
	err = libbpf_get_error(btf);
	if (err) {
		p_err("failed to load vmlinux BTF: %s", strerror(-err));
		btf = NULL;
		goto out;
	}

	err = resolve_entries(btf, entries, entry_cnt, &resolved, &owners,
			      &owner_cnt);
	if (err) {
		if (err == -ENOMEM)
			p_err("failed to allocate fmod_ret function information");
		goto out;
	}

	if (json_output)
		jsonw_start_array(json_wtr);
	for (i = 0; i < entry_cnt; i++) {
		if (json_output)
			show_entry_json(&entries[i], &resolved[i]);
		else
			show_entry_plain(&entries[i], &resolved[i]);
	}
	if (json_output)
		jsonw_end_array(json_wtr);

	err = 0;
out:
	if (iter_fd >= 0)
		close(iter_fd);
	fmodret_iter_bpf__destroy(skel);
	free_owners(owners, owner_cnt);
	btf__free(btf);
	free(resolved);
	free(entries);
	return err;
}

#endif /* BPFTOOL_WITHOUT_SKELETONS */

static int do_help(int argc, char **argv)
{
	if (json_output) {
		jsonw_null(json_wtr);
		return 0;
	}

	fprintf(stderr,
		"Usage: %1$s %2$s { list }\n"
		"       %1$s %2$s help\n"
		"       " HELP_SPEC_OPTIONS " }\n"
		"\n",
		bin_name, "fmodret");
	return 0;
}

static const struct cmd cmds[] = {
	{ "list",	do_list },
	{ "help",	do_help },
	{ 0 }
};

int do_fmodret(int argc, char **argv)
{
	return cmd_select(cmds, argc, argv, do_help);
}
