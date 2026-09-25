/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RESOLVE_BTFIDS_FMODRET_H
#define RESOLVE_BTFIDS_FMODRET_H

struct btf;

int fmodret_ids_generate(const char *elf_path, const struct btf *btf,
			 int elf_encoding, const char *out_path,
			 int verbose);

#endif /* RESOLVE_BTFIDS_FMODRET_H */
