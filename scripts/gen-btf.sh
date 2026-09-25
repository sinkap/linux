#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
#
# This script generates BTF data for the provided ELF file.
#
# Kernel BTF generation involves these conceptual steps:
#   1. pahole generates BTF from DWARF data
#   2. resolve_btfids applies kernel-specific btf2btf
#      transformations and computes .BTF_ids and .BTF_fmodret_ids data
#   3. the result gets linked/objcopied into the target binary
#
# How step (3) should be done differs between vmlinux, and
# kernel modules, which is the primary reason for the existence
# of this script.
#
# For modules the script expects vmlinux passed in as --btf_base.
# Generated .BTF, .BTF.base, .BTF_ids and .BTF_fmodret_ids sections
# become embedded into the input ELF file with objcopy.
#
# For vmlinux the input file remains unchanged and these files are produced:
#   - ${1}.btf.o with .BTF and any .BTF_fmodret_ids data, ready for linking
#   - ${1}.BTF_ids with .BTF_ids data blob
#   - ${1}.BTF_fmodret_ids with the optional fmodret ID set
# This output is consumed by scripts/link-vmlinux.sh

set -e

usage()
{
	echo "Usage: $0 [--btf_base <file>] <target ELF file>"
	exit 1
}

BTF_BASE=""

while [ $# -gt 0 ]; do
	case "$1" in
	--btf_base)
		BTF_BASE="$2"
		shift 2
		;;
	-*)
		echo "Unknown option: $1" >&2
		usage
		;;
	*)
		break
		;;
	esac
done

if [ $# -ne 1 ]; then
	usage
fi

ELF_FILE="$1"
shift

is_enabled() {
	grep -q "^$1=y" ${objtree}/include/config/auto.conf
}

case "${KBUILD_VERBOSE}" in
*1*)
	set -x
	;;
esac

gen_btf_data()
{
	inline=${BTF_INLINE:+--inline}
	btf1="${ELF_FILE}.BTF.1"
	${PAHOLE} -J ${PAHOLE_FLAGS}			\
		${BTF_BASE:+--btf_base ${BTF_BASE}}	\
		--btf_encode_detached=${btf1}		\
		"${ELF_FILE}"

	${RESOLVE_BTFIDS} ${RESOLVE_BTFIDS_FLAGS}	\
		${BTF_BASE:+--btf_base ${BTF_BASE}}	\
		${inline}				\
		--btf ${btf1} "${ELF_FILE}"
}

gen_btf_o()
{
	btf_data=${ELF_FILE}.btf.o
	btf_o_sections="--only-section=.BTF"

	# Create ${btf_data} with BTF sections and any generated fmodret IDs.
	# Mark the sections SHF_ALLOC for the vmlinux image. --strip-all removes
	# symbols, including __start_BTF and __stop_BTF, which the linker script
	# redefines.
	echo "" | ${CC} ${CLANG_FLAGS} ${KBUILD_CPPFLAGS} ${KBUILD_CFLAGS} -fno-lto -c -x c -o ${btf_data} -
	${OBJCOPY} --add-section .BTF=${ELF_FILE}.BTF \
		--set-section-flags .BTF=alloc,readonly ${btf_data}
	btf_inline=${ELF_FILE}.BTF.inline
	if [ "${BTF_INLINE}" = "m" ]; then
		if [ -f "${btf_inline}" ]; then
			cp "${btf_inline}" "${objtree}/vmlinux.BTF.inline"
		else
			rm -f "${objtree}/vmlinux.BTF.inline"
		fi
	fi
	if [ "${BTF_INLINE}" = "y" ] && [ -f "${btf_inline}" ]; then
		${OBJCOPY} --add-section .BTF.inline=${btf_inline} \
			--set-section-flags .BTF.inline=alloc,readonly ${btf_data}
		btf_o_sections="${btf_o_sections} --only-section=.BTF.inline"
	fi
	if [ -f "${ELF_FILE}.BTF_fmodret_ids" ]; then
		${OBJCOPY} --add-section .BTF_fmodret_ids=${ELF_FILE}.BTF_fmodret_ids \
			--set-section-flags .BTF_fmodret_ids=alloc,readonly ${btf_data}
		${OBJCOPY} --set-section-alignment .BTF_fmodret_ids=8 ${btf_data}
		btf_o_sections="${btf_o_sections} --only-section=.BTF_fmodret_ids"
	fi
	${OBJCOPY} ${btf_o_sections} --strip-all ${btf_data}

	# Change e_type to ET_REL so that it can be used to link final vmlinux.
	# GNU ld 2.35+ and lld do not allow an ET_EXEC input.
	if is_enabled CONFIG_CPU_BIG_ENDIAN; then
		et_rel='\0\1'
	else
		et_rel='\1\0'
	fi
	printf "${et_rel}" | dd of="${btf_data}" conv=notrunc bs=1 seek=16 status=none
}

embed_btf_data()
{
	${OBJCOPY} --add-section .BTF=${ELF_FILE}.BTF ${ELF_FILE}

	# a module might not have a .BTF_ids or .BTF.base section
	btf_base="${ELF_FILE}.BTF.base"
	if [ -f "${btf_base}" ]; then
		${OBJCOPY} --add-section .BTF.base=${btf_base} ${ELF_FILE}
	fi
	btf_inline=${ELF_FILE}.BTF.inline
	case "${ELF_FILE}" in
	*/btf_vmlinux_inline.ko)
		btf_inline=${BTF_BASE}.BTF.inline
		;;
	esac
	if [ -n "${BTF_INLINE}" ] && [ -f "${btf_inline}" ]; then
		${OBJCOPY} --add-section .BTF.inline=${btf_inline} ${ELF_FILE}
	fi
	btf_ids="${ELF_FILE}.BTF_ids"
	if [ -f "${btf_ids}" ]; then
		${RESOLVE_BTFIDS} --patch_btfids ${btf_ids} ${ELF_FILE}
	fi
	if [ -f "${ELF_FILE}.BTF_fmodret_ids" ]; then
		${OBJCOPY} --add-section .BTF_fmodret_ids=${ELF_FILE}.BTF_fmodret_ids \
			--set-section-flags .BTF_fmodret_ids=alloc,readonly ${ELF_FILE}
		${OBJCOPY} --set-section-alignment .BTF_fmodret_ids=8 ${ELF_FILE}
	fi
}

cleanup()
{
	rm -f "${ELF_FILE}.BTF.1"
	rm -f "${ELF_FILE}.BTF"
	rm -f "${ELF_FILE}.BTF.inline"
	rm -f "${ELF_FILE}.BTF.inline.link"
	if [ "${BTFGEN_MODE}" = "module" ]; then
		rm -f "${ELF_FILE}.BTF.base"
		rm -f "${ELF_FILE}.BTF_ids"
		rm -f "${ELF_FILE}.BTF_fmodret_ids"
	fi
}
trap cleanup EXIT

BTFGEN_MODE="vmlinux"
if [ -n "${BTF_BASE}" ]; then
	BTFGEN_MODE="module"
fi

gen_btf_data

case "${BTFGEN_MODE}" in
vmlinux)
	gen_btf_o
	;;
module)
	embed_btf_data
	;;
esac

exit 0
