// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../../../include/linux/filter.h"
#include "bpf_misc.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, long long);
} map_array SEC(".maps");

#ifdef CAN_USE_CACHE_OPS

/*
 * Load a pointer to a map value into r1. On success r1 points to writable
 * map memory, on lookup failure the program exits.
 */
#define MAP_VALUE_PTR						\
	"r1 = %[map_array] ll;"					\
	"r2 = 0;"						\
	"*(u32 *)(r10 - 4) = r2;"				\
	"r2 = r10;"						\
	"r2 += -4;"						\
	"call %[bpf_map_lookup_elem];"				\
	"if r0 != 0 goto 1f;"					\
	"exit;"							\
"1:"								\
	"r1 = r0;"

SEC("socket")
__description("cache invalidate on map value")
__success __retval(0)
__naked void cache_inval_map_value(void)
{
	asm volatile (
	MAP_VALUE_PTR
	".8byte %[cache_insn];"		// cache_inval((u8 *)(r1 + 0));
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(map_array),
	  __imm_insn(cache_insn,
		     BPF_CACHE_OP(BPF_CACHE_INVAL, BPF_REG_1, 0))
	: __clobber_all);
}

SEC("socket")
__description("cache clean on map value")
__success __retval(0)
__naked void cache_clean_map_value(void)
{
	asm volatile (
	MAP_VALUE_PTR
	".8byte %[cache_insn];"		// cache_clean((u8 *)(r1 + 0));
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(map_array),
	  __imm_insn(cache_insn,
		     BPF_CACHE_OP(BPF_CACHE_CLEAN, BPF_REG_1, 0))
	: __clobber_all);
}

SEC("socket")
__description("cache flush on map value with offset")
__success __retval(0)
__naked void cache_flush_map_value_off(void)
{
	asm volatile (
	MAP_VALUE_PTR
	".8byte %[cache_insn];"		// cache_flush((u8 *)(r1 + 4));
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(map_array),
	  __imm_insn(cache_insn,
		     BPF_CACHE_OP(BPF_CACHE_FLUSH, BPF_REG_1, 4))
	: __clobber_all);
}

SEC("socket")
__description("cache maintenance is rejected without CAP_PERFMON")
__success
__failure_unpriv __msg_unpriv("cache maintenance instructions require CAP_PERFMON")
__naked void cache_op_unpriv(void)
{
	asm volatile (
	MAP_VALUE_PTR
	".8byte %[cache_insn];"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(map_array),
	  __imm_insn(cache_insn,
		     BPF_CACHE_OP(BPF_CACHE_FLUSH, BPF_REG_1, 0))
	: __clobber_all);
}

SEC("socket")
__description("cache maintenance with invalid size")
__failure __msg("cache maintenance instructions only support the BPF_B size modifier")
__naked void cache_op_bad_size(void)
{
	asm volatile (
	MAP_VALUE_PTR
	".8byte %[cache_insn];"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(map_array),
	  __imm_insn(cache_insn,
		     BPF_ATOMIC_OP(BPF_W, BPF_CACHE_INVAL, BPF_REG_1, BPF_REG_0, 0))
	: __clobber_all);
}

SEC("socket")
__description("cache maintenance with non-zero src_reg")
__failure __msg("cache maintenance instructions use reserved fields")
__naked void cache_op_bad_src(void)
{
	asm volatile (
	MAP_VALUE_PTR
	".8byte %[cache_insn];"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(map_array),
	  __imm_insn(cache_insn,
		     BPF_ATOMIC_OP(BPF_B, BPF_CACHE_INVAL, BPF_REG_1, BPF_REG_2, 0))
	: __clobber_all);
}

SEC("socket")
__description("cache maintenance with uninitialized address register")
__failure __msg("R2 !read_ok")
__naked void cache_op_uninit_reg(void)
{
	asm volatile (
	".8byte %[cache_insn];"
	"r0 = 0;"
	"exit;"
	:
	: __imm_insn(cache_insn,
		     BPF_CACHE_OP(BPF_CACHE_INVAL, BPF_REG_2, 0))
	: __clobber_all);
}

SEC("socket")
__description("cache maintenance on scalar")
__failure __msg("R1 invalid mem access 'scalar'")
__naked void cache_op_scalar(void)
{
	asm volatile (
	"r1 = 0;"
	".8byte %[cache_insn];"
	"r0 = 0;"
	"exit;"
	:
	: __imm_insn(cache_insn,
		     BPF_CACHE_OP(BPF_CACHE_INVAL, BPF_REG_1, 0))
	: __clobber_all);
}

SEC("socket")
__description("cache maintenance on stack is rejected")
__failure __msg("cache maintenance on stack memory is not allowed")
__naked void cache_op_stack(void)
{
	asm volatile (
	"r1 = 0;"
	"*(u64 *)(r10 - 8) = r1;"
	"r1 = r10;"
	"r1 += -8;"
	".8byte %[cache_insn];"
	"r0 = 0;"
	"exit;"
	:
	: __imm_insn(cache_insn,
		     BPF_CACHE_OP(BPF_CACHE_INVAL, BPF_REG_1, 0))
	: __clobber_all);
}

SEC("tc")
__description("cache maintenance on ctx is rejected")
__failure __msg("cache maintenance on R1 ctx is not allowed")
__naked void cache_op_ctx(void)
{
	asm volatile (
	".8byte %[cache_insn];"
	"r0 = 0;"
	"exit;"
	:
	: __imm_insn(cache_insn,
		     BPF_CACHE_OP(BPF_CACHE_INVAL, BPF_REG_1, 0))
	: __clobber_all);
}

#else

SEC("socket")
__description("cache maintenance unsupported arch")
__success
__naked void cache_op_unsupported(void)
{
	asm volatile (
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

#endif /* CAN_USE_CACHE_OPS */

char _license[] SEC("license") = "GPL";
