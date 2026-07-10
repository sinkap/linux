/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _MULTINODE_BPF_PROG_H
#define _MULTINODE_BPF_PROG_H

#include <linux/bpf.h>

/* Minimal BPF instruction encoders (subset of samples/bpf/bpf_insn.h). */
#define INSN(CODE, DST, SRC, OFF, IMM) \
	((struct bpf_insn){ .code = (CODE), .dst_reg = (DST), \
			    .src_reg = (SRC), .off = (OFF), .imm = (IMM) })

#define MOV64_REG(D, S)     INSN(BPF_ALU64|BPF_MOV|BPF_X, D, S, 0, 0)
#define MOV64_IMM(D, I)     INSN(BPF_ALU64|BPF_MOV|BPF_K, D, 0, 0, I)
#define ALU64_IMM(OP, D, I) INSN(BPF_ALU64|BPF_OP(OP)|BPF_K, D, 0, 0, I)
#define LDX_MEM(SZ, D, S, O) INSN(BPF_LDX|BPF_SIZE(SZ)|BPF_MEM, D, S, O, 0)
#define STX_MEM(SZ, D, S, O) INSN(BPF_STX|BPF_SIZE(SZ)|BPF_MEM, D, S, O, 0)
#define JMP_REG(OP, D, S, O) INSN(BPF_JMP|BPF_OP(OP)|BPF_X, D, S, O, 0)
#define JMP_IMM(OP, D, I, O) INSN(BPF_JMP|BPF_OP(OP)|BPF_K, D, 0, O, I)
#define EMIT_CALL(F)        INSN(BPF_JMP|BPF_CALL, 0, 0, 0, F)
#define EXIT_INSN()         INSN(BPF_JMP|BPF_EXIT, 0, 0, 0, 0)
#define LD_MAP_FD(D, FD) \
	INSN(BPF_LD|BPF_DW|BPF_IMM, D, BPF_PSEUDO_MAP_FD, 0, FD), \
	INSN(0, 0, 0, 0, 0)

/*
 * XDP producer: read an 8-byte sequence from the packet, reserve an
 * 8-byte record in the ringbuf and submit it. Works unchanged for an
 * arena-backed ring buffer — the map API is the same; only the backing
 * pages come from the shared arena.
 *
 *   r2 = ctx->data; r3 = ctx->data_end
 *   if (r2 + 8 > r3) goto out
 *   r7 = *(u64 *)r2                    // sequence
 *   p = bpf_ringbuf_reserve(map, 8, 0)
 *   if (!p) goto out
 *   *(u64 *)p = r7
 *   bpf_ringbuf_submit(p, 0)
 * out:
 *   return XDP_PASS
 */
static inline int build_producer_prog(struct bpf_insn *p, int ringbuf_fd)
{
	struct bpf_insn prog[] = {
		LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, 0),	/* data */
		LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1, 4),	/* data_end */
		MOV64_REG(BPF_REG_4, BPF_REG_2),
		ALU64_IMM(BPF_ADD, BPF_REG_4, 8),
		JMP_REG(BPF_JGT, BPF_REG_4, BPF_REG_3, 11),	/* -> out */
		LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_2, 0),	/* seq */
		LD_MAP_FD(BPF_REG_1, ringbuf_fd),
		MOV64_IMM(BPF_REG_2, 8),
		MOV64_IMM(BPF_REG_3, 0),
		EMIT_CALL(BPF_FUNC_ringbuf_reserve),
		JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 4),		/* -> out */
		STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_7, 0),
		MOV64_REG(BPF_REG_1, BPF_REG_0),
		MOV64_IMM(BPF_REG_2, 0),
		EMIT_CALL(BPF_FUNC_ringbuf_submit),
		MOV64_IMM(BPF_REG_0, 2),			/* out: XDP_PASS */
		EXIT_INSN(),
	};
	int n = sizeof(prog) / sizeof(prog[0]);

	for (int i = 0; i < n; i++)
		p[i] = prog[i];
	return n;
}

#endif /* _MULTINODE_BPF_PROG_H */
