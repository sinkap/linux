/* SPDX-License-Identifier: GPL-2.0-only */
/* Internal interface of the BPF verifier core.
 *
 * This header collects the verifier's private types, macros, inline
 * helpers, and cross-file function declarations.  Anything declared
 * here is an implementation detail of the verifier and may change
 * without notice.  The kernel-wide API the rest of the BPF subsystem
 * (and a loadable verifier module, see kernel/bpf/verifier_dispatch.c)
 * depends on lives in <linux/bpf_verifier.h>.
 *
 * Do not include this file from outside kernel/bpf/.  In particular it
 * is intended to be #included only by the verifier set:
 *   - kernel/bpf/verifier.c
 *   - kernel/bpf/{liveness,states,backtrack,cfg,check_btf,const_fold,fixups}.c
 * and by the in-vmlinux print/log helpers in kernel/bpf/log.c that walk
 * verifier-internal state for diagnostics.
 */
#ifndef _KERNEL_BPF_VERIFIER_INTERNAL_H
#define _KERNEL_BPF_VERIFIER_INTERNAL_H 1

#include <linux/bpf_verifier.h>

/* 4-byte stack slot granularity for liveness analysis */
#define BPF_HALF_REG_SIZE	4
#define STACK_SLOT_SZ		4
#define STACK_SLOTS		(MAX_BPF_STACK / BPF_HALF_REG_SIZE)	/* 128 */

typedef struct {
	u64 v[2];
} spis_t;

#define SPIS_ZERO	((spis_t){})
#define SPIS_ALL	((spis_t){{ U64_MAX, U64_MAX }})

static inline bool spis_is_zero(spis_t s)
{
	return s.v[0] == 0 && s.v[1] == 0;
}

static inline bool spis_equal(spis_t a, spis_t b)
{
	return a.v[0] == b.v[0] && a.v[1] == b.v[1];
}

static inline spis_t spis_or(spis_t a, spis_t b)
{
	return (spis_t){{ a.v[0] | b.v[0], a.v[1] | b.v[1] }};
}

static inline spis_t spis_and(spis_t a, spis_t b)
{
	return (spis_t){{ a.v[0] & b.v[0], a.v[1] & b.v[1] }};
}

static inline spis_t spis_not(spis_t s)
{
	return (spis_t){{ ~s.v[0], ~s.v[1] }};
}

static inline bool spis_test_bit(spis_t s, u32 slot)
{
	return s.v[slot / 64] & BIT_ULL(slot % 64);
}

static inline void spis_or_range(spis_t *mask, u32 lo, u32 hi)
{
	u32 w;

	for (w = lo; w <= hi && w < STACK_SLOTS; w++)
		mask->v[w / 64] |= BIT_ULL(w % 64);
}

struct bpf_reference_state {
	/* Each reference object has a type. Ensure REF_TYPE_PTR is zero to
	 * default to pointer reference on zero initialization of a state.
	 */
	enum ref_state_type {
		REF_TYPE_PTR		= (1 << 1),
		REF_TYPE_IRQ		= (1 << 2),
		REF_TYPE_LOCK		= (1 << 3),
		REF_TYPE_RES_LOCK 	= (1 << 4),
		REF_TYPE_RES_LOCK_IRQ	= (1 << 5),
		REF_TYPE_LOCK_MASK	= REF_TYPE_LOCK | REF_TYPE_RES_LOCK | REF_TYPE_RES_LOCK_IRQ,
	} type;
	/* Track each reference created with a unique id, even if the same
	 * instruction creates the reference multiple times (eg, via CALL).
	 */
	int id;
	/* Instruction where the allocation of this reference occurred. This
	 * is used purely to inform the user of a reference leak.
	 */
	int insn_idx;
	/* Use to keep track of the source object of a lock, to ensure
	 * it matches on unlock.
	 */
	void *ptr;
};

/* instruction history flags, used in bpf_jmp_history_entry.flags field */
enum {
	/* instruction references stack slot through PTR_TO_STACK register;
	 * we also store stack's frame number in lower 3 bits (MAX_CALL_FRAMES is 8)
	 * and accessed stack slot's index in next 6 bits (MAX_BPF_STACK is 512,
	 * 8 bytes per slot, so slot index (spi) is [0, 63])
	 */
	INSN_F_FRAMENO_MASK = 0x7, /* 3 bits */

	INSN_F_SPI_MASK = 0x3f, /* 6 bits */
	INSN_F_SPI_SHIFT = 3, /* shifted 3 bits to the left */

	INSN_F_STACK_ACCESS = BIT(9),

	INSN_F_DST_REG_STACK = BIT(10), /* dst_reg is PTR_TO_STACK */
	INSN_F_SRC_REG_STACK = BIT(11), /* src_reg is PTR_TO_STACK */
	/* total 12 bits are used now. */
};

static_assert(INSN_F_FRAMENO_MASK + 1 >= MAX_CALL_FRAMES);
static_assert(INSN_F_SPI_MASK + 1 >= MAX_BPF_STACK / 8);

struct bpf_jmp_history_entry {
	u32 idx;
	/* insn idx can't be bigger than 1 million */
	u32 prev_idx : 20;
	/* special INSN_F_xxx flags */
	u32 flags : 12;
	/* additional registers that need precision tracking when this
	 * jump is backtracked, vector of six 10-bit records
	 */
	u64 linked_regs;
};

#define bpf_get_spilled_reg(slot, frame, mask)				\
	(((slot < frame->allocated_stack / BPF_REG_SIZE) &&		\
	  ((1 << frame->stack[slot].slot_type[BPF_REG_SIZE - 1]) & (mask))) \
	 ? &frame->stack[slot].spilled_ptr : NULL)

/* Iterate over 'frame', setting 'reg' to either NULL or a spilled register. */
#define bpf_for_each_spilled_reg(iter, frame, reg, mask)			\
	for (iter = 0, reg = bpf_get_spilled_reg(iter, frame, mask);		\
	     iter < frame->allocated_stack / BPF_REG_SIZE;		\
	     iter++, reg = bpf_get_spilled_reg(iter, frame, mask))

#define bpf_for_each_reg_in_vstate_mask(__vst, __state, __reg, __mask, __expr)   \
	({                                                               \
		struct bpf_verifier_state *___vstate = __vst;            \
		int ___i, ___j;                                          \
		for (___i = 0; ___i <= ___vstate->curframe; ___i++) {    \
			struct bpf_reg_state *___regs;                   \
			__state = ___vstate->frame[___i];                \
			___regs = __state->regs;                         \
			for (___j = 0; ___j < MAX_BPF_REG; ___j++) {     \
				__reg = &___regs[___j];                  \
				(void)(__expr);                          \
			}                                                \
			bpf_for_each_spilled_reg(___j, __state, __reg, __mask) { \
				if (!__reg)                              \
					continue;                        \
				(void)(__expr);                          \
			}                                                \
		}                                                        \
	})

/* Invoke __expr over regsiters in __vst, setting __state and __reg */
#define bpf_for_each_reg_in_vstate(__vst, __state, __reg, __expr) \
	bpf_for_each_reg_in_vstate_mask(__vst, __state, __reg, 1 << STACK_SPILL, __expr)

/* linked list of verifier states used to prune search */
struct bpf_verifier_state_list {
	struct bpf_verifier_state state;
	struct list_head node;
	u32 miss_cnt;
	u32 hit_cnt:31;
	u32 in_free_list:1;
};

static inline void mark_prune_point(struct bpf_verifier_env *env, int idx)
{
	env->insn_aux_data[idx].prune_point = true;
}

static inline bool bpf_is_prune_point(struct bpf_verifier_env *env, int insn_idx)
{
	return env->insn_aux_data[insn_idx].prune_point;
}

static inline void mark_force_checkpoint(struct bpf_verifier_env *env, int idx)
{
	env->insn_aux_data[idx].force_checkpoint = true;
}

static inline bool bpf_is_force_checkpoint(struct bpf_verifier_env *env, int insn_idx)
{
	return env->insn_aux_data[insn_idx].force_checkpoint;
}

static inline void mark_calls_callback(struct bpf_verifier_env *env, int idx)
{
	env->insn_aux_data[idx].calls_callback = true;
}

static inline bool bpf_calls_callback(struct bpf_verifier_env *env, int insn_idx)
{
	return env->insn_aux_data[insn_idx].calls_callback;
}

static inline void mark_jmp_point(struct bpf_verifier_env *env, int idx)
{
	env->insn_aux_data[idx].jmp_point = true;
}

static inline struct bpf_func_state *cur_func(struct bpf_verifier_env *env)
{
	struct bpf_verifier_state *cur = env->cur_state;

	return cur->frame[cur->curframe];
}

static inline struct bpf_reg_state *cur_regs(struct bpf_verifier_env *env)
{
	return cur_func(env)->regs;
}

/* verifier state waiting for propagate_backedges() */
struct bpf_scc_backedge {
	struct bpf_scc_backedge *next;
	struct bpf_verifier_state state;
};

struct bpf_scc_visit {
	struct bpf_scc_callchain callchain;
	/* first state in current verification path that entered SCC
	 * identified by the callchain
	 */
	struct bpf_verifier_state *entry_state;
	struct bpf_scc_backedge *backedges; /* list of backedges */
	u32 num_backedges;
};

/* An array of bpf_scc_visit structs sharing tht same bpf_scc_callchain->scc
 * but having different bpf_scc_callchain->callsites.
 */
struct bpf_scc_info {
	u32 num_visits;
	struct bpf_scc_visit visits[];
};

int mark_chain_precision(struct bpf_verifier_env *env, int regno);

int bpf_is_state_visited(struct bpf_verifier_env *env, int insn_idx);
int bpf_update_branch_counts(struct bpf_verifier_env *env, struct bpf_verifier_state *st);

void bpf_clear_jmp_history(struct bpf_verifier_state *state);
int bpf_copy_verifier_state(struct bpf_verifier_state *dst_state,
			    const struct bpf_verifier_state *src);
struct list_head *bpf_explored_state(struct bpf_verifier_env *env, int idx);
void bpf_free_verifier_state(struct bpf_verifier_state *state, bool free_self);
void bpf_free_backedges(struct bpf_scc_visit *visit);
int bpf_push_jmp_history(struct bpf_verifier_env *env, struct bpf_verifier_state *cur,
			 int insn_flags, u64 linked_regs);
void bpf_bt_sync_linked_regs(struct backtrack_state *bt, struct bpf_jmp_history_entry *hist);
void bpf_mark_reg_not_init(const struct bpf_verifier_env *env,
			   struct bpf_reg_state *reg);
void bpf_mark_reg_unknown_imprecise(struct bpf_reg_state *reg);
int unbound_reg_init(void);
extern struct btf *btf_vmlinux;
void bpf_mark_all_scalars_precise(struct bpf_verifier_env *env,
				  struct bpf_verifier_state *st);
void bpf_clear_singular_ids(struct bpf_verifier_env *env, struct bpf_verifier_state *st);
int bpf_mark_chain_precision(struct bpf_verifier_env *env,
			     struct bpf_verifier_state *starting_state,
			     int regno, bool *changed);

static inline int bpf_get_spi(s32 off)
{
	return (-off - 1) / BPF_REG_SIZE;
}

static inline struct bpf_func_state *bpf_func(struct bpf_verifier_env *env,
					      const struct bpf_reg_state *reg)
{
	struct bpf_verifier_state *cur = env->cur_state;

	return cur->frame[reg->frameno];
}

/* Return IP for a given frame in a call stack */
static inline u32 bpf_frame_insn_idx(struct bpf_verifier_state *st, u32 frame)
{
	return frame == st->curframe
	       ? st->insn_idx
	       : st->frame[frame + 1]->callsite;
}

static inline bool bpf_is_jmp_point(struct bpf_verifier_env *env, int insn_idx)
{
	return env->insn_aux_data[insn_idx].jmp_point;
}

static inline bool bpf_is_spilled_reg(const struct bpf_stack_state *stack)
{
	return stack->slot_type[BPF_REG_SIZE - 1] == STACK_SPILL;
}

static inline bool bpf_is_spilled_scalar_reg(const struct bpf_stack_state *stack)
{
	return bpf_is_spilled_reg(stack) && stack->spilled_ptr.type == SCALAR_VALUE;
}

static inline bool bpf_register_is_null(struct bpf_reg_state *reg)
{
	return reg->type == SCALAR_VALUE && tnum_equals_const(reg->var_off, 0);
}

static inline void bpf_bt_set_frame_reg(struct backtrack_state *bt, u32 frame, u32 reg)
{
	bt->reg_masks[frame] |= 1 << reg;
}

static inline void bpf_bt_set_frame_slot(struct backtrack_state *bt, u32 frame, u32 slot)
{
	bt->stack_masks[frame] |= 1ull << slot;
}

static inline bool bt_is_frame_reg_set(struct backtrack_state *bt, u32 frame, u32 reg)
{
	return bt->reg_masks[frame] & (1 << reg);
}

static inline bool bt_is_frame_slot_set(struct backtrack_state *bt, u32 frame, u32 slot)
{
	return bt->stack_masks[frame] & (1ull << slot);
}

static inline void mark_reg_scratched(struct bpf_verifier_env *env, u32 regno)
{
	env->scratched_regs |= 1U << regno;
}

static inline void mark_stack_slot_scratched(struct bpf_verifier_env *env, u32 spi)
{
	env->scratched_stack_slots |= 1ULL << spi;
}

static inline bool reg_scratched(const struct bpf_verifier_env *env, u32 regno)
{
	return (env->scratched_regs >> regno) & 1;
}

static inline bool stack_slot_scratched(const struct bpf_verifier_env *env, u64 regno)
{
	return (env->scratched_stack_slots >> regno) & 1;
}

static inline bool verifier_state_scratched(const struct bpf_verifier_env *env)
{
	return env->scratched_regs || env->scratched_stack_slots;
}

static inline void mark_verifier_state_clean(struct bpf_verifier_env *env)
{
	env->scratched_regs = 0U;
	env->scratched_stack_slots = 0ULL;
}

/* Used for printing the entire verifier state. */
static inline void mark_verifier_state_scratched(struct bpf_verifier_env *env)
{
	env->scratched_regs = ~0U;
	env->scratched_stack_slots = ~0ULL;
}

static inline bool bpf_stack_narrow_access_ok(int off, int fill_size, int spill_size)
{
#ifdef __BIG_ENDIAN
	off -= spill_size - fill_size;
#endif

	return !(off % BPF_REG_SIZE);
}

static inline bool insn_is_gotox(struct bpf_insn *insn)
{
	return BPF_CLASS(insn->code) == BPF_JMP &&
	       BPF_OP(insn->code) == BPF_JA &&
	       BPF_SRC(insn->code) == BPF_X;
}

const char *reg_type_str(struct bpf_verifier_env *env, enum bpf_reg_type type);
const char *dynptr_type_str(enum bpf_dynptr_type type);
const char *iter_type_str(const struct btf *btf, u32 btf_id);
const char *iter_state_str(enum bpf_iter_state state);

void print_verifier_state(struct bpf_verifier_env *env, const struct bpf_verifier_state *vstate,
			  u32 frameno, bool print_all);
void print_insn_state(struct bpf_verifier_env *env, const struct bpf_verifier_state *vstate,
		      u32 frameno);
u32 bpf_vlog_alignment(u32 pos);

struct bpf_subprog_info *bpf_find_containing_subprog(struct bpf_verifier_env *env, int off);
int bpf_jmp_offset(struct bpf_insn *insn);
struct bpf_iarray *bpf_insn_successors(struct bpf_verifier_env *env, u32 idx);
void bpf_fmt_stack_mask(char *buf, ssize_t buf_sz, u64 stack_mask);
bool bpf_subprog_is_global(const struct bpf_verifier_env *env, int subprog);

int bpf_find_subprog(struct bpf_verifier_env *env, int off);
int bpf_compute_const_regs(struct bpf_verifier_env *env);
int bpf_prune_dead_branches(struct bpf_verifier_env *env);
int bpf_check_cfg(struct bpf_verifier_env *env);
int bpf_compute_postorder(struct bpf_verifier_env *env);
int bpf_compute_scc(struct bpf_verifier_env *env);

struct bpf_call_summary {
	u8 num_params;
	bool is_void;
	bool fastcall;
};

struct bpf_map_desc {
	struct bpf_map *ptr;
	int uid;
};

struct bpf_kfunc_call_arg_meta {
	/* In parameters */
	struct btf *btf;
	u32 func_id;
	u32 kfunc_flags;
	const struct btf_type *func_proto;
	const char *func_name;
	/* Out parameters */
	u32 ref_obj_id;
	u8 release_regno;
	bool r0_rdonly;
	u32 ret_btf_id;
	u64 r0_size;
	u32 subprogno;
	struct {
		u64 value;
		bool found;
	} arg_constant;

	/* arg_{btf,btf_id,owning_ref} are used by kfunc-specific handling,
	 * generally to pass info about user-defined local kptr types to later
	 * verification logic
	 *   bpf_obj_drop/bpf_percpu_obj_drop
	 *     Record the local kptr type to be drop'd
	 *   bpf_refcount_acquire (via KF_ARG_PTR_TO_REFCOUNTED_KPTR arg type)
	 *     Record the local kptr type to be refcount_incr'd and use
	 *     arg_owning_ref to determine whether refcount_acquire should be
	 *     fallible
	 */
	struct btf *arg_btf;
	u32 arg_btf_id;
	bool arg_owning_ref;
	bool arg_prog;

	struct {
		struct btf_field *field;
	} arg_list_head;
	struct {
		struct btf_field *field;
	} arg_rbtree_root;
	struct {
		enum bpf_dynptr_type type;
		u32 id;
		u32 ref_obj_id;
	} initialized_dynptr;
	struct {
		u8 spi;
		u8 frameno;
	} iter;
	struct bpf_map_desc map;
	u64 mem_size;
};

int bpf_get_helper_proto(struct bpf_verifier_env *env, int func_id,
			 const struct bpf_func_proto **ptr);
int bpf_fetch_kfunc_arg_meta(struct bpf_verifier_env *env, s32 func_id,
			     s16 offset, struct bpf_kfunc_call_arg_meta *meta);
bool bpf_is_async_callback_calling_insn(struct bpf_insn *insn);
bool bpf_is_sync_callback_calling_insn(struct bpf_insn *insn);
static inline bool bpf_is_iter_next_kfunc(struct bpf_kfunc_call_arg_meta *meta)
{
	return meta->kfunc_flags & KF_ITER_NEXT;
}

static inline bool bpf_is_kfunc_sleepable(struct bpf_kfunc_call_arg_meta *meta)
{
	return meta->kfunc_flags & KF_SLEEPABLE;
}
bool bpf_is_kfunc_pkt_changing(struct bpf_kfunc_call_arg_meta *meta);
struct bpf_iarray *bpf_iarray_realloc(struct bpf_iarray *old, size_t n_elem);
int bpf_copy_insn_array_uniq(struct bpf_map *map, u32 start, u32 end, u32 *off);
bool bpf_insn_is_cond_jump(u8 code);
bool bpf_is_may_goto_insn(struct bpf_insn *insn);

void bpf_verbose_insn(struct bpf_verifier_env *env, struct bpf_insn *insn);
bool bpf_get_call_summary(struct bpf_verifier_env *env, struct bpf_insn *call,
			  struct bpf_call_summary *cs);
s64 bpf_helper_stack_access_bytes(struct bpf_verifier_env *env,
				  struct bpf_insn *insn, int arg,
				  int insn_idx);
s64 bpf_kfunc_stack_access_bytes(struct bpf_verifier_env *env,
				 struct bpf_insn *insn, int arg,
				 int insn_idx);
int bpf_compute_subprog_arg_access(struct bpf_verifier_env *env);

int bpf_stack_liveness_init(struct bpf_verifier_env *env);
void bpf_stack_liveness_free(struct bpf_verifier_env *env);
int bpf_live_stack_query_init(struct bpf_verifier_env *env, struct bpf_verifier_state *st);
bool bpf_stack_slot_alive(struct bpf_verifier_env *env, u32 frameno, u32 spi);
int bpf_compute_live_registers(struct bpf_verifier_env *env);

#define BPF_MAP_KEY_POISON	(1ULL << 63)
#define BPF_MAP_KEY_SEEN	(1ULL << 62)

static inline bool bpf_map_ptr_poisoned(const struct bpf_insn_aux_data *aux)
{
	return aux->map_ptr_state.poison;
}

static inline bool bpf_map_ptr_unpriv(const struct bpf_insn_aux_data *aux)
{
	return aux->map_ptr_state.unpriv;
}

static inline bool bpf_map_key_poisoned(const struct bpf_insn_aux_data *aux)
{
	return aux->map_key_state & BPF_MAP_KEY_POISON;
}

static inline bool bpf_map_key_unseen(const struct bpf_insn_aux_data *aux)
{
	return !(aux->map_key_state & BPF_MAP_KEY_SEEN);
}

static inline u64 bpf_map_key_immediate(const struct bpf_insn_aux_data *aux)
{
	return aux->map_key_state & ~(BPF_MAP_KEY_SEEN | BPF_MAP_KEY_POISON);
}

#define MAX_PACKET_OFF 0xffff
#define CALLER_SAVED_REGS 6

enum bpf_reg_arg_type {
	SRC_OP,		/* register is used as source operand */
	DST_OP,		/* register is used as destination operand */
	DST_OP_NO_MARK	/* same as above, check only, don't mark */
};

#define MAX_KFUNC_DESCS 256

struct bpf_kfunc_desc {
	struct btf_func_model func_model;
	u32 func_id;
	s32 imm;
	u16 offset;
	unsigned long addr;
};

struct bpf_kfunc_desc_tab {
	/* Sorted by func_id (BTF ID) and offset (fd_array offset) during
	 * verification. JITs do lookups by bpf_insn, where func_id may not be
	 * available, therefore at the end of verification do_misc_fixups()
	 * sorts this by imm and offset.
	 */
	struct bpf_kfunc_desc descs[MAX_KFUNC_DESCS];
	u32 nr_descs;
};

/* Functions exported from verifier.c, used by fixups.c */
bool bpf_is_reg64(struct bpf_insn *insn, u32 regno, struct bpf_reg_state *reg, enum bpf_reg_arg_type t);
void bpf_clear_insn_aux_data(struct bpf_verifier_env *env, int start, int len);
void bpf_mark_subprog_exc_cb(struct bpf_verifier_env *env, int subprog);
bool bpf_allow_tail_call_in_subprogs(struct bpf_verifier_env *env);
bool bpf_verifier_inlines_helper_call(struct bpf_verifier_env *env, s32 imm);
int bpf_add_kfunc_call(struct bpf_verifier_env *env, u32 func_id, u16 offset);
int bpf_fixup_kfunc_call(struct bpf_verifier_env *env, struct bpf_insn *insn,
			 struct bpf_insn *insn_buf, int insn_idx, int *cnt);

/* Functions in fixups.c, called from bpf_check() */
int bpf_remove_fastcall_spills_fills(struct bpf_verifier_env *env);
int bpf_optimize_bpf_loop(struct bpf_verifier_env *env);
void bpf_opt_hard_wire_dead_code_branches(struct bpf_verifier_env *env);
int bpf_opt_remove_dead_code(struct bpf_verifier_env *env);
int bpf_opt_remove_nops(struct bpf_verifier_env *env);
int bpf_opt_subreg_zext_lo32_rnd_hi32(struct bpf_verifier_env *env, const union bpf_attr *attr);
int bpf_convert_ctx_accesses(struct bpf_verifier_env *env);
int bpf_jit_subprogs(struct bpf_verifier_env *env);
int bpf_fixup_call_args(struct bpf_verifier_env *env);
int bpf_do_misc_fixups(struct bpf_verifier_env *env);

#endif /* _KERNEL_BPF_VERIFIER_INTERNAL_H */

/* Verifier-internal callers go directly to the _impl functions, skipping
 * the dispatcher wrapper.  Outside the verifier set these macros are not
 * visible, so calls to e.g. bpf_get_btf_vmlinux() resolve to the
 * dispatcher wrapper in verifier_dispatch.c instead.
 */
struct bpf_prog *bpf_patch_insn_data_impl(struct bpf_verifier_env *env, u32 off,
					  const struct bpf_insn *patch, u32 len);
struct bpf_insn_aux_data *bpf_dup_insn_aux_data_impl(struct bpf_verifier_env *env);
void bpf_restore_insn_aux_data_impl(struct bpf_verifier_env *env,
				    struct bpf_insn_aux_data *orig);
int bpf_get_kfunc_addr_impl(const struct bpf_prog *prog, u32 func_id,
			    u16 btf_fd_idx, u8 **func_addr);
void bpf_free_kfunc_btf_tab_impl(struct bpf_kfunc_btf_tab *tab);
bool bpf_prog_has_kfunc_call_impl(const struct bpf_prog *prog);

#define bpf_patch_insn_data		bpf_patch_insn_data_impl
#define bpf_dup_insn_aux_data		bpf_dup_insn_aux_data_impl
#define bpf_restore_insn_aux_data	bpf_restore_insn_aux_data_impl
#define bpf_get_kfunc_addr		bpf_get_kfunc_addr_impl
#define bpf_free_kfunc_btf_tab		bpf_free_kfunc_btf_tab_impl
#define bpf_prog_has_kfunc_call		bpf_prog_has_kfunc_call_impl
int map_set_for_each_callback_args_impl(struct bpf_verifier_env *env,
					struct bpf_func_state *caller,
					struct bpf_func_state *callee);
