# BPF signing v2: policy on top of the merged scheme

This branch continues the "Signed BPF programs" work merged in Linux
6.17. The merged scheme defines how a loader proves a metadata map is
the one it was signed against. This series adds the pieces an LSM
needs to enforce policy on that decision, in-tree, inside BPF.

## Why this and not Hornet

In parallel, the Hornet LSM series proposes a second signing scheme
for BPF: a separate signed-attribute format in PKCS#7, C-side map-hash
verification in `security/hornet/`, and a new LSM hook that only
fires when Hornet is enabled. BPF does not need a second signing
scheme. It needs a policy framework that consumes the verdict the
existing signing pipeline already produces.

Two parallel signing stacks for the same problem is harmful UX for
Cilium, bpftrace, systemd, distros, and everyone shipping signed
lskels. Building a parallel signing implementation outside the BPF
subsystem, without the BPF maintainers in the loop, has been NACK'd
repeatedly on layering and TOCTOU grounds; iterating on it in
`security/` rather than addressing the layering concerns is not how
this should move forward.

## What this series adds

- `bpf_prog_aux.sig_verdict` (UNSIGNED / OK / METADATA_VERIFIED) and
  `keyring_used`, populated by the syscall path before
  `security_bpf_prog_load` fires.
- `bpf_loader_verify_metadata` kfunc — the metadata check moves from
  ~24 inline insns in the loader to a single in-kernel call that
  promotes the verdict to METADATA_VERIFIED.
- Loader-side prog BTF plus a new `BPF_PSEUDO_KFUNC_CALL_PROG_BTF`
  pseudo, so the kfunc CALL is reproducible across build hosts and
  resolved at load time.
- `security_bpf_prog_load_post_integrity` LSM hook, fired by the
  kfunc on a successful metadata check.
- IPE properties (`bpf_signature`, `bpf_keyring`, `bpf_kernel`) and
  two ops (`BPF_PROG_LOAD`, `BPF_PROG_LOAD_POST_INTEGRITY`) so policy
  can gate either timing without a second kernel-side verifier.

## What this addresses

- **Alexei**: no `copy_from_bpfptr_offset` from an LSM, no direct
  `bpf_map_fops` deref, no parallel verifier in `security/`. Metadata
  verification stays inside BPF.
- **Daniel**: one signing scheme. One signature, one keyring story,
  one userspace contract.
- **Fan Wu**: policy can gate before metadata verification
  (`BPF_PROG_LOAD`, `sig_verdict <= OK`) or after
  (`BPF_PROG_LOAD_POST_INTEGRITY`, `sig_verdict == METADATA_VERIFIED`).
  Both timings live in an existing LSM (IPE).
- **Paul Moore**: no `lsm_integrity_verdict` enum, no per-prog blob,
  no new hook plumbing outside what BPF needs anyway.

## Built on

This branch applies on top of two small fixes already sent to bpf:

- `bpf: reject NULL data/sig in bpf_verify_pkcs7_signature`
  (`bpf_sign_null_fix`)
- `bpf, libbpf: reject non-exclusive metadata maps in the signed
  loader` (`excl_maps_loader_reject`)

Both close holes in the merged signing path and are prerequisites for
the policy work in this series.
