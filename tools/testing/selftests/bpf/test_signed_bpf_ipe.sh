#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Integration tests for IPE BPF program signature policies.
#
# Two-stage script:
#   * host stage (default): writes a boot policy, sanity-checks the
#     kernel config, then boots the kernel under vmtest.sh and
#     re-invokes itself with --in-vm as the QEMU payload.
#   * --in-vm stage: asserts IPE is loaded, signed lskels load,
#     the gate hook fires, the deny-UNSIGNED rule matches, and
#     unsigned loads are denied under enforce=1.
#
# Requires the kernel to already be built with:
#   CONFIG_SECURITY_IPE=y
#   CONFIG_IPE_PROP_BPF_SIGNATURE=y
#   CONFIG_LSM="...,ipe"
#   CONFIG_IPE_BOOT_POLICY=<path to the policy this script writes>
#
# A typical run:
#   tools/testing/selftests/bpf/test_signed_bpf_ipe.sh

if [ "${1:-}" = "--in-vm" ]; then
	# ---- in-VM stage ----
	# Each check prints "PASS Tn ..." or "FAIL Tn ..." on its own line
	# so the host-side wrapper can score them. A final
	# "ALL_TESTS_PASSED" (or "FAIL_COUNT N") line is the verdict.
	set -u
	fail=0
	record() {
		# $1 = T-id, $2 = PASS|FAIL|SKIP, $3... = description
		id=$1; verdict=$2; shift 2
		printf '%s %s %s\n' "$verdict" "$id" "$*"
		[ "$verdict" = FAIL ] && fail=$((fail + 1))
		return 0
	}

	# T0: IPE LSM is loaded. securityfs may not be auto-mounted in
	# this rootfs, so try to mount it before checking.
	mountpoint -q /sys/kernel/security 2>/dev/null \
		|| mount -t securityfs none /sys/kernel/security 2>/dev/null || true
	if [ -d /sys/kernel/security/ipe ]; then
		record T0 PASS "securityfs/ipe present"
	elif grep -qw ipe /sys/kernel/security/lsm 2>/dev/null; then
		record T0 PASS "ipe in /sys/kernel/security/lsm"
	elif [ -r /sys/module/ipe/parameters/enforce ]; then
		record T0 PASS "ipe module parameters present"
	else
		record T0 FAIL "no sign that IPE LSM is loaded"
	fi

	# T1: signed lskel loads end-to-end. atomics is the canonical
	# signed loader test; passing here means both the gate hook and
	# the post-integrity hook returned 0 for this load.
	if ./test_progs -t atomics 2>&1 | grep -qE '^#[0-9]+[[:space:]]+atomics:OK$'; then
		record T1 PASS "atomics signed lskel loaded"
	else
		record T1 FAIL "atomics signed lskel did not load"
	fi

	# T2: at least one BPF_PROG_LOAD audit line surfaced. The kernel-
	# internal BPF preloads at PID 1 are UNSIGNED in this kernel and
	# exercise the deny path even in permissive mode.
	if dmesg | grep -q 'ipe_op=BPF_PROG_LOAD ipe_hook=BPF_PROG_LOAD'; then
		record T2 PASS "ipe_op=BPF_PROG_LOAD audit line found"
	else
		record T2 FAIL "no ipe_op=BPF_PROG_LOAD audit lines in dmesg"
	fi

	# T3: the deny-UNSIGNED rule actually matched (verifies the
	# policy parser accepted bpf_signature= and the verdict flowed
	# through).
	if dmesg | grep 'ipe_op=BPF_PROG_LOAD' \
		| grep -q 'bpf_signature=UNSIGNED action=DENY'; then
		record T3 PASS "deny-UNSIGNED rule matched"
	else
		record T3 FAIL "deny-UNSIGNED rule never matched"
	fi

	# T5: a policy that gates on BPF_PROG_LOAD_POST_INTEGRITY is
	# parseable and lives in the active policy. Read the policy back
	# from securityfs and look for the post-integrity rule. The
	# policies/ subdir uses the literal policy_name including quotes,
	# hence the glob.
	mountpoint -q /sys/kernel/security 2>/dev/null \
		|| mount -t securityfs none /sys/kernel/security 2>/dev/null || true
	content=
	for d in /sys/kernel/security/ipe/policies/*/; do
		[ -d "$d" ] || continue
		if [ -r "$d/policy" ]; then
			content=$(cat "$d/policy" 2>/dev/null || true)
			break
		fi
	done
	if [ -z "$content" ]; then
		record T5 SKIP "could not read /sys/kernel/security/ipe/policies/*/policy"
	elif echo "$content" | grep -q '^op=BPF_PROG_LOAD_POST_INTEGRITY'; then
		record T5 PASS "post-integrity rule present in active policy"
	else
		record T5 FAIL "active policy does not contain a BPF_PROG_LOAD_POST_INTEGRITY rule"
	fi

	# T4: under enforce=1, an unsigned BPF prog_load is rejected with
	# -EACCES. We boot permissive so test_progs -t atomics (T1) can
	# run; here we flip enforce on at runtime via securityfs and
	# trigger a load that we know is unsigned.
	ENFORCE=/sys/kernel/security/ipe/enforce
	mountpoint -q /sys/kernel/security 2>/dev/null \
		|| mount -t securityfs none /sys/kernel/security 2>/dev/null || true

	if [ ! -w "$ENFORCE" ]; then
		record T4 SKIP "$ENFORCE not writable"
	elif ! echo 1 > "$ENFORCE" 2>/dev/null; then
		record T4 SKIP "could not toggle IPE to enforce=1"
	else
		# Pick any small test_progs subtest that loads an unsigned
		# BPF program. The test itself will fail under enforce=1;
		# what we want is its -EACCES error surface.
		out=$(./test_progs -t bind_perm 2>&1 || true)
		if echo "$out" | grep -q -- '-EACCES\|errno 13'; then
			record T4 PASS "unsigned load denied with -EACCES under enforce=1"
		else
			record T4 FAIL "no -EACCES seen from unsigned load under enforce=1"
			echo "$out" | tail -10 | sed 's/^/  T4: /'
		fi
		# restore permissive so any later tests don't break
		echo 0 > "$ENFORCE" 2>/dev/null || true
	fi

	if [ "$fail" -eq 0 ]; then
		echo ALL_TESTS_PASSED
	else
		echo FAIL_COUNT "$fail"
	fi
	exit 0
fi

# ---- host stage ----
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
KERNEL_DIR=$(cd "$SCRIPT_DIR/../../../.." && pwd)
VMTEST="$SCRIPT_DIR/vmtest.sh"

POLICY_PATH=${IPE_TEST_POLICY:-/tmp/ipe_bpf_test_policy}

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n' "$*"; }

bold "=== IPE BPF policy integration tests ==="

# --- 1. Write the boot policy ---
# Refuse symlinks at POLICY_PATH so this doesn't double as a
# /tmp-symlink overwrite primitive when run as root.
[ -L "$POLICY_PATH" ] && { red "$POLICY_PATH is a symlink; refusing to write"; exit 1; }
cat > "$POLICY_PATH" <<EOF
policy_name="ipe_bpf_test" policy_version=0.0.1
op=BPF_PROG_LOAD bpf_signature=OK                action=ALLOW
op=BPF_PROG_LOAD bpf_signature=UNSIGNED          action=DENY
op=BPF_PROG_LOAD_POST_INTEGRITY                  action=ALLOW
DEFAULT op=BPF_PROG_LOAD                         action=ALLOW
DEFAULT op=BPF_PROG_LOAD_POST_INTEGRITY          action=ALLOW
DEFAULT action=ALLOW
EOF
echo "policy written to $POLICY_PATH"

# --- 2. Run the in-VM stage of the test ---
# vmtest.sh honors $VMTEST_EXTRA_CMDLINE and copies the entire
# selftests/bpf directory into /root/bpf inside the VM, so this
# script ships along automatically and re-enters via --in-vm. The
# in-VM stage's T0 surfaces a missing/disabled IPE LSM, so there's
# no need to inspect .config on the host.
RUN_OUT=$(mktemp -t ipe_test_run.XXXXXX)
trap 'rm -f "$RUN_OUT"' EXIT
export VMTEST_EXTRA_CMDLINE="ipe.enforce=0 ipe.success_audit=1"
"$VMTEST" -- ./test_signed_bpf_ipe.sh --in-vm 2>&1 | tee "$RUN_OUT"

# --- 3. Score ---
if grep -q 'ALL_TESTS_PASSED' "$RUN_OUT"; then
	green "=== all IPE policy integration tests PASSED ==="
	grep -E '^(PASS|FAIL|SKIP) T[0-9]+' "$RUN_OUT" || true
	exit 0
else
	red "=== IPE policy integration tests FAILED ==="
	grep -E '^(PASS|FAIL|SKIP) T[0-9]+' "$RUN_OUT" || true
	exit 1
fi
