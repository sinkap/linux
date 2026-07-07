#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Build and run the multinode test under QEMU for one or both
# architectures, and report a combined result.
#
# Usage:
#   run.sh [--arch x86_64|arm64|both] [--x86 <dir>] [--arm64 <dir>]
#
# --arch   which architecture(s) to run (default: both)
# --x86    x86_64 kbuild dir: <dir>/arch/x86/boot/bzImage + <dir>/usr/include
# --arm64  arm64 kbuild dir:  <dir>/arch/arm64/boot/Image + <dir>/usr/include
#
# i.e. build each kernel with `make O=<dir> ... {bzImage|Image}
# headers_install` beforehand. Override the cross compiler with
# CROSS_CXX (default aarch64-linux-gnu-g++).
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
ARCHES=both
X86_DIR=""
ARM_DIR=""
CROSS_CXX=${CROSS_CXX:-aarch64-linux-gnu-g++}

usage() { sed -n '3,17p' "$0" | sed 's/^# \?//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
	case "$1" in
	--arch)  ARCHES=$2; shift 2 ;;
	--x86)   X86_DIR=$(realpath "$2"); shift 2 ;;
	--arm64) ARM_DIR=$(realpath "$2"); shift 2 ;;
	-h|--help) usage 0 ;;
	*) echo "unknown argument: $1" >&2; usage 2 ;;
	esac
done

case "$ARCHES" in
x86_64|arm64|both) ;;
*) echo "--arch must be x86_64, arm64 or both" >&2; exit 2 ;;
esac

# Build a static per-arch binary and boot it via run_qemu.sh.
run_one() {
	local arch=$1 cxx=$2 dir=$3 kernel=$4
	local bin="multinode_test-$arch"

	echo "############## $arch ##############"
	if [ -z "$dir" ]; then
		echo "$arch: no kbuild dir given (use --x86/--arm64)"; return 2
	fi
	make -C "$here" -s clean
	if ! make -C "$here" -s CXX="$cxx" KHDR="$dir/usr/include" BIN="$bin"; then
		echo "$arch: BUILD FAILED"; return 1
	fi
	ARCH="$arch" "$here/run_qemu.sh" "$kernel" "$here/$bin"
}

x86_rc=-1
arm_rc=-1
if [ "$ARCHES" = x86_64 ] || [ "$ARCHES" = both ]; then
	run_one x86_64 "${CXX:-g++}" "$X86_DIR" "$X86_DIR/arch/x86/boot/bzImage"
	x86_rc=$?
fi
if [ "$ARCHES" = arm64 ] || [ "$ARCHES" = both ]; then
	run_one arm64 "$CROSS_CXX" "$ARM_DIR" "$ARM_DIR/arch/arm64/boot/Image"
	arm_rc=$?
fi

echo "==========================================="
verdict() { [ "$1" = -1 ] && echo "-" || { [ "$1" = 0 ] && echo PASS || echo FAIL; }; }
echo "x86_64 : $(verdict $x86_rc)"
echo "arm64  : $(verdict $arm_rc)"

# Fail if any selected arch did not pass.
if { [ $x86_rc -eq 0 ] || [ $x86_rc -eq -1 ]; } &&
   { [ $arm_rc -eq 0 ] || [ $arm_rc -eq -1 ]; }; then
	echo "RESULT: PASS"; exit 0
fi
echo "RESULT: FAIL"; exit 1
