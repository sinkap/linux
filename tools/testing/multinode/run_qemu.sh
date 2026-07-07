#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Boot a kernel under QEMU with a minimal initramfs and run the
# multinode functional test. Standalone: no external VM tooling and no
# busybox — the statically linked test binary is the initramfs /init
# (it mounts proc/sys/devtmpfs itself and powers off when done). Prints
# the guest serial log and exits non-zero unless the guest reports
# "MULTINODE: ALL PASS".
#
# Usage:
#   ARCH=x86_64 run_qemu.sh <bzImage> <multinode_test>
#   ARCH=arm64  run_qemu.sh <Image>   <multinode_test>
#
# ARCH defaults to the host (uname -m). The test binary must be built
# for the target architecture (see the Makefile's CXX override).
#
# The xnode_shmem window is reserved differently per arch: x86_64 uses
# memmap= on the cmdline; arm64 'virt' has no memmap=, so the runner
# generates a DTB with a reserved-memory node (needs dtc). If dtc is
# missing on arm64 the window is not set up and the driver sub-test is
# skipped; the dma-heap ringbuf/arena sub-tests still run and exercise
# the real dc civac/ivac maintenance.
set -euo pipefail

KERNEL=${1:?kernel image path}
TESTBIN=${2:?multinode_test path}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

DTB_ARG=()
case "${ARCH:=$(uname -m)}" in
x86_64)
	QEMU=qemu-system-x86_64
	CONSOLE=ttyS0
	MACHINE=(-machine q35)
	WIN_BASE=0x30000000
	WIN_SIZE=0x100000
	WINDOW_CMDLINE="memmap=${WIN_SIZE}\$${WIN_BASE} \
		xnode_shmem.base=${WIN_BASE} xnode_shmem.size=${WIN_SIZE} xnode_shmem.expose_mmio=1"
	;;
arm64|aarch64)
	QEMU=qemu-system-aarch64
	CONSOLE=ttyAMA0
	MACHINE=(-machine virt -cpu max)
	WIN_BASE=0x50000000		# within virt RAM (0x40000000 + 1 GiB)
	WIN_SIZE=0x100000
	WINDOW_CMDLINE=""
	if command -v dtc >/dev/null; then
		# Reserve the window in a patched copy of the virt DTB.
		"$QEMU" -machine virt,dumpdtb="$work/virt.dtb" -cpu max \
			-m 1024 -smp 2 -nographic >/dev/null 2>&1
		dtc -I dtb -O dts "$work/virt.dtb" -o "$work/virt.dts" 2>/dev/null
		# Insert a reserved-memory node after the memory node.
		awk -v base="$WIN_BASE" -v size="$WIN_SIZE" '
			{ print }
			/device_type = "memory";/ { in_mem = 1 }
			in_mem && /};/ {
				print "\treserved-memory {"
				print "\t\t#address-cells = <0x02>;"
				print "\t\t#size-cells = <0x02>;"
				print "\t\tranges;"
				print "\t\txnode@50000000 {"
				printf "\t\t\treg = <0x00 %s 0x00 %s>;\n", base, size
				print "\t\t\tno-map;"
				print "\t\t};"
				print "\t};"
				in_mem = 0
			}' "$work/virt.dts" > "$work/virt-xnode.dts"
		dtc -I dts -O dtb "$work/virt-xnode.dts" -o "$work/virt-xnode.dtb" 2>/dev/null
		DTB_ARG=(-dtb "$work/virt-xnode.dtb")
		WINDOW_CMDLINE="xnode_shmem.base=${WIN_BASE} xnode_shmem.size=${WIN_SIZE} xnode_shmem.expose_mmio=1"
	else
		echo "note: dtc not found; xnode_shmem window not set up on arm64" >&2
	fi
	;;
*)
	echo "unsupported ARCH: $ARCH" >&2
	exit 2
	;;
esac

mkdir -p "$work/initramfs"

cp "$TESTBIN" "$work/initramfs/init"
chmod +x "$work/initramfs/init"

( cd "$work/initramfs" && find . | cpio -o -H newc 2>/dev/null | gzip ) \
	> "$work/initramfs.cpio.gz"

log="$work/serial.log"
"$QEMU" \
	-kernel "$KERNEL" \
	-initrd "$work/initramfs.cpio.gz" \
	"${MACHINE[@]}" "${DTB_ARG[@]}" -m 1024 -smp 2 -no-reboot -nographic \
	-append "console=${CONSOLE} panic=-1 ${WINDOW_CMDLINE}" \
	2>&1 | tee "$log"

echo "-------------------------------------------"
if grep -q "MULTINODE: ALL PASS" "$log"; then
	echo "RESULT: PASS"
	exit 0
fi
echo "RESULT: FAIL"
exit 1
