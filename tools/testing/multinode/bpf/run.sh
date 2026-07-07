#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Boot the libbpf multinode BPF selftest under QEMU (x86_64). The static
# binary is the initramfs /init; the BPF object is placed alongside it so
# the driver can bpf_object__open_file() it.
#
# Usage: run.sh <bzImage>
set -euo pipefail

KERNEL=${1:?bzImage path}
here=$(cd "$(dirname "$0")" && pwd)

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/i"
cp "$here/multinode_bpf" "$work/i/init"
chmod +x "$work/i/init"
cp "$here/multinode.bpf.o" "$work/i/multinode.bpf.o"
( cd "$work/i" && find . | cpio -o -H newc 2>/dev/null | gzip ) > "$work/ir.gz"

log="$work/serial.log"
qemu-system-x86_64 -kernel "$KERNEL" -initrd "$work/ir.gz" \
	-machine q35 -m 1024 -smp 2 -no-reboot -nographic \
	-append "console=ttyS0 panic=-1" 2>&1 | tee "$log"

echo "-------------------------------------------"
if grep -q "MULTINODE_BPF: ALL PASS" "$log"; then
	echo "RESULT: PASS"; exit 0
fi
echo "RESULT: FAIL"; exit 1
