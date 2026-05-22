#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Reproduce: __bpf_md_ptr does NOT fix BPF_LDX_MEM(BPF_DW) on 32-bit.
#
# Applies __bpf_md_ptr to excl_prog_sha (Alexei's suggestion), builds
# the real atomics signed lskel on x86_64, cross-compiles a 32-bit
# loader, and boots it in QEMU i386 with the test signing key.
#
# Result:
#   cannot access ptr member excl_prog_sha with moff 0 in struct (anon) with off 0 size 8
#
# Prerequisites: gcc-multilib, qemu-system-x86, debootstrap
# Run from the kernel source tree root (excl_maps_loader_reject branch).

set -uo pipefail

KDIR=$(pwd)
OUTDIR=/tmp/bpf32-repro
ROOTFS=/tmp/rootfs-i386-repro
BUILD_LOG=/tmp/bpf32-build.log

> "$BUILD_LOG"

echo "=== Git state ==="
git log --oneline -3

echo ""
echo "=== __bpf_md_ptr patch (Alexei's suggestion) ==="
git show --stat HEAD
echo ""
git show HEAD -- include/linux/bpf.h

echo ""
echo "Building (deps, selftests, 32-bit kernel, rootfs)..."
echo "Full log: $BUILD_LOG"
{
    sudo apt-get install -y gcc-multilib libc6-dev-i386 \
        libssl-dev:i386 libelf-dev:i386 zlib1g-dev:i386 \
        qemu-system-x86 debootstrap cpio

    make -C tools/testing/selftests/bpf -k -j"$(nproc)" 2>&1 || true

    mkdir -p "$OUTDIR"
    make ARCH=i386 defconfig O="$OUTDIR"
    SIGNING_KEY=$(realpath tools/testing/selftests/bpf/tools/build/signing_key.pem)
    "$KDIR/scripts/config" --file "$OUTDIR/.config" \
        --enable BPF_SYSCALL --enable BPF_JIT --enable CRYPTO_LIB_SHA256 \
        --enable DEBUG_INFO --enable DEBUG_INFO_BTF --enable DEBUG_INFO_DWARF5 \
        --enable KEYS --enable ASYMMETRIC_KEY_TYPE \
        --enable ASYMMETRIC_PUBLIC_KEY_SUBTYPE --enable X509_CERTIFICATE_PARSER \
        --enable PKCS7_MESSAGE_PARSER --enable SYSTEM_DATA_VERIFICATION \
        --enable SYSTEM_TRUSTED_KEYRING \
        --set-str SYSTEM_TRUSTED_KEYS "$SIGNING_KEY"
    make ARCH=i386 olddefconfig O="$OUTDIR"
    make ARCH=i386 -j"$(nproc)" O="$OUTDIR" bzImage vmlinux

    cat > /tmp/test_atomics_32.c << 'CEOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <linux/bpf.h>
#include <linux/keyctl.h>
#include "skel_internal.h"
#include "atomics.lskel.h"

int main(void) {
    struct atomics_lskel *skel;
    char log[16384] = {};
    skel = atomics_lskel__open();
    if (!skel) { printf("FAIL: open: %s\n", strerror(errno)); return 1; }
    skel->ctx.log_buf = (long)log;
    skel->ctx.log_size = sizeof(log);
    skel->ctx.log_level = 1;
    if (atomics_lskel__load(skel)) {
        printf("REJECTED: load: %s (errno %d)\n", strerror(errno), errno);
        if (log[0]) printf("LOG: %.4096s\n", log);
        atomics_lskel__destroy(skel);
        return 1;
    }
    printf("ACCEPTED: atomics signed lskel loaded\n");
    atomics_lskel__destroy(skel);
    return 0;
}
CEOF
    gcc -m32 -static \
        -I tools/testing/selftests/bpf -I tools/lib/bpf \
        -I tools/include -I tools/include/uapi \
        -o /tmp/test_atomics_32 /tmp/test_atomics_32.c

    sudo rm -rf "$ROOTFS"
    sudo debootstrap --arch=i386 --variant=minbase noble "$ROOTFS" \
        http://archive.ubuntu.com/ubuntu
    sudo cp /tmp/test_atomics_32 "$ROOTFS/root/"
    sudo chmod +x "$ROOTFS/root/test_atomics_32"
    sudo tee "$ROOTFS/init" > /dev/null << 'INITEOF'
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
echo "=== Running atomics signed lskel on 32-bit ==="
/root/test_atomics_32
echo "=== Test done ==="
echo o > /proc/sysrq-trigger
INITEOF
    sudo chmod +x "$ROOTFS/init"
    cd "$ROOTFS" && sudo find . | sudo cpio -o -H newc 2>/dev/null \
        | gzip > /tmp/initramfs-i386-repro.gz
} >> "$BUILD_LOG" 2>&1

echo "done."

echo ""
echo "=== 32-bit BTF ==="
bpftool btf dump file "$OUTDIR/vmlinux" | grep -A8 "'bpf_map'" | head -10

echo ""
echo "=== Boot 32-bit QEMU ==="
rm -f /tmp/qemu32-repro.log
qemu-system-i386 \
    -kernel "$OUTDIR/arch/x86/boot/bzImage" \
    -initrd /tmp/initramfs-i386-repro.gz \
    -append "console=ttyS0 init=/init panic=1" \
    -display none -serial file:/tmp/qemu32-repro.log \
    -no-reboot \
    -m 512 &
QPID=$!
for i in $(seq 1 30); do
    grep -q "Test done" /tmp/qemu32-repro.log 2>/dev/null && break
    sleep 1
done
kill $QPID 2>/dev/null
wait $QPID 2>/dev/null

echo ""
echo "=== QEMU serial output ==="
cat /tmp/qemu32-repro.log

