#!/usr/bin/env bash
# Build both seccomp builds, package them into an initramfs, boot them in QEMU
# and print the differential report.
#
# Nothing here installs a seccomp filter on the host. Every filter is installed
# by a short-lived child process inside the VM.
#
# Usage: ./run.sh [kernel-image]
#   KERNEL=/path/to/vmlinuz   kernel to boot (default: the one fetched into /tmp)
#   VMDIFF_FULL=1             print both full reports, not just the divergences
#   VMDIFF_ONLY=a,b           restrict to named cases
#   TIMEOUT=600               QEMU wall-clock limit
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"

KERNEL="${1:-${KERNEL:-/tmp/kern/root/boot/vmlinuz-6.8.0-146-generic}}"
if [[ ! -r "$KERNEL" ]]; then
  echo "run.sh: kernel $KERNEL is not readable; fetch one with:" >&2
  echo "  curl -O https://archive.ubuntu.com/ubuntu/pool/main/l/linux/linux-image-unsigned-6.8.0-146-generic_6.8.0-146.146_amd64.deb" >&2
  echo "  dpkg-deb -x linux-image-unsigned-*.deb /tmp/kern" >&2
  exit 1
fi

work="${VMDIFF_WORK:-/tmp/vmdiff-run}"
rm -rf "$work"
mkdir -p "$work/stage"

echo "== building the go build (CGO_ENABLED=0) =="
(cd "$repo" && CGO_ENABLED=0 go build -ldflags "-s -w" -o "$work/stage/runner" ./libcontainer/seccomp/vmdiff)

echo "== building the libseccomp build (cgo, -tags seccomp) =="
(cd "$repo" && CGO_ENABLED=1 go build -tags seccomp \
  -ldflags '-s -w -extldflags "-static"' -o "$work/stage/runner-cgo" ./libcontainer/seccomp/vmdiff)

echo "== packaging the initramfs =="
cd "$work/stage"
mkdir -p dev proc sys
ln -sf runner init
find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$work/initramfs.gz"

echo "== booting qemu (kernel $(basename "$KERNEL")) =="
log="$work/console.log"
rm -f "$log"
timeout "${TIMEOUT:-600}" qemu-system-x86_64 \
  -kernel "$KERNEL" \
  -initrd "$work/initramfs.gz" \
  -append "console=ttyS0 panic=-1 audit=0${VMDIFF_ONLY:+ VMDIFF_ONLY=$VMDIFF_ONLY}${VMDIFF_FULL:+ VMDIFF_FULL=$VMDIFF_FULL}${VMDIFF_PROGRESS:+ VMDIFF_PROGRESS=$VMDIFF_PROGRESS}" \
  -no-reboot -enable-kvm -cpu host -smp 4 -m 1024 \
  -serial "file:$log" -display none -monitor none \
  >/dev/null 2>&1 || true

echo "== console =="
cat "$log"
echo
echo "== full console log: $log =="
