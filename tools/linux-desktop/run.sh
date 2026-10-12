#!/usr/bin/env bash
# Real systemd VM, persistent ext4 root; NIC and USB passthrough are absent.
set -euo pipefail
# shellcheck source=tools/linux-desktop/env.sh
. "$(dirname "$0")/env.sh"
desktop_dir=$(cd "$LK_DESKTOP_DIR" && pwd -P)
[ -f "$desktop_dir/root.img" ] && [ -f "$desktop_dir/Image" ]
if [ "$LK_DESKTOP_ARCH" = aarch64 ]; then
    qemu=(qemu-system-aarch64 -M virt -cpu 'max,pauth-impdef=on')
    console=ttyAMA0
else
    [ -f "$desktop_dir/initrd" ]
    qemu=(qemu-system-x86_64 -M q35 -cpu max -initrd /out/initrd)
    console=ttyS0
fi
docker run --rm -i --network none --cpus 2 --memory 6g --name localkey-desktop-vm \
    -v "$desktop_dir":/out "$desktop_image" \
    timeout -k 10 1800 "${qemu[@]}" -smp 2 -m 3072 \
    -nographic -nic none -no-reboot -device virtio-rng-pci \
    -rtc base=2026-10-12T08:00:00 \
    -kernel /out/Image -drive file=/out/root.img,format=raw,if=virtio \
    -append "root=/dev/vda rw rootwait console=$console loglevel=4 systemd.show_status=1" \
    2>&1 | tee "$desktop_dir/console.log"
grep -q '===== LK-DESKTOP-END rc=0 =====' "$desktop_dir/console.log"
