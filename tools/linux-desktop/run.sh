#!/usr/bin/env bash
# Real systemd VM, persistent ext4 root; NIC and USB passthrough are absent.
set -euo pipefail
# shellcheck source=tools/linux-desktop/env.sh
. "$(dirname "$0")/env.sh"
desktop_dir=$(cd "$LK_DESKTOP_DIR" && pwd -P)
[ -f "$desktop_dir/root.img" ] && [ -f "$desktop_dir/Image" ]
extra=(-device virtio-rng-pci)
memory=3072
duration=1800
if [ "$LK_DESKTOP_DISTRO" = ubuntu ]; then
    mkdir -p "$desktop_dir/screens"
    memory=4096
    duration=3600
    extra+=(-initrd /out/initrd -device 'virtio-gpu-pci,xres=1280,yres=800'
           -device qemu-xhci -device usb-kbd -device usb-tablet
           -qmp 'unix:/out/qmp.sock,server=on,wait=off'
           -qmp 'unix:/out/debug-qmp.sock,server=on,wait=off'
           -chardev 'socket,id=gui,path=/out/qmp.sock,reconnect-ms=1000'
           -device virtio-serial-pci -device 'virtserialport,chardev=gui,name=localkey.test-qmp'
           -fsdev 'local,id=screens,path=/out/screens,security_model=none,readonly=on'
           -device 'virtio-9p-pci,fsdev=screens,mount_tag=screens')
fi
if [ "$LK_DESKTOP_ARCH" = aarch64 ]; then
    qemu=(qemu-system-aarch64 -M virt -cpu 'max,pauth-impdef=on')
    console=ttyAMA0
else
    [ -f "$desktop_dir/initrd" ]
    qemu=(qemu-system-x86_64 -M q35 -cpu max)
    if [ "$LK_DESKTOP_DISTRO" = debian ]; then extra+=(-initrd /out/initrd); fi
    console=ttyS0
fi
docker run --rm -i --network none --cpus 2 --memory 6g --name localkey-desktop-vm \
    -v "$desktop_dir":/out "$desktop_image" \
    timeout -k 10 "$duration" "${qemu[@]}" -smp 2 -m "$memory" "${extra[@]}" \
    -nographic -nic none \
    -rtc base=2026-10-12T08:00:00 \
    -kernel /out/Image -drive file=/out/root.img,format=raw,if=virtio \
    -append "root=/dev/vda rw rootwait console=$console loglevel=4 systemd.show_status=1" \
    2>&1 | tee "$desktop_dir/console.log"
grep -q '===== LK-DESKTOP-END rc=0 =====' "$desktop_dir/console.log"
