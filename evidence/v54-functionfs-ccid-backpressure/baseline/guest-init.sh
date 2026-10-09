#!/bin/busybox sh
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
export HOME=/guest-state
export PYTHONUNBUFFERED=1
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /tmp
mkdir -p /dev/pts /guest-state
mount -t devpts devpts /dev/pts
echo SKE_V54_CCID_BACKPRESSURE_BASELINE_START
ip link set lo up
/sbin/modprobe hid-generic || exit 80
mkdir -p /dev/gadget
if /usr/lib/systemd/systemd-udevd --daemon --resolve-names=never && /sbin/modprobe udc-core && /sbin/insmod /opt/dummy_hcd.ko is_high_speed=1 requested_ep_addresses=1 && /sbin/modprobe gadgetfs && /sbin/modprobe usbhid && mount -t gadgetfs gadgetfs /dev/gadget; then
    /sbin/modprobe libcomposite && /sbin/modprobe usb_f_fs && mount -t configfs configfs /sys/kernel/config || exit 82
    mkdir -p /sys/kernel/config/usb_gadget/ske/strings/0x409 /sys/kernel/config/usb_gadget/ske/configs/c.1 /sys/kernel/config/usb_gadget/ske/functions/ffs.ske /dev/ffs-ske
    ln -s /sys/kernel/config/usb_gadget/ske/functions/ffs.ske /sys/kernel/config/usb_gadget/ske/configs/c.1/ske
    mount -t functionfs ske /dev/ffs-ske || exit 83
    /opt/ske-venv/bin/python /opt/verification/verify_ccid_backpressure.py baseline
    ske_guest_rc=$?
else
    ske_guest_rc=81
fi
echo SKE_V54_CCID_BACKPRESSURE_BASELINE_EXIT=$ske_guest_rc
if [ "$ske_guest_rc" -ne 0 ]; then dmesg | tail -n 55; fi
sync
poweroff -f
