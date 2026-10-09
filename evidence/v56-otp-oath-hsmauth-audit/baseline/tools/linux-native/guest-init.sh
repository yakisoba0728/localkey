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
echo SKE_NATIVE_GUEST_START
uname -a
ip link set lo up
if /sbin/modprobe hid-generic && /sbin/modprobe uhid; then
    /opt/ske-venv/bin/python /opt/verification/verify-native.py
    ske_guest_rc=$?
    if [ "$ske_guest_rc" -eq 0 ] && [ -f /opt/isolated-ske-native-extra ]; then
        /opt/ske-venv/bin/python /opt/verification/verify-native-extra.py
        ske_guest_rc=$?
    fi
else
    ske_guest_rc=80
fi
if [ "$ske_guest_rc" -eq 0 ] && [ -f /opt/isolated-ske-usb-guest ]; then
    mkdir -p /dev/gadget
    if /usr/lib/systemd/systemd-udevd --daemon --resolve-names=never && /sbin/modprobe udc-core && /sbin/insmod /opt/dummy_hcd.ko is_high_speed=0 requested_ep_addresses=1 && /sbin/modprobe gadgetfs && /sbin/modprobe usbhid && mount -t gadgetfs gadgetfs /dev/gadget; then
        /sbin/modprobe libcomposite && /sbin/modprobe usb_f_fs && mount -t configfs configfs /sys/kernel/config || exit 82
        mkdir -p /sys/kernel/config/usb_gadget/ske/strings/0x409 /sys/kernel/config/usb_gadget/ske/configs/c.1 /sys/kernel/config/usb_gadget/ske/functions/ffs.ske /dev/ffs-ske
        ln -s /sys/kernel/config/usb_gadget/ske/functions/ffs.ske /sys/kernel/config/usb_gadget/ske/configs/c.1/ske
        mount -t functionfs ske /dev/ffs-ske || exit 83
        /opt/ske-venv/bin/python /opt/verification/verify-composite.py
        ske_guest_rc=$?
        if [ "$ske_guest_rc" -eq 0 ]; then
            /opt/ske-venv/bin/python /opt/verification/verify-composite-extra.py
            ske_guest_rc=$?
        fi
        if [ "$ske_guest_rc" -eq 0 ]; then
            /opt/ske-venv/bin/python /opt/verification/verify-composite-reboot.py
            ske_guest_rc=$?
        fi
        if [ "$ske_guest_rc" -eq 0 ]; then
            /opt/ske-venv/bin/python /opt/verification/verify-usb-state.py
            ske_guest_rc=$?
        fi
        if [ "$ske_guest_rc" -eq 0 ]; then
            /opt/ske-venv/bin/python /opt/verification/verify-usb-power.py
            ske_guest_rc=$?
        fi
        if [ "$ske_guest_rc" -eq 0 ]; then
            /opt/ske-venv/bin/python /opt/verification/verify-usb-interrupt.py
            ske_guest_rc=$?
        fi
        if [ "$ske_guest_rc" -eq 0 ]; then
            /opt/ske-venv/bin/python /opt/verification/verify-usb-runtime.py
            ske_guest_rc=$?
        fi
        if [ "$ske_guest_rc" -eq 0 ]; then
            /opt/ske-venv/bin/python /opt/verification/verify-usb-runtime-pending.py
            ske_guest_rc=$?
        fi
        if [ "$ske_guest_rc" -eq 0 ]; then
            /opt/ske-venv/bin/python /opt/verification/verify-usb-reboot-pending.py
            ske_guest_rc=$?
        fi
        if [ "$ske_guest_rc" -eq 0 ]; then
            /opt/ske-venv/bin/python /opt/verification/verify-usb-long-cutover.py
            ske_guest_rc=$?
        fi
        if [ "$ske_guest_rc" -eq 0 ]; then
            /opt/ske-venv/bin/python /opt/verification/verify-usb-partial-interrupt.py
            ske_guest_rc=$?
        fi
        if [ "$ske_guest_rc" -eq 0 ]; then
            /opt/ske-venv/bin/python /opt/verification/verify-usb-large-partial-runtime.py
            ske_guest_rc=$?
        fi
        if [ "$ske_guest_rc" -eq 0 ]; then
            /opt/ske-venv/bin/python /opt/verification/verify-stock-libccid-large.py
            ske_guest_rc=$?
        fi
        if [ "$ske_guest_rc" -eq 0 ]; then
            /opt/ske-venv/bin/python /opt/verification/verify-browser.py
            ske_guest_rc=$?
        fi
        if [ "$ske_guest_rc" -eq 0 ]; then
            /opt/ske-venv/bin/python /opt/verification/verify-browser-resident.py
            ske_guest_rc=$?
        fi
        if [ "$ske_guest_rc" -eq 0 ]; then
            /opt/ske-venv/bin/python /opt/verification/verify-browser-prf.py
            ske_guest_rc=$?
        fi
        if [ "$ske_guest_rc" -eq 0 ]; then
            /opt/ske-venv/bin/python /opt/verification/verify-browser-attestation.py
            ske_guest_rc=$?
        fi
        if [ "$ske_guest_rc" -eq 0 ]; then
            /bin/busybox sh /opt/verification/largeblob-guest-init.sh
            ske_guest_rc=$?
        fi
    else
        ske_guest_rc=81
    fi
fi
echo SKE_NATIVE_GUEST_EXIT=$ske_guest_rc
if [ "$ske_guest_rc" -ne 0 ]; then
    dmesg | tail -n 55
fi
sync
poweroff -f
