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
echo SKE_V62_STAGE_COMBINED_START
uname -a
ip link set lo up
/sbin/modprobe hid-generic || exit 80
ske_guest_rc=0
if [ "$ske_guest_rc" -eq 0 ] && [ -f /opt/isolated-ske-usb-guest ]; then
    mkdir -p /dev/gadget
    if /usr/lib/systemd/systemd-udevd --daemon --resolve-names=never && /sbin/modprobe udc-core && /sbin/insmod /opt/dummy_hcd.ko is_high_speed=1 requested_ep_addresses=1 && /sbin/modprobe gadgetfs && /sbin/modprobe usbhid && mount -t gadgetfs gadgetfs /dev/gadget; then
        /sbin/modprobe libcomposite && /sbin/modprobe usb_f_fs && mount -t configfs configfs /sys/kernel/config || exit 82
        mkdir -p /sys/kernel/config/usb_gadget/ske/strings/0x409 /sys/kernel/config/usb_gadget/ske/configs/c.1 /sys/kernel/config/usb_gadget/ske/functions/ffs.ske /dev/ffs-ske
        ln -s /sys/kernel/config/usb_gadget/ske/functions/ffs.ske /sys/kernel/config/usb_gadget/ske/configs/c.1/ske
        mount -t functionfs ske /dev/ffs-ske || exit 83
        /opt/ske-venv/bin/python /opt/verification/verify-touch-reset.py fixed
        ske_reset_rc=$?
        echo SKE_V53_RESET_BOUNDARY_EXIT=$ske_reset_rc
        /opt/ske-venv/bin/python /opt/verification/verify-touch-usb.py
        ske_touch_rc=$?
        echo SKE_TOUCH_USB_EXIT=$ske_touch_rc
        /opt/ske-venv/bin/python /opt/verification/verify-composite-extra.py
        ske_extra_rc=$?
        echo SKE_MERGED_EXTRA_EXIT=$ske_extra_rc
        /opt/ske-venv/bin/python /opt/verification/verify-stock-libccid-large.py
        ske_stock_rc=$?
        echo SKE_MERGED_STOCK_EXIT=$ske_stock_rc
        /opt/ske-venv/bin/python /opt/verification/verify-merged-cert.py
        ske_cert_rc=$?
        echo SKE_MERGED_CERT_EXIT=$ske_cert_rc
        /opt/ske-venv/bin/python /opt/verification/native_enterprise.py
        ske_enterprise_rc=$?
        echo SKE_V50_NATIVE_ENTERPRISE_EXIT=$ske_enterprise_rc
        /opt/ske-venv/bin/python /opt/verification/verify-empty-allowlist-usb.py
        ske_allow_rc=$?
        echo SKE_V52_EMPTY_ALLOWLIST_EXIT=$ske_allow_rc
        /opt/ske-venv/bin/python /opt/verification/verify-hmac-upfalse-usb.py
        ske_hmac_rc=$?
        echo SKE_V53_HMAC_UPFALSE_USB_EXIT=$ske_hmac_rc
        /opt/ske-venv/bin/python /opt/verification/verify_float_usb.py
        ske_float_rc=$?
        echo SKE_V54_FLOAT_USB_EXIT=$ske_float_rc
        /opt/ske-venv/bin/python /opt/verification/verify_ccid_backpressure.py fixed
        ske_ccid_bp_rc=$?
        echo SKE_V54_CCID_BACKPRESSURE_EXIT=$ske_ccid_bp_rc
        /opt/ske-venv/bin/python /opt/verification/verify-composite-reboot.py
        ske_reboot_rc=$?
        echo SKE_SEVEN_PROFILES_EXIT=$ske_reboot_rc
        if [ "$ske_reset_rc" -ne 0 ] || [ "$ske_touch_rc" -ne 0 ] ||
           [ "$ske_reboot_rc" -ne 0 ] ||
           [ "$ske_extra_rc" -ne 0 ] || [ "$ske_stock_rc" -ne 0 ] ||
           [ "$ske_cert_rc" -ne 0 ] || [ "$ske_enterprise_rc" -ne 0 ] ||
           [ "$ske_allow_rc" -ne 0 ] || [ "$ske_hmac_rc" -ne 0 ] ||
           [ "$ske_float_rc" -ne 0 ] || [ "$ske_ccid_bp_rc" -ne 0 ]; then
            ske_guest_rc=1
        fi
    else
        ske_guest_rc=81
    fi
fi
echo SKE_V62_STAGE_COMBINED_EXIT=$ske_guest_rc
if [ "$ske_guest_rc" -ne 0 ]; then
    dmesg | tail -n 55
fi
sync
poweroff -f
