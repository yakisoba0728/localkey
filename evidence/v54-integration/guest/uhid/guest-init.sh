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
echo SKE_V54_COMBINED_UHID_START
ip link set lo up
if /sbin/modprobe hid-generic && /sbin/modprobe uhid; then
    /opt/ske-venv/bin/python /opt/verification/verify-native-extra.py
    ske_guest_rc=$?
else
    ske_guest_rc=80
fi
echo SKE_V54_COMBINED_UHID_EXIT=$ske_guest_rc
if [ "$ske_guest_rc" -ne 0 ]; then dmesg | tail -n 55; fi
sync
poweroff -f
