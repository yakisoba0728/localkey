# Smoke test: the kernel, the modules, the dummy UDC, localkeyd's uhid transport (two hidraw
# devices) and its gadget transport (a 1050:0407 USB device on dummy_hcd).
set -u
. /localkey/lib.sh
fail=0

section kernel
uname -a
cat /proc/cmdline
echo "tainted=$(cat /proc/sys/kernel/tainted)"

section modules
lsmod
for m in uhid dummy_hcd libcomposite usb_f_fs usbhid hid_generic; do
    if [ -d "/sys/module/$m" ]; then note "module $m loaded"; else note "module $m MISSING"; fail=1; fi
done

section udc
ls /sys/class/udc
[ -e /sys/class/udc/dummy_udc.0 ] || { note "dummy_udc.0 MISSING"; fail=1; }
ls -l /dev/uhid

section userland
note "python-fido2 $(python3 -c 'import fido2; print(fido2.__version__)' 2>&1)"
note "ykman $(ykman --version 2>&1 | head -n 1)"
note "$(fido2-token -V 2>&1 | head -n 1) (fido2-token)"
note "$(pcscd --version 2>&1 | head -n 1)"
note "$(opensc-tool --info 2>&1 | head -n 1)"
note "$(gpg --version 2>&1 | head -n 1)"
note "$(lsusb --version 2>&1 | head -n 1)"
for tool in pcsc_scan scdaemon evtest strace busybox; do
    command -v "$tool" >/dev/null || [ -x "/usr/lib/gnupg/$tool" ] && note "$tool present" || { note "$tool MISSING"; fail=1; }
done
ls /usr/lib/pcsc/drivers 2>&1

section localkeyd
"$LK_BIN" --help 2>&1 | head -n 3

section "uhid transport"
lk_start uhid --transport uhid -vv
if wait_for 30 sh -c '[ "$(ls /sys/class/hidraw | wc -l)" -ge 2 ]'; then
    note "two hidraw devices present"
else
    note "hidraw devices did not appear"; fail=1
fi
udevadm settle --timeout=10
hidraw_report
for h in /dev/hidraw*; do
    note "udev properties of $h:"
    udevadm info --query=property "$h" | grep -E '^(ID_|DEVNAME|TAGS|CURRENT_TAGS)' | sed 's/^/    /'
done
note "input devices:"
cat /proc/bus/input/devices
lk_ctl uhid status
t0=$(date +%s%N)
lk_stop uhid || fail=1
note "uhid daemon stopped in $(( ($(date +%s%N) - t0) / 1000000 )) ms"
wait_for 10 sh -c '[ -z "$(ls /sys/class/hidraw)" ]' && note "hidraw devices removed" || { note "hidraw devices left behind"; fail=1; }

section "gadget transport"
lk_start gadget --transport gadget --udc dummy_udc.0 --profile yubikey-5c-nano-5.7.4 -vv
if wait_for 60 usb_dev 1050 0407; then
    dev=$(usb_dev 1050 0407)
    note "USB device $dev"
else
    dev=
    note "no 1050:0407 device appeared"; fail=1
fi
udevadm settle --timeout=20
lsusb
if [ -n "$dev" ]; then
    d=/sys/bus/usb/devices/$dev
    for f in idVendor idProduct bcdDevice version speed manufacturer product serial bNumConfigurations bConfigurationValue; do
        printf '    %s = %s\n' "$f" "$(cat "$d/$f" 2>&1)"
    done
    echo "descriptors: $(hex "$d/descriptors")"
    for i in "$d"/"$dev":*; do
        drv=none
        [ -e "$i/driver" ] && drv=$(basename "$(readlink -f "$i/driver")")
        printf '    %s: class %s sub %s proto %s driver %s\n' "$(basename "$i")" \
            "$(cat "$i/bInterfaceClass")" "$(cat "$i/bInterfaceSubClass")" "$(cat "$i/bInterfaceProtocol")" "$drv"
        for e in "$i"/ep_*; do
            [ -e "$e" ] && printf '        %s: %s %s maxp %s interval %s\n' "$(basename "$e")" \
                "$(cat "$e/type")" "$(cat "$e/direction")" "$(cat "$e/wMaxPacketSize")" "$(cat "$e/bInterval")"
        done
    done
    lsusb -v -d 1050:0407 2>&1
fi
hidraw_report
lk_ctl gadget status
note "gadget ConfigFS tree:"
find /sys/kernel/config/usb_gadget -maxdepth 3 | sort | sed 's/^/    /'
t0=$(date +%s%N)
lk_stop gadget || fail=1
note "gadget daemon stopped in $(( ($(date +%s%N) - t0) / 1000000 )) ms"
wait_for 10 usb_gone 1050 0407 && note "USB device removed" || { note "USB device left behind"; fail=1; }
[ -d /sys/kernel/config/usb_gadget/localkey ] && { note "ConfigFS tree left behind"; fail=1; } || note "ConfigFS tree removed"
grep functionfs /proc/mounts && { note "FunctionFS still mounted"; fail=1; } || note "FunctionFS unmounted"

section dmesg
dmesg | grep -v -E '^\[ *[0-9.]+\] (Booting|Linux version|KASLR|random:)' | tail -n 80

section result
note "smoke fail=$fail"
exit "$fail"
