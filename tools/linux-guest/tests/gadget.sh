# The gadget transport against a real kernel and real host software, all inside the guest:
# ConfigFS + FunctionFS on dummy_hcd's dummy_udc.0, enumerated by the guest's own USB host
# stack (usbhid, hidraw, input, usbfs), with libfido2, python-fido2, ykman, pcscd + libccid,
# OpenSC and GnuPG as clients. Profile yubikey-5c-nano-5.7.4 throughout, so libccid, ykman
# and libfido2 recognise the device.
#
#   1 enumeration       lsusb -v; the host's device and configuration descriptors against
#                       the engine's (from the wire transport's IDENTITY frame), named
#                       field by field; the string descriptors; DEVICE_QUALIFIER
#   2 HID               hidraw nodes, libfido2 (list, info, make and verify a credential,
#                       get an assertion), python-fido2, ykman otp info, HMAC-SHA1
#                       challenge-response (GET_REPORT/SET_REPORT(feature) on ep0), a
#                       static password typed through the kernel's input layer
#   3 CCID              pcscd + libccid, the ATR, ykman info/oath/piv/openpgp over CCID,
#                       gpg --card-status through pcscd, raw APDUs with opensc-tool,
#                       messages of whole 64-byte packets in both directions (usbmon)
#   4 bus events        runtime suspend and resume, USBDEVFS_RESET, authorized 0/1
#   5 re-enumeration    ykman config usb over CCID, OTP HID and FIDO HID; the FIDO+CCID
#                       configuration against the reference key's; strace of ep0 reopens
#   6 kill -9, restart  the leftover gadget is reclaimed, state kept
#   E extra             external unbind/bind, interface GET_STATUS, a stalled CCID class
#                       request, FUNCTIONFS_VIRTUAL_ADDR, dummy_hcd full-speed-only and
#                       SuperSpeed controllers
#
# Every step prints "STEP <n> PASS" or "STEP <n> FAIL"; the summary at the end repeats them.
# The state directories are on tmpfs (/run/lk).
set -u
. /localkey/lib.sh
PY=/localkey/py
W=/run/lk-work
mkdir -p "$W"
YK=yubikey-5c-nano-5.7.4
UDC=dummy_udc.0
STATIC=Hello1World
MGMT=010203040506070801020304050607080102030405060708
PIV_PIN=123456
ATR="3b fd 13 00 00 81 31 fe 15 80 73 c0 21 c0 57 59 75 62 69 4b 65 79 40"
# reference/yubikey-5c-nano-5.7.4/usb-reference-observation.json: configuration_descriptor_hex
# of the reference key (FIDO+CCID, 1050:0406).
REF_0406_CONFIG="09027d00020100800f090400000203000000092110010001222200070504034000020705840340000209040100030b00000036210001000702000000a00f0000a00f00000000b0040000b0040000f60b00000000000000000000fe000400000c0000ffff00000001070502024000000705820240000007058303080020"
export LK_LOG_QUIET=1
results=()
step=
step_ok=1
PCSCD_PID=

step_begin() { step=$1; step_ok=1; section "STEP $*"; }
step_end() {
    local verdict=PASS
    [ "$step_ok" = 1 ] || verdict=FAIL
    echo "STEP $step $verdict"
    results+=("STEP $step $verdict")
}
ok() { note "ok: $*"; }
bad() { note "FAILED: $*"; step_ok=0; }
check() {
    local what=$1
    shift
    if "$@"; then ok "$what"; else bad "$what"; fi
}
same() { [ "$1" = "$2" ]; }
quiet() { "$@" > /dev/null 2>&1; }
# run CMD...: show the command, its output and its exit code (a program gets 60 s); returns
# the exit code.
run() {
    echo "\$ $*"
    if declare -F "$1" >/dev/null; then "$@"; else timeout -k 5 60 "$@"; fi
    local rc=$?
    echo "[exit $rc]"
    return "$rc"
}
log_of() { echo "$LK_RUN/$1/log"; }
log_mark() { wc -l < "$(log_of "$1")"; }
log_since() { tail -n +"$(($2 + 1))" "$(log_of "$1")"; }
# gadget_lines NAME MARK: the log lines of daemon NAME since MARK without per-transfer lines.
gadget_lines() { log_since "$1" "$2" | grep -v -E 'gadget: (<-|->) '; }
dev_of() { usb_dev 1050 "$1"; }
has_dev() { usb_dev 1050 "$1" >/dev/null; }
sysdev() { echo "/sys/bus/usb/devices/$(dev_of "$1")"; }
devnode() { local d; d=$(sysdev "$1"); printf '/dev/bus/usb/%03d/%03d' "$(cat "$d/busnum")" "$(cat "$d/devnum")"; }
has_hidraw() { hidraw_of "$1" >/dev/null; }
no_0407() { ! has_dev 0407; }
fido_answers() { local n; n=$(hidraw_of fido) && timeout 30 fido2-token -I "$n" | grep -q aaguid; }
input_event_of() {
    local e
    for e in /sys/class/hidraw/"$(basename "$1")"/device/input/input*/event*; do
        [ -e "$e" ] && { echo "/dev/input/$(basename "$e")"; return 0; }
    done
    return 1
}
reader_seen() { timeout 10 opensc-tool -l 2>/dev/null | grep -q -i yubico; }
start_pcscd() {
    local extra=
    pcscd --help 2>&1 | grep -q -- '--disable-polkit' && extra=--disable-polkit
    LIBCCID_ifdLogLevel=0x0003 pcscd --foreground --debug $extra >> "$W/pcscd.log" 2>&1 &
    PCSCD_PID=$!
    note "pcscd started (pid $PCSCD_PID${extra:+, $extra})"
    wait_for 30 reader_seen
}
stop_pcscd() {
    gpgconf --kill scdaemon >/dev/null 2>&1
    if [ -n "$PCSCD_PID" ]; then
        kill "$PCSCD_PID" 2>/dev/null
        wait "$PCSCD_PID" 2>/dev/null
        note "pcscd stopped"
        PCSCD_PID=
    fi
}
# transfer_summary NAME MARK: the -vv transfer lines since MARK as counts of (direction,
# endpoint, size).
transfer_summary() {
    log_since "$1" "$2" | sed -n 's/.*gadget: \(<-\|->\) \([a-z-]*\), \([0-9]*\) bytes.*/\1 \2 \3/p' |
        sort | uniq -c | sort -k3,3 -k4,4n | sed 's/^/    /'
}
setup_summary() {
    log_since "$1" "$2" | sed -n 's/.*gadget: setup \(.*\)$/\1/p' | sort | uniq -c | sed 's/^/    /'
}

section versions
note "kernel $(uname -r); $(fido2-token -V 2>&1 | head -n 1) (libfido2); python-fido2 $(python3 -c 'import importlib.metadata as m; print(m.version("fido2"))'); ykman $(ykman --version 2>&1 | head -n 1)"
note "$(pcscd --version 2>&1 | head -n 1); libccid $(ls /usr/lib/pcsc/drivers 2>&1 | tr '\n' ' '); $(opensc-tool --info 2>&1 | head -n 1); $(gpg --version | head -n 1)"
note "dummy_hcd parameters: is_high_speed=$(cat /sys/module/dummy_hcd/parameters/is_high_speed) is_super_speed=$(cat /sys/module/dummy_hcd/parameters/is_super_speed)"

# ---------------------------------------------------------------------------------------
step_begin 1 "enumeration (profile $YK)"
lk_start ykwire --profile "$YK"
wait_for 20 test -S "$LK_RUN/ykwire/state/wire.sock" || bad "wire socket"
python3 "$PY/wire_identity.py" "$LK_RUN/ykwire/state/wire.sock" > "$W/identity"
sed 's/^/    engine: /' "$W/identity"
lk_stop ykwire > /dev/null
ident() { sed -n "s/^$1=//p" "$W/identity"; }
mark=0
lk_start yk --profile "$YK" --transport gadget --udc "$UDC" -vv
check "1050:0407 appeared" wait_for 60 has_dev 0407
udevadm settle --timeout=20
D=$(sysdev 0407)
note "host device $(basename "$D"), node $(devnode 0407)"
for f in idVendor idProduct bcdDevice version speed manufacturer product serial bNumConfigurations bConfigurationValue bmAttributes bMaxPower; do
    printf '    %s = %s\n' "$f" "$(cat "$D/$f" 2>&1)"
done
host_desc=$(hex "$D/descriptors")
engine_desc="$(ident device) $(ident configuration)"
echo "    host:   $host_desc"
echo "    engine: $engine_desc"
python3 "$PY/desc_diff.py" --allow iSerialNumber --allow bEndpointAddress "$engine_desc" "$host_desc" | sed 's/^/    /'
check "host descriptors = engine's except iSerialNumber and bEndpointAddress" \
    quiet python3 "$PY/desc_diff.py" --allow iSerialNumber --allow bEndpointAddress "$engine_desc" "$host_desc"
check "manufacturer string Yubico" same "$(cat "$D/manufacturer")" "$(ident manufacturer)"
check "product string '$(ident product_name)'" same "$(cat "$D/product")" "$(ident product_name)"
check "speed 12 (full speed)" same "$(cat "$D/speed")" 12
run lsusb -v -d 1050:0407 > "$W/lsusb-0407" 2>&1
sed 's/^/    /' "$W/lsusb-0407"
note "string descriptors through usbfs (GET_DESCRIPTOR(STRING, index), LANGID 0x0409):"
for i in 0 1 2 3; do
    echo "    string $i: $(python3 "$PY/usbfs.py" "$(devnode 0407)" control 0x80 0x06 $((0x0300 + i)) $([ $i = 0 ] && echo 0 || echo 0x0409) 255)"
done
note "GET_DESCRIPTOR(DEVICE_QUALIFIER): $(python3 "$PY/usbfs.py" "$(devnode 0407)" control 0x80 0x06 0x0600 0 10)"
note "GET_DESCRIPTOR(OTHER_SPEED_CONFIGURATION): $(python3 "$PY/usbfs.py" "$(devnode 0407)" control 0x80 0x06 0x0700 0 9)"
note "GET_DESCRIPTOR(BOS): $(python3 "$PY/usbfs.py" "$(devnode 0407)" control 0x80 0x06 0x0f00 0 5)"
note "interface drivers:"
for i in "$D"/"$(basename "$D")":*; do
    drv=none
    [ -e "$i/driver" ] && drv=$(basename "$(readlink -f "$i/driver")")
    echo "    $(basename "$i"): class $(cat "$i/bInterfaceClass") driver $drv"
done
note "control requests during enumeration (count, request):"
setup_summary yk 0
gadget_lines yk 0 | sed 's/^/    log: /'
step_end

# ---------------------------------------------------------------------------------------
step_begin 2 "HID through the gadget: libfido2, python-fido2, ykman OTP, keyboard"
check "FIDO hidraw node" wait_for 20 has_hidraw fido
check "OTP hidraw node" wait_for 20 has_hidraw otp
fido=$(hidraw_of fido)
otp=$(hidraw_of otp)
note "FIDO $fido ($(hid_id "$fido")), OTP $otp ($(hid_id "$otp"))"
hidraw_report
mark=$(log_mark yk)
run fido2-token -L | tee "$W/token-L"
check "fido2-token -L lists $fido as 1050:0407" grep -q "^$fido: vendor=0x1050, product=0x0407" "$W/token-L"
run fido2-token -I "$fido" > "$W/token-I"
sed 's/^/    /' "$W/token-I"
check "fido2-token -I (aaguid of the profile)" grep -q -i 'ff4dac45ede84ec2acedcf66103f4335' "$W/token-I"
printf '%s\n%s\n%s\n%s\n' "$(head -c 32 /dev/urandom | base64)" localkey.example alice \
    "$(head -c 32 /dev/urandom | base64)" > "$W/cred-param"
lk_tap yk > "$W/tap-cred" &
tapper=$!
echo "\$ fido2-cred -M -i cred-param -o cred $fido es256   (touch by lk_tap)"
timeout 60 fido2-cred -M -i "$W/cred-param" -o "$W/cred" "$fido" es256 < /dev/null
rc=$?
wait "$tapper"
cat "$W/tap-cred"
check "fido2-cred -M made a credential (exit $rc)" [ "$rc" = 0 ]
run fido2-cred -V -i "$W/cred" -o "$W/cred-pubkey" es256
check "fido2-cred -V verified the attestation" [ $? = 0 ]
printf '%s\n%s\n%s\n' "$(head -c 32 /dev/urandom | base64)" localkey.example "$(sed -n 5p "$W/cred")" > "$W/assert-param"
lk_tap yk > "$W/tap-assert" &
tapper=$!
timeout 60 fido2-assert -G -p -i "$W/assert-param" -o "$W/assert" "$fido" < /dev/null
rc=$?
wait "$tapper"
check "fido2-assert -G (exit $rc)" [ "$rc" = 0 ]
run fido2-assert -V -p -i "$W/assert" "$W/cred-pubkey" es256
check "fido2-assert -V -p" [ $? = 0 ]
run python3 "$PY/fido2_flow.py" --control "$LK_RUN/yk/state/control.sock" --vendor 1050 --product 0407
check "python-fido2 flow" [ $? = 0 ]
note "FIDO transfers (count, direction, endpoint, size):"
transfer_summary yk "$mark"
mark=$(log_mark yk)
run ykman list
run ykman info
check "ykman info over HID" sh -c 'timeout 60 ykman info >/dev/null'
run ykman otp info
check "ykman otp info" sh -c 'timeout 60 ykman otp info >/dev/null'
run ykman otp chalresp --generate 2 --force | tee "$W/chalresp"
key=$(grep -o -i -E '[0-9a-f]{40}' "$W/chalresp" | head -n 1)
chal=$(head -c 32 /dev/urandom | od -An -tx1 -v | tr -d ' \n')
r1=$(timeout 60 ykman otp calculate 2 "$chal")
r2=$(timeout 60 ykman otp calculate 2 "$chal")
want=$(python3 -c 'import hmac,hashlib,sys; print(hmac.new(bytes.fromhex(sys.argv[1]), bytes.fromhex(sys.argv[2]), hashlib.sha1).hexdigest())' "$key" "$chal" 2>/dev/null)
note "slot 2 key ${key:-<none>}; challenge $chal"
note "responses $r1 / $r2; HMAC-SHA1 $want"
check "two calculations agree and are non-empty" sh -c "[ -n '$r1' ] && [ '$r1' = '$r2' ]"
check "the response is HMAC-SHA1 of the challenge under the generated key" same "$r1" "$want"
run ykman otp static 1 "$STATIC" --keyboard-layout US --force
event=$(input_event_of "$otp")
note "OTP keyboard input node $event"
python3 "$PY/evdev_keys.py" --event "$event" --hidraw "$otp" --seconds 15 > "$W/keys" &
capture=$!
wait_for 10 grep -q capturing "$W/keys"
run lk_ctl yk tap
wait "$capture"
sed 's/^/    /' "$W/keys"
check "the keyboard typed $STATIC + Enter" same "$(sed -n 's/^typed=//p' "$W/keys")" "'$STATIC\\n'"
note "OTP control requests (count, request: outcome):"
setup_summary yk "$mark"
transfer_summary yk "$mark"
gadget_lines yk "$mark" | grep -v 'gadget: setup' | sed 's/^/    log: /'
step_end

# ---------------------------------------------------------------------------------------
step_begin 3 "CCID through the gadget: pcscd + libccid, ykman, OpenSC, GnuPG"
mark=$(log_mark yk)
check "pcscd sees the reader" start_pcscd
run pcsc_scan -r
run opensc-tool -l
run opensc-tool -a | tee "$W/atr"
got_atr=$(grep -i -o -E '([0-9a-f]{2}:){10,}[0-9a-f]{2}' "$W/atr" | head -n 1 | tr ':' ' ' | tr A-F a-f)
check "ATR = the profile's ($ATR)" same "$got_atr" "$ATR"
run opensc-tool -s 00A4040006D27600012401 | tee "$W/apdu-select"
check "raw SELECT OpenPGP answered 90 00" grep -q -i 'SW1=0x90, SW2=0x00' "$W/apdu-select"
run opensc-tool -s 00A4040008A000000308000010 -s 00FD000000 | tee "$W/apdu-piv"
check "raw SELECT PIV + GET VERSION answered 90 00" sh -c "grep -c -i 'SW1=0x90, SW2=0x00' '$W/apdu-piv' | grep -q '^2'"
run ykman --reader yubico info | tee "$W/ykman-info-ccid"
check "ykman info over CCID" grep -q 'YubiKey 5C Nano' "$W/ykman-info-ccid"
run ykman --reader yubico oath accounts add -t test JBSWY3DPEHPK3PXP
check "oath account added" sh -c 'timeout 60 ykman --reader yubico oath accounts list | grep -q "^test"'
lk_tap yk > "$W/tap-oath" &
tapper=$!
code=$(timeout 60 ykman --reader yubico oath accounts code -s test)
rc=$?
wait "$tapper"
cat "$W/tap-oath"
expected=$(python3 - <<'PY'
import base64, hashlib, hmac, struct, time
key = base64.b32decode("JBSWY3DPEHPK3PXP")
step = int(time.time()) // 30
out = []
for t in (step - 1, step):
    h = hmac.new(key, struct.pack(">Q", t), hashlib.sha1).digest()
    o = h[-1] & 15
    out.append("%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000))
print(" ".join(out))
PY
)
note "oath code '$code' (exit $rc); TOTP of the last two steps: $expected"
check "the touch-required OATH code is the RFC 6238 TOTP" sh -c "[ -n '$code' ] && echo ' $expected ' | grep -q ' $code '"
run ykman --reader yubico piv info
check "ykman piv info" sh -c 'timeout 60 ykman --reader yubico piv info >/dev/null'
run ykman --reader yubico piv keys generate -m "$MGMT" -a ECCP256 --pin-policy DEFAULT --touch-policy DEFAULT 9a "$W/pub.pem"
check "piv keys generate 9a" grep -q 'BEGIN PUBLIC KEY' "$W/pub.pem"
run ykman --reader yubico piv certificates generate -m "$MGMT" -P "$PIV_PIN" -s "CN=localkey gadget" 9a "$W/pub.pem"
check "piv certificates generate 9a (signed on the device, PUT DATA)" [ $? = 0 ]
run ykman --reader yubico piv certificates export 9a "$W/cert.pem"
check "piv certificates export 9a (GET DATA)" grep -q 'BEGIN CERTIFICATE' "$W/cert.pem"
# Whole-packet messages: PUT DATA of a 678-byte object is a 704-byte PC_to_RDR_XfrBlock
# (10 + 7 extended-APDU header + 5C 03 5F C1 0D + 53 82 02 A6 + 678 = 11 packets), and
# GET DATA of a 624-byte object a 640-byte RDR_to_PC_DataBlock (10 + 53 82 02 70 + 624 +
# SW = 10 packets), which needs a zero-length packet to end the host's bulk read.
head -c 678 /dev/urandom > "$W/obj678"
head -c 624 /dev/urandom > "$W/obj624"
cat /sys/kernel/debug/usb/usbmon/1u > "$W/usbmon" &
mon=$!
xmark=$(log_mark yk)
run ykman --reader yubico piv objects import -m "$MGMT" 5fc10d "$W/obj678"
run ykman --reader yubico piv objects import -m "$MGMT" 5fc10e "$W/obj624"
run ykman --reader yubico piv objects export 5fc10d "$W/obj678.out"
run ykman --reader yubico piv objects export 5fc10e "$W/obj624.out"
sleep 0.5
kill "$mon" 2>/dev/null
wait "$mon" 2>/dev/null
check "the 678-byte object round-trips" cmp -s "$W/obj678" "$W/obj678.out"
check "the 624-byte object round-trips" cmp -s "$W/obj624" "$W/obj624.out"
check "a 704-byte bulk-OUT message (11 whole packets) reached the device" \
    sh -c "tail -n +$((xmark + 1)) '$(log_of yk)' | grep -q 'gadget: <- ccid-out, 704 bytes'"
check "a 640-byte bulk-IN message (10 whole packets) was sent" \
    sh -c "tail -n +$((xmark + 1)) '$(log_of yk)' | grep -q 'gadget: -> ccid-in, 640 bytes'"
note "usbmon: the bulk URBs of those four commands with 64 bytes or more (event, endpoint, status, length):"
awk '$3 ~ /^[SC]$/ && $4 ~ /^B[io]:/ && $6 >= 64 { print "    " $3, $4, $5, $6 }' "$W/usbmon" | head -n 40
check "usbmon: one bulk-IN URB completed with exactly 640 bytes (ended by the zero-length packet)" \
    sh -c "awk '\$3 == \"C\" && \$4 ~ /^Bi:/ && \$6 == 640' '$W/usbmon' | grep -q ."
run ykman --reader yubico openpgp info
check "ykman openpgp info" sh -c 'timeout 60 ykman --reader yubico openpgp info >/dev/null'
export GNUPGHOME=$W/gnupg
mkdir -p -m 0700 "$GNUPGHOME"
{
    echo disable-ccid
    lib=$(ls /usr/lib/*/libpcsclite.so.1 2>/dev/null | head -n 1)
    [ -n "$lib" ] && echo "pcsc-driver $lib"
} > "$GNUPGHOME/scdaemon.conf"
note "scdaemon.conf: $(tr '\n' ' ' < "$GNUPGHOME/scdaemon.conf")"
run gpg --card-status | tee "$W/gpg-card"
check "gpg --card-status (through pcscd)" grep -q -E 'Manufacturer .*Yubico' "$W/gpg-card"
gpgconf --kill scdaemon
note "CCID transfers (count, direction, endpoint, size):"
transfer_summary yk "$mark"
gadget_lines yk "$mark" | grep -v 'gadget: setup' | sed 's/^/    log: /'
setup_summary yk "$mark"
note "pcscd/libccid log (errors and reader lines):"
grep -i -E 'error|fail|timeout|reader|Yubico' "$W/pcscd.log" | grep -v -i 'SCardGetStatusChange' | tail -n 30 | sed 's/^/    /'
step_end

# ---------------------------------------------------------------------------------------
step_begin 4 "bus events: suspend, resume, reset, authorized"
stop_pcscd
D=$(sysdev 0407)
dev=$(basename "$D")
mark=$(log_mark yk)
note "unbind usbhid from interfaces 0 and 1 (the kernel's keyboard handler keeps the OTP interface open, and usbhid then needs remote wakeup, which the device does not offer)"
for i in 0 1; do echo -n "$dev:1.$i" > /sys/bus/usb/drivers/usbhid/unbind; done
echo 0 > "$D/power/autosuspend_delay_ms"
echo auto > "$D/power/control"
check "the host suspended the device (runtime_status suspended)" wait_for 15 grep -q '^suspended$' "$D/power/runtime_status"
note "runtime_status $(cat "$D/power/runtime_status")"
check "the daemon reports suspended" wait_for 10 sh -c "'$LK_BIN' ctl --control '$LK_RUN/yk/state/control.sock' status | grep -q '^suspended=true'"
lk_ctl yk status | sed 's/^/    /'
echo on > "$D/power/control"
check "the host resumed the device" wait_for 15 grep -q '^active$' "$D/power/runtime_status"
check "the daemon reports resumed" wait_for 10 sh -c "'$LK_BIN' ctl --control '$LK_RUN/yk/state/control.sock' status | grep -q '^suspended=false'"
for i in 0 1; do echo -n "$dev:1.$i" > /sys/bus/usb/drivers/usbhid/bind; done
check "hidraw nodes back after rebinding usbhid" wait_for 20 sh -c '[ "$(ls /sys/class/hidraw | wc -l)" -ge 2 ]'
gadget_lines yk "$mark" | sed 's/^/    log: /'
check "bus Suspend and Resume reached the engine" \
    sh -c "tail -n +$((mark + 1)) '$(log_of yk)' | grep -q 'bus Suspend' && tail -n +$((mark + 1)) '$(log_of yk)' | grep -q 'bus Resume'"
mark=$(log_mark yk)
run python3 "$PY/usbfs.py" "$(devnode 0407)" reset
wait_for 20 sh -c "'$LK_BIN' ctl --control '$LK_RUN/yk/state/control.sock' status | grep -q '^attached=true'"
sleep 1
gadget_lines yk "$mark" | sed 's/^/    log: /'
check "USBDEVFS_RESET reached the engine as bus Reset" sh -c "tail -n +$((mark + 1)) '$(log_of yk)' | grep -q 'bus Reset'"
udevadm settle --timeout=10
check "FIDO answers after the reset" wait_for 20 fido_answers
mark=$(log_mark yk)
D=$(sysdev 0407)
echo 0 > "$D/authorized"
sleep 1
lk_ctl yk status | grep -E '^(attached|suspended)=' | sed 's/^/    after authorized=0: /'
echo 1 > "$D/authorized"
wait_for 20 sh -c "'$LK_BIN' ctl --control '$LK_RUN/yk/state/control.sock' status | grep -q '^attached=true'"
sleep 1
lk_ctl yk status | grep -E '^(attached|suspended)=' | sed 's/^/    after authorized=1: /'
gadget_lines yk "$mark" | sed 's/^/    log: /'
check "authorized 0/1 (SET_CONFIGURATION 0, then 1) reached the engine as bus Reset" \
    sh -c "tail -n +$((mark + 1)) '$(log_of yk)' | grep -q 'bus Reset'"
udevadm settle --timeout=10
check "FIDO answers after re-authorization" wait_for 20 fido_answers
step_end

# ---------------------------------------------------------------------------------------
step_begin 5 "re-enumeration through Management (ykman config usb)"
mark=$(log_mark yk)
pid_var=LK_PID_yk
strace -f -tt -e trace=openat,write -e signal=none -o "$W/strace" -p "${!pid_var}" 2>/dev/null &
tracer=$!
sleep 1
start_pcscd >/dev/null
run ykman --reader yubico config usb --disable OTP --force > "$W/cfg1" 2>&1
rc=$?; cat "$W/cfg1"
check "--disable OTP over CCID succeeded (exit $rc)" sh -c "[ $rc = 0 ] && grep -q 'configuration updated' '$W/cfg1'"
check "the host sees 1050:0406" wait_for 30 has_dev 0406
udevadm settle --timeout=20
D6=$(sysdev 0406)
host6=$(hex "$D6/descriptors")
echo "    host 0406: $host6"
python3 "$PY/desc_diff.py" --allow bEndpointAddress "$REF_0406_CONFIG" "${host6:54}" | sed 's/^/    /'
check "the FIDO+CCID configuration = the reference key's except bEndpointAddress" \
    quiet python3 "$PY/desc_diff.py" --allow bEndpointAddress "$REF_0406_CONFIG" "${host6:54}"
note "device descriptor 0406: $(echo "$host6" | cut -c1-53)"
check "device descriptor 0406: bcdUSB 0200, idProduct 0406, bcdDevice 0574" \
    sh -c "echo '$host6' | grep -q '^12 01 00 02 00 00 00 40 50 10 06 04 74 05 '"
run lsusb -v -d 1050:0406 > "$W/lsusb-0406" 2>&1
grep -E 'idProduct|iProduct|bInterfaceClass|bEndpointAddress|dwMaxCCIDMessageLength' "$W/lsusb-0406" | sed 's/^/    /'
check "pcscd sees the reader again" wait_for 30 reader_seen
run ykman --reader yubico config usb --enable OTP --force > "$W/cfg2" 2>&1
rc=$?; cat "$W/cfg2"
check "--enable OTP over CCID succeeded (exit $rc)" sh -c "[ $rc = 0 ] && grep -q 'configuration updated' '$W/cfg2'"
check "the host sees 1050:0407 again" wait_for 30 has_dev 0407
stop_pcscd
udevadm settle --timeout=20
wait_for 20 has_hidraw otp
run ykman config usb --disable OTP --force > "$W/cfg3" 2>&1
rc=$?; cat "$W/cfg3"
check "--disable OTP over OTP HID succeeded (exit $rc)" sh -c "[ $rc = 0 ] && grep -q 'configuration updated' '$W/cfg3'"
check "the host sees 1050:0406" wait_for 30 has_dev 0406
udevadm settle --timeout=20
wait_for 20 has_hidraw fido
run ykman config usb --enable OTP --force > "$W/cfg4" 2>&1
rc=$?; cat "$W/cfg4"
check "--enable OTP over FIDO HID succeeded (exit $rc)" sh -c "[ $rc = 0 ] && grep -q 'configuration updated' '$W/cfg4'"
check "the host sees 1050:0407 again" wait_for 30 has_dev 0407
udevadm settle --timeout=20
run ykman otp info
check "ykman otp info after re-enabling (slot 2 still programmed)" sh -c 'timeout 60 ykman otp info | grep -q "Slot 2: programmed"'
kill "$tracer" 2>/dev/null
wait "$tracer" 2>/dev/null
gadget_lines yk "$mark" | grep -E 'enumerat|bound|unbound|Failed|did not|stop|bus |dropped|failed|re-enumeration' | sed 's/^/    log: /'
note "the -vv lines around each unbind (the drain: what went out right before it):"
log_since yk "$mark" | grep -B4 -A1 -E 'gadget: unbound$' | sed 's/^/    log: /'
check "no bus Suspend of an ending session reached the device" \
    sh -c "! tail -n +$((mark + 1)) '$(log_of yk)' | grep -q 'bus Suspend'"
check "no re-enumeration reported an undelivered response" \
    sh -c "! tail -n +$((mark + 1)) '$(log_of yk)' | grep -q 're-enumeration:'"
note "strace of the daemon: ep0 opens and UDC writes (time, thread, call, result):"
grep -E 'ffs-localkey/ep0|/UDC' "$W/strace" | sed 's/^/    /' | head -n 60
note "strace: interrupted calls (EINTR) while it was attached: $(grep -c 'EINTR' "$W/strace")"
step_end

# ---------------------------------------------------------------------------------------
step_begin 6 "kill -9 and restart"
lk_kill yk
check "the USB device went away after SIGKILL" wait_for 15 no_0407
note "left behind: $(find /sys/kernel/config/usb_gadget -maxdepth 4 | sort | tr '\n' ' ')"
note "UDC '$(cat /sys/kernel/config/usb_gadget/localkey/UDC 2>&1)'; mounts: $(grep functionfs /proc/mounts | tr '\n' ' ')"
check "the ConfigFS tree and the FunctionFS mount are left (the leftover)" \
    sh -c '[ -d /sys/kernel/config/usb_gadget/localkey ] && grep -q "^localkey .* functionfs " /proc/mounts'
check "the leftover's UDC reads empty" same "$(cat /sys/kernel/config/usb_gadget/localkey/UDC 2>/dev/null)" ""
mark=$(log_mark yk)
lk_resume yk --profile "$YK" --transport gadget --udc "$UDC" -vv
check "1050:0407 came back" wait_for 60 has_dev 0407
gadget_lines yk "$mark" | grep -v 'gadget: setup' | sed 's/^/    log: /'
check "the daemon removed the leftover gadget" sh -c "tail -n +$((mark + 1)) '$(log_of yk)' | grep -q 'removed the leftover gadget'"
udevadm settle --timeout=20
wait_for 20 has_hidraw fido
fido=$(hidraw_of fido)
lk_tap yk > "$W/tap-assert2" &
tapper=$!
timeout 60 fido2-assert -G -p -i "$W/assert-param" -o "$W/assert2" "$fido" < /dev/null
rc=$?
wait "$tapper"
check "an assertion with the step-2 credential (exit $rc)" [ "$rc" = 0 ]
run fido2-assert -V -p -i "$W/assert2" "$W/cred-pubkey" es256
check "verifies with the step-2 public key" [ $? = 0 ]
r3=$(timeout 60 ykman otp calculate 2 "$chal")
check "OTP slot 2 still answers $r1" same "$r3" "$r1"
start_pcscd >/dev/null
run ykman --reader yubico piv info > "$W/piv-info2" 2>&1
cat "$W/piv-info2"
check "the PIV certificate in 9a is kept" grep -q 'CN=localkey gadget' "$W/piv-info2"
check "the OATH account is kept" sh -c 'timeout 60 ykman --reader yubico oath accounts list | grep -q "^test"'
stop_pcscd
step_end

# ---------------------------------------------------------------------------------------
step_begin E "extra: external unbind, GET_STATUS, stall, VIRTUAL_ADDR, other controllers"
D=$(sysdev 0407)
note "GET_STATUS (standard, device / interface 2 / endpoint 0x81) through usbfs, pcscd stopped:"
mark=$(log_mark yk)
echo "    device:       $(python3 "$PY/usbfs.py" "$(devnode 0407)" control 0x80 0x00 0 0 2)"
echo "    interface 2:  $(python3 "$PY/usbfs.py" "$(devnode 0407)" control 0x81 0x00 0 2 2 2>&1)"
echo "    endpoint 81:  $(python3 "$PY/usbfs.py" "$(devnode 0407)" control 0x82 0x00 0 0x81 2)"
note "CCID GET_CLOCK_FREQUENCIES (a1 02, stalled by the transport) then ABORT (21 01, acknowledged) on interface 2:"
echo "    GET_CLOCK_FREQUENCIES: $(python3 "$PY/usbfs.py" "$(devnode 0407)" control 0xa1 0x02 0 2 4 2>&1)"
echo "    ABORT slot 0 seq 7:    $(python3 "$PY/usbfs.py" "$(devnode 0407)" control 0x21 0x01 0x0700 2 0 2>&1)"
echo "    GET_DATA_RATES:        $(python3 "$PY/usbfs.py" "$(devnode 0407)" control 0xa1 0x03 0 2 4 2>&1)"
sleep 0.5
log_since yk "$mark" | grep -E 'setup|Abort|abort' | sed 's/^/    log: /'
check "GET_CLOCK_FREQUENCIES stalled and ABORT acknowledged" \
    sh -c "tail -n +$((mark + 1)) '$(log_of yk)' | grep -q 'setup a1 02 .*: stall' && tail -n +$((mark + 1)) '$(log_of yk)' | grep -q 'setup 21 01 value 0x0700 index 2 length 0: ack'"

note "an external unbind (echo > UDC) while the daemon runs, then an external bind:"
mark=$(log_mark yk)
echo "" > /sys/kernel/config/usb_gadget/localkey/UDC
check "the device went away" wait_for 15 no_0407
sleep 1
log_since yk "$mark" | sed 's/^/    log: /'
lk_ctl yk status | grep -E '^attached=' | sed 's/^/    /'
check "the daemon ended the session (unbound by someone else)" \
    sh -c "tail -n +$((mark + 1)) '$(log_of yk)' | grep -q 'unbound by someone else'"
if echo "$UDC" > /sys/kernel/config/usb_gadget/localkey/UDC 2> "$W/bind-err"; then
    note "external bind accepted"
    bad "an external bind after the session ended should be refused"
else
    note "external bind refused: $(cat "$W/bind-err")"
    ok "an external bind after the session ended is refused"
fi
t0=$(date +%s%N)
lk_stop yk > "$W/stop-after-unbind" 2>&1
rc=$?
note "daemon stopped in $(( ($(date +%s%N) - t0) / 1000000 )) ms, exit code $rc"
tail -n 8 "$(log_of yk)" | sed 's/^/    log: /'
check "clean shutdown after an external unbind (exit 0, tree removed, unmounted)" \
    sh -c "[ $rc = 0 ] && [ ! -d /sys/kernel/config/usb_gadget/localkey ] && ! grep -q functionfs /proc/mounts"

note "FUNCTIONFS_VIRTUAL_ADDR: the engine's descriptors with flags 0x01 (as the transport) and 0x11:"
for flags in 0x01 0x11; do
    echo "  --- flags $flags ---"
    python3 "$PY/ffs_virtual.py" --config "$(ident configuration)" --udc "$UDC" --flags "$flags" --seconds 4 2>&1 |
        grep -v -E 'kernel: .*(random|audit)' | sed 's/^/    /' | tee "$W/virt-$flags"
done
check "without VIRTUAL_ADDR the host configures the device" grep -q "bConfigurationValue '1'" "$W/virt-0x01"

for params in "is_high_speed=0" "is_super_speed=1"; do
    note "dummy_hcd $params:"
    rmmod dummy_hcd && modprobe dummy_hcd $params
    wait_for 10 test -e "/sys/class/udc/$UDC"
    lk_resume yk --profile "$YK" --transport gadget --udc "$UDC" -v
    if wait_for 60 has_dev 0407; then
        D=$(sysdev 0407)
        echo "    $(basename "$D"): speed $(cat "$D/speed"), version $(cat "$D/version"), descriptors $(hex "$D/descriptors" | cut -c1-53)"
        echo "    DEVICE_QUALIFIER: $(python3 "$PY/usbfs.py" "$(devnode 0407)" control 0x80 0x06 0x0600 0 10)"
        echo "    BOS: $(python3 "$PY/usbfs.py" "$(devnode 0407)" control 0x80 0x06 0x0f00 0 64)"
        lsusb -v -d 1050:0407 2>&1 | grep -E 'bcdUSB|Device Qualifier|Binary Object|Capability|bmAttributes|Speed' | sed 's/^/    lsusb: /'
        dmesg | grep -E 'usb 1-1|usb [0-9]-1:' | tail -n 4 | sed 's/^/    kernel: /'
    else
        bad "no device with dummy_hcd $params"
        dmesg | tail -n 20 | sed 's/^/    kernel: /'
    fi
    lk_stop yk > /dev/null 2>&1 || note "yk exit code $?"
done
rmmod dummy_hcd && modprobe dummy_hcd
step_end

# ---------------------------------------------------------------------------------------
section "summary"
for line in "${results[@]}"; do echo "$line"; done
fail=0
for line in "${results[@]}"; do case "$line" in *FAIL) fail=1 ;; esac; done
lk_alive yk 2>/dev/null && lk_stop yk > /dev/null
section "daemon log (yk) without per-transfer and setup lines"
grep -v -E 'gadget: (<-|->|setup) ' "$(log_of yk)" | tail -n 150 | sed 's/^/    /'
section "dmesg (usb, gadget, hid)"
dmesg | grep -i -E 'usb|gadget|ffs|hid|dummy' | tail -n 60
exit "$fail"
