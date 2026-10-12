# The uhid transport against a real kernel and real host software, all inside the guest:
# the HID core, hidraw and the input layer; libfido2 (fido2-token, fido2-cred,
# fido2-assert); python-fido2; ykman over the OTP HID interface; the OTP keyboard as evdev
# key events.
#
#   1 enumeration       hidraw identity and report descriptors against the engine's (read
#                       from the wire transport's IDENTITY frame), UHID_START dev_flags
#   2 libfido2          list, info, set PIN, make and verify a credential, get and verify
#                       an assertion (touches through `localkeyd ctl tap`)
#   3 python-fido2      list, getInfo, make_credential/get_assertion (Ctap2 and
#                       Fido2Client + Fido2Server)
#   4 ykman / OTP       list, info, otp info, HMAC-SHA1 challenge-response in slot 2
#                       (feature reports through hidraw ioctls), a static password in slot
#                       1 typed through the kernel's input layer
#   5 re-enumeration    ykman config usb --disable OTP / --enable OTP
#   6 kill -9, restart  no devices left behind, state kept (FIDO PIN, OTP slots)
#   E extra             report-number rule, driver unbind/bind (UHID_STOP without
#                       DESTROY), a hidraw writer flooding the device
#
# Every step prints "STEP <n> PASS" or "STEP <n> FAIL"; the summary at the end repeats them.
# The state directories are on tmpfs (/run/lk).
set -u
. /localkey/lib.sh
PY=/localkey/py
W=/run/lk-work
mkdir -p "$W"
PIN=314159
STATIC=Hello1World
YK=yubikey
export LK_LOG_QUIET=1
results=()
step=
step_ok=1

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
# run CMD...: show the command, its output and its exit code; returns the exit code.
run() {
    echo "\$ $*"
    "$@"
    local rc=$?
    echo "[exit $rc]"
    return "$rc"
}
two_hidraw() { [ "$(hidraw_count)" -ge 2 ]; }
no_hidraw() { [ "$(hidraw_count)" = 0 ]; }
has_hidraw() { hidraw_of "$1" >/dev/null; }
lacks_hidraw() { ! hidraw_of "$1" >/dev/null; }
fido_is() { local n; n=$(hidraw_of fido) && [ "$(hid_id "$n")" = "$1" ]; }
uevent() { sed -n "s/^$2=//p" "/sys/class/hidraw/$(basename "$1")/device/uevent"; }
log_of() { echo "$LK_RUN/$1/log"; }
# input_event_of NODE: the evdev node of the input device a hidraw node's HID device has.
input_event_of() {
    local e
    for e in /sys/class/hidraw/"$(basename "$1")"/device/input/input*/event*; do
        [ -e "$e" ] && { echo "/dev/input/$(basename "$e")"; return 0; }
    done
    return 1
}
# event_summary NAME: the -vv trace of daemon NAME as counts of (interface, direction,
# event, data size), then every other line.
event_summary() {
    note "UHID events of $1 (count, interface, direction, event, data bytes):"
    sed -n 's/.*uhid: \(otp\|fido\) \(<-\|->\) \([A-Z_0-9]*\), \([0-9]*\) bytes.*/\1 \2 \3 \4/p' "$(log_of "$1")" |
        sort | uniq -c | sed 's/^/    /'
    note "other log lines of $1:"
    grep -v -E 'uhid: (otp|fido) (<-|->) ' "$(log_of "$1")" | sed 's/^/    /'
}

section versions
note "kernel $(uname -r); $(fido2-token -V 2>&1 | head -n 1) (libfido2); python-fido2 $(python3 -c 'import importlib.metadata as m; print(m.version("fido2"))'); ykman $(ykman --version 2>&1 | head -n 1)"

# ---------------------------------------------------------------------------------------
step_begin 1 "enumeration (profile own)"
lk_start own --profile own
wait_for 20 test -S "$LK_RUN/own/state/wire.sock" || bad "wire socket"
python3 "$PY/wire_identity.py" "$LK_RUN/own/state/wire.sock" > "$W/identity-own"
sed 's/^/    engine: /' "$W/identity-own"
lk_stop own >/dev/null
ident() { sed -n "s/^$1=//p" "$W/identity-own"; }
lk_resume own --profile own --transport uhid -vv
check "two hidraw nodes appeared" wait_for 30 two_hidraw
udevadm settle --timeout=10
fido=$(hidraw_of fido)
otp=$(hidraw_of otp)
note "FIDO node $fido, OTP node $otp"
expected_id=$(printf '0003:0000%s:0000%s' "$(ident vendor | tr a-f A-F)" "$(ident product | tr a-f A-F)")
for kind in fido otp; do
    node=${!kind}
    sys=/sys/class/hidraw/$(basename "$node")/device
    note "$kind: $(grep -E '^(DRIVER|HID_ID|HID_NAME|HID_PHYS|HID_UNIQ)=' "$sys/uevent" | tr '\n' ' ')"
    check "$kind HID_ID $(uevent "$node" HID_ID) = $expected_id" same "$(uevent "$node" HID_ID)" "$expected_id"
    check "$kind HID_NAME = product string '$(ident product_name)'" same "$(uevent "$node" HID_NAME)" "$(ident product_name)"
    check "$kind HID_UNIQ = serial string '$(ident serial)'" same "$(uevent "$node" HID_UNIQ)" "$(ident serial)"
    check "$kind report_descriptor equals the engine's ($(wc -c < "$sys/report_descriptor") bytes)" \
        same "$(hex "$sys/report_descriptor")" "$(ident "${kind}_rd")"
    python3 "$PY/hidraw_info.py" "$node" | sed "s/^/    $kind ioctl: /"
    check "$kind HIDIOCGRAWINFO bus 0003 (BUS_USB)" same "$(python3 "$PY/hidraw_info.py" "$node" | sed -n 's/^bus=//p')" 0003
done
grep -E 'device (started|created)' "$(log_of own)" | sed 's/^/    /'
check "UHID_START dev_flags 0x0 for both devices" same "$(grep -c 'device started (dev_flags 0x0)' "$(log_of own)")" 2
note "input devices:"
grep -B1 -A8 'Phys=localkey' /proc/bus/input/devices | sed 's/^/    /'
step_end

# ---------------------------------------------------------------------------------------
step_begin 2 "libfido2 (profile own)"
run fido2-token -L | tee "$W/token-L"
check "fido2-token -L lists $fido" grep -q "^$fido: " "$W/token-L"
run fido2-token -I "$fido" > "$W/token-I1"
sed 's/^/    /' "$W/token-I1"
check "getInfo before: noclientPin" grep -q -E '(^|[ ,])noclientPin(,|$)' "$W/token-I1"
echo "\$ fido2-token -S $fido   (new PIN twice on stdin)"
printf '%s\n%s\n' "$PIN" "$PIN" | fido2-token -S "$fido"
check "fido2-token -S set the PIN (exit $?)" [ $? = 0 ]
run fido2-token -I "$fido" > "$W/token-I2"
grep -E '^(options|pin protocols|pin retries|uv retries)' "$W/token-I2" | sed 's/^/    /'
check "getInfo after: clientPin" grep -q -E '(^|[ ,])clientPin(,|$)' "$W/token-I2"
# fido2-cred(1): the input is the client data hash, the relying party id, the user name and
# the user id; fido2-assert(1): the client data hash, the relying party id, the credential id.
printf '%s\n%s\n%s\n%s\n' "$(head -c 32 /dev/urandom | base64)" localkey.example alice \
    "$(head -c 32 /dev/urandom | base64)" > "$W/cred-param"
lk_tap own > "$W/tap-cred" &
tapper=$!
echo "\$ fido2-cred -M -i cred-param -o cred $fido es256   (PIN on stdin if asked, touch by lk_tap)"
echo "$PIN" | fido2-cred -M -i "$W/cred-param" -o "$W/cred" "$fido" es256
rc=$?
wait "$tapper"
cat "$W/tap-cred"
check "fido2-cred -M made a credential (exit $rc)" [ "$rc" = 0 ]
note "credential: format $(sed -n 3p "$W/cred"), id $(sed -n 5p "$W/cred" | base64 -d 2>/dev/null | wc -c) bytes, $(wc -l < "$W/cred") lines"
run fido2-cred -V -i "$W/cred" -o "$W/cred-pubkey" es256
check "fido2-cred -V verified the attestation" [ $? = 0 ]
head -n 2 "$W/cred-pubkey" | sed 's/^/    /'
printf '%s\n%s\n%s\n' "$(head -c 32 /dev/urandom | base64)" localkey.example "$(sed -n 5p "$W/cred")" > "$W/assert-param"
lk_tap own > "$W/tap-assert" &
tapper=$!
echo "\$ fido2-assert -G -p -i assert-param -o assert $fido   (PIN on stdin if asked, touch by lk_tap)"
echo "$PIN" | fido2-assert -G -p -i "$W/assert-param" -o "$W/assert" "$fido"
rc=$?
wait "$tapper"
cat "$W/tap-assert"
check "fido2-assert -G got an assertion (exit $rc)" [ "$rc" = 0 ]
run fido2-assert -V -p -i "$W/assert" "$W/cred-pubkey" es256
check "fido2-assert -V -p verified the signature and the UP flag" [ $? = 0 ]
step_end

# ---------------------------------------------------------------------------------------
step_begin 3 "python-fido2 (profile own)"
run python3 "$PY/fido2_flow.py" --control "$LK_RUN/own/state/control.sock" --pin "$PIN"
check "python-fido2 flow" [ $? = 0 ]
step_end

note "UHID_OPEN/CLOSE and report sizes seen in steps 1-3:"
event_summary own
lk_stop own >/dev/null || note "own exit code $?"

# ---------------------------------------------------------------------------------------
step_begin 4 "ykman and the OTP interface (profile $YK)"
lk_start yk --profile "$YK" --transport uhid -vv
check "two hidraw nodes appeared" wait_for 30 two_hidraw
udevadm settle --timeout=10
fido=$(hidraw_of fido)
otp=$(hidraw_of otp)
for kind in fido otp; do
    node=${!kind}
    note "$kind $node: HID_ID $(uevent "$node" HID_ID) HID_NAME '$(uevent "$node" HID_NAME)'"
    check "$kind HID_ID 0003:00001050:00000407" same "$(uevent "$node" HID_ID)" 0003:00001050:00000407
    note "$kind udev: $(udevadm info --query=property "$node" | grep -E '^(ID_FIDO_TOKEN|ID_SECURITY_TOKEN|TAGS)=' | tr '\n' ' ')"
done
run ykman list
check "ykman list shows a YubiKey" sh -c 'ykman list 2>/dev/null | grep -q YubiKey'
run ykman info
check "ykman info" sh -c 'ykman info >/dev/null'
run ykman otp info
check "ykman otp info" sh -c 'ykman otp info >/dev/null'
run ykman otp chalresp --generate 2 --force | tee "$W/chalresp"
key=$(grep -o -i -E '[0-9a-f]{40}' "$W/chalresp" | head -n 1)
note "slot 2 HMAC-SHA1 key: ${key:-<not printed>}"
chal=$(head -c 32 /dev/urandom | od -An -tx1 -v | tr -d ' \n')
r1=$(ykman otp calculate 2 "$chal")
r2=$(ykman otp calculate 2 "$chal")
want=$(python3 -c 'import hmac,hashlib,sys; print(hmac.new(bytes.fromhex(sys.argv[1]), bytes.fromhex(sys.argv[2]), hashlib.sha1).hexdigest())' "$key" "$chal" 2>/dev/null)
note "challenge $chal"
note "response 1 $r1"
note "response 2 $r2"
note "HMAC-SHA1(key, challenge) $want"
check "two calculations agree and are non-empty" sh -c "[ -n '$r1' ] && [ '$r1' = '$r2' ]"
check "the response is HMAC-SHA1 of the challenge under the generated key" same "$r1" "$want"
run ykman otp static 1 "$STATIC" --keyboard-layout US --force
run ykman otp info
event=$(input_event_of "$otp")
note "OTP keyboard input node $event"
python3 "$PY/evdev_keys.py" --event "$event" --hidraw "$otp" --seconds 15 > "$W/keys" &
capture=$!
wait_for 10 grep -q capturing "$W/keys"
run lk_ctl yk tap
wait "$capture"
sed 's/^/    /' "$W/keys"
check "the keyboard typed $STATIC + Enter" same "$(sed -n 's/^typed=//p' "$W/keys")" "'$STATIC\\n'"
check "every hidraw input report is 8 bytes (no report number)" \
    sh -c "! grep '^hidraw:' '$W/keys' | grep -v '^hidraw: 8 bytes'"
step_end

# ---------------------------------------------------------------------------------------
step_begin 5 "re-enumeration (profile $YK)"
run ykman config usb --disable OTP --force > "$W/config-disable" 2>&1
rc=$?
cat "$W/config-disable"
check "ykman config usb --disable OTP succeeded (exit $rc, over OTP HID)" \
    sh -c "[ $rc = 0 ] && grep -q 'configuration updated' '$W/config-disable'"
check "the OTP hidraw node went away" wait_for 20 lacks_hidraw otp
check "the FIDO node is 1050:0406 (FIDO+CCID)" wait_for 20 fido_is 0003:00001050:00000406
udevadm settle --timeout=10
hidraw_report
run ykman info
check "ykman info over FIDO after the reboot" sh -c 'ykman info >/dev/null'
run ykman config usb --enable OTP --force > "$W/config-enable" 2>&1
rc=$?
cat "$W/config-enable"
check "ykman config usb --enable OTP succeeded (exit $rc, over FIDO HID)" \
    sh -c "[ $rc = 0 ] && grep -q 'configuration updated' '$W/config-enable'"
check "the OTP hidraw node came back" wait_for 20 has_hidraw otp
check "the FIDO node is 1050:0407 again" wait_for 20 fido_is 0003:00001050:00000407
udevadm settle --timeout=10
run ykman otp info
check "ykman otp info after re-enabling" sh -c 'ykman otp info | grep -q "Slot 2: programmed"'
grep -E 'enumerated|created|destroyed|started|stopped|ended|Failed|did not' "$(log_of yk)" | sed 's/^/    /'
step_end

# ---------------------------------------------------------------------------------------
step_begin 6 "kill -9 and restart"
before=$(ls /sys/bus/hid/devices)
note "HID devices before: $(echo $before)"
lk_kill yk
check "both hidraw nodes went away after SIGKILL" wait_for 10 no_hidraw
check "no HID device left" wait_for 10 sh -c '[ -z "$(ls /sys/bus/hid/devices)" ]'
check "no input device with Phys=localkey left" sh -c '! grep -q "Phys=localkey" /proc/bus/input/devices'
lk_resume yk --profile "$YK" --transport uhid -vv
check "the devices came back" wait_for 30 two_hidraw
udevadm settle --timeout=10
run ykman otp info
check "OTP slots kept" sh -c 'ykman otp info | grep -q "Slot 1: programmed" && ykman otp info | grep -q "Slot 2: programmed"'
r3=$(ykman otp calculate 2 "$chal")
check "slot 2 still answers $r1" same "$r3" "$r1"
lk_stop yk >/dev/null || note "yk exit code $?"
event_summary yk

lk_resume own --profile own --transport uhid -vv
check "own devices up" wait_for 30 two_hidraw
lk_kill own
check "both hidraw nodes went away after SIGKILL" wait_for 10 no_hidraw
lk_resume own --profile own --transport uhid -vv
check "own devices up again" wait_for 30 two_hidraw
udevadm settle --timeout=10
fido=$(hidraw_of fido)
run fido2-token -I "$fido" > "$W/token-I3"
grep -E '^(options|pin retries)' "$W/token-I3" | sed 's/^/    /'
check "the FIDO PIN is still set (clientPin)" grep -q -E '(^|[ ,])clientPin(,|$)' "$W/token-I3"
lk_tap own > "$W/tap-assert2" &
tapper=$!
echo "$PIN" | fido2-assert -G -p -i "$W/assert-param" -o "$W/assert2" "$fido"
rc=$?
wait "$tapper"
check "an assertion with the step-2 credential (exit $rc)" [ "$rc" = 0 ]
run fido2-assert -V -p -i "$W/assert2" "$W/cred-pubkey" es256
check "verifies with the step-2 public key" [ $? = 0 ]
step_end

# ---------------------------------------------------------------------------------------
step_begin E "extra: report numbers, driver unbind, flood (profile own)"
fido=$(hidraw_of fido)
otp=$(hidraw_of otp)
note "report-number rule through raw hidraw calls (the -vv log shows what reached /dev/uhid):"
mark=$(wc -l < "$(log_of own)")
python3 "$PY/hidraw_info.py" "$otp" --get-feature 9 --get-feature 8 | grep '^get_feature' | sed 's/^/    /'
python3 - "$otp" "$fido" <<'PY'
import fcntl, os, sys
otp, fido = sys.argv[1], sys.argv[2]
def sfeature(size):  # HIDIOCSFEATURE(size)
    return (3 << 30) | (size << 16) | (ord("H") << 8) | 0x06
reset = bytes(7) + b"\xff"           # yubikit's _reset_state report
fd = os.open(otp, os.O_RDWR)
for name, buf in (("9 bytes: 00 + report", b"\0" + reset), ("8 bytes: the report alone", reset)):
    try:
        got = fcntl.ioctl(fd, sfeature(len(buf)), bytearray(buf), True)
        print(f"    HIDIOCSFEATURE {name}: returned {got}")
    except OSError as error:
        print(f"    HIDIOCSFEATURE {name}: error {error.errno} ({os.strerror(error.errno)})")
os.close(fd)
fd = os.open(fido, os.O_RDWR)
init = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0x86, 0x00, 0x08]) + bytes(range(1, 9))
for name, buf in (("65 bytes: 00 + report", b"\0" + init.ljust(64, b"\0")), ("64 bytes: the report alone", init.ljust(64, b"\0"))):
    print(f"    write() {name}: returned {os.write(fd, buf)}")
    reply = os.read(fd, 4096)
    print(f"    read(): {len(reply)} bytes, CTAPHID command 0x{reply[4]:02x}, nonce echoed: {reply[7:15] == init[7:15]}")
os.close(fd)
PY
sleep 0.5
tail -n +"$((mark + 1))" "$(log_of own)" | grep -E 'SET_REPORT|GET_REPORT|OUTPUT|refused' | sed 's/^/    log: /'
check "a 65-byte write with report number 0 reaches the device as 65 bytes" \
    sh -c "tail -n +$((mark + 1)) '$(log_of own)' | grep -q 'fido <- OUTPUT, 65 bytes'"
check "a 64-byte write reaches the device as 64 bytes" \
    sh -c "tail -n +$((mark + 1)) '$(log_of own)' | grep -q 'fido <- OUTPUT, 64 bytes'"
check "a 9-byte HIDIOCSFEATURE arrives as a 9-byte SET_REPORT" \
    sh -c "tail -n +$((mark + 1)) '$(log_of own)' | grep -q 'otp <- SET_REPORT, 9 bytes'"
check "an 8-byte HIDIOCSFEATURE arrives as an 8-byte SET_REPORT" \
    sh -c "tail -n +$((mark + 1)) '$(log_of own)' | grep -q 'otp <- SET_REPORT, 8 bytes'"

note "udev and the OTP node: a uhid device has no USB ancestor, so rules keyed on USB attributes cannot match it:"
udevadm info --attribute-walk "$otp" | grep -E "looking at (parent )?device" | sed 's/^ */    /'
note "OTP node tags without a rule: $(udevadm info --query=property "$otp" | sed -n 's/^TAGS=//p')"
echo 'SUBSYSTEM=="hidraw", DEVPATH=="/devices/virtual/misc/uhid/0003:1209:0001.*", TAG+="uaccess"' \
    > /etc/udev/rules.d/70-localkey-otp.rules
udevadm control --reload
udevadm trigger --action=change "$otp"
udevadm settle --timeout=10
note "OTP node tags with a rule on the uhid device path: $(udevadm info --query=property "$otp" | sed -n 's/^TAGS=//p')"
check "a rule on DEVPATH==/devices/virtual/misc/uhid/0003:<vendor>:<product>.* tags the OTP node uaccess" \
    sh -c "udevadm info --query=property '$otp' | grep -q '^TAGS=.*:uaccess:'"
rm -f /etc/udev/rules.d/70-localkey-otp.rules
udevadm control --reload

note "unbind hid-generic from the FIDO device, bind it again, unbind it, then stop the daemon:"
hid=$(basename "$(readlink -f "/sys/class/hidraw/$(basename "$fido")/device")")
note "FIDO HID device $hid"
mark=$(wc -l < "$(log_of own)")
echo -n "$hid" > /sys/bus/hid/drivers/hid-generic/unbind
check "the FIDO hidraw node went away on unbind" wait_for 10 lacks_hidraw fido
sleep 0.5
echo -n "$hid" > /sys/bus/hid/drivers/hid-generic/bind
check "the FIDO hidraw node came back on bind" wait_for 10 has_hidraw fido
sleep 0.5
echo -n "$hid" > /sys/bus/hid/drivers/hid-generic/unbind
wait_for 10 lacks_hidraw fido
sleep 0.5
t0=$(date +%s%N)
lk_stop own > "$W/stop-unbound" 2>&1
rc=$?
note "daemon stopped in $(( ($(date +%s%N) - t0) / 1000000 )) ms, exit code $rc"
check "clean shutdown after driver unbind" same "$rc" 0
check "no reader thread left behind" sh -c "! grep -q 'reader thread did not end' '$(log_of own)'"
tail -n +"$((mark + 1))" "$(log_of own)" | grep -v -E 'uhid: (otp|fido) (<-|->) INPUT2|OUTPUT' | sed 's/^/    log: /'
check "UHID_STOP on unbind, UHID_START on bind" \
    sh -c "tail -n +$((mark + 1)) '$(log_of own)' | grep -c 'fido device st' | grep -q '^[3-9]'"
check "no device left after the daemon stopped" wait_for 10 no_hidraw

note "a hidraw client floods the FIDO device with CTAPHID INIT reports:"
lk_resume own --profile own --transport uhid -v
wait_for 30 two_hidraw
udevadm settle --timeout=10
fido=$(hidraw_of fido)
dmesg -C
dmesg -w > "$W/kmsg" 2>&1 &
follower=$!
python3 - "$fido" 5000 <<'PY'
import os, select, sys, threading, time
fd = os.open(sys.argv[1], os.O_RDWR)
count = int(sys.argv[2])
answers = [0]
done = threading.Event()
def read_answers():
    while not done.is_set():
        if select.select([fd], [], [], 0.2)[0] and os.read(fd, 64)[4] == 0x86:
            answers[0] += 1
reader = threading.Thread(target=read_answers)
reader.start()
errors, start = 0, time.monotonic()
for i in range(count):
    nonce = i.to_bytes(8, "big")
    try:
        os.write(fd, b"\0" + bytes([0xFF, 0xFF, 0xFF, 0xFF, 0x86, 0x00, 0x08]) + nonce + bytes(64 - 15))
    except OSError:
        errors += 1
took = time.monotonic() - start
last, quiet = -1, time.monotonic()
while time.monotonic() - quiet < 1.0:
    if answers[0] != last:
        last, quiet = answers[0], time.monotonic()
    time.sleep(0.05)
done.set()
reader.join()
os.close(fd)
print(f"    wrote {count - errors} of {count} reports in {took:.2f} s ({errors} write errors); "
      f"{answers[0]} INIT answers read back (answers can also be lost in hidraw's 64-report client buffer)")
PY
sleep 1
kill "$follower" 2>/dev/null
wait "$follower" 2>/dev/null
note "kernel 'Output queue is full' warnings during the flood: $(grep -c 'Output queue is full' "$W/kmsg") (dmesg -w after dmesg -C)"
grep 'Output queue is full' "$W/kmsg" | sed -n '1p;$p' | sed 's/^/    /'
run lk_ctl own status
run fido2-token -I "$fido" > "$W/token-I4"
check "the device still answers after the flood" grep -q -E '(^|[ ,])clientPin(,|$)' "$W/token-I4"
step_end

# ---------------------------------------------------------------------------------------
section "summary"
for line in "${results[@]}"; do echo "$line"; done
fail=0
for line in "${results[@]}"; do case "$line" in *FAIL) fail=1 ;; esac; done
lk_stop own >/dev/null || true
section "dmesg (hid, uhid, input)"
dmesg | grep -i -E 'hid|input|uhid' | tail -n 60
exit "$fail"
