# The vpcd transport, alone and with uhid, against the real vsmartcard vpcd (the image's
# vsmartcard-vpcd package, loaded by pcscd from /etc/reader.conf.d/vpcd) and real host
# software, all inside the guest: pcsc-tools, OpenSC, ykman, GnuPG (scdaemon through
# pcscd), pyscard, libfido2, python-fido2. Profile yubikey-5c-nano-5.7.4 throughout; touches
# through localkeyd's control socket (`localkeyd ctl tap`, or py/lk_tap.py, which sends the
# same `tap` request when the presence indicator turns to waiting).
#
#   (a) localkeyd run --transport vpcd
#   1 insertion         localkeyd first (vpcd not listening: retried), then pcscd: the
#                       "Virtual PCD 00 00" reader with a card (pcsc_scan, opensc-tool -l),
#                       the profile's ATR (opensc-tool -a), status attached=true
#   2 CCID clients      reader renamed "Yubico YubiKey OTP+FIDO+CCID" (ykman needs that
#                       name; pcscd restarted, the card follows): ykman info, OATH with
#                       touch (RFC 6238), PIV keys and certificates generate, OpenPGP info,
#                       gpg --card-status
#   3 large transfers   a PIV certificate of about 2.9 KB imported and exported byte for
#                       byte; an extended APDU of 4007 bytes (pyscard; more than one CCID
#                       message)
#   4 touch by ctl tap  a PIV key with --touch-policy ALWAYS signs a certificate once
#                       `localkeyd ctl tap` touches; the signature verifies
#   5 ctl shutdown      `localkeyd ctl shutdown` prints ok, stopped and exits 0; the daemon
#                       exits 0, the card leaves the reader, the sockets are removed
#   (b) localkeyd run --transport uhid,vpcd
#   6 whole device      fido2-token -L/-I, fido2-cred -M/-V through UHID; ykman reaches
#                       the key through CCID, OTP and FIDO; ykman list and info show all
#                       three interfaces
#   7 CCID off and on   ykman config usb disabling every CCID application (ykman 5.8
#                       has no CCID switch; over CCID): the card leaves the reader, the
#                       HID devices become 1050:0403; enabling them (over HID): back
#   8 config mode       ykman config mode OTP+FIDO / OTP+FIDO+CCID (no REBOOT, as on a
#                       YubiKey 5), then `localkeyd ctl power-cycle` as the re-plug
#   9 kill -9, restart  devices and card gone, back after a restart with the state kept
#   (c)
#  10 ctl shutdown      with uhid,vpcd: the HID devices removed, the card out, exit 0
#   E extra             systemd-analyze verify and udevadm verify of tools/service, when it
#                       is passed with -f and systemd-analyze exists
#
# Every step prints "STEP <n> PASS" or "STEP <n> FAIL"; the summary at the end repeats them.
# The state directories are on tmpfs (/run/lk). Run:
#   tools/linux-guest/guest-run.sh -t 1500 -f tools/service vpcd.sh
set -u
. /localkey/lib.sh
PY=/localkey/py
W=/run/lk-work
mkdir -p "$W"
YK=yubikey-5c-nano-5.7.4
MGMT=010203040506070801020304050607080102030405060708
PIV_PIN=123456
ATR="3b fd 13 00 00 81 31 fe 15 80 73 c0 21 c0 57 59 75 62 69 4b 65 79 40"
CONF=/etc/reader.conf.d/vpcd
YUBICO_NAME="Yubico YubiKey OTP+FIDO+CCID"
R="$YUBICO_NAME 00 00"
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
# run CMD...: show the command, its output and its exit code (a program gets 90 s); returns
# the exit code.
run() {
    echo "\$ $*"
    if declare -F "$1" >/dev/null; then "$@"; else timeout -k 5 90 "$@"; fi
    local rc=$?
    echo "[exit $rc]"
    return "$rc"
}
log_of() { echo "$LK_RUN/$1/log"; }
log_mark() { wc -l < "$(log_of "$1")"; }
log_since() { tail -n +"$(($2 + 1))" "$(log_of "$1")"; }
log_has_since() { log_since "$1" "$2" | grep -q -- "$3"; }
# events NAME MARK: the log lines of daemon NAME since MARK without per-message and
# per-report lines.
events() { log_since "$1" "$2" | grep -v -E '(vpcd|uhid): ((otp|fido) )?(<-|->) '; }
# sizes NAME MARK KIND: the sizes of the vpcd messages of one kind ("<- APDU" or
# "-> response") since MARK, largest first.
sizes() { log_since "$1" "$2" | sed -n "s/.*vpcd: $3, \([0-9]*\) bytes.*/\1/p" | sort -n -r | uniq | head -n 5 | paste -sd ' '; }
largest() { sizes "$1" "$2" "$3" | cut -d' ' -f1; }

# The reader slot vpcd's first port feeds is "<name> 00 00"; the card is in it or not.
readers() { timeout 10 opensc-tool -l 2>/dev/null; }
card_in() { readers | grep -q -E '^[0-9]+ +Yes .* 00 00$'; }
card_out() { readers | grep -q -E '^[0-9]+ +No .* 00 00$'; }
reader_named() { readers | grep -q -F "$1 00 00"; }
status_of() { lk_ctl "$1" status 2>/dev/null | sed -n "s/^$2=//p"; }
attached() { same "$(status_of "$1" attached)" true; }
interfaces_are() { same "$(status_of "$1" interfaces)" "$2"; }
# exited PID: the process is gone or a zombie (exited, not yet reaped).
exited() { [ ! -e "/proc/$1" ] || grep -q '^State:[[:space:]]*Z' "/proc/$1/status" 2>/dev/null; }
waiting() { same "$(status_of "$1" presence)" waiting; }
two_hidraw() { [ "$(hidraw_count)" -ge 2 ]; }
no_hidraw() { [ "$(hidraw_count)" = 0 ]; }
fido_is() { local n; n=$(hidraw_of fido) && same "$(hid_id "$n")" "$1"; }

start_pcscd() {
    local extra=
    pcscd --help 2>&1 | grep -q -- '--disable-polkit' && extra=--disable-polkit
    rm -f /run/pcscd/pcscd.pid /run/pcscd/pcscd.comm
    pcscd --foreground --debug $extra >> "$W/pcscd.log" 2>&1 &
    PCSCD_PID=$!
    note "pcscd started (pid $PCSCD_PID${extra:+, $extra})"
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
pcscd_mark() { wc -l < "$W/pcscd.log"; }
pcscd_since() { tail -n +"$(($1 + 1))" "$W/pcscd.log"; }
# ctl_tap_on_wait NAME OUT: in the background, `localkeyd ctl tap` once daemon NAME's
# status says presence=waiting (polled with `localkeyd ctl status`); the tap's reply goes
# to OUT. Sets TAPPER.
ctl_tap_on_wait() {
    local name=$1 out=$2
    (
        if wait_for 60 waiting "$name"; then
            echo "presence=waiting seen; localkeyd ctl tap:"
            lk_ctl "$name" tap
        else
            echo "presence=waiting never seen"
        fi
    ) > "$out" 2>&1 &
    TAPPER=$!
}
totp() {
    python3 - <<'PY'
import base64, hashlib, hmac, struct, time
key = base64.b32decode("JBSWY3DPEHPK3PXP")
step = int(time.time()) // 30
out = []
for t in sorted({max(step - 1, 0), step}):  # the guest's clock starts at 1970-01-01
    h = hmac.new(key, struct.pack(">Q", t), hashlib.sha1).digest()
    o = h[-1] & 15
    out.append("%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000))
print(" ".join(out))
PY
}
code_is_totp() { [ -n "$1" ] && echo " $(totp) " | grep -q " $1 "; }
# shutdown_by_ctl NAME: `localkeyd ctl shutdown`, its output and exit code checked, then the
# daemon reaped and its exit code checked.
shutdown_by_ctl() {
    local name=$1 out rc t0
    t0=$(date +%s%N)
    out=$(lk_ctl "$name" shutdown 2>&1)
    rc=$?
    note "localkeyd ctl shutdown: exit $rc after $(( ($(date +%s%N) - t0) / 1000000 )) ms, output: $(echo "$out" | paste -sd '|')"
    check "ctl shutdown printed ok, then stopped" same "$(echo "$out" | paste -sd '|')" "ok|stopped"
    check "ctl shutdown exited 0" same "$rc" 0
    local pid_var="LK_PID_$name"
    check "the daemon has exited when ctl returns" exited "${!pid_var}"
    lk_stop "$name" 5
    rc=$?
    check "the daemon exited 0" same "$rc" 0
    check "the control socket was removed" sh -c "[ ! -e '$LK_RUN/$name/state/control.sock' ]"
    check "the log ends with stopped" sh -c "tail -n 3 '$(log_of "$name")' | grep -q 'stopped'"
}

section versions
note "kernel $(uname -r); $(pcscd --version 2>&1 | head -n 1); vsmartcard-vpcd $(dpkg-query -W -f '${Version}' vsmartcard-vpcd 2>&1)"
note "$(opensc-tool --info 2>&1 | head -n 1); ykman $(ykman --version 2>&1 | head -n 1); $(gpg --version | head -n 1); $(fido2-token -V 2>&1 | head -n 1) (libfido2); pyscard $(python3 -c 'import importlib.metadata as m; print(m.version("pyscard"))' 2>&1)"
note "loopback: $(busybox ifconfig lo 2>&1 | grep -o -E 'inet addr:[0-9.]+|UP' | paste -sd ' ')"
note "$CONF:"
sed 's/^/    /' "$CONF"
note "the driver: $(ls -l "$(sed -n 's/^LIBPATH[[:space:]]*//p' "$CONF")" 2>&1)"

# =======================================================================================
# (a) --transport vpcd
# =======================================================================================
step_begin 1 "insertion: localkeyd --transport vpcd, then pcscd with vpcd"
lk_start va --transport vpcd --profile "$YK" -vv
check "the daemon serves (status answers)" wait_for 20 lk_ctl va status
sleep 2.5
check "with nothing listening it retries, and says so once" \
    same "$(grep -c 'vpcd: cannot connect to 127.0.0.1:35963' "$(log_of va)")" 1
check "status attached=false while vpcd does not listen" same "$(status_of va attached)" false
mark=$(log_mark va)
start_pcscd
check "pcscd shows the vpcd reader" wait_for 30 reader_named "Virtual PCD"
check "the card is in the reader" wait_for 20 card_in
run opensc-tool -l
note "vpcd's listeners (/proc/net/tcp; 8C7B = 35963, 8C7C = 35964; 0A = LISTEN, 01 = ESTABLISHED):"
awk 'NR == 1 || $2 ~ /:8C7[BC]$/ || $3 ~ /:8C7[BC]$/ { print "    " $2, $3, $4 }' /proc/net/tcp
check "vpcd listens on 0.0.0.0:35963" grep -q -E '^ *[0-9]+: 00000000:8C7B 00000000:0000 0A' /proc/net/tcp
check "and the card's connection to it is established" grep -q -E '^ *[0-9]+: 0100007F:[0-9A-F]{4} 0100007F:8C7B 01' /proc/net/tcp
run pcsc_scan -r
timeout 15 pcsc_scan -c > "$W/pcsc-scan" 2>&1
note "pcsc_scan -c:"
sed 's/^/    /' "$W/pcsc-scan" | head -n 30
check "pcsc_scan names the reader" grep -q 'Virtual PCD 00 00' "$W/pcsc-scan"
run opensc-tool -r 0 -a | tee "$W/atr"
got_atr=$(grep -i -o -E '([0-9a-f]{2}:){10,}[0-9a-f]{2}' "$W/atr" | head -n 1 | tr ':' ' ' | tr A-F a-f)
check "the ATR is the profile's ($ATR)" same "$got_atr" "$ATR"
check "status attached=true" attached va
run lk_ctl va status
events va "$mark" | sed 's/^/    log: /'
note "vpcd messages after the connection, in order: $(log_since va "$mark" | sed -n 's/.*vpcd: <- \([a-zA-Z ]*\),.*/\1/p' | head -n 6 | paste -sd '|')"
step_end

# ---------------------------------------------------------------------------------------
step_begin 2 "CCID clients through vpcd: ykman, OATH with touch, PIV, OpenPGP, GnuPG"
mark=$(log_mark va)
note "ykman counts only readers named 'Yubico YubiKey ...' as YubiKeys; with the packaged name:"
run ykman --reader "Virtual PCD 00 00" info
sed -i "s/^FRIENDLYNAME.*/FRIENDLYNAME \"$YUBICO_NAME\"/" "$CONF"
run cat "$CONF"
pm=$(pcscd_mark)
stop_pcscd
check "the card notices that vpcd went away" wait_for 10 log_has_since va "$mark" 'card removed'
start_pcscd
check "pcscd shows the renamed reader" wait_for 30 reader_named "$YUBICO_NAME"
check "the card is in it" wait_for 20 card_in
run opensc-tool -l
run ykman --reader "$R" info | tee "$W/ykman-info"
check "ykman info over vpcd: YubiKey 5C Nano 5.7.4" sh -c "grep -q 'YubiKey 5C Nano' '$W/ykman-info' && grep -q 'Firmware version: 5.7.4' '$W/ykman-info'"
serial=$(sed -n 's/^Serial number: //p' "$W/ykman-info")
check "ykman's serial ($serial) is the daemon's" same "$serial" "$(status_of va serial)"
run ykman --reader "$R" oath accounts add -t test JBSWY3DPEHPK3PXP
check "OATH account added" sh -c "timeout 60 ykman --reader '$R' oath accounts list | grep -q '^test'"
lk_tap va > "$W/tap-oath" &
tapper=$!
code=$(timeout 90 ykman --reader "$R" oath accounts code -s test)
rc=$?
wait "$tapper"
cat "$W/tap-oath"
note "oath code '$code' (exit $rc); TOTP of the last two steps: $(totp)"
check "the touch-required OATH code is the RFC 6238 TOTP" code_is_totp "$code"
run ykman --reader "$R" piv info
check "ykman piv info" sh -c "timeout 60 ykman --reader '$R' piv info >/dev/null"
run ykman --reader "$R" piv keys generate -m "$MGMT" -a ECCP256 9a "$W/pub9a.pem"
check "piv keys generate 9a" grep -q 'BEGIN PUBLIC KEY' "$W/pub9a.pem"
run ykman --reader "$R" piv certificates generate -m "$MGMT" -P "$PIV_PIN" -s "CN=localkey vpcd" 9a "$W/pub9a.pem"
check "piv certificates generate 9a (signed on the device)" [ $? = 0 ]
run ykman --reader "$R" piv certificates export 9a "$W/cert9a.pem"
check "piv certificates export 9a" grep -q 'BEGIN CERTIFICATE' "$W/cert9a.pem"
run python3 "$PY/certs.py" verify "$W/cert9a.pem"
check "the 9a certificate's signature verifies" sh -c "python3 '$PY/certs.py' verify '$W/cert9a.pem' | grep -q 'signature valid'"
run ykman --reader "$R" openpgp info
check "ykman openpgp info" sh -c "timeout 60 ykman --reader '$R' openpgp info >/dev/null"
export GNUPGHOME=$W/gnupg
mkdir -p -m 0700 "$GNUPGHOME"
{
    echo disable-ccid
    lib=$(ls /usr/lib/*/libpcsclite.so.1 2>/dev/null | head -n 1)
    [ -n "$lib" ] && echo "pcsc-driver $lib"
} > "$GNUPGHOME/scdaemon.conf"
note "scdaemon.conf: $(tr '\n' ' ' < "$GNUPGHOME/scdaemon.conf")"
run gpg --card-status | tee "$W/gpg-card"
check "gpg --card-status (scdaemon through pcscd)" grep -q -E 'Manufacturer .*Yubico' "$W/gpg-card"
check "gpg sees the daemon's serial" grep -q -E "Serial number .*: 0*$serial\$" "$W/gpg-card"
gpgconf --kill scdaemon
if log_has_since va "$mark" 'answered with 6F00'; then bad "an APDU was answered with 6F00"; else ok "no APDU answered with 6F00"; fi
events va "$mark" | sed 's/^/    log: /'
step_end

# ---------------------------------------------------------------------------------------
step_begin 3 "large transfers: a 2.9 KB PIV certificate, a 4007-byte extended APDU"
mark=$(log_mark va)
run python3 "$PY/certs.py" large "$W/big.pem" "$W/big.der" 2900 3052
check "a certificate of 2900 to 3052 bytes" [ -s "$W/big.der" ]
run ykman --reader "$R" piv certificates import -m "$MGMT" 9e "$W/big.pem"
check "piv certificates import 9e (PUT DATA)" [ $? = 0 ]
run ykman --reader "$R" piv certificates export -F DER 9e "$W/big.out.der"
check "piv certificates export 9e (GET DATA)" [ -s "$W/big.out.der" ]
check "the $(wc -c < "$W/big.der")-byte certificate came back byte for byte" cmp -s "$W/big.der" "$W/big.out.der"
note "largest APDUs vpcd sent the card: $(sizes va "$mark" '<- APDU') bytes; largest responses: $(sizes va "$mark" '-> response') bytes"
check "the import travelled as one APDU of more than 2900 bytes" sh -c "[ '$(largest va "$mark" '<- APDU')' -gt 2900 ]"
check "the export came back as one response of more than 2900 bytes" sh -c "[ '$(largest va "$mark" '-> response')' -gt 2900 ]"
pmark=$(log_mark va)
run python3 "$PY/pcsc_big_apdu.py" "$R" 4007 | tee "$W/bigapdu"
check "the 4007-byte APDU reached the card whole (6A82: no such application)" grep -q 'SW 6A82' "$W/bigapdu"
check "it travelled as one vpcd message of 4007 bytes" log_has_since va "$pmark" 'vpcd: <- APDU, 4007 bytes'
check "and the card works on (SELECT OATH 9000)" grep -q 'SELECT OATH afterwards: SW 9000' "$W/bigapdu"
if log_has_since va "$mark" 'answered with 6F00'; then bad "an APDU was answered with 6F00"; else ok "no APDU answered with 6F00"; fi
step_end

# ---------------------------------------------------------------------------------------
step_begin 4 "a touch-requiring PIV signature completed with localkeyd ctl tap"
mark=$(log_mark va)
run ykman --reader "$R" piv keys generate -m "$MGMT" -a ECCP256 --touch-policy ALWAYS 9d "$W/pub9d.pem"
check "piv keys generate 9d with touch policy ALWAYS" grep -q 'BEGIN PUBLIC KEY' "$W/pub9d.pem"
run ykman --reader "$R" piv keys info 9d
ctl_tap_on_wait va "$W/tap-piv"
t0=$(date +%s%N)
run ykman --reader "$R" piv certificates generate -m "$MGMT" -P "$PIV_PIN" -s "CN=localkey touch" 9d "$W/pub9d.pem"
rc=$?
took=$(( ($(date +%s%N) - t0) / 1000000 ))
wait "$TAPPER"
sed 's/^/    tapper: /' "$W/tap-piv"
check "ctl tap was sent while the device waited, and answered ok" sh -c "grep -q 'presence=waiting seen' '$W/tap-piv' && grep -q '^ok$' '$W/tap-piv'"
check "the signature completed after the tap (exit $rc, ${took} ms)" same "$rc" 0
run ykman --reader "$R" piv certificates export 9d "$W/cert9d.pem"
run python3 "$PY/certs.py" verify "$W/cert9d.pem"
check "the touch-gated signature verifies with the 9d public key" sh -c "python3 '$PY/certs.py' verify '$W/cert9d.pem' | grep -q 'signature valid'"
events va "$mark" | sed 's/^/    log: /'
check "the device waited for the touch, then stopped waiting" sh -c \
    "tail -n +$((mark + 1)) '$(log_of va)' | grep -A3 'presence: waiting' | grep -q 'presence: idle'"
step_end

# ---------------------------------------------------------------------------------------
step_begin 5 "localkeyd ctl shutdown (--transport vpcd)"
pm=$(pcscd_mark)
shutdown_by_ctl va
check "the card left the reader" wait_for 15 card_out
note "pcscd: $(pcscd_since "$pm" | grep -i -o -E 'card (removed|inserted)[a-z ]*.*' | paste -sd '|')"
check "pcscd saw the card removed" sh -c "tail -n +$((pm + 1)) '$W/pcscd.log' | grep -q -i 'card removed'"
tail -n 6 "$(log_of va)" | sed 's/^/    log: /'
step_end

# =======================================================================================
# (b) --transport uhid,vpcd
# =======================================================================================
step_begin 6 "the whole device: --transport uhid,vpcd"
lk_start vb --transport uhid,vpcd --profile "$YK" -vv
check "two hidraw nodes appeared" wait_for 30 two_hidraw
check "the card is in the reader" wait_for 30 card_in
udevadm settle --timeout=10
serial=$(status_of vb serial)
note "serial $serial (a new state directory)"
grep -m 1 'serving:' "$(log_of vb)" | sed 's/^/    log: /'
check "the serving line names both transports" sh -c "grep -m 1 'serving:' '$(log_of vb)' | grep -q uhid && grep -m 1 'serving:' '$(log_of vb)' | grep -q vpcd"
run lk_ctl vb status
check "status: interfaces=otp,fido,ccid attached=true" same "$(status_of vb interfaces) $(status_of vb attached)" "otp,fido,ccid true"
fido=$(hidraw_of fido)
otp=$(hidraw_of otp)
note "FIDO node $fido ($(hid_id "$fido")), OTP node $otp ($(hid_id "$otp"))"
check "the FIDO node is 1050:0407" fido_is 0003:00001050:00000407
run fido2-token -L | tee "$W/token-L"
check "fido2-token -L lists $fido" grep -q "^$fido: " "$W/token-L"
run fido2-token -I "$fido" > "$W/token-I"
sed 's/^/    /' "$W/token-I" | head -n 20
check "fido2-token -I answers (aaguid)" grep -q aaguid "$W/token-I"
printf '%s\n%s\n%s\n%s\n' "$(head -c 32 /dev/urandom | base64)" localkey.example alice \
    "$(head -c 32 /dev/urandom | base64)" > "$W/cred-param"
lk_tap vb > "$W/tap-cred" &
tapper=$!
echo "\$ fido2-cred -M -i cred-param -o cred $fido es256   (touch by lk_tap)"
timeout 90 fido2-cred -M -i "$W/cred-param" -o "$W/cred" "$fido" es256 < /dev/null
rc=$?
wait "$tapper"
cat "$W/tap-cred"
check "fido2-cred -M made a credential (exit $rc)" same "$rc" 0
run fido2-cred -V -i "$W/cred" -o "$W/cred-pubkey" es256
check "fido2-cred -V verified the attestation" [ $? = 0 ]
run python3 "$PY/yk_connections.py" | tee "$W/connections"
for kind in SmartCardConnection OtpConnection FidoConnection; do
    check "ykman reaches serial $serial through $kind" grep -q -E "^$kind count=1 .*serial=$serial " "$W/connections"
done
echo "\$ ykman list"
timeout 90 ykman list > "$W/ykman-list" 2> "$W/ykman-list.err"
echo "[exit $?]"
sed 's/^/    stdout: /' "$W/ykman-list"
sed 's/^/    stderr: /' "$W/ykman-list.err"
check "ykman list: one YubiKey 5C Nano with OTP+FIDO+CCID" sh -c \
    "[ \$(grep -c . '$W/ykman-list') = 1 ] && grep -q -E 'YubiKey 5C Nano .*\\[OTP\\+FIDO\\+CCID\\].*Serial: $serial' '$W/ykman-list'"
note "ykman's 'Failed opening device' warning is the empty second vpcd slot ('$YUBICO_NAME 00 01', no card)"
run ykman info | tee "$W/ykman-info-b"
check "ykman info: enabled USB interfaces OTP, FIDO, CCID" grep -q 'Enabled USB interfaces: OTP, FIDO, CCID' "$W/ykman-info-b"
run ykman oath accounts add whole JBSWY3DPEHPK3PXP
check "an OATH account added (over CCID)" sh -c "timeout 60 ykman --reader '$R' oath accounts list | grep -q '^whole'"
step_end

# ---------------------------------------------------------------------------------------
# ykman 5.8 has no CCID switch in `config usb` (it takes applications: OTP, U2F, FIDO2, OATH,
# PIV, OPENPGP, HSMAUTH); the CCID interface goes when every CCID application is disabled
# over USB, which is how a YubiKey 5 derives its interfaces.
CCID_APPS_OFF="-d OATH -d PIV -d OPENPGP -d HSMAUTH"
CCID_APPS_ON="-e OATH -e PIV -e OPENPGP -e HSMAUTH"
step_begin 7 "CCID off and on: ykman config usb (Management write with REBOOT)"
mark=$(log_mark vb)
pm=$(pcscd_mark)
run ykman config usb $CCID_APPS_OFF -f | tee "$W/cfg-off"
check "disabling every CCID application accepted (over CCID: vpcd)" grep -q 'configuration updated' "$W/cfg-off"
check "the card left the reader" wait_for 20 card_out
check "the HID devices are 1050:0403 (OTP+FIDO)" wait_for 20 fido_is 0003:00001050:00000403
check "status: interfaces=otp,fido" wait_for 10 interfaces_are vb otp,fido
check "the daemon logged vpcd without CCID" log_has_since vb "$mark" 'vpcd: enumerated without CCID; no card'
check "and the card removed because CCID is disabled" log_has_since vb "$mark" 'vpcd: disconnected (CCID is disabled); card removed'
sleep 3
check "the card stays out" card_out
check "no connection to 35963 while CCID is disabled" sh -c "! grep -q -E '^ *[0-9]+: 0100007F:[0-9A-F]{4} 0100007F:8C7B 01' /proc/net/tcp"
udevadm settle --timeout=10
wait_for 20 two_hidraw
# ykman counts devices by PID without opening them (scan_devices, ykman/device.py): the
# reader's static name says OTP+FIDO+CCID (0407), the HID devices now say 0403, and the
# empty vpcd slots still exist, so without --device ykman reports several YubiKeys.
timeout 90 ykman info > "$W/ykman-plain-off" 2>&1
note "plain 'ykman info' with CCID off: $(grep -v WARNING "$W/ykman-plain-off" | head -n 1)"
run ykman --device "$serial" info | tee "$W/ykman-info-off"
check "ykman --device info (over HID): enabled USB interfaces OTP, FIDO" grep -q 'Enabled USB interfaces: OTP, FIDO$' "$W/ykman-info-off"
run ykman --device "$serial" config usb $CCID_APPS_ON -f | tee "$W/cfg-on"
check "enabling them again accepted (over HID)" grep -q 'configuration updated' "$W/cfg-on"
check "the card is back in the reader" wait_for 20 card_in
check "the HID devices are 1050:0407 again" wait_for 20 fido_is 0003:00001050:00000407
events vb "$mark" | grep -v -E 'device (opened|closed) by' | sed 's/^/    log: /'
note "pcscd: $(pcscd_since "$pm" | grep -i -o -E 'card (removed|inserted).*' | paste -sd '|')"
check "pcscd saw the card removed and inserted" sh -c \
    "tail -n +$((pm + 1)) '$W/pcscd.log' | grep -q -i 'card removed' && tail -n +$((pm + 1)) '$W/pcscd.log' | grep -q -i 'card inserted'"
udevadm settle --timeout=10
run ykman --reader "$R" oath accounts list
check "the OATH account answers over CCID again" sh -c "timeout 60 ykman --reader '$R' oath accounts list | grep -q '^whole'"
step_end

# ---------------------------------------------------------------------------------------
# `ykman config mode` on a YubiKey 5 writes the configuration without REBOOT (yubikit
# ManagementSession.set_mode: "reboot=False, since we're using the older set_mode
# command"; ykman then says "remove and re-insert your YubiKey"). The key keeps its
# interfaces until it is re-plugged; `localkeyd ctl power-cycle` is that re-plug, and the
# device re-enumerates when the interfaces changed.
step_begin 8 "CCID off and on: ykman config mode, then localkeyd ctl power-cycle"
mark=$(log_mark vb)
run ykman --reader "$R" config mode OTP+FIDO -f > "$W/mode-off" 2>&1
rc=$?
cat "$W/mode-off"
check "config mode OTP+FIDO accepted (over CCID, exit $rc)" same "$rc" 0
sleep 2
check "no re-enumeration yet: the card stays in, interfaces=otp,fido,ccid" sh -c \
    "'$LK_BIN' ctl --control '$LK_RUN/vb/state/control.sock' status | grep -q '^interfaces=otp,fido,ccid\$'"
check "the card is still in the reader" card_in
run lk_ctl vb power-cycle
check "after ctl power-cycle the card left the reader" wait_for 20 card_out
check "and the HID devices are 1050:0403" wait_for 20 fido_is 0003:00001050:00000403
udevadm settle --timeout=10
wait_for 20 two_hidraw
run ykman --device "$serial" config mode OTP+FIDO+CCID -f > "$W/mode-on" 2>&1
rc=$?
cat "$W/mode-on"
check "config mode OTP+FIDO+CCID accepted (over HID, exit $rc)" same "$rc" 0
sleep 2
check "no re-enumeration yet: interfaces=otp,fido" interfaces_are vb otp,fido
run lk_ctl vb power-cycle
check "after ctl power-cycle the card is back" wait_for 20 card_in
check "and the HID devices are 1050:0407" wait_for 20 fido_is 0003:00001050:00000407
events vb "$mark" | grep -v -E 'device (opened|closed) by' | sed 's/^/    log: /'
udevadm settle --timeout=10
run ykman --reader "$R" oath accounts list
check "the OATH account answers over CCID" sh -c "timeout 60 ykman --reader '$R' oath accounts list | grep -q '^whole'"
step_end

# ---------------------------------------------------------------------------------------
step_begin 9 "kill -9 and restart (uhid,vpcd)"
lk_kill vb
check "the hidraw nodes went away after SIGKILL" wait_for 15 no_hidraw
check "the card left the reader" wait_for 15 card_out
mark=$(log_mark vb)
lk_resume vb --transport uhid,vpcd --profile "$YK" -vv
check "the hidraw nodes came back" wait_for 30 two_hidraw
check "the card is back" wait_for 30 card_in
udevadm settle --timeout=10
events vb "$mark" | head -n 20 | sed 's/^/    log: /'
run ykman --reader "$R" oath accounts list
check "the OATH account is kept" sh -c "timeout 60 ykman --reader '$R' oath accounts list | grep -q '^whole'"
run ykman --reader "$R" info | tee "$W/ykman-info-2"
check "CCID is still enabled (all three interfaces)" grep -q 'Enabled USB interfaces: OTP, FIDO, CCID' "$W/ykman-info-2"
fido=$(hidraw_of fido)
printf '%s\n%s\n%s\n' "$(head -c 32 /dev/urandom | base64)" localkey.example "$(sed -n 5p "$W/cred")" > "$W/assert-param"
lk_tap vb > "$W/tap-assert" &
tapper=$!
timeout 90 fido2-assert -G -p -i "$W/assert-param" -o "$W/assert" "$fido" < /dev/null
rc=$?
wait "$tapper"
check "an assertion with the step-6 credential (exit $rc)" same "$rc" 0
run fido2-assert -V -p -i "$W/assert" "$W/cred-pubkey" es256
check "verifies with the step-6 public key" [ $? = 0 ]
step_end

# =======================================================================================
# (c) ctl shutdown with uhid,vpcd
# =======================================================================================
step_begin 10 "localkeyd ctl shutdown (--transport uhid,vpcd)"
pm=$(pcscd_mark)
shutdown_by_ctl vb
check "the hidraw nodes were removed" wait_for 10 no_hidraw
check "no HID device left" sh -c '[ -z "$(ls /sys/bus/hid/devices)" ]'
check "the card left the reader" wait_for 15 card_out
check "pcscd saw the card removed" sh -c "tail -n +$((pm + 1)) '$W/pcscd.log' | grep -q -i 'card removed'"
tail -n 8 "$(log_of vb)" | sed 's/^/    log: /'
step_end

# ---------------------------------------------------------------------------------------
step_begin E "extra: tools/service checked with systemd-analyze verify"
S=/localkey/extra/service
if [ ! -d "$S" ]; then
    note "skipped: tools/service not passed (guest-run.sh -f tools/service)"
elif ! command -v systemd-analyze >/dev/null; then
    note "skipped: no systemd-analyze in the guest"
else
    # The unit names /usr/local/bin/localkeyd; verify checks that ExecStart exists.
    mkdir -p /usr/local/bin
    ln -sf "$LK_BIN" /usr/local/bin/localkeyd
    note "$(systemd-analyze --version | head -n 1)"
    run systemd-analyze verify "$S/localkeyd-uhid-vpcd.service"
    check "systemd-analyze verify localkeyd-uhid-vpcd.service" [ $? = 0 ]
    run udevadm verify "$S/70-localkey.rules"
    check "udevadm verify 70-localkey.rules" [ $? = 0 ]
fi
step_end

stop_pcscd
section "pcscd log (card and vpcd lines)"
grep -i -E 'card (removed|inserted)|vpcd.*(error|fail)|Virtual|Yubico YubiKey' "$W/pcscd.log" | grep -v -i -E 'SCardGetStatusChange|IFDHControl not supported|unknown tag' | tail -n 30 | sed 's/^/    /'
section summary
printf '%s\n' "${results[@]}"
for r in "${results[@]}"; do case "$r" in *FAIL) exit 1 ;; esac; done
exit 0
