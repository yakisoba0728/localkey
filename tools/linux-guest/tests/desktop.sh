# Private-test bundle: staged installer, installed helper and own-profile FIDO flow.
# Run with guest-run.sh -f /path/to/localkey-...tar.gz desktop.sh. No real host devices.
set -euo pipefail
. /localkey/lib.sh
W=/run/localkey-desktop
mkdir -p "$W"
archive=$(find /localkey/extra -maxdepth 1 -name 'localkey-*.tar.gz')
[ -f "$archive" ]
tar -xzf "$archive" -C "$W"
bundle=$(find "$W" -mindepth 1 -maxdepth 1 -type d)
stage=$W/stage

section "bundle integrity and explicit private-test opt-in"
(cd "$bundle" && sha256sum --check --quiet SHA256SUMS)
if "$bundle/install.sh" install --destdir "$stage"; then exit 1; fi
[ ! -e "$stage/usr/local/bin/localkeyd" ]
"$bundle/install.sh" install --development --destdir "$stage"
[ -x "$stage/usr/local/bin/localkeyd" ]
[ -x "$stage/usr/local/libexec/localkey-control" ]
[ ! -e "$stage/etc/localkey/storage.key" ]
[ ! -e "$stage/var/lib/localkey" ]
test "$(stat -c %a "$stage/usr/local/bin/localkeyd")" = 755

section "staging symlink escape refused"
mkdir -p "$W/escape" "$W/symlink-stage"
ln -s "$W/escape" "$W/symlink-stage/usr"
if "$bundle/install.sh" install --development --destdir "$W/symlink-stage"; then exit 1; fi
[ ! -e "$W/escape/local/bin/localkeyd" ]

section "remove preserves key and state, then reinstall"
mkdir -p "$stage/etc/localkey" "$stage/var/lib/localkey"
echo key-marker > "$stage/etc/localkey/storage.key"
echo record-marker > "$stage/var/lib/localkey/record"
"$bundle/install.sh" uninstall --destdir "$stage"
[ "$(cat "$stage/etc/localkey/storage.key")" = key-marker ]
[ "$(cat "$stage/var/lib/localkey/record")" = record-marker ]
[ ! -e "$stage/usr/local/bin/localkeyd" ]
"$bundle/install.sh" install --development --destdir "$stage"

section "installed paths and service syntax (guest PID 1 is not systemd)"
install -d /usr/local/bin /usr/local/libexec /etc/systemd/system
install -m 0755 "$stage/usr/local/bin/localkeyd" /usr/local/bin/localkeyd
install -m 0755 "$stage/usr/local/libexec/localkey-control" /usr/local/libexec/localkey-control
install -m 0644 "$stage/etc/systemd/system/localkeyd.service" /etc/systemd/system/localkeyd.service
systemd-analyze verify /etc/systemd/system/localkeyd.service
install -m 0644 "$stage/etc/udev/rules.d/70-localkey.rules" /etc/udev/rules.d/70-localkey.rules
udevadm verify /etc/udev/rules.d/70-localkey.rules
udevadm control --reload
install -d -m 0700 /etc/localkey /var/lib/localkey
/usr/local/bin/localkeyd keygen --key-file /etc/localkey/storage.key

pid=
cleanup() {
    if [ -n "$pid" ]; then
        /usr/local/bin/localkeyd ctl --control /var/lib/localkey/control.sock shutdown >/dev/null 2>&1 || true
        wait "$pid" || true
    fi
}
trap cleanup EXIT
start_key() {
    /usr/local/bin/localkeyd run --state /var/lib/localkey --key-file /etc/localkey/storage.key \
        --transport uhid --profile own -v >> "$W/daemon.log" 2>&1 &
    pid=$!
    wait_for 30 /usr/local/libexec/localkey-control status
    wait_for 30 sh -c 'fido2-token -L | grep -q localkey'
    udevadm settle --timeout=10
}
stop_key() {
    /usr/local/bin/localkeyd ctl --control /var/lib/localkey/control.sock shutdown
    wait "$pid"
    pid=
}
tap_when_waiting() {
    wait_for 60 sh -c '/usr/local/libexec/localkey-control status | grep -q "^presence=waiting$"'
    /usr/local/libexec/localkey-control tap
}
section "own HID identity and limited helper"
start_key
/usr/local/libexec/localkey-control status | tee "$W/status"
grep -q '^product=localkey' "$W/status"
if /usr/local/libexec/localkey-control tap; then exit 1; fi
if /usr/local/libexec/localkey-control shutdown; then exit 1; fi
fido2-token -L | tee "$W/tokens"
grep -q 'localkey' "$W/tokens"
fido=$(sed -n 's/^\([^:]*\): .*localkey.*/\1/p' "$W/tokens" | head -n 1)
[ -n "$fido" ]

section "libfido2 register, explicit helper touch and verified assertion after restart"
printf '%s\n' 'gaorbCe1M0gFjZ1Rc/yoTfJeKoEs4A9pGsY+UYJzSkY=' 'localhost' 'test user' \
    'ZnVkZ2U=' > "$W/cred-param"
tap_when_waiting > "$W/tap-register" &
tapper=$!
fido2-cred -M -i "$W/cred-param" -o "$W/cred" "$fido" es256
wait "$tapper"
fido2-cred -V -i "$W/cred" -o "$W/cred-verified" es256
head -n 2 "$W/cred-param" > "$W/assert-param"
sed -n 5p "$W/cred" >> "$W/assert-param"
stop_key
start_key
fido=$(fido2-token -L | sed -n 's/^\([^:]*\): .*localkey.*/\1/p' | head -n 1)
tap_when_waiting > "$W/tap-login" &
tapper=$!
fido2-assert -G -p -i "$W/assert-param" -o "$W/assert" "$fido" es256
wait "$tapper"
fido2-assert -V -p -i "$W/assert" "$W/cred-verified" es256
stop_key
note "desktop bundle checks passed; actual systemd desktop/polkit/browser checks remain"
