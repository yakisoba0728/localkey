#!/bin/busybox sh
# Only private guest filesystems, X server, D-Bus and existing own USB fixture.
mount --bind /proc /opt/chromium-root/proc || exit 84
mount --bind /sys /opt/chromium-root/sys || exit 84
mount --bind /dev /opt/chromium-root/dev || exit 84
mount --bind /tmp /opt/chromium-root/tmp || exit 84
mount --bind /run /opt/chromium-root/run || exit 84
export DISPLAY=:99
export DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/ske-session-bus
mkdir -p /tmp/ske-runtime
/bin/busybox chmod 700 /tmp/ske-runtime
export XDG_RUNTIME_DIR=/tmp/ske-runtime
/usr/bin/Xvfb :99 -screen 0 1280x1024x24 -nolisten tcp > /tmp/ske-xvfb.log 2>&1 &
ske_xvfb_pid=$!
/usr/bin/dbus-uuidgen --ensure=/etc/machine-id
# --fork returns after the session socket is ready; prevents the measured race.
/usr/bin/dbus-daemon --session --fork --address=unix:path=/tmp/ske-session-bus > /tmp/ske-dbus.log 2>&1 || exit 85
/usr/libexec/at-spi-bus-launcher --launch-immediately --a11y=1 > /tmp/ske-atspi.log 2>&1 &
ske_atspi_pid=$!
/opt/ske-venv/bin/python /opt/verification/verify-browser-largeblob.py
ske_largeblob_rc=$?
cat /tmp/ske-xvfb.log
cat /tmp/ske-dbus.log
cat /tmp/ske-atspi.log
kill "$ske_atspi_pid" "$ske_xvfb_pid" 2>/dev/null
exit "$ske_largeblob_rc"
