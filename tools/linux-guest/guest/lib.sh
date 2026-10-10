# Helpers for guest test scripts: `. /localkey/lib.sh`. Bash only.
# shellcheck shell=bash

LK_BIN=/localkey/bin/localkeyd
LK_RUN=/run/lk

section() { echo; echo "----- $* -----"; }
note() { echo "# $*"; }

# hex FILE: the file's bytes as one line of lowercase hex pairs.
hex() { od -An -tx1 -v "$1" | tr -s ' \n' ' ' | sed 's/^ //; s/ $//'; }

# wait_for SECONDS COMMAND...: run COMMAND every 0.2 s until it succeeds; 1 on timeout.
wait_for() {
    local limit=$1 i=0
    shift
    while ! "$@" >/dev/null 2>&1; do
        i=$((i + 1))
        [ "$i" -ge $((limit * 5)) ] && return 1
        sleep 0.2
    done
}

# lk_keygen: one storage key for every daemon of the test, at $LK_RUN/key.
lk_keygen() {
    mkdir -p -m 0700 "$LK_RUN"
    [ -f "$LK_RUN/key" ] || "$LK_BIN" keygen --key-file "$LK_RUN/key"
}

# lk_start NAME RUN-ARGS...: start `localkeyd run --state $LK_RUN/NAME/state --key-file
# $LK_RUN/key --exit-on-stdin-eof RUN-ARGS...` in the background. Its stdin is a FIFO held
# open by this shell (lk_stop closes it: a clean shutdown); stderr goes to $LK_RUN/NAME/log.
# Sets LK_PID_<NAME> and LK_FD_<NAME>. The control socket is $LK_RUN/NAME/state/control.sock.
lk_start() {
    local name=$1
    shift
    lk_keygen
    local dir=$LK_RUN/$name
    rm -rf "$dir"
    mkdir -p -m 0700 "$dir"
    mkfifo -m 0600 "$dir/stdin"
    "$LK_BIN" run --state "$dir/state" --key-file "$LK_RUN/key" --exit-on-stdin-eof "$@" \
        < "$dir/stdin" 2> "$dir/log" &
    local pid=$!
    local fd
    exec {fd}> "$dir/stdin"
    printf -v "LK_PID_$name" %s "$pid"
    printf -v "LK_FD_$name" %s "$fd"
    note "started localkeyd ($name) pid $pid: run $*"
}

# lk_resume NAME RUN-ARGS...: start daemon NAME again on the state directory it had (after
# lk_stop or lk_kill): like lk_start, but the state survives; the new log is appended to the
# old one after a marker line.
lk_resume() {
    local name=$1
    shift
    local dir=$LK_RUN/$name
    [ -d "$dir/state" ] || { note "lk_resume: no state for $name"; return 1; }
    rm -f "$dir/stdin"
    mkfifo -m 0600 "$dir/stdin"
    echo "----- resumed -----" >> "$dir/log"
    "$LK_BIN" run --state "$dir/state" --key-file "$LK_RUN/key" --exit-on-stdin-eof "$@" \
        < "$dir/stdin" 2>> "$dir/log" &
    local pid=$!
    local fd
    exec {fd}> "$dir/stdin"
    printf -v "LK_PID_$name" %s "$pid"
    printf -v "LK_FD_$name" %s "$fd"
    note "resumed localkeyd ($name) pid $pid: run $*"
}

# lk_kill NAME: kill -9 daemon NAME (no clean shutdown) and reap it.
lk_kill() {
    local name=$1
    local pid_var="LK_PID_$name" fd_var="LK_FD_$name"
    local pid=${!pid_var} fd=${!fd_var}
    kill -9 "$pid"
    wait "$pid" 2>/dev/null
    exec {fd}>&-
    note "localkeyd ($name) pid $pid killed with SIGKILL"
}

# lk_ctl NAME ARGS...: `localkeyd ctl` against daemon NAME.
lk_ctl() {
    local name=$1
    shift
    "$LK_BIN" ctl --control "$LK_RUN/$name/state/control.sock" "$@"
}

# lk_alive NAME: the daemon is still running.
lk_alive() {
    local pid_var="LK_PID_$1"
    kill -0 "${!pid_var}" 2>/dev/null
}

# lk_stop NAME [SECONDS]: close the daemon's stdin, wait for it (default 20 s; then kill),
# print its exit code and its log (only its path with LK_LOG_QUIET=1). Returns the exit code.
lk_stop() {
    local name=$1 limit=${2:-20}
    local pid_var="LK_PID_$name" fd_var="LK_FD_$name"
    local pid=${!pid_var} fd=${!fd_var}
    exec {fd}>&-
    if ! wait_for "$limit" sh -c "! kill -0 $pid"; then
        note "localkeyd ($name) still running after ${limit}s; killing it"
        kill -9 "$pid"
    fi
    wait "$pid"
    local rc=$?
    note "localkeyd ($name) exit code $rc"
    if [ "${LK_LOG_QUIET:-0}" = 1 ]; then
        note "localkeyd ($name) log: $LK_RUN/$name/log ($(wc -l < "$LK_RUN/$name/log") lines, not shown)"
    else
        note "localkeyd ($name) log:"
        sed 's/^/    /' "$LK_RUN/$name/log"
    fi
    return "$rc"
}

# usb_dev VID PID: the sysfs name of the first USB device with that vendor and product.
usb_dev() {
    local d
    for d in /sys/bus/usb/devices/*; do
        [ -f "$d/idVendor" ] || continue
        if [ "$(cat "$d/idVendor")" = "$1" ] && [ "$(cat "$d/idProduct")" = "$2" ]; then
            basename "$d"
            return 0
        fi
    done
    return 1
}

usb_gone() { ! usb_dev "$@"; }

# hidraw_report: for every hidraw node, its uevent identity and report descriptor.
hidraw_report() {
    local h
    for h in /sys/class/hidraw/hidraw*; do
        [ -e "$h" ] || { note "no hidraw devices"; return 0; }
        echo "$(basename "$h"):"
        grep -E '^(HID_ID|HID_NAME|HID_PHYS|HID_UNIQ|DRIVER)=' "$h/device/uevent" | sed 's/^/    /'
        echo "    report_descriptor: $(hex "$h/device/report_descriptor")"
        echo "    node: $(ls -l "/dev/$(basename "$h")" 2>&1)"
    done
}

# hidraw_of KIND: the /dev node of the hidraw device whose report descriptor starts as the
# engine's FIDO (`fido`: usage page F1D0) or OTP (`otp`: generic desktop, keyboard) one.
hidraw_of() {
    local want h
    case "$1" in
        fido) want="06 d0 f1" ;;
        otp) want="05 01 09 06" ;;
        *) return 2 ;;
    esac
    for h in /sys/class/hidraw/hidraw*; do
        [ -e "$h/device/report_descriptor" ] || continue
        case "$(hex "$h/device/report_descriptor")" in
            "$want"*) echo "/dev/$(basename "$h")"; return 0 ;;
        esac
    done
    return 1
}

# hid_id NODE: the HID_ID of a hidraw node (/dev/hidrawN), e.g. 0003:00001209:00000001.
hid_id() { sed -n 's/^HID_ID=//p' "/sys/class/hidraw/$(basename "$1")/device/uevent"; }

# hidraw_count: how many hidraw nodes exist.
hidraw_count() { local n=0 h; for h in /sys/class/hidraw/hidraw*; do [ -e "$h" ] && n=$((n + 1)); done; echo "$n"; }

# lk_tap NAME [ARGS...]: the helper /localkey/py/lk_tap.py against daemon NAME's control
# socket (taps whenever the presence indicator turns to waiting; see the script).
lk_tap() {
    local name=$1
    shift
    python3 /localkey/py/lk_tap.py "$LK_RUN/$name/state/control.sock" "$@"
}
