#!/usr/bin/env bash
# Boot the test guest once and run one test script in it.
#
#   guest-run.sh [-t SECONDS] [-k "KERNEL ARGS"] [-f PATH]... TEST
#
#   TEST       a script in tools/linux-guest/tests/ (by name), or a path to a script
#   -t         hard timeout for the whole run, boot included (default 900); the test itself
#              gets 60 s less
#   -k         extra kernel command-line words (e.g. "loglevel=7" or "lk.udev=0")
#   -f PATH    an extra file or directory, copied into the guest as /localkey/extra/<name>
#
# The guest runs in a container with no network (--network none) and QEMU has no NIC
# (-nic none). Output is shown and saved to $LK_GUEST_DIR/logs/<test>-<time>.log. Exit code:
# the test's (from the LK-TEST-END marker), 124 on timeout, 125 when no marker was seen.
set -euo pipefail
. "$(dirname "$0")/env.sh"

timeout=900
kargs=
extras=()
while getopts t:k:f: opt; do
    case "$opt" in
        t) timeout=$OPTARG ;;
        k) kargs=$OPTARG ;;
        f) extras+=("$OPTARG") ;;
        *) die "usage: guest-run.sh [-t SECONDS] [-k ARGS] [-f PATH]... TEST" ;;
    esac
done
shift $((OPTIND - 1))
[ $# -eq 1 ] || die "usage: guest-run.sh [-t SECONDS] [-k ARGS] [-f PATH]... TEST"
case "$timeout" in ''|*[!0-9]*) die "-t needs whole seconds" ;; esac
[ "$timeout" -ge 120 ] || die "-t must be at least 120"

test_arg=$1
if [ -f "$test_arg" ]; then test_file=$test_arg; else test_file=$here/tests/$test_arg; fi
[ -f "$test_file" ] || die "no test script $test_arg"
test_name=$(basename "$test_file")

for f in Image base.cpio.gz bin/localkeyd; do
    [ -f "$LK_GUEST_DIR/$f" ] || die "missing $LK_GUEST_DIR/$f (run build-image.sh and build-localkeyd.sh)"
done
docker image inspect "$GUEST_IMAGE" >/dev/null 2>&1 || die "missing image $GUEST_IMAGE (run build-image.sh)"
if [ -n "$(docker ps -aq -f "name=^${RUN_CONTAINER}\$")" ]; then
    die "container $RUN_CONTAINER exists: one guest at a time (docker rm -f $RUN_CONTAINER if it is stale)"
fi

# The overlay: /init, the helpers (lib.sh, py/*.py), every test, the chosen test, localkeyd and the extras.
stage=$LK_GUEST_DIR/stage
rm -rf "$stage"
mkdir -p "$stage/localkey/tests" "$stage/localkey/bin" "$stage/localkey/extra" "$stage/localkey/py"
cp "$here/guest/init" "$stage/init"
cp "$here/guest/lib.sh" "$stage/localkey/lib.sh"
cp "$here"/guest/py/*.py "$stage/localkey/py/"
cp "$here"/tests/* "$stage/localkey/tests/"
cp "$test_file" "$stage/localkey/tests/$test_name"
cp "$LK_GUEST_DIR/bin/localkeyd" "$stage/localkey/bin/localkeyd"
for e in ${extras[@]+"${extras[@]}"}; do cp -R "$e" "$stage/localkey/extra/"; done

log=$LK_GUEST_DIR/logs/${test_name%.*}-$(date +%Y%m%d-%H%M%S).log
cleanup() { docker rm -f "$RUN_CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT
trap 'exit 130' INT TERM

test_timeout=$((timeout - 60))
append="console=ttyAMA0 rdinit=/init panic=-1 loglevel=4 lk.test=$test_name lk.timeout=$test_timeout $kargs"
echo "linux-guest: $test_name, timeout ${timeout}s, log $log"
start=$(date +%s)
set +e
docker run --rm --network none "${DOCKER_CAPS[@]}" --name "$RUN_CONTAINER" \
    -v "$LK_GUEST_DIR/Image":/guest/Image:ro \
    -v "$LK_GUEST_DIR/base.cpio.gz":/guest/base.cpio.gz:ro \
    -v "$stage":/guest/stage:ro \
    -e "APPEND=$append" -e "TIMEOUT=$timeout" \
    "$GUEST_IMAGE" bash -euc -o pipefail '
        mkdir /tmp/ovl
        cp -a /guest/stage/. /tmp/ovl/
        mkdir -p /tmp/ovl/dev
        mknod -m 0600 /tmp/ovl/dev/console c 5 1
        chmod 0755 /tmp/ovl/init /tmp/ovl/localkey/bin/localkeyd
        (cd /tmp/ovl && find . -mindepth 1 | LC_ALL=C sort | cpio -o -H newc -R 0:0 --quiet | gzip -1) > /tmp/overlay.cpio.gz
        cat /guest/base.cpio.gz /tmp/overlay.cpio.gz > /tmp/rootfs.cpio.gz
        timeout -k 10 "$TIMEOUT" qemu-system-aarch64 \
            -M virt -cpu max,pauth-impdef=on -smp 2 -m 2048 \
            -nographic -nic none -no-reboot \
            -device virtio-rng-pci \
            -kernel /guest/Image -initrd /tmp/rootfs.cpio.gz \
            -append "$APPEND" 2>&1 | sed -u "s/\r\$//"
    ' 2>&1 | tee "$log"
status=${PIPESTATUS[0]}
set -e
end=$(date +%s)
echo "linux-guest: container exit $status after $((end - start)) s; log $log"

rc=$(sed -n 's/^===== LK-TEST-END .* rc=\([0-9]*\) =====$/\1/p' "$log" | tail -n 1)
if [ -n "$rc" ]; then exit "$rc"; fi
if [ "$status" = 124 ]; then echo "linux-guest: timed out" >&2; exit 124; fi
echo "linux-guest: no LK-TEST-END marker" >&2
exit 125
