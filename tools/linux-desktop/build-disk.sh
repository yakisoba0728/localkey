#!/usr/bin/env bash
# Creates a private disk with only fixture accounts/keys; it never mounts host devices.
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd -P)
# shellcheck source=tools/linux-desktop/env.sh
. "$(dirname "$0")/env.sh"
: "${LK_GECKODRIVER_TAR:?set LK_GECKODRIVER_TAR to the verified matching Linux geckodriver archive}"
[ -f "$LK_GECKODRIVER_TAR" ]
desktop_dir=$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve())' "$LK_DESKTOP_DIR")
case "$desktop_dir" in "$repo"|"$repo/"*|/) echo "use an output directory outside the repository, not /" >&2; exit 2 ;; esac
[ ! -e "$desktop_dir/root.img" ] || { echo "root.img already exists; keep its verification state" >&2; exit 2; }
bundle=${LK_DESKTOP_BUNDLE:-$repo/work/releases/localkey-0.1.0-dev-$LK_DESKTOP_ARCH-unknown-linux-musl.tar.gz}
[ -f "$bundle" ] || { echo "generate the matching test bundle first" >&2; exit 2; }
mkdir -p "$desktop_dir"
chmod 0700 "$desktop_dir"
docker run --rm --network none --cpus 2 --memory 6g \
    -v "$repo/tools/linux-desktop":/tests:ro \
    -v "$bundle":/bundle.tar.gz:ro \
    -v "$LK_GECKODRIVER_TAR":/geckodriver.tar.gz:ro \
    -v "$desktop_dir":/out "$desktop_image" bash -euc '
        cp /tests/*.py /tests/rp.html /tests/session.sh /rootfs/localkey/
        cp /bundle.tar.gz /rootfs/localkey/bundle.tar.gz
        tar -xzf /geckodriver.tar.gz -C /rootfs/usr/local/bin
        rm -f /rootfs/.dockerenv /rootfs/etc/resolv.conf
        printf "127.0.0.1 localhost\n127.0.1.1 localkey-desktop\n::1 localhost\n" > /rootfs/etc/hosts
        printf "localkey-desktop\n" > /rootfs/etc/hostname
        chown -R 1000:1000 /rootfs/localkey/results
        truncate -s 4G /out/root.img
        mkfs.ext4 -q -F -d /rootfs /out/root.img
        cp /kernel/Image /out/Image
        if [ -f /kernel/initrd ]; then cp /kernel/initrd /out/initrd; fi
    '
