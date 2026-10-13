#!/usr/bin/env bash
# Creates a private disk with only fixture accounts/keys; it never mounts host devices.
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd -P)
# shellcheck source=tools/linux-desktop/env.sh
. "$(dirname "$0")/env.sh"
fixture_mounts=(-v "$repo/tools/linux-desktop":/tests:ro)
if [ "$LK_DESKTOP_DISTRO" = debian ]; then
    : "${LK_GECKODRIVER_TAR:?set LK_GECKODRIVER_TAR to the verified matching Linux geckodriver archive}"
    [ -f "$LK_GECKODRIVER_TAR" ]
    fixture_mounts+=(-v "$LK_GECKODRIVER_TAR":/geckodriver.tar.gz:ro)
fi
desktop_dir=$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve())' "$LK_DESKTOP_DIR")
case "$desktop_dir" in "$repo"|"$repo/"*|/) echo "use an output directory outside the repository, not /" >&2; exit 2 ;; esac
[ ! -e "$desktop_dir/root.img" ] || { echo "root.img already exists; keep its verification state" >&2; exit 2; }
bundle=${LK_DESKTOP_BUNDLE:-$repo/work/releases/localkey-0.1.0-dev-$LK_DESKTOP_ARCH-unknown-linux-musl.tar.gz}
[ -f "$bundle" ] || { echo "generate the matching test bundle first" >&2; exit 2; }
mkdir -p "$desktop_dir"
chmod 0700 "$desktop_dir"
docker run --rm --network none --cpus 2 --memory 6g \
    "${fixture_mounts[@]}" \
    -v "$bundle":/bundle.tar.gz:ro \
    -e LK_DESKTOP_DISTRO="$LK_DESKTOP_DISTRO" \
    -v "$desktop_dir":/out "$desktop_image" bash -euc '
        cp /tests/*.py /tests/rp.html /rootfs/localkey/
        if [ "$LK_DESKTOP_DISTRO" = ubuntu ]; then
            cp /tests/ubuntu-session.sh /rootfs/localkey/session.sh
            cp /tests/ubuntu-setup.sh /rootfs/localkey/setup.sh
            disk_size=16G
        else cp /tests/session.sh /rootfs/localkey/session.sh; disk_size=4G; fi
        cp /bundle.tar.gz /rootfs/localkey/bundle.tar.gz
        if [ -f /geckodriver.tar.gz ]; then tar -xzf /geckodriver.tar.gz -C /rootfs/usr/local/bin; fi
        rm -f /rootfs/.dockerenv /rootfs/etc/resolv.conf
        printf "127.0.0.1 localhost\n127.0.1.1 localkey-desktop\n::1 localhost\n" > /rootfs/etc/hosts
        printf "localkey-desktop\n" > /rootfs/etc/hostname
        chown -R 1000:1000 /rootfs/localkey/results
        truncate -s "$disk_size" /out/root.img
        mkfs.ext4 -q -F -d /rootfs /out/root.img
        cp /kernel/Image /out/Image
        if [ -f /kernel/initrd ]; then cp /kernel/initrd /out/initrd; fi
    '
