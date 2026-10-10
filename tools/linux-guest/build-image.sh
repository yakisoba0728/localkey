#!/usr/bin/env bash
# Build localkey-guest-build:1 (QEMU + Ubuntu arm64 kernel + guest root filesystem) and copy
# its artifacts (Image, base.cpio.gz, config, kernel-release, modules.list, rootfs-size)
# to $LK_GUEST_DIR. The build is the only step that uses the network (apt downloads).
set -euo pipefail
. "$(dirname "$0")/env.sh"

docker build -f "$here/Dockerfile" -t "$GUEST_IMAGE" "$@" "$here"

# Copy the artifacts out without network.
docker run --rm --network none "${DOCKER_CAPS[@]}" --name localkey-guest-export \
    -v "$LK_GUEST_DIR":/guest "$GUEST_IMAGE" \
    sh -c 'cp /opt/localkey-guest/* /guest/ && chmod 0644 /guest/Image'
ls -l "$LK_GUEST_DIR"
