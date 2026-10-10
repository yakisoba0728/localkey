#!/usr/bin/env bash
# Build a static aarch64 musl localkeyd for the guest, offline, and install it as
# $LK_GUEST_DIR/bin/localkeyd.
#
#   LK_VENDOR_DIR  directory made by `cargo vendor` for this workspace (required; the build
#                  container has no network)
#   --rebuild-image  rebuild localkey-rust-musl:1 even if it exists
#
# The repository is mounted read-only; the target directory is $LK_GUEST_DIR/target.
set -euo pipefail
. "$(dirname "$0")/env.sh"

: "${LK_VENDOR_DIR:?set LK_VENDOR_DIR to a cargo vendor directory for this workspace}"
LK_VENDOR_DIR=$(cd "$LK_VENDOR_DIR" && pwd -P)

if [ "${1:-}" = --rebuild-image ] || ! docker image inspect "$MUSL_IMAGE" >/dev/null 2>&1; then
    docker build -f "$here/Dockerfile.musl" --build-arg RUST_BASE="$RUST_BASE_IMAGE" -t "$MUSL_IMAGE" "$here"
fi

mkdir -p "$LK_GUEST_DIR/target"
docker run --rm --network none "${DOCKER_CAPS[@]}" --name localkey-musl-build \
    -v "$repo":/src:ro -v "$LK_VENDOR_DIR":/vendor:ro -v "$LK_GUEST_DIR/target":/target \
    -e CARGO_TARGET_DIR=/target -e CARGO_BUILD_JOBS=2 -w /src "$MUSL_IMAGE" \
    nice -n 10 cargo build --release --offline --locked --target "$MUSL_TARGET" -p localkeyd \
        --config 'source.crates-io.replace-with="vendored-sources"' \
        --config 'source.vendored-sources.directory="/vendor"'

cp "$LK_GUEST_DIR/target/$MUSL_TARGET/release/localkeyd" "$LK_GUEST_DIR/bin/localkeyd"
file "$LK_GUEST_DIR/bin/localkeyd" 2>/dev/null || true
ls -l "$LK_GUEST_DIR/bin/localkeyd"
