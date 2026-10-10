# Shared settings for the tools/linux-guest scripts. Sourced, not run.
# shellcheck shell=bash

die() { echo "linux-guest: $*" >&2; exit 2; }

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo=$(cd "$here/../.." && pwd -P)

GUEST_IMAGE=localkey-guest-build:1
MUSL_IMAGE=localkey-rust-musl:1
RUST_BASE_IMAGE=${LK_RUST_BASE_IMAGE:-localkey-rust:1.98-clippy}
RUN_CONTAINER=localkey-guest-run
MUSL_TARGET=aarch64-unknown-linux-musl

# Resource caps (the safety boundary in README.md): at most 2 CPUs and 6 GiB per container.
DOCKER_CAPS=(--cpus 2 --memory 6g)

: "${LK_GUEST_DIR:?set LK_GUEST_DIR to a directory outside the repository (kernel, initramfs, binaries, logs)}"
mkdir -p "$LK_GUEST_DIR"
LK_GUEST_DIR=$(cd "$LK_GUEST_DIR" && pwd -P)
case "$LK_GUEST_DIR/" in
    "$repo/"*) die "LK_GUEST_DIR ($LK_GUEST_DIR) is inside the repository; large artifacts must live outside it" ;;
esac
mkdir -p "$LK_GUEST_DIR/logs" "$LK_GUEST_DIR/bin"
