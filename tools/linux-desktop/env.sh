#!/usr/bin/env bash
# shellcheck disable=SC2034 # Values are used by the scripts sourcing this file.
: "${LK_DESKTOP_DIR:?set LK_DESKTOP_DIR outside the source tree}"
LK_DESKTOP_ARCH=${LK_DESKTOP_ARCH:-aarch64}
case "$LK_DESKTOP_ARCH" in
    aarch64) desktop_image=localkey-desktop-build:1 ;;
    x86_64) desktop_image=localkey-desktop-x86-build:1 ;;
    *) echo "unsupported LK_DESKTOP_ARCH" >&2; exit 2 ;;
esac
