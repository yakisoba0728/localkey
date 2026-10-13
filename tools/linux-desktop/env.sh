#!/usr/bin/env bash
# shellcheck disable=SC2034 # Values are used by the scripts sourcing this file.
: "${LK_DESKTOP_DIR:?set LK_DESKTOP_DIR outside the source tree}"
LK_DESKTOP_ARCH=${LK_DESKTOP_ARCH:-aarch64}
LK_DESKTOP_DISTRO=${LK_DESKTOP_DISTRO:-debian}
case "$LK_DESKTOP_DISTRO:$LK_DESKTOP_ARCH" in
    debian:aarch64) desktop_image=localkey-desktop-build:1 ;;
    debian:x86_64) desktop_image=localkey-desktop-x86-build:1 ;;
    ubuntu:aarch64) desktop_image=localkey-ubuntu-desktop-arm:1 ;;
    ubuntu:x86_64) desktop_image=localkey-ubuntu-desktop-x86:1 ;;
    *) echo "unsupported LK_DESKTOP_ARCH" >&2; exit 2 ;;
esac
