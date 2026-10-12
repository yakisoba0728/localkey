#!/usr/bin/env bash
# Install a reviewed bundle; --destdir stages files without changing the host or keys.
set -euo pipefail
bundle=$(cd "$(dirname "$0")" && pwd -P)
action=${1:-}
shift || true
dest=
development=no
while [ $# -gt 0 ]; do
    case "$1" in
        --destdir) [ $# -ge 2 ] || exit 2; dest=$2; shift 2 ;;
        --development) development=yes; shift ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done
case "$action" in install|uninstall) ;; *) echo "usage: install.sh install|uninstall [--development] [--destdir ABSOLUTE_PATH]" >&2; exit 2 ;; esac
case "$dest" in '') ;; /*) [ "$dest" != / ] || exit 2 ;; *) echo "--destdir must be absolute and not /" >&2; exit 2 ;; esac

paths=(usr/local/bin/localkeyd usr/local/bin/localkey-touch usr/local/libexec/localkey-control
       etc/systemd/system/localkeyd.service etc/udev/rules.d/70-localkey.rules
       usr/share/polkit-1/actions/org.localkey.control.policy usr/share/applications/localkey-touch.desktop)
if [ -n "$dest" ]; then
    mkdir -p "$dest"
    dest=$(cd "$dest" && pwd -P)
    [ "$dest" != / ] || exit 2
    for relative in "${paths[@]}" usr/local/share/doc/localkey/licenses; do
        path="$dest/$relative"
        while [ "$path" != "$dest" ]; do
            [ ! -L "$path" ] || { echo "refusing staging symlink: $path" >&2; exit 2; }
            path=$(dirname "$path")
        done
    done
fi
if [ -z "$dest" ]; then
    if [ "$(uname -s)" != Linux ] || [ "$(id -u)" != 0 ]; then
        echo "run on Linux with sudo" >&2; exit 2
    fi
    [ -d /run/systemd/system ] || { echo "systemd must be running" >&2; exit 2; }
    command -v systemctl >/dev/null
    command -v udevadm >/dev/null
fi
if [ "$action" = uninstall ]; then
    if [ -z "$dest" ] && [ "$(systemctl show --property=LoadState --value localkeyd.service)" != not-found ]; then
        systemctl disable --now localkeyd.service
    fi
    for path in "${paths[@]}"; do rm -f "$dest/$path"; done
    rm -rf "$dest/usr/local/share/doc/localkey"
    if [ -z "$dest" ]; then systemctl daemon-reload; udevadm control --reload; fi
    echo "Removed program files. Kept /etc/localkey and /var/lib/localkey (storage key and state)."
    exit 0
fi

if [ ! -f "$bundle/manifest.json" ] || [ ! -f "$bundle/SHA256SUMS" ]; then
    echo "install from a generated bundle" >&2; exit 2
fi
if [ -f "$bundle/DEVELOPMENT_ONLY" ] && [ "$development" != yes ]; then
    echo "This bundle uses test USB identifiers; internal testing requires --development." >&2
    exit 2
fi
(cd "$bundle" && sha256sum --check --quiet SHA256SUMS)
if [ -z "$dest" ]; then
    [ -x /usr/bin/pkexec ] || { echo "install polkit's pkexec package first" >&2; exit 2; }
    /usr/bin/python3 -I -c 'import tkinter' || { echo "install python3-tk first" >&2; exit 2; }
    if systemctl is-active --quiet localkeyd-uhid-vpcd.service; then
        echo "Stop the existing localkeyd-uhid-vpcd service before using this installer." >&2
        exit 2
    fi
    for path in /etc/localkey /var/lib/localkey; do
        [ ! -L "$path" ] || { echo "refusing symlink: $path" >&2; exit 2; }
        if [ -e "$path" ]; then
            if [ ! -d "$path" ] || [ "$(stat -c '%a:%u' "$path")" != 700:0 ]; then
                echo "existing $path must be a root-owned 0700 directory" >&2; exit 2
            fi
        fi
    done
    # Existing state must never acquire a new key when the old key is missing.
    if [ -d /var/lib/localkey ] && [ -n "$(ls -A /var/lib/localkey)" ] && [ ! -f /etc/localkey/storage.key ]; then
        echo "Existing state has no storage key. Restore the original key before installing." >&2
        exit 2
    fi
    if [ -e /etc/localkey/storage.key ] || [ -L /etc/localkey/storage.key ]; then
        if [ -L /etc/localkey/storage.key ] || [ ! -f /etc/localkey/storage.key ] ||
            [ "$(stat -c '%a:%u' /etc/localkey/storage.key)" != 600:0 ]; then
            echo "existing storage key must be a root-owned 0600 regular file" >&2; exit 2
        fi
    fi
    modprobe uhid
    if [ "$(systemctl show --property=LoadState --value localkeyd.service)" != not-found ]; then
        systemctl stop localkeyd.service
    fi
fi
sources=(bin/localkeyd linux/localkey-touch linux/localkey-control linux/localkeyd.service
         linux/70-localkey.rules linux/org.localkey.control.policy linux/localkey-touch.desktop)
for i in "${!paths[@]}"; do
    mode=0644
    [ "$i" -ge 3 ] || mode=0755
    target="$dest/${paths[$i]}"
    install -d -m 0755 "$(dirname "$target")"
    # Replace the executable by rename so an interrupted copy cannot truncate it.
    temporary=$(mktemp "${target}.XXXXXX")
    install -m "$mode" "${bundle}/${sources[$i]}" "$temporary"
    mv -f "$temporary" "$target"
done
docs="$dest/usr/local/share/doc/localkey"
install -d -m 0755 "$docs"
for path in LICENSE NOTICE THIRD_PARTY.md README.md manifest.json; do install -m 0644 "$bundle/$path" "$docs/"; done
cp -R "$bundle/licenses" "$docs/"
if [ -n "$dest" ]; then
    echo "Staged files in $dest. No service started; no storage key or state created."
    exit 0
fi
install -d -m 0700 /etc/localkey
if [ ! -e /etc/localkey/storage.key ]; then /usr/local/bin/localkeyd keygen --key-file /etc/localkey/storage.key; fi
systemctl daemon-reload
systemd-analyze verify /etc/systemd/system/localkeyd.service
udevadm control --reload
systemctl enable --now localkeyd.service
echo "Service started. Open localkey Touch as your desktop user."
echo "Back up /etc/localkey/storage.key and the stopped /var/lib/localkey together."
