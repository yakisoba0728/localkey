#!/bin/bash
# Root setup inside this private Ubuntu VM only; retain Snap/AppArmor confinement.
set -euo pipefail
mountpoint -q /localkey/screens || mount -t 9p -o trans=virtio,version=9p2000.L screens /localkey/screens
ip link set lo up
date -u -s '2026-10-13 08:00:00'
if [ ! -f /localkey/snaps-installed ]; then
    systemctl start snapd.socket
    snap wait system seed.loaded
    for assertion in /localkey/snaps/*.assert; do snap ack "$assertion"; done
    snap install /localkey/snaps/*.snap
    touch /localkey/snaps-installed
fi
snap list > /localkey/results/snaps.txt
snap connections firefox > /localkey/results/firefox-connections.txt
snap connections chromium > /localkey/results/chromium-connections.txt
aa-status > /localkey/results/apparmor.txt
chmod 0644 /localkey/results/*.txt
