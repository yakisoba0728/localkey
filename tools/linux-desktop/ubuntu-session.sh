#!/bin/bash
set -eu
exec >> /localkey/results/session.log 2>&1
# GNOME runs autostart units under the user manager without XDG_SESSION_ID.
XDG_SESSION_ID=$(loginctl show-user "$(id -u)" -p Display --value)
export XDG_SESSION_ID
[ -n "$XDG_SESSION_ID" ]
[ "$(loginctl show-session "$XDG_SESSION_ID" -p User --value)" = "$(id -u)" ]
loginctl session-status
gsettings set org.gnome.desktop.session idle-delay 0
gsettings set org.gnome.desktop.screensaver lock-enabled false
gsettings set org.gnome.shell favorite-apps "['localkey-touch.desktop', 'chromium_chromium.desktop', 'firefox_firefox.desktop']"
gsettings set org.gnome.shell.extensions.dash-to-dock click-action 'focus-or-previews'
gsettings set org.gnome.desktop.interface enable-animations false
gsettings set org.gnome.desktop.interface toolkit-accessibility true
sudo -S -p '' /localkey/setup.sh <<< localkey-test-only
exec python3 /localkey/ubuntu-flow.py
