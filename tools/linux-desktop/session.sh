#!/bin/bash
# Runs inside LightDM's real user session, not a root/synthetic WebAuthn client.
set -u
exec > /localkey/results/session.log 2>&1
echo "localkey desktop session started"
env | sort
loginctl session-status
lxpolkit &
exec python3 /localkey/desktop_flow.py
