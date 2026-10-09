#!/bin/sh
set -eu
cd /Users/yakisoba0728/Documents/Codex/2026-10-07/new-chat
export PYTHONDONTWRITEBYTECODE=1
python=outputs/security-key-emulator/.venv/bin/python
audit=work/v56-otp-oath-hsmauth-audit
"$python" -B "$audit/baseline/tools/verify_smartcard.py" --work-dir /tmp --report "$audit/smartcard.json" > "$audit/smartcard.log" 2>&1
"$python" -B "$audit/baseline/tools/verify_oath_profile.py" --work-dir /tmp --report "$audit/oath.json" > "$audit/oath.log" 2>&1
"$python" -B "$audit/baseline/tools/verify_otp_hmac_boundary.py" --report "$audit/otp.json" > "$audit/otp.log" 2>&1
