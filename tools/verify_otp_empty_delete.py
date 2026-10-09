#!/usr/bin/env python3
"""YubiKit OTP deletion boundary over a private Unix CCID socket."""

import argparse
import hashlib
import hmac
import json
import sys
import tempfile
from pathlib import Path

from yubikit.core.smartcard import ApduError
from yubikit.yubiotp import HmacSha1SlotConfiguration, SLOT, YubiOtpSession


HERE = Path(__file__).resolve().parent
KEYS = {SLOT.ONE: bytes(range(20)), SLOT.TWO: bytes(range(20, 40))}
CHALLENGE = b"v60-delete"


def fixture(root):
    sys.path.insert(0, str(root))
    from tools.verify_smartcard import Fixture

    return Fixture


def delete_empty(root, present, expected):
    with tempfile.TemporaryDirectory(prefix="v60otp-", dir="/tmp") as tmp:
        f = fixture(root)(root, Path(tmp))
        connection = f.start()
        try:
            sdk = YubiOtpSession(connection)
            sdk.put_configuration(present, HmacSha1SlotConfiguration(KEYS[present]))
            before = sdk._status[3]
            empty = SLOT.TWO if present == SLOT.ONE else SLOT.ONE
            try:
                sdk.delete_slot(empty)
                outcome = "accepted"
            except ApduError as error:
                outcome = f"rejected:{error.sw:04x}"
            assert outcome == expected, outcome
            fresh = YubiOtpSession(connection)
            after = fresh._status[3]
            assert after == before + (1 if expected == "accepted" else 0)
            assert fresh.get_config_state().is_configured(present)
            assert not fresh.get_config_state().is_configured(empty)
            response = fresh.calculate_hmac_sha1(present, CHALLENGE)
            assert response == hmac.digest(KEYS[present], CHALLENGE, "sha1")
            return {"configured": present.name, "deleted": empty.name,
                    "outcome": outcome, "sequence_before": before,
                    "sequence_after": after, "remaining_hmac_sha1": response.hex(),
                    "passed": True}
        finally:
            f.stop()


def delete_present(root):
    with tempfile.TemporaryDirectory(prefix="v60otp-", dir="/tmp") as tmp:
        f = fixture(root)(root, Path(tmp))
        connection = f.start()
        try:
            sdk = YubiOtpSession(connection)
            for slot in (SLOT.ONE, SLOT.TWO):
                sdk.put_configuration(slot, HmacSha1SlotConfiguration(KEYS[slot]))
            before = sdk._status[3]
            sdk.delete_slot(SLOT.ONE)
            fresh = YubiOtpSession(connection)
            after = fresh._status[3]
            assert after == before + 1
            assert not fresh.get_config_state().is_configured(SLOT.ONE)
            assert fresh.get_config_state().is_configured(SLOT.TWO)
            response = fresh.calculate_hmac_sha1(SLOT.TWO, CHALLENGE)
            assert response == hmac.digest(KEYS[SLOT.TWO], CHALLENGE, "sha1")
            return {"configured": "ONE,TWO", "deleted": "ONE",
                    "outcome": "accepted", "sequence_before": before,
                    "sequence_after": after, "remaining_hmac_sha1": response.hex(),
                    "passed": True}
        finally:
            f.stop()


def delete_when_both_empty(root, expected_sw):
    with tempfile.TemporaryDirectory(prefix="v60otp-", dir="/tmp") as tmp:
        f = fixture(root)(root, Path(tmp))
        connection = f.start()
        try:
            sdk = YubiOtpSession(connection)
            before = sdk._status.hex()
            # Official CONFIG_1 command with a zeroed 52-byte config and
            # six zero access-code bytes; no SDK sequence-number heuristic.
            apdu = bytes([0, 1, 1, 0, 58]) + bytes(58)
            _, sw = connection.send_and_receive(apdu)
            after = YubiOtpSession(connection)._status.hex()
            assert sw == expected_sw, hex(sw)
            assert after == before
            return {"configured": "none", "deleted": "ONE", "raw_sw": f"{sw:04x}",
                    "status_unchanged": True, "passed": True}
        finally:
            f.stop()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--variant", choices=("baseline", "fixed"), required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--root", type=Path)
    args = parser.parse_args()
    root = args.root or HERE / args.variant
    expected = "accepted" if args.variant == "baseline" else "rejected:6985"
    checks = [delete_when_both_empty(root, 0x9000 if args.variant == "baseline" else 0x6985)]
    checks.extend(delete_empty(root, present, expected) for present in (SLOT.ONE, SLOT.TWO))
    checks.append(delete_present(root))
    result = {"variant": args.variant, "platform": sys.platform,
              "source_sha256": hashlib.sha256((root / "emucard/core.py").read_bytes()).hexdigest(),
              "unmodified_yubikit": True, "private_unix_ccid": True,
              "physical_or_host_device_access": False,
              "firmware_5_7_4_differential": False, "checks": checks}
    args.result.write_text(json.dumps(result, indent=2) + "\n")
    print(f"{len(checks)}/{len(checks)} {args.variant} delete checks passed")


if __name__ == "__main__":
    main()
