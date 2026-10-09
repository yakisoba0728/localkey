#!/usr/bin/env python3
"""YubiKit OTP swap boundary over an owned private CCID Unix socket."""

import argparse
import hashlib
import hmac
import json
import sys
import tempfile
from pathlib import Path

from yubikit.core.smartcard import ApduError
from yubikit.yubiotp import HmacSha1SlotConfiguration, SLOT, YubiOtpSession


KEYS = {SLOT.ONE: bytes(range(20)), SLOT.TWO: bytes(range(20, 40))}


def exercise(root: Path, configured: tuple[SLOT, ...], expect: str):
    sys.path.insert(0, str(root))
    from tools.verify_smartcard import Fixture

    with tempfile.TemporaryDirectory(prefix="v58otp-", dir="/tmp") as tmp:
        fixture = Fixture(root, Path(tmp))
        connection = fixture.start()
        try:
            sdk = YubiOtpSession(connection)
            for slot in configured:
                sdk.put_configuration(slot, HmacSha1SlotConfiguration(KEYS[slot]))
            before = {
                "slot1": sdk.get_config_state().is_configured(SLOT.ONE),
                "slot2": sdk.get_config_state().is_configured(SLOT.TWO),
                "sequence": sdk._status[3],
            }
            try:
                sdk.swap_slots()
                outcome = "accepted"
            except ApduError as exc:
                outcome = f"rejected:{exc.sw:04x}"
            after_sdk = YubiOtpSession(connection)
            after = {
                "slot1": after_sdk.get_config_state().is_configured(SLOT.ONE),
                "slot2": after_sdk.get_config_state().is_configured(SLOT.TWO),
                "sequence": after_sdk._status[3],
            }
            if len(configured) == 1 and expect == "documented":
                assert outcome == "rejected:6985", outcome
                assert after == before, (before, after)
                slot = configured[0]
                assert after_sdk.calculate_hmac_sha1(slot, b"v58") == hmac.digest(
                    KEYS[slot], b"v58", "sha1"
                )
            elif len(configured) == 1 and expect == "published":
                assert outcome == "accepted", outcome
                assert after["slot1"] != before["slot1"]
                assert after["slot2"] != before["slot2"]
                moved = SLOT.TWO if configured[0] == SLOT.ONE else SLOT.ONE
                assert after_sdk.calculate_hmac_sha1(moved, b"v58") == hmac.digest(
                    KEYS[configured[0]], b"v58", "sha1"
                )
            elif len(configured) == 2:
                assert outcome == "accepted", outcome
                assert after["slot1"] and after["slot2"]
                for slot in configured:
                    moved = SLOT.TWO if slot == SLOT.ONE else SLOT.ONE
                    assert after_sdk.calculate_hmac_sha1(moved, b"v58") == hmac.digest(
                        KEYS[slot], b"v58", "sha1"
                    )
            return {"configured": [slot.name for slot in configured], "before": before,
                    "outcome": outcome, "after": after, "passed": True}
        finally:
            fixture.stop()


def exercise_empty(root: Path, expect: str):
    sys.path.insert(0, str(root))
    from tools.verify_smartcard import Fixture

    with tempfile.TemporaryDirectory(prefix="v58otp-", dir="/tmp") as tmp:
        fixture = Fixture(root, Path(tmp))
        connection = fixture.start()
        try:
            before = YubiOtpSession(connection)._status.hex()
            _, sw = connection.send_and_receive(bytes.fromhex("00010600"))
            after = YubiOtpSession(connection)._status.hex()
            assert sw == (0x9000 if expect == "published" else 0x6985), hex(sw)
            assert before == after, (before, after)
            return {"configured": [], "before": before, "outcome": f"raw:{sw:04x}",
                    "after": after, "passed": True}
        finally:
            fixture.stop()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--expect-fixed", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    expected = "documented" if args.expect_fixed else "published"
    checks = [exercise_empty(root, expected)]
    checks.extend(exercise(root, (slot,), expected) for slot in (SLOT.ONE, SLOT.TWO))
    checks.append(exercise(root, (SLOT.ONE, SLOT.TWO), expected))
    result = {
        "passed": True,
        "platform": sys.platform,
        "expect_fixed": args.expect_fixed,
        "source_sha256": hashlib.sha256((root / "emucard/core.py").read_bytes()).hexdigest(),
        "private_unix_ccid": True,
        "unmodified_yubikit": True,
        "physical_or_host_device_access": False,
        "firmware_5_7_4_differential": False,
        "checks": checks,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(f"{len(checks)}/{len(checks)} swap checks passed")


if __name__ == "__main__":
    main()
