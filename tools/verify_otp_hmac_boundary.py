#!/usr/bin/env python3
"""OTP HMAC challenge-length boundary over stock Yubico SDK backends."""

import argparse
import hmac
import json
import sys
from pathlib import Path

from yubikit.core.otp import OtpConnection
from yubikit.yubiotp import HmacSha1SlotConfiguration, SLOT, YubiOtpSession

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from emucard import Card, EmulatorConnection, EncryptedState
from emucard.otp_hid import OtpHidDevice


KEY = bytes(range(20))


class LocalOtpConnection(OtpConnection):
    """In-memory eight-byte feature-report wire, with no host HID access."""

    def __init__(self, card):
        self.device = OtpHidDevice(card)

    def receive(self):
        return self.device.receive()

    def send(self, data):
        self.device.send(data)

    def close(self):
        pass


def check_backend(name, connection_factory):
    card = Card(EncryptedState(), lambda _: True)
    session = YubiOtpSession(connection_factory(card))
    session.put_configuration(SLOT.ONE, HmacSha1SlotConfiguration(KEY))
    cases = [
        ("empty", b"", b"\0"),
        ("single_zero", b"\0", b"\0"),
        ("single_nonzero", b"A", b"A"),
        ("embedded_zero", b"A\0B", b"A\0B"),
        ("63_bytes", bytes(range(63)), bytes(range(63))),
    ]
    observed = []
    for label, input_value, effective in cases:
        actual = session.calculate_hmac_sha1(SLOT.ONE, input_value)
        expected = hmac.digest(KEY, effective, "sha1")
        observed.append(
            {
                "backend": name,
                "case": label,
                "input_bytes": len(input_value),
                "expected_sha1_hmac": expected.hex(),
                "actual_sha1_hmac": actual.hex(),
                "matched": actual == expected,
            }
        )
    session.put_configuration(SLOT.ONE, HmacSha1SlotConfiguration(KEY).lt64(False))
    fixed = b"\0" * 64
    actual = session.calculate_hmac_sha1(SLOT.ONE, fixed)
    expected = hmac.digest(KEY, fixed, "sha1")
    observed.append(
        {
            "backend": name,
            "case": "fixed_64_zero_bytes",
            "input_bytes": 64,
            "expected_sha1_hmac": expected.hex(),
            "actual_sha1_hmac": actual.hex(),
            "matched": actual == expected,
        }
    )
    return observed


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    rows = check_backend("PCSC_APDU", EmulatorConnection)
    rows += check_backend("OTP_HID", LocalOtpConnection)
    result = {"passed": all(row["matched"] for row in rows), "count": len(rows),
              "tests": [{"name": row["backend"] + " " + row["case"],
                         "passed": row["matched"]} for row in rows],
              "checks": rows, "physical_device_access": False,
              "firmware_5_7_4_differential_verified": False}
    for row in rows:
        print(("PASS" if row["matched"] else "FAIL"), row["backend"], row["case"], flush=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    raise SystemExit(0 if result["passed"] else 1)
