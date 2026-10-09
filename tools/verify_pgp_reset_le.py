#!/usr/bin/env python3
"""Compare explicit-Le RESET RETRY COUNTER against local software cards."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from emucard.core import Apdu
from verify_smartcard import Fixture
from yubikit.core import InvalidPinError
from yubikit.core.smartcard import ApduError, ExtendedApduFormatter
from yubikit.openpgp import OpenPgpSession


RESET_CODE = "87654321"
OLD_PIN = "123456"
NEW_PIN = "654321"
FINAL_PIN = "111111"


def status(operation):
    try:
        operation()
    except ApduError as error:
        return error.sw
    return 0x9000


def accepted(operation):
    try:
        operation()
    except (ApduError, InvalidPinError):
        return False
    return True


def run(root, expect, ifd_driver):
    formatter = ExtendedApduFormatter(65535)
    observations = {}
    # The native IFD driver has a shorter socket-path limit than macOS AF_UNIX.
    with tempfile.TemporaryDirectory(prefix="ske-pgp-reset-le-", dir="/tmp") as base:
        for name, p1, data in (
            ("admin", 2, NEW_PIN.encode()),
            ("reset_code", 0, (RESET_CODE + NEW_PIN).encode()),
        ):
            for le in (1, 256):
                label = f"{name}_le{le}"
                directory = Path(base) / label
                directory.mkdir()
                fixture = Fixture(root, directory, ifd_driver)
                try:
                    connection = fixture.start()
                    sent = []
                    original = connection.send_and_receive

                    def capture(apdu):
                        sent.append(bytes(apdu))
                        return original(apdu)

                    connection.send_and_receive = capture
                    pgp = OpenPgpSession(connection)
                    pgp.verify_admin("12345678")
                    if name == "reset_code":
                        pgp.set_reset_code(RESET_CODE)
                    wire = formatter.format_apdu(0, 0x2C, p1, 0x81, data, le)
                    observations[label + "_wire"] = wire.hex()
                    observations[label + "_decoded_le"] = Apdu.decode(wire).le
                    before = (directory / "state.bin").read_bytes()
                    observations[label + "_sw"] = status(
                        lambda: pgp.protocol.send_apdu(0, 0x2C, p1, 0x81, data, le=le)
                    )
                    observations[label + "_sent_wire_matches"] = sent[-1] == wire
                    observations[label + "_state_unchanged"] = (
                        directory / "state.bin"
                    ).read_bytes() == before
                    observations[label + "_user_retries"] = pgp.get_pin_status().attempts_user

                    connection = fixture.restart()
                    sent_normal = []
                    original_normal = connection.send_and_receive

                    def capture_normal(apdu):
                        sent_normal.append(bytes(apdu))
                        return original_normal(apdu)

                    connection.send_and_receive = capture_normal
                    pgp = OpenPgpSession(connection)
                    if expect == "baseline":
                        observations[label + "_old_pin_works"] = accepted(
                            lambda: pgp.verify_pin(OLD_PIN)
                        )
                        observations[label + "_new_pin_works"] = accepted(
                            lambda: pgp.verify_pin(NEW_PIN)
                        )
                    else:
                        observations[label + "_new_pin_works"] = accepted(
                            lambda: pgp.verify_pin(NEW_PIN)
                        )
                        observations[label + "_old_pin_works"] = accepted(
                            lambda: pgp.verify_pin(OLD_PIN)
                        )

                    if name == "admin":
                        pgp.verify_admin("12345678")
                        pgp.reset_pin(FINAL_PIN)
                    else:
                        pgp.reset_pin(FINAL_PIN, reset_code=RESET_CODE)
                    normal_reset = next(
                        apdu for apdu in reversed(sent_normal) if apdu[1] == 0x2C
                    )
                    observations[label + "_normal_sdk_le_absent"] = (
                        Apdu.decode(normal_reset).le is None
                    )
                    pgp = OpenPgpSession(fixture.restart())
                    observations[label + "_normal_sdk_reset_persists"] = accepted(
                        lambda: pgp.verify_pin(FINAL_PIN)
                    )
                finally:
                    fixture.stop()

    expected = {}
    for name in ("admin", "reset_code"):
        for le in (1, 256):
            label = f"{name}_le{le}"
            expected[label + "_decoded_le"] = le
            expected[label + "_sent_wire_matches"] = True
            expected[label + "_sw"] = 0x9000 if expect == "baseline" else 0x6700
            expected[label + "_state_unchanged"] = expect == "guarded"
            expected[label + "_user_retries"] = 3
            expected[label + "_old_pin_works"] = expect == "guarded"
            expected[label + "_new_pin_works"] = expect == "baseline"
            expected[label + "_normal_sdk_reset_persists"] = True
            expected[label + "_normal_sdk_le_absent"] = True
    mismatches = {
        key: {"expected": value, "actual": observations.get(key)}
        for key, value in expected.items()
        if observations.get(key) != value
    }
    return {
        "passed": not mismatches,
        "count": len(expected),
        "tests": [
            {"name": key, "passed": key not in mismatches} for key in expected
        ],
        "expect": expect,
        "transport": "direct IFD ABI" if ifd_driver else "private CCID socket",
        "observations": observations,
        "mismatches": mismatches,
        "physical_key_accessed": False,
        "source": "OpenPGP Smart Card Application 3.4.1 section 7.2.4",
        "note": "6700 is the emulator choice; exact firmware 5.7.4 status/tolerance unmeasured",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--expect", required=True, choices=("baseline", "guarded"))
    parser.add_argument("--ifd-driver", type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    report = run(args.root.resolve(), args.expect, args.ifd_driver)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "checks": report["count"]}))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
