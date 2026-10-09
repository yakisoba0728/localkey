#!/usr/bin/env python3
"""A/B regression for PIV SET MANAGEMENT KEY APDU headers."""

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from verify_smartcard import Fixture
from yubikit.core import BadResponseError
from yubikit.core.smartcard import ApduError
from yubikit.core.smartcard.scp import Scp03KeyParams
from yubikit.piv import DEFAULT_MANAGEMENT_KEY, MANAGEMENT_KEY_TYPE, PivSession


NEW_KEY = bytes(range(1, 25))
SDK_KEY = bytes(range(25, 49))
DATA = b"\x03\x9b\x18" + NEW_KEY
CASES = {
    "nonzero_wrong_p1": bytes([0, 0xFF, 0, 0xFF, len(DATA)]) + DATA,
    "invalid_touch_policy_p2": bytes([0, 0xFF, 0xFF, 0, len(DATA)]) + DATA,
    "explicit_le_1": bytes([0, 0xFF, 0xFF, 0xFF, len(DATA)]) + DATA + b"\x01",
}


def run_case(root, ifd, name, packet, fixed):
    with tempfile.TemporaryDirectory(prefix="piv-mgmt-header-") as td:
        directory = Path(td)
        fixture = Fixture(root, directory, ifd)
        try:
            piv = PivSession(fixture.start())
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
            before = (directory / "state.bin").read_bytes()
            response, sw = fixture.connection.send_and_receive(packet)
            after = (directory / "state.bin").read_bytes()
            assert response == b"" and sw == (
                (0x6700 if name == "explicit_le_1" else 0x6A86) if fixed else 0x9000
            ), (name, hex(sw))
            assert (before == after) == fixed

            piv = PivSession(fixture.restart())
            piv.authenticate(DEFAULT_MANAGEMENT_KEY if fixed else NEW_KEY)
            piv = PivSession(fixture.restart())
            try:
                piv.authenticate(NEW_KEY if fixed else DEFAULT_MANAGEMENT_KEY)
            except (BadResponseError, ApduError):
                wrong_key_rejected = True
            else:
                raise AssertionError("wrong management key still authenticates")
            piv = PivSession(fixture.restart())
            piv.authenticate(DEFAULT_MANAGEMENT_KEY if fixed else NEW_KEY)
            piv.set_management_key(MANAGEMENT_KEY_TYPE.TDES, SDK_KEY)
            piv = PivSession(fixture.restart())
            piv.authenticate(SDK_KEY)
            return {
                "name": name,
                "malformed_apdu": packet.hex(),
                "sw": f"{sw:04x}",
                "malformed_state_unchanged": before == after,
                "expected_key_authenticates_after_restart": True,
                "wrong_key_rejected_after_restart": wrong_key_rejected,
                "normal_sdk_management_key_change": True,
            }
        finally:
            fixture.stop()


def run_scp03(root, ifd):
    with tempfile.TemporaryDirectory(prefix="piv-mgmt-scp03-") as td:
        directory = Path(td)
        fixture = Fixture(root, directory, ifd)
        try:
            piv = PivSession(fixture.start(), Scp03KeyParams())
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
            piv.set_management_key(MANAGEMENT_KEY_TYPE.TDES, SDK_KEY)
            piv = PivSession(fixture.restart())
            piv.authenticate(SDK_KEY)
            return {"unmodified_sdk_scp03_management_key_change": True,
                    "restart_persisted": True}
        finally:
            fixture.stop()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--ifd", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--expect-fixed", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    digest = hashlib.sha256((root / "emucard/core.py").read_bytes()).hexdigest()
    ifd = args.ifd.resolve() if args.ifd else None
    rows = [run_case(root, ifd, name, packet, args.expect_fixed)
            for name, packet in CASES.items()]
    result = {
        "passed": True,
        "transport": "direct IFD" if ifd else "private CCID socket",
        "core_sha256": digest,
        "fixed": args.expect_fixed,
        "rows": rows,
        "scp03": run_scp03(root, ifd),
        "physical_key_accessed": False,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
