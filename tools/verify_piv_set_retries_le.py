#!/usr/bin/env python3
"""SET PIN RETRIES must not replace PIN/PUK on malformed Le."""

import argparse
import json
import tempfile
from pathlib import Path

from verify_smartcard import Fixture
from yubikit.core.smartcard.scp import Scp03KeyParams
from yubikit.piv import DEFAULT_MANAGEMENT_KEY, PivSession


MALFORMED = {
    "short_le_1": "00fa050501",
    "extended_le_256": "00fa0505000100",
}


def run_case(root, ifd, name, apdu_hex, fixed):
    with tempfile.TemporaryDirectory(prefix="piv-retries-le-") as td:
        directory = Path(td)
        fixture = Fixture(root, directory, ifd)
        try:
            piv = PivSession(fixture.start())
            piv.change_pin("123456", "654321")
            piv.change_puk("12345678", "87654321")
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
            piv.verify_pin("654321")
            before = (directory / "state.bin").read_bytes()
            response, sw = fixture.connection.send_and_receive(bytes.fromhex(apdu_hex))
            after = (directory / "state.bin").read_bytes()
            assert response == b""
            assert sw == (0x6700 if fixed else 0x9000), (name, hex(sw))
            assert (before == after) == fixed, name

            piv = PivSession(fixture.restart())
            assert piv.get_pin_metadata().attempts_remaining == (3 if fixed else 5)
            assert piv.get_puk_metadata().attempts_remaining == (3 if fixed else 5)
            piv.change_puk("87654321" if fixed else "12345678", "76543210")
            piv.verify_pin("654321" if fixed else "123456")
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
            piv.set_pin_attempts(6, 7)  # Unmodified SDK's valid APDU still works.
            piv = PivSession(fixture.restart())
            assert piv.get_pin_metadata().attempts_remaining == 6
            assert piv.get_puk_metadata().attempts_remaining == 7
            piv.verify_pin("123456")
            return {
                "name": name,
                "apdu": apdu_hex,
                "sw": f"{sw:04x}",
                "malformed_state_unchanged": before == after,
                "pin_and_puk_checked_after_restart": True,
                "normal_sdk_set_attempts_after_restart": True,
            }
        finally:
            fixture.stop()


def run_scp03(root, ifd):
    with tempfile.TemporaryDirectory(prefix="piv-retries-scp03-") as td:
        directory = Path(td)
        fixture = Fixture(root, directory, ifd)
        try:
            piv = PivSession(fixture.start(), Scp03KeyParams())
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
            piv.verify_pin("123456")
            piv.set_pin_attempts(6, 7)
            piv = PivSession(fixture.restart())
            assert piv.get_pin_metadata().attempts_remaining == 6
            assert piv.get_puk_metadata().attempts_remaining == 7
            return {"unmodified_sdk_scp03_set_attempts": True,
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
    ifd = args.ifd.resolve() if args.ifd else None
    result = {
        "passed": True,
        "transport": "direct IFD" if ifd else "private CCID socket",
        "fixed": args.expect_fixed,
        "rows": [run_case(root, ifd, name, apdu, args.expect_fixed)
                 for name, apdu in MALFORMED.items()],
        "scp03": run_scp03(root, ifd),
        "physical_key_accessed": False,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
