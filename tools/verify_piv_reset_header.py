#!/usr/bin/env python3
"""PIV RESET must not erase state for a malformed command APDU."""

import argparse
import json
import tempfile
from pathlib import Path

from verify_smartcard import Fixture
from yubikit.core import InvalidPinError
from yubikit.core.smartcard import ApduError
from yubikit.core.smartcard.scp import Scp03KeyParams
from yubikit.piv import DEFAULT_MANAGEMENT_KEY, KEY_TYPE, SLOT, PivSession


MALFORMED = {
    "nonzero_p1": ("00fb0100", 0x6A86),
    "nonzero_p2": ("00fb0001", 0x6A86),
    "command_data": ("00fb000001aa", 0x6700),
    "explicit_le_1": ("00fb000001", 0x6700),
}


def absent_slot(piv):
    try:
        piv.get_slot_metadata(SLOT.AUTHENTICATION)
    except ApduError as error:
        assert error.sw == 0x6A88, hex(error.sw)
    else:
        raise AssertionError("PIV user key survived a successful reset")


def run_case(root, ifd, name, apdu_hex, expected_fixed, expect_fixed):
    with tempfile.TemporaryDirectory(prefix="piv-reset-header-") as td:
        directory = Path(td)
        fixture = Fixture(root, directory, ifd)
        try:
            conn = fixture.start()
            piv = PivSession(conn)
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
            piv.generate_key(SLOT.AUTHENTICATION, KEY_TYPE.ECCP256)
            for _ in range(3):
                try:
                    piv.verify_pin("000000")
                except InvalidPinError:
                    pass
                else:
                    raise AssertionError("wrong PIN verified")
            for _ in range(3):
                try:
                    piv.change_puk("00000000", "87654321")
                except InvalidPinError:
                    pass
                else:
                    raise AssertionError("wrong PUK verified")
            assert piv.get_pin_metadata().attempts_remaining == 0
            assert piv.get_puk_metadata().attempts_remaining == 0

            before = (directory / "state.bin").read_bytes()
            response, sw = conn.send_and_receive(bytes.fromhex(apdu_hex))
            after = (directory / "state.bin").read_bytes()
            assert response == b""
            assert sw == (expected_fixed if expect_fixed else 0x9000), (name, hex(sw))
            assert (after == before) == expect_fixed, name

            piv = PivSession(fixture.restart())
            if expect_fixed:
                assert piv.get_slot_metadata(SLOT.AUTHENTICATION).key_type == KEY_TYPE.ECCP256
                assert piv.get_pin_metadata().attempts_remaining == 0
                assert piv.get_puk_metadata().attempts_remaining == 0
            else:
                absent_slot(piv)
                assert piv.get_pin_metadata().attempts_remaining == 3
            piv.reset()  # Unmodified SDK must still issue a valid RESET.
            absent_slot(piv)
            assert piv.get_pin_metadata().attempts_remaining == 3
            return {
                "name": name,
                "malformed_apdu": apdu_hex,
                "sw": f"{sw:04x}",
                "state_unchanged_on_malformed": before == after,
                "normal_sdk_reset": True,
            }
        finally:
            fixture.stop()


def run_scp03_reset(root, ifd):
    """The unmodified SDK must still reset PIV over its secure channel."""
    with tempfile.TemporaryDirectory(prefix="piv-reset-scp03-") as td:
        directory = Path(td)
        fixture = Fixture(root, directory, ifd)
        try:
            conn = fixture.start()
            piv = PivSession(conn, Scp03KeyParams())
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
            piv.generate_key(SLOT.AUTHENTICATION, KEY_TYPE.ECCP256)
            before = (directory / "state.bin").read_bytes()
            piv.reset()
            after = (directory / "state.bin").read_bytes()
            assert before != after
            piv = PivSession(fixture.restart())
            absent_slot(piv)
            assert piv.get_pin_metadata().attempts_remaining == 3
            return {"unmodified_sdk_scp03_reset": True,
                    "reset_persisted_after_restart": True}
        finally:
            fixture.stop()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--ifd", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--expect-fixed", action="store_true")
    args = parser.parse_args()

    rows = [
        run_case(args.root.resolve(), args.ifd.resolve() if args.ifd else None,
                 name, apdu, sw, args.expect_fixed)
        for name, (apdu, sw) in MALFORMED.items()
    ]
    result = {
        "passed": True,
        "transport": "direct IFD" if args.ifd else "private CCID socket",
        "expect_fixed": args.expect_fixed,
        "rows": rows,
        "scp03": run_scp03_reset(
            args.root.resolve(), args.ifd.resolve() if args.ifd else None
        ),
        "physical_key_accessed": False,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
