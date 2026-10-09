#!/usr/bin/env python3
"""Compare independent SDK APDUs at OpenPGP VERIFY/CHANGE header boundaries."""

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from verify_smartcard import Fixture
from yubikit.core import InvalidPinError
from yubikit.core.smartcard import ApduError
from yubikit.openpgp import OpenPgpSession


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
    observations = {}
    with tempfile.TemporaryDirectory(prefix="ske-pgp-hdr-") as base:
        directory = Path(base) / "verify"
        directory.mkdir()
        fixture = Fixture(root, directory, ifd_driver)
        try:
            pgp = OpenPgpSession(fixture.start())
            before = (directory / "state.bin").read_bytes()
            observations["invalid_verify_p1_bad_pin_sw"] = status(
                lambda: pgp.protocol.send_apdu(0, 0x20, 1, 0x81, b"badbad")
            )
            observations["invalid_verify_p1_state_unchanged"] = (directory / "state.bin").read_bytes() == before
            observations["invalid_verify_p1_retries"] = pgp.get_pin_status().attempts_user

            pgp.verify_pin("123456")
            observations["verified_status_before_ff_data"] = status(
                lambda: pgp.protocol.send_apdu(0, 0x20, 0, 0x81)
            )
            before = (directory / "state.bin").read_bytes()
            observations["invalid_verify_ff_with_data_sw"] = status(
                lambda: pgp.protocol.send_apdu(0, 0x20, 0xFF, 0x81, b"junk")
            )
            observations["invalid_ff_data_state_unchanged"] = (directory / "state.bin").read_bytes() == before
            observations["status_after_invalid_ff_data"] = status(
                lambda: pgp.protocol.send_apdu(0, 0x20, 0, 0x81)
            )
            observations["valid_verify_ff_empty_sw"] = status(
                lambda: pgp.protocol.send_apdu(0, 0x20, 0xFF, 0x81)
            )
            observations["status_after_valid_ff_empty"] = status(
                lambda: pgp.protocol.send_apdu(0, 0x20, 0, 0x81)
            )
        finally:
            fixture.stop()

        for name, reference, old, new in (
            ("user", 0x81, "123456", "654321"),
            ("admin", 0x83, "12345678", "87654321"),
        ):
            directory = Path(base) / name
            directory.mkdir()
            fixture = Fixture(root, directory, ifd_driver)
            try:
                pgp = OpenPgpSession(fixture.start())
                before = (directory / "state.bin").read_bytes()
                observations[f"invalid_change_{name}_p1_sw"] = status(
                    lambda: pgp.protocol.send_apdu(
                        0, 0x24, 1, reference, (old + new).encode()
                    )
                )
                observations[f"invalid_change_{name}_state_unchanged"] = (
                    directory / "state.bin"
                ).read_bytes() == before
                pgp = OpenPgpSession(fixture.restart())
                verify = pgp.verify_pin if name == "user" else pgp.verify_admin
                observations[f"invalid_change_{name}_old_pin_works"] = accepted(
                    lambda: verify(old)
                )
                observations[f"invalid_change_{name}_new_pin_works"] = accepted(
                    lambda: verify(new)
                )
                if expect == "fixed":
                    # A legal command still changes the correct credential.
                    current = old
                    observations[f"valid_change_{name}_sw"] = status(
                        lambda: pgp.protocol.send_apdu(
                            0, 0x24, 0, reference, (current + new).encode()
                        )
                    )
                    pgp = OpenPgpSession(fixture.restart())
                    verify = pgp.verify_pin if name == "user" else pgp.verify_admin
                    observations[f"valid_change_{name}_new_pin_works"] = accepted(
                        lambda: verify(new)
                    )
            finally:
                fixture.stop()

    expected_common = {
        "verified_status_before_ff_data": 0x9000,
        "valid_verify_ff_empty_sw": 0x9000,
        "status_after_valid_ff_empty": 0x63C3,
    }
    expected_before = {
        "invalid_verify_p1_bad_pin_sw": 0x6982,
        "invalid_verify_p1_retries": 2,
        "invalid_verify_p1_state_unchanged": False,
        "invalid_verify_ff_with_data_sw": 0x9000,
        "status_after_invalid_ff_data": 0x63C3,
        "invalid_ff_data_state_unchanged": False,
        "invalid_change_user_p1_sw": 0x9000,
        "invalid_change_user_state_unchanged": False,
        "invalid_change_user_old_pin_works": False,
        "invalid_change_user_new_pin_works": True,
        "invalid_change_admin_p1_sw": 0x9000,
        "invalid_change_admin_state_unchanged": False,
        "invalid_change_admin_old_pin_works": False,
        "invalid_change_admin_new_pin_works": True,
    }
    expected_after = {
        "invalid_verify_p1_bad_pin_sw": 0x6A86,
        "invalid_verify_p1_retries": 3,
        "invalid_verify_p1_state_unchanged": True,
        "invalid_verify_ff_with_data_sw": 0x6700,
        "status_after_invalid_ff_data": 0x9000,
        "invalid_ff_data_state_unchanged": True,
        "invalid_change_user_p1_sw": 0x6A86,
        "invalid_change_user_state_unchanged": True,
        "invalid_change_user_old_pin_works": True,
        "invalid_change_user_new_pin_works": False,
        "invalid_change_admin_p1_sw": 0x6A86,
        "invalid_change_admin_state_unchanged": True,
        "invalid_change_admin_old_pin_works": True,
        "invalid_change_admin_new_pin_works": False,
        "valid_change_user_sw": 0x9000,
        "valid_change_user_new_pin_works": True,
        "valid_change_admin_sw": 0x9000,
        "valid_change_admin_new_pin_works": True,
    }
    expected = expected_common | (expected_before if expect == "baseline" else expected_after)
    mismatches = {key: {"expected": value, "actual": observations.get(key)} for key, value in expected.items() if observations.get(key) != value}
    result = {
        "passed": not mismatches,
        "count": len(expected),
        "tests": [{"name": key, "passed": key not in mismatches}
                  for key in expected],
        "expect": expect,
        "transport": "direct IFD ABI" if ifd_driver else "private CCID socket",
        "observations": observations,
        "mismatches": mismatches,
        "physical_key_accessed": False,
        "source": "OpenPGP Smart Card Application 3.4.1 sections 7.2.2 and 7.2.3",
        "note": "status words are emulator contracts; exact physical 5.7.4 rejection status unmeasured",
    }
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--expect", choices=("baseline", "fixed"), required=True)
    parser.add_argument("--ifd-driver", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.root.resolve(), args.expect, args.ifd_driver)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"passed": result["passed"], "checks": len(result["observations"]) - len(result["mismatches"])}))
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
