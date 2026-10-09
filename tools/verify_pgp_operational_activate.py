#!/usr/bin/env python3
"""ACTIVATE FILE in operational state is a successful no-op."""

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from verify_smartcard import Fixture
from emucard.core import EncryptedState
from yubikit.core.smartcard import ApduError
from yubikit.openpgp import DO, INS, OpenPgpSession


URL = b"https://example.test/openpgp-operational-activate"


def run(root, ifd, fixed):
    with tempfile.TemporaryDirectory(prefix="pgp-activate-") as td:
        directory = Path(td)
        fixture = Fixture(root, directory, ifd)
        try:
            conn = fixture.start()
            pgp = OpenPgpSession(conn)
            pgp.verify_admin("12345678")
            pgp.put_data(DO.URL, URL)
            assert pgp.get_data(DO.URL) == URL
            before = (directory / "state.bin").read_bytes()
            before_state = EncryptedState(directory / "state.bin").data

            # Existing malformed-header guards must remain in force.
            for packet, expected in (("00440100", 0x6A86),
                                     ("0044000001", 0x6700)):
                response, sw = conn.send_and_receive(bytes.fromhex(packet))
                assert response == b"" and sw == expected
                assert (directory / "state.bin").read_bytes() == before

            response, sw = conn.send_and_receive(bytes.fromhex("00440000"))
            after = (directory / "state.bin").read_bytes()
            after_state = EncryptedState(directory / "state.bin").data
            assert response == b""
            assert sw == (0x9000 if fixed else 0x6985), hex(sw)
            assert before_state == after_state
            assert pgp.get_data(DO.URL) == URL

            try:
                sdk_response = pgp.protocol.send_apdu(0, INS.ACTIVATE, 0, 0)
            except ApduError as error:
                assert not fixed and error.sw == 0x6985
                sdk_result = "6985 error"
            else:
                assert fixed and sdk_response == b""
                sdk_result = "9000 success"
            assert EncryptedState(directory / "state.bin").data == before_state

            pgp = OpenPgpSession(fixture.restart())
            assert pgp.get_data(DO.URL) == URL
            pgp.reset()  # Unmodified YubiKit TERMINATE then ACTIVATE path.
            pgp = OpenPgpSession(fixture.restart())
            assert pgp.get_data(DO.URL) == b""
            assert pgp.get_pin_status().attempts_admin == 3
            return {
                "operational_activate_sw": f"{sw:04x}",
                "operational_state_semantically_identical": before_state == after_state,
                "encrypted_state_bytes_identical": before == after,
                "unmodified_sdk_operational_activate": sdk_result,
                "malformed_headers_rejected_immutably": True,
                "url_preserved_after_restart": True,
                "unmodified_sdk_reset_terminated_activation": True,
                "reset_persisted_after_restart": True,
            }
        finally:
            fixture.stop()


def run_pristine_state(root, ifd, fixed):
    """A successful no-op must not lazily install an attestation key."""
    with tempfile.TemporaryDirectory(prefix="pgp-activate-pristine-") as td:
        directory = Path(td)
        fixture = Fixture(root, directory, ifd)
        try:
            conn = fixture.start()
            _, sw = conn.send_and_receive(bytes.fromhex("00a4040006d27600012401"))
            assert sw == 0x9000
            before = EncryptedState(directory / "state.bin").data
            assert "129" not in before["openpgp"]["keys"]
            response, sw = conn.send_and_receive(bytes.fromhex("00440000"))
            assert response == b"" and sw == (0x9000 if fixed else 0x6985)
            after = EncryptedState(directory / "state.bin").data
            assert before == after
            fixture.restart()
            assert EncryptedState(directory / "state.bin").data == before
            return {"pristine_state_no_attestation_created": True,
                    "pristine_state_survives_restart": True}
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
    row = run(root, ifd, args.expect_fixed)
    report = {
        "passed": True,
        "core_sha256": hashlib.sha256((root / "emucard/core.py").read_bytes()).hexdigest(),
        "transport": "direct IFD" if ifd else "private CCID socket",
        "expect_fixed": args.expect_fixed,
        **row,
        "pristine": run_pristine_state(root, ifd, args.expect_fixed),
        "physical_key_accessed": False,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
