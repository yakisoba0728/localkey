#!/usr/bin/env python3
"""Malformed SELECT DATA Le must not advance the certificate pointer."""

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from emucard.core import EncryptedState
from verify_smartcard import Fixture, certificate
from yubikit.core.smartcard import ApduError
from yubikit.openpgp import DO, INS, KEY_REF, OpenPgpSession


MALFORMED = bytes.fromhex("00a502040660045c027f2101")
VALID_LE_ZERO = bytes.fromhex("00a502040660045c027f2100")


def encoded(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def run(root, ifd, fixed):
    with tempfile.TemporaryDirectory(prefix="pgp-select-le-") as td:
        directory = Path(td)
        fixture = Fixture(root, directory, ifd)
        try:
            conn = fixture.start()
            pgp = OpenPgpSession(conn)
            pgp.verify_admin("12345678")
            aut = certificate(ec.generate_private_key(ec.SECP256R1()))
            sig = certificate(ec.generate_private_key(ec.SECP256R1()))
            pgp.put_certificate(KEY_REF.AUT, aut)
            pgp.put_certificate(KEY_REF.SIG, sig)
            assert encoded(pgp.get_certificate(KEY_REF.AUT)) == encoded(aut)
            before = EncryptedState(directory / "state.bin").data
            response, sw = conn.send_and_receive(MALFORMED)
            malformed_sw = sw
            after = EncryptedState(directory / "state.bin").data
            assert response == b"" and sw == (0x6700 if fixed else 0x9000), hex(sw)
            assert before == after
            selected = pgp.get_data(DO.CARDHOLDER_CERTIFICATE)
            assert selected == encoded(aut if fixed else sig)

            response, sw = conn.send_and_receive(VALID_LE_ZERO)
            assert response == b"" and sw == 0x9000
            assert pgp.get_data(DO.CARDHOLDER_CERTIFICATE) == encoded(sig)
            # Unmodified SDK omits Le and must still select each certificate.
            assert encoded(pgp.get_certificate(KEY_REF.AUT)) == encoded(aut)
            assert encoded(pgp.get_certificate(KEY_REF.SIG)) == encoded(sig)

            assert encoded(pgp.get_certificate(KEY_REF.AUT)) == encoded(aut)
            select_data = bytes.fromhex("60045c027f21")
            try:
                pgp.protocol.send_apdu(0, INS.SELECT_DATA, 2, 4, select_data, le=1)
            except ApduError as error:
                assert fixed and error.sw == 0x6700
            else:
                assert not fixed
            assert pgp.get_data(DO.CARDHOLDER_CERTIFICATE) == encoded(
                aut if fixed else sig
            )

            pgp = OpenPgpSession(fixture.restart())
            assert encoded(pgp.get_certificate(KEY_REF.AUT)) == encoded(aut)
            assert encoded(pgp.get_certificate(KEY_REF.SIG)) == encoded(sig)
            return {
                "malformed_apdu": MALFORMED.hex(),
                "malformed_sw": f"{malformed_sw:04x}",
                "persistent_state_unchanged_on_malformed": before == after,
                "malformed_selection_preserved": fixed,
                "valid_spec_le_zero_select": True,
                "normal_unmodified_sdk_select_and_read": True,
                "sdk_malformed_select_detected": True,
                "certificates_persist_after_restart": True,
            }
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
        "fixed": args.expect_fixed,
        **row,
        "physical_key_accessed": False,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
