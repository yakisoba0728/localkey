#!/usr/bin/env python3
"""Yubico OpenPGP INS FB must not attest on an explicit nonzero Le."""

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from verify_smartcard import Fixture, certificate
from yubikit.openpgp import KEY_REF, OID, OpenPgpSession


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--ifd", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--expect-fixed", action="store_true")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="pgp-attestation-le-") as td:
        directory = Path(td)
        fixture = Fixture(args.root.resolve(), directory, args.ifd.resolve() if args.ifd else None)
        try:
            conn = fixture.start()
            pgp = OpenPgpSession(conn)
            pgp.verify_admin("12345678")
            pgp.generate_ec_key(KEY_REF.SIG, OID.SECP256R1)
            original = certificate(ec.generate_private_key(ec.SECP256R1()))
            original_der = original.public_bytes(serialization.Encoding.DER)
            pgp.put_certificate(KEY_REF.SIG, original)
            assert pgp.get_certificate(KEY_REF.SIG).public_bytes(serialization.Encoding.DER) == original_der
            pgp.verify_pin("123456")

            persisted_before = (directory / "state.bin").read_bytes()
            response, sw = conn.send_and_receive(bytes.fromhex("80fb010001"))
            persisted_after = (directory / "state.bin").read_bytes()
            assert response == b""
            assert sw == (0x6700 if args.expect_fixed else 0x9000), hex(sw)
            assert (persisted_after == persisted_before) == args.expect_fixed
            after_bad_le = pgp.get_certificate(KEY_REF.SIG).public_bytes(serialization.Encoding.DER)
            assert (after_bad_le == original_der) == args.expect_fixed

            # Unmodified YubiKit must still be able to attest and read the SIG cert.
            statement = pgp.attest_key(KEY_REF.SIG)
            attestation = pgp.get_certificate(KEY_REF.ATT)
            attestation.public_key().verify(
                statement.signature,
                statement.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            statement_der = statement.public_bytes(serialization.Encoding.DER)
            assert statement_der != original_der
            assert pgp.get_certificate(KEY_REF.SIG).public_bytes(serialization.Encoding.DER) == statement_der
            result = {
                "passed": True,
                "transport": "direct IFD" if args.ifd else "private CCID socket",
                "expect_fixed": args.expect_fixed,
                "explicit_le_1_sw": f"{sw:04x}",
                "malformed_command_overwrote_sig_certificate": after_bad_le != original_der,
                "malformed_command_mutated_persistent_state": persisted_after != persisted_before,
                "normal_sdk_attestation_signature_verified": True,
                "physical_key_accessed": False,
            }
        finally:
            fixture.stop()

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
