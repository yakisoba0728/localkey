#!/usr/bin/env python3
"""Exercise GET NEXT DATA exhaustion through private CCID and unmodified YubiKit."""

import argparse
import json
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from verify_smartcard import Fixture, certificate
from emucard.core import EncryptedState
from yubikit.core.smartcard import ApduError
from yubikit.openpgp import DO, KEY_REF, OpenPgpSession


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--ifd", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--expect-fixed", action="store_true")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="pgp-next-exhaust-") as td:
        directory = Path(td)
        fixture = Fixture(args.root.resolve(), directory, args.ifd.resolve() if args.ifd else None)
        try:
            pgp = OpenPgpSession(fixture.start())
            pgp.verify_admin("12345678")
            certificates = {}
            for ref in (KEY_REF.AUT, KEY_REF.DEC, KEY_REF.SIG, KEY_REF.ATT):
                cert = certificate(ec.generate_private_key(ec.SECP256R1()))
                certificates[ref.name] = cert.public_bytes(serialization.Encoding.DER)
                pgp.put_certificate(ref, cert)
                assert pgp.get_certificate(ref).public_bytes(serialization.Encoding.DER) == certificates[ref.name]

            pgp.protocol.send_apdu(0, 0xA5, 0, 4, bytes.fromhex("60045c027f21"))
            assert pgp.get_data(DO.CARDHOLDER_CERTIFICATE) == certificates["AUT"]
            for ref in (KEY_REF.DEC, KEY_REF.SIG, KEY_REF.ATT):
                assert pgp.protocol.send_apdu(0, 0xCC, 0x7F, 0x21) == certificates[ref.name]
                assert pgp.get_data(DO.CARDHOLDER_CERTIFICATE) == certificates[ref.name]

            try:
                pgp.protocol.send_apdu(0, 0xCC, 0x7F, 0x21)
            except ApduError as e:
                assert e.sw == 0x6A88, hex(e.sw)
                invalid_sw = e.sw
            else:
                raise AssertionError("GET NEXT DATA past last occurrence succeeded")

            after_failure = pgp.get_data(DO.CARDHOLDER_CERTIFICATE)
            assert after_failure == (certificates["ATT"] if args.expect_fixed else b"")
            replacement = b"replacement-certificate-payload"
            pgp.put_data(DO.CARDHOLDER_CERTIFICATE, replacement)
            objects = EncryptedState(directory / "state.bin").data["openpgp"]["objects"]
            assert objects.get("certificateNone") == (None if args.expect_fixed else replacement.hex())
            assert objects[str(0xFC)] == (replacement if args.expect_fixed else certificates["ATT"]).hex()
            assert pgp.get_data(DO.CARDHOLDER_CERTIFICATE) == replacement

            pgp = OpenPgpSession(fixture.restart())
            assert pgp.get_data(DO.ATT_CERTIFICATE) == (replacement if args.expect_fixed else certificates["ATT"])

            # Normal SDK selection must still restore each valid occurrence.
            for ref in (KEY_REF.AUT, KEY_REF.DEC, KEY_REF.SIG):
                assert pgp.get_certificate(ref).public_bytes(serialization.Encoding.DER) == certificates[ref.name]
            result = {
                "passed": True,
                "transport": "direct IFD" if args.ifd else "private CCID socket",
                "expect_fixed": args.expect_fixed,
                "invalid_sw": f"{invalid_sw:04x}",
                "last_occurrence_preserved_after_error": after_failure == certificates["ATT"],
                "put_data_created_certificateNone": "certificateNone" in objects,
                "write_destination_survived_restart": True,
                "normal_sdk_certificate_paths": True,
                "physical_key_accessed": False,
            }
        finally:
            fixture.stop()

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
