#!/usr/bin/env python3
"""Verify OpenPGP KDF and local software attestation on a fresh CCID card."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from emucard.core import Card, EmulatorConnection, EncryptedState
from verify_smartcard import Fixture, certificate
from yubikit.core import InvalidPinError
from yubikit.core.smartcard import ApduError
from yubikit.openpgp import (
    DO,
    HASH_ALGORITHM,
    KEY_REF,
    OID,
    UIF,
    KdfIterSaltedS2k,
    KdfNone,
    OpenPgpSession,
)


def point(pub):
    return pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def run(root, directory, report):
    fixture = Fixture(root, directory)
    checks = []
    completed = False

    def check(value, name):
        if not value:
            raise AssertionError(name)
        checks.append({"name": name, "passed": True})
        print("PASS", name, flush=True)

    def denied(sw, fn, name):
        try:
            fn()
        except ApduError as e:
            check(e.sw == sw, name)
        else:
            raise AssertionError("accepted: " + name)

    try:
        conn = fixture.start()
        pgp = OpenPgpSession(conn)
        pgp.verify_admin("12345678")
        kdf = KdfIterSaltedS2k.create(HASH_ALGORITHM.SHA256, 32768)
        pgp.set_kdf(kdf)
        check(
            bytes(pgp.get_kdf()) == bytes(kdf),
            "OpenPGP KDF TLV configuration round trip",
        )
        pgp.verify_pin("123456")
        pgp.verify_admin("12345678")
        check(True, "OpenPGP SDK SHA256 iterated salted S2K PIN verification")
        denied(
            0x6982,
            lambda: pgp.protocol.send_apdu(0, 0x20, 0, 0x81, b"123456"),
            "KDF rejects plaintext PIN on wire",
        )
        check(
            pgp.get_pin_status().attempts_user == 2,
            "KDF wrong PIN decrements retries durably",
        )
        conn = fixture.restart()
        pgp = OpenPgpSession(conn)
        check(
            pgp.get_pin_status().attempts_user == 2
            and isinstance(pgp.get_kdf(), KdfIterSaltedS2k),
            "KDF settings and PIN retry survive restart",
        )
        pgp.verify_pin("123456")
        pgp.change_pin("123456", "654321")
        pgp.change_admin("12345678", "87654321")
        pgp.verify_admin("87654321")
        pgp.verify_pin("654321")
        check(True, "KDF user and admin PIN changes")
        pgp.set_reset_code("12345678")
        for _ in range(3):
            try:
                pgp.verify_pin("bad-pin")
            except InvalidPinError:
                pass
        check(pgp.get_pin_status().attempts_user == 0, "KDF PIN blocking")
        pgp.reset_pin("111111", reset_code="12345678")
        pgp.verify_pin("111111")
        check(True, "KDF hashed reset code unblocks user PIN")
        pgp.verify_admin("87654321")
        pgp.set_kdf(KdfIterSaltedS2k.create(HASH_ALGORITHM.SHA512, 65536))
        pgp.verify_admin("12345678")
        pgp.verify_pin("123456")
        check(True, "OpenPGP SDK SHA512 S2K PIN verification and default reset")
        pub = pgp.generate_ec_key(KEY_REF.SIG, OID.SECP256R1)
        denied(
            0x6985,
            lambda: pgp.set_kdf(KdfNone()),
            "KDF cannot change while user private key exists",
        )
        pgp.verify_pin("123456")
        message = b"OpenPGP hashed PIN signature"
        pub.verify(
            pgp.sign(message, hashes.SHA256()), message, ec.ECDSA(hashes.SHA256())
        )
        check(True, "KDF protected signature independently verified")
        denied(
            0x6982,
            lambda: pgp.attest_key(KEY_REF.SIG),
            "OpenPGP attestation requires user PIN",
        )
        pgp.verify_pin("123456", extended=True)
        template_cert = pgp.get_certificate(KEY_REF.ATT)
        leaf = pgp.attest_key(KEY_REF.SIG)
        leaf.verify_directly_issued_by(template_cert)
        check(
            point(leaf.public_key()) == point(pub)
            and "Local software" in template_cert.subject.rfc4514_string(),
            "OpenPGP attestation signature and software identity",
        )
        check(
            pgp.get_algorithm_attributes(KEY_REF.ATT) is not None
            and KEY_REF.ATT in pgp.get_key_information(),
            "fourth OpenPGP key attributes and metadata",
        )
        pgp.set_generation_time(KEY_REF.ATT, 1000)
        pgp.set_fingerprint(KEY_REF.ATT, bytes(range(20)))
        check(
            pgp.get_data(DO.GENERATION_TIME_ATT) == b"\0\0\x03\xe8"
            and pgp.get_data(DO.FINGERPRINT_ATT) == bytes(range(20)),
            "OpenPGP attestation slot time and fingerprint",
        )
        imported = ec.generate_private_key(ec.SECP256R1())
        pgp.put_key(KEY_REF.SIG, imported)
        denied(
            0x6A80,
            lambda: pgp.attest_key(KEY_REF.SIG),
            "imported OpenPGP key cannot claim generated provenance",
        )
        pgp.put_key(KEY_REF.ATT, imported)
        pgp.put_certificate(KEY_REF.ATT, certificate(imported))
        pub = pgp.generate_ec_key(KEY_REF.AUT, OID.SECP256R1)
        leaf = pgp.attest_key(KEY_REF.AUT)
        imported.public_key().verify(
            leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256())
        )
        check(
            point(leaf.public_key()) == point(pub),
            "custom OpenPGP attestation key and certificate import",
        )
        denied(
            0x6A80,
            lambda: pgp.put_data(
                DO.ALGORITHM_ATTRIBUTES_ATT, b"\x16" + bytes(OID.Ed25519)
            ),
            "OpenPGP attestation excludes curve25519 family",
        )
        pgp.protocol.send_apdu(0, 0xA5, 3, 4, bytes.fromhex("60045c027f21"))
        check(
            pgp.get_data(DO.CARDHOLDER_CERTIFICATE) == pgp.get_data(DO.ATT_CERTIFICATE),
            "fourth certificate SELECT DATA index",
        )
        pgp.protocol.send_apdu(0, 0xA5, 0, 4, bytes.fromhex("60045c027f21"))
        for _ in range(3):
            next_cert = pgp.protocol.send_apdu(0, 0xCC, 0x7F, 0x21)
        check(
            next_cert == pgp.get_data(DO.ATT_CERTIFICATE),
            "GET NEXT DATA iterates all four certificate slots",
        )
        state = EncryptedState(directory / "state.bin")
        d = state.data["openpgp"]
        check(
            d["pin"] == d["admin"] == "" and len(bytes.fromhex(d["pin_value"])) == 64,
            "KDF state stores hashes without plaintext PIN",
        )
        # An independent callback verifies cached touch reuse and expiry directly.
        touched = []
        card = Card(touch=lambda label: touched.append(label) or True)
        direct = OpenPgpSession(EmulatorConnection(card))
        direct.verify_admin("12345678")
        key = direct.generate_ec_key(KEY_REF.AUT, OID.SECP256R1)
        direct.set_uif(KEY_REF.AUT, UIF.CACHED_FIXED)
        direct.verify_pin("123456", extended=True)
        for _ in range(2):
            key.verify(
                direct.authenticate(message, hashes.SHA256()),
                message,
                ec.ECDSA(hashes.SHA256()),
            )
        check(len(touched) == 1, "OpenPGP cached touch reused for 15 seconds")
        card.cached_touch["OpenPGP key 3"] -= 16
        direct.authenticate(message, hashes.SHA256())
        check(len(touched) == 2, "OpenPGP cached touch expires")
        direct.verify_pin("123456")
        try:
            direct.verify_pin("bad-pin", extended=True)
        except InvalidPinError:
            pass
        denied(
            0x6982,
            lambda: direct.sign(message, hashes.SHA256()),
            "failed OpenPGP PIN clears SIG authorization",
        )
        denied(
            0x6982,
            lambda: direct.authenticate(message, hashes.SHA256()),
            "failed OpenPGP PIN clears extended authorization",
        )
        denied(
            0x6985,
            lambda: direct.put_data(DO.UIF_AUT, b"\0\x20"),
            "OpenPGP cached fixed touch cannot downgrade",
        )
        pgp.reset()
        pgp = OpenPgpSession(conn)
        check(
            isinstance(pgp.get_kdf(), KdfNone),
            "OpenPGP reset removes KDF configuration",
        )
        pgp.verify_admin("12345678")
        pgp.verify_pin("123456")
        check(
            point(pgp.get_certificate(KEY_REF.ATT).public_key())
            == point(imported.public_key()),
            "OpenPGP reset retains current independent attestation issuer",
        )
        completed = True
    finally:
        fixture.stop()
        report.write_text(
            json.dumps(
                {"passed": completed, "tests": checks, "physical_key_accessed": False},
                indent=2,
            )
            + "\n"
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", type=Path, default=Path(tempfile.gettempdir()))
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ske-pgp-", dir=args.work_dir) as directory:
        run(Path(__file__).resolve().parents[1], Path(directory), args.report)


if __name__ == "__main__":
    main()
