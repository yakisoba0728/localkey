#!/usr/bin/env python3
"""Verify PIV initial data, F9 lifecycle and retry boundaries on fresh cards.

Independent Yubico SDK and cryptography; no physical reader is opened.
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from emucard.core import EncryptedState, dump_key
from verify_smartcard import Fixture
from yubikit.core import InvalidPinError, Tlv
from yubikit.core.smartcard import AID, ApduError
from yubikit.oath import HASH_ALGORITHM, OATH_TYPE, CredentialData, OathSession
from yubikit.piv import (
    DEFAULT_MANAGEMENT_KEY,
    KEY_TYPE,
    PIN_POLICY,
    SLOT,
    TOUCH_POLICY,
    PivSession,
)


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def public_bytes(key):
    return key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def issuer_certificate(public, signing_key):
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name(
        [
            x509.NameAttribute(
                x509.NameOID.COMMON_NAME, "Local software custom PIV issuer fixture"
            )
        ]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=5))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(signing_key, hashes.SHA256())
    )


def run(root, directory, report, ifd_driver=None):
    fixture = Fixture(root, directory, ifd_driver)
    tests = []
    completed = False

    def check(value, name):
        if not value:
            raise AssertionError(name)
        tests.append({"name": name, "passed": True})
        print("PASS", name, flush=True)

    def denied(sw, operation, name):
        try:
            operation()
        except ApduError as error:
            check(error.sw == sw, name)
        else:
            raise AssertionError("accepted invalid operation: " + name)

    def wrong(operation, name, expected=15):
        try:
            operation()
        except InvalidPinError as error:
            check(error.attempts_remaining == expected, name)
        else:
            raise AssertionError("accepted wrong PIN/PUK: " + name)

    try:
        connection = fixture.start()
        piv = PivSession(connection)
        for aid in (
            bytes(AID.PIV)[:5],
            bytes(AID.PIV),
            bytes.fromhex("a000000308000010000100"),
        ):
            response = piv.protocol.send_apdu(0, 0xA4, 4, 0, aid)
            check(
                response == bytes.fromhex("61114f0600001000010079074f05a000000308"),
                f"PIV SELECT returns application template for {len(aid)}-byte AID",
            )
        discovery = piv.get_object(0x7E)
        check(
            discovery == bytes.fromhex("4f0ba0000003080000100001005f2f024000"),
            "SDK reads fixed Discovery AID and PIN policy without authentication",
        )
        denied(
            0x6A82,
            lambda: piv.get_object(0x7F61),
            "unsupported biometric group template is absent on fresh non-biometric card",
        )
        for oid in (0x5FC102, 0x5FC105, 0x5FC106, 0x5FC107, 0x5FC10C):
            denied(
                0x6A82,
                lambda oid=oid: piv.get_object(oid),
                f"initial standard object {oid:06x} remains empty",
            )
        issuer = piv.get_certificate(SLOT.ATTESTATION)
        metadata = piv.get_slot_metadata(SLOT.ATTESTATION)
        check(
            "Local software" in issuer.subject.rfc4514_string()
            and public_bytes(issuer.public_key()) == public_bytes(metadata.public_key)
            and metadata.key_type == KEY_TYPE.ECCP256,
            "own F9 key and certificate are present before generating or attesting a user key",
        )
        initial_issuer = der(issuer)
        piv.authenticate(DEFAULT_MANAGEMENT_KEY)
        for oid in (0x7E, 0x7F61):
            old = (directory / "state.bin").read_bytes()
            denied(
                0x6A80,
                lambda oid=oid: piv.put_object(oid, b"overwrite"),
                f"read-only PIV object {oid:x} rejects PUT DATA",
            )
            check(
                (directory / "state.bin").read_bytes() == old,
                f"rejected object {oid:x} write leaves ciphertext unchanged",
            )
        piv.verify_pin("123456")
        piv.set_pin_attempts(255, 200)
        wrong(
            lambda: piv.verify_pin("wrong"),
            "wrong PIN status saturates at 15 remaining attempts",
        )
        wrong(
            lambda: piv.change_puk("wrong", "87654321"),
            "wrong PUK status saturates at 15 remaining attempts",
        )
        check(
            piv.get_pin_metadata().attempts_remaining == 254
            and piv.get_puk_metadata().attempts_remaining == 199,
            "metadata preserves actual 8-bit PIN/PUK counters beyond status-word nibble",
        )
        denied(
            0x63CF,
            lambda: piv.protocol.send_apdu(0, 0x20, 0, 0x80),
            "PIN status query saturates at 15 without consuming an attempt",
        )
        before = piv.get_pin_metadata().attempts_remaining
        denied(
            0x6700,
            lambda: piv.protocol.send_apdu(0, 0x20, 0, 0x80, b"1234567"),
            "malformed VERIFY length is rejected without a PIN comparison",
        )
        check(
            piv.get_pin_metadata().attempts_remaining == before,
            "malformed PIN input and status query preserve actual retries",
        )
        connection = fixture.restart()
        piv = PivSession(connection)
        check(
            piv.get_pin_metadata().attempts_remaining == 254
            and piv.get_puk_metadata().attempts_remaining == 199
            and der(piv.get_certificate(SLOT.ATTESTATION)) == initial_issuer,
            "large retry counters and preinitialized issuer survive process restart",
        )
        piv.verify_pin("123456")
        check(
            piv.get_pin_metadata().attempts_remaining == 255,
            "successful PIN verification restores complete configured retry count",
        )
        piv.authenticate(DEFAULT_MANAGEMENT_KEY)
        piv.set_pin_attempts(16, 16)
        wrong(
            lambda: piv.verify_pin("wrong"),
            "16-attempt PIN limit reports 15 after first failure",
        )
        wrong(
            lambda: piv.verify_pin("wrong"),
            "retry status resumes exact value below nibble limit",
            14,
        )
        check(
            piv.get_pin_metadata().attempts_remaining == 14,
            "status and metadata agree after crossing 15-attempt boundary",
        )
        piv.verify_pin("123456")
        piv.set_pin_attempts(3, 3)
        piv.verify_pin("123456")
        old = piv.get_pin_metadata()
        denied(
            0x6A80,
            lambda: piv.protocol.send_apdu(0, 0xFA, 0, 3),
            "zero PIN retry configuration is rejected",
        )
        denied(
            0x6700,
            lambda: piv.protocol.send_apdu(0, 0xFA, 3, 3, b"bad"),
            "SET PIN RETRIES rejects unexpected body",
        )
        check(
            piv.get_pin_metadata() == old,
            "invalid retry settings leave metadata unchanged",
        )
        target = piv.generate_key(
            SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, PIN_POLICY.ONCE, TOUCH_POLICY.NEVER
        )
        leaf = piv.attest_key(SLOT.AUTHENTICATION)
        leaf.verify_directly_issued_by(issuer)
        check(
            public_bytes(leaf.public_key()) == public_bytes(target)
            and leaf.not_valid_before_utc == issuer.not_valid_before_utc
            and leaf.not_valid_after_utc == issuer.not_valid_after_utc
            and 0 < leaf.serial_number < (1 << 128),
            "own attestation verifies, copies issuer dates and uses 16-byte random serial profile",
        )
        extensions = {
            item.oid.dotted_string: item.value.value
            for item in leaf.extensions
            if isinstance(item.value, x509.UnrecognizedExtension)
        }
        serial = int.from_bytes(
            Tlv.unpack(2, extensions["1.3.6.1.4.1.41482.3.7"]), "big"
        )
        check(
            extensions["1.3.6.1.4.1.41482.3.3"] == b"\x05\x07\x04"
            and extensions["1.3.6.1.4.1.41482.3.8"] == b"\x02\x01"
            and extensions["1.3.6.1.4.1.41482.3.9"] == b"\x04"
            and serial == piv.get_serial()
            and not any(oid.endswith((".10", ".11")) for oid in extensions),
            "attestation carries own serial, public profile and policies without factory certification claims",
        )
        denied(
            0x6A86,
            lambda: piv.sign(
                SLOT.ATTESTATION,
                KEY_TYPE.ECCP256,
                b"arbitrary message",
                hashes.SHA256(),
            ),
            "F9 key is restricted to attestation rather than arbitrary GENERAL AUTHENTICATE",
        )
        denied(
            0x6A88,
            lambda: piv.attest_key(SLOT.ATTESTATION),
            "F9 cannot recursively attest itself",
        )
        for alg in (KEY_TYPE.RSA1024, KEY_TYPE.ED25519, KEY_TYPE.X25519):
            denied(
                0x6A80,
                lambda alg=alg: piv.generate_key(SLOT.ATTESTATION, alg),
                f"unsupported F9 algorithm {alg.name} is rejected",
            )
        external = ec.generate_private_key(ec.SECP256R1())
        for alg in (
            KEY_TYPE.ECCP256,
            KEY_TYPE.ECCP384,
            KEY_TYPE.RSA2048,
            KEY_TYPE.RSA3072,
            KEY_TYPE.RSA4096,
        ):
            public = piv.generate_key(SLOT.ATTESTATION, alg)
            custom = issuer_certificate(public, external)
            piv.put_certificate(SLOT.ATTESTATION, custom)
            leaf = piv.attest_key(SLOT.AUTHENTICATION)
            leaf.verify_directly_issued_by(custom)
            check(
                public_bytes(leaf.public_key()) == public_bytes(target)
                and piv.get_slot_metadata(SLOT.ATTESTATION).generated,
                f"generated F9 {alg.name} signs independently verified statements under custom issuer",
            )
        for private in (
            ec.generate_private_key(ec.SECP384R1()),
            rsa.generate_private_key(65537, 2048),
        ):
            custom = issuer_certificate(private.public_key(), external)
            piv.put_key(SLOT.ATTESTATION, private)
            piv.put_certificate(SLOT.ATTESTATION, custom)
            leaf = piv.attest_key(SLOT.AUTHENTICATION)
            leaf.verify_directly_issued_by(custom)
            check(
                not piv.get_slot_metadata(SLOT.ATTESTATION).generated,
                f"imported F9 {type(private).__name__} is the actual attesting key",
            )
        saved_issuer = der(custom)
        saved_public = public_bytes(custom.public_key())
        mismatched = issuer_certificate(
            rsa.generate_private_key(65537, 2048).public_key(), external
        )
        piv.put_certificate(SLOT.ATTESTATION, mismatched)
        invalid_leaf = piv.attest_key(SLOT.AUTHENTICATION)
        try:
            invalid_leaf.verify_directly_issued_by(mismatched)
        except InvalidSignature:
            check(
                True,
                "mismatched replacement certificate remains loadable but its attestation fails independent signature verification",
            )
        else:
            raise AssertionError("mismatched issuer unexpectedly verifies")
        check(
            der(piv.get_certificate(SLOT.ATTESTATION)) == der(mismatched),
            "mismatched F9 certificate is retained rather than silently repaired",
        )
        invalid_object = bytes(Tlv(0x70, b"invalid DER fixture"))
        piv.put_object(0x5FFF01, invalid_object)
        old_ciphertext = (directory / "state.bin").read_bytes()
        denied(
            0x6A80,
            lambda: piv.attest_key(SLOT.AUTHENTICATION),
            "malformed stored issuer cannot produce an attestation",
        )
        check(
            (directory / "state.bin").read_bytes() == old_ciphertext
            and piv.get_object(0x5FFF01) == invalid_object,
            "failed attestation preserves malformed issuer and durable state",
        )
        piv.put_certificate(SLOT.ATTESTATION, custom)
        piv.put_object(0x5FFF05, b"reset removes user data")
        oath = OathSession(connection)
        oath_credential = oath.put_credential(
            CredentialData(
                "PIV reset isolation",
                OATH_TYPE.HOTP,
                HASH_ALGORITHM.SHA1,
                b"12345678901234567890",
                digits=6,
            )
        )
        check(
            [oath.calculate_code(oath_credential).value for _ in range(2)]
            == ["755224", "287082"],
            "independent OATH HOTP fixture advances before PIV reset",
        )
        piv = PivSession(connection)
        piv.reset()
        check(
            der(piv.get_certificate(SLOT.ATTESTATION)) == saved_issuer
            and public_bytes(piv.get_slot_metadata(SLOT.ATTESTATION).public_key)
            == saved_public,
            "PIV app reset retains replacement F9 key and certificate",
        )
        denied(
            0x6A88,
            lambda: piv.get_slot_metadata(SLOT.AUTHENTICATION),
            "PIV reset clears generated user private key",
        )
        denied(
            0x6A82,
            lambda: piv.get_object(0x5FFF05),
            "PIV reset clears user data objects",
        )
        check(
            piv.get_pin_metadata().default_value
            and piv.get_pin_metadata().attempts_remaining == 3
            and piv.get_object(0x7E) == discovery,
            "reset restores defaults and immutable Discovery",
        )
        oath = OathSession(connection)
        check(
            len(oath.list_credentials()) == 1
            and oath.calculate_code(oath_credential).value == "359152",
            "PIV reset preserves other application's OATH key and durable HOTP counter",
        )
        connection = fixture.restart()
        piv = PivSession(connection)
        check(
            der(piv.get_certificate(SLOT.ATTESTATION)) == saved_issuer,
            "replacement F9 survives app reset followed by process restart",
        )
        piv.authenticate(DEFAULT_MANAGEMENT_KEY)
        target = piv.generate_key(SLOT.AUTHENTICATION, KEY_TYPE.ECCP256)
        piv.attest_key(SLOT.AUTHENTICATION).verify_directly_issued_by(custom)
        check(True, "retained custom F9 signs newly generated user key after reset")
        piv.delete_certificate(SLOT.ATTESTATION)
        piv.reset()
        connection = fixture.restart()
        piv = PivSession(connection)
        denied(
            0x6A82,
            lambda: piv.get_certificate(SLOT.ATTESTATION),
            "deliberately deleted F9 certificate is not silently regenerated after reset/restart",
        )
        check(
            public_bytes(piv.get_slot_metadata(SLOT.ATTESTATION).public_key)
            == saved_public,
            "deleted F9 certificate leaves its private key metadata intact",
        )
        fixture.stop()

        legacy_dir = directory / "legacy"
        legacy_dir.mkdir()
        legacy = EncryptedState(legacy_dir / "state.bin")
        old = legacy.data["piv"]
        previous_issuer = bytes.fromhex(old["objects"][str(0x5FFF01)])
        old["development_ca"] = old["keys"].pop(str(0xF9))["key"]
        old["development_ca_certificate"] = Tlv.unpack(0x70, previous_issuer).hex()
        old["objects"][str(0x5FFF05)] = b"existing object".hex()
        legacy_user_key = ec.generate_private_key(ec.SECP256R1())
        old["keys"][str(int(SLOT.AUTHENTICATION))] = {
            "key": dump_key(legacy_user_key),
            "alg": int(KEY_TYPE.ECCP256),
            "pin_policy": int(PIN_POLICY.ONCE),
            "touch_policy": int(TOUCH_POLICY.NEVER),
            "generated": True,
        }
        legacy.flush()
        previous_issuer = x509.load_der_x509_certificate(
            Tlv.unpack(0x70, previous_issuer)
        )
        legacy_fixture = Fixture(root, legacy_dir, ifd_driver)
        try:
            piv = PivSession(legacy_fixture.start())
            check(
                der(piv.get_certificate(SLOT.ATTESTATION)) == der(previous_issuer)
                and piv.get_object(0x5FFF05) == b"existing object",
                "legacy lazy-CA state migrates to F9 while preserving issuer certificate and other objects",
            )
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
            piv.verify_pin("123456")
            migration_message = b"preserved user key after F9 migration"
            signature = piv.sign(
                SLOT.AUTHENTICATION,
                KEY_TYPE.ECCP256,
                migration_message,
                hashes.SHA256(),
            )
            legacy_user_key.public_key().verify(
                signature, migration_message, ec.ECDSA(hashes.SHA256())
            )
            check(
                public_bytes(piv.get_slot_metadata(SLOT.AUTHENTICATION).public_key)
                == public_bytes(legacy_user_key.public_key()),
                "legacy migration preserves existing user private key proven by independent signature",
            )
            piv.attest_key(SLOT.AUTHENTICATION).verify_directly_issued_by(
                previous_issuer
            )
            check(
                True,
                "migrated F9 retains original private key verified through independent certificate signature",
            )
        finally:
            legacy_fixture.stop()
        completed = True
    finally:
        fixture.stop()
        report.write_text(
            json.dumps(
                {
                    "passed": completed,
                    "tests": tests,
                    "scope": "fresh software card; independent SDK and crypto; direct IFD ABI"
                    if ifd_driver
                    else "fresh software card; independent SDK and crypto over CCID socket",
                    "physical_device_access": False,
                    "manufacturer_trust_reproduced": False,
                    "differential_firmware_verification": False,
                    "unverified": [
                        "reference status at F9/readonly/malformed-input rejection boundaries",
                        "exact replacement-certificate parsing restrictions and firmware allocation overhead",
                    ],
                },
                indent=2,
            )
            + "\n"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--ifd-driver", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(
        prefix="ske-pivprof-", dir=args.work_dir or "/tmp"
    ) as directory:
        run(
            Path(__file__).resolve().parents[1],
            Path(directory),
            args.report.resolve(),
            args.ifd_driver,
        )


if __name__ == "__main__":
    main()
