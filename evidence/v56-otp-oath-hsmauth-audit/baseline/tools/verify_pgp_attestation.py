#!/usr/bin/env python3
"""Verify own OpenPGP attestation metadata and retained issuer lifecycle.

Fresh software fixtures only. Independent SDK/crypto parse and verify generated
certificates; no physical reader, factory certificate or private key is used.
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
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from emucard.core import EncryptedState
from verify_smartcard import Fixture
from yubikit.core.smartcard import ApduError
from yubikit.oath import HASH_ALGORITHM, OATH_TYPE, CredentialData, OathSession
from yubikit.openpgp import DO, KEY_REF, OID, UIF, KdfNone, OpenPgpSession
from yubikit.piv import SLOT, PivSession


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def public(key):
    return key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def own_issuer(key, label, large_subject=None):
    name = large_subject or x509.Name(
        [x509.NameAttribute(x509.NameOID.COMMON_NAME, "Local software " + label)]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(
            x509.Name(
                [
                    x509.NameAttribute(
                        x509.NameOID.COMMON_NAME, "Local software test root"
                    )
                ]
            )
        )
        .public_key(key.public_key())
        .serial_number(17)
        .not_valid_before(
            datetime.datetime(2001, 2, 3, 4, 5, 6, tzinfo=datetime.timezone.utc)
        )
        .not_valid_after(
            datetime.datetime(2002, 3, 4, 5, 6, 7, tzinfo=datetime.timezone.utc)
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .sign(key, hashes.SHA256())
    )


def decoded(value, tag):
    # An independent minimal DER reader for these primitive extension values.
    if len(value) < 2 or value[0] != tag or value[1] & 0x80:
        raise AssertionError("unexpected primitive extension encoding")
    if len(value) != value[1] + 2:
        raise AssertionError("extension length mismatch")
    return value[2:]


def integer(value):
    number = decoded(value, 2)
    if not number or number[0] & 0x80:
        raise AssertionError("negative or empty public integer")
    if len(number) > 1 and number[0] == 0 and not number[1] & 0x80:
        raise AssertionError("nonminimal public integer")
    return int.from_bytes(number, "big")


def run(root, directory, report, ifd_driver=None):
    # A known independent software serial exercises DER's positive sign byte.
    state = EncryptedState(directory / "state.bin")
    state.data["serial"] = "80000001"
    state.flush()
    fixture = Fixture(root, directory, ifd_driver)
    checks = []
    passed = False

    def check(condition, name):
        if not condition:
            raise AssertionError(name)
        checks.append({"name": name, "passed": True})
        print("PASS", name, flush=True)

    def denied(sw, operation, name):
        before = (directory / "state.bin").read_bytes()
        try:
            operation()
        except ApduError as error:
            check(
                error.sw == sw and (directory / "state.bin").read_bytes() == before,
                name + "; persistent state unchanged",
            )
        else:
            raise AssertionError("accepted forbidden attestation request: " + name)

    try:
        connection = fixture.start()
        piv = PivSession(connection)
        peer_piv = der(piv.get_certificate(SLOT.ATTESTATION))
        oath = OathSession(connection)
        peer_oath = oath.put_credential(
            CredentialData(
                "OpenPGP reset isolation",
                OATH_TYPE.HOTP,
                HASH_ALGORITHM.SHA1,
                b"12345678901234567890",
                digits=6,
            )
        )
        check(
            oath.calculate_code(peer_oath).value == "755224",
            "independent OATH peer advances before OpenPGP reset",
        )
        pgp = OpenPgpSession(connection)
        initial_cert = pgp.get_certificate(KEY_REF.ATT)
        initial_public = public(pgp.get_public_key(KEY_REF.ATT))
        pgp.verify_admin("12345678")
        pgp.generate_ec_key(KEY_REF.SIG, OID.SECP256R1)
        pgp.put_data(DO.NAME, b"RESET<<REMOVES")
        for ins in (0x44, 0xE6):
            denied(
                0x6A86,
                lambda ins=ins: pgp.protocol.send_apdu(0, ins, 1, 0),
                f"lifecycle command {ins:02x} rejects malformed header",
            )
        pgp.reset()
        pgp = OpenPgpSession(connection)
        check(
            der(pgp.get_certificate(KEY_REF.ATT)) == der(initial_cert)
            and public(pgp.get_public_key(KEY_REF.ATT)) == initial_public,
            "app reset preserves preinitialized own issuer certificate and public key",
        )
        check(
            all(
                int(pgp.get_key_information()[slot]) == 0
                for slot in (KEY_REF.SIG, KEY_REF.DEC, KEY_REF.AUT)
            ),
            "app reset removes all three user keys",
        )
        check(
            pgp.get_data(DO.NAME) == b""
            and pgp.get_signature_counter() == 0
            and isinstance(pgp.get_kdf(), KdfNone),
            "app reset removes user objects and restores plain PIN/counter defaults",
        )
        pgp.verify_admin("12345678")
        generated = pgp.generate_ec_key(KEY_REF.SIG, OID.Ed25519)
        pgp.verify_pin("123456", extended=True)
        proof = pgp.attest_key(KEY_REF.SIG)
        proof.verify_directly_issued_by(initial_cert)
        check(
            public(proof.public_key()) == public(generated),
            "retained original own private issuer signs a new generated user key after reset",
        )
        piv = PivSession(connection)
        check(
            der(piv.get_certificate(SLOT.ATTESTATION)) == peer_piv,
            "OpenPGP reset preserves separate PIV own issuer",
        )
        oath = OathSession(connection)
        check(
            len(oath.list_credentials()) == 1
            and oath.calculate_code(peer_oath).value == "287082",
            "OpenPGP reset preserves separate OATH key and durable HOTP counter",
        )
        pgp = OpenPgpSession(connection)
        pgp.verify_admin("12345678")

        # Three roles expose their own fingerprint/date/UIF and only SIG exposes
        # the digital-signature counter. All values belong to this fixture.
        holders = b"REN\xc9<<SOFTWARE"
        pgp.put_data(DO.NAME, holders)
        keys = {
            KEY_REF.SIG: pgp.generate_ec_key(KEY_REF.SIG, OID.Ed25519),
            KEY_REF.DEC: pgp.generate_ec_key(KEY_REF.DEC, OID.X25519),
            KEY_REF.AUT: pgp.generate_ec_key(KEY_REF.AUT, OID.SECP384R1),
        }
        fingerprints = {slot: bytes(range(slot * 16, slot * 16 + 20)) for slot in keys}
        for slot in keys:
            pgp.set_fingerprint(slot, fingerprints[slot])
            pgp.set_generation_time(slot, 0x80000000 + slot)
            pgp.set_uif(slot, UIF.CACHED)
        pgp.verify_pin("123456")
        keys[KEY_REF.SIG].verify(
            pgp.sign(b"owned digital-signature counter", hashes.SHA256()),
            b"owned digital-signature counter",
        )
        pgp.verify_pin("123456", extended=True)
        serials = []
        for slot, pub in keys.items():
            leaf = pgp.attest_key(slot)
            leaf.verify_directly_issued_by(initial_cert)
            check(
                public(leaf.public_key()) == public(pub)
                and leaf.issuer == initial_cert.subject
                and "Local software" in leaf.subject.rfc4514_string(),
                f"{slot.name} own attestation independently verifies public key/issuer/software label",
            )
            check(
                leaf.not_valid_before_utc == initial_cert.not_valid_before_utc
                and leaf.not_valid_after_utc == initial_cert.not_valid_after_utc,
                f"{slot.name} attestation copies exact template validity",
            )
            check(
                leaf.signature_algorithm_oid.dotted_string == "1.2.840.113549.1.1.11"
                and leaf.signature_hash_algorithm.name == "sha256",
                f"{slot.name} RSA issuer uses SHA256 PKCS1v1.5",
            )
            check(
                0 < leaf.serial_number < 1 << 128 and len(der(leaf)) <= 2048,
                f"{slot.name} attestation has positive 128-bit serial profile and bounded certificate",
            )
            serials.append(leaf.serial_number)
            values = {
                int(ext.oid.dotted_string.rsplit(".", 1)[1]): ext.value.value
                for ext in leaf.extensions
                if ext.oid.dotted_string.startswith("1.3.6.1.4.1.41482.5.")
            }
            check(
                set(values)
                == set(range(1, 12)) - ({6} if slot != KEY_REF.SIG else set()),
                f"{slot.name} public extension set includes counter only for SIG",
            )
            check(
                decoded(values[1], 0x0C) == "RENÉ<<SOFTWARE".encode(),
                f"{slot.name} Latin1 cardholder name encodes as DER UTF8String",
            )
            check(
                integer(values[2]) == 1 and decoded(values[3], 4) == b"\x05\x07\x04",
                f"{slot.name} generated software source and compatible firmware fields decode independently",
            )
            check(
                decoded(values[4], 4) == fingerprints[slot]
                and decoded(values[5], 4) == (0x80000000 + slot).to_bytes(4, "big"),
                f"{slot.name} fingerprint and generation date refer to the attested key",
            )
            check(
                values[7] == b"\x02\x05\x00\x80\x00\x00\x01"
                and integer(values[7]) == 0x80000001,
                f"{slot.name} owned card serial retains positive DER integer sign",
            )
            check(
                decoded(values[8], 4) == b"\3"
                and decoded(values[9], 4) == b"\4"
                and decoded(values[10], 4) == decoded(values[11], 4) == b"\0",
                f"{slot.name} key UIF/profile form factor decoded; FIPS/CSPN claims absent",
            )
            check(
                all(
                    not ext.critical
                    for ext in leaf.extensions
                    if ext.oid.dotted_string.startswith("1.3.6.1.4.1.41482.5.")
                ),
                f"{slot.name} public metadata extensions are noncritical",
            )
            if slot == KEY_REF.SIG:
                check(
                    integer(values[6]) == pgp.get_signature_counter() == 1,
                    "SIG attestation captures current counter without incrementing it",
                )
        check(
            len(set(serials)) == 3,
            "independent attestation requests use different random own certificate serials",
        )
        denied(
            0x6E00,
            lambda: pgp.protocol.send_apdu(0, 0xFB, 1, 0),
            "attestation requires proprietary CLA 80",
        )
        denied(
            0x6A86,
            lambda: pgp.protocol.send_apdu(0x80, 0xFB, 1, 1),
            "attestation rejects nonzero P2",
        )
        denied(
            0x6A86,
            lambda: pgp.protocol.send_apdu(0x80, 0xFB, 1, 0, b"x"),
            "attestation rejects unexpected data",
        )
        denied(
            0x6A86,
            lambda: pgp.protocol.send_apdu(0x80, 0xFB, 0x81, 0),
            "attestation issuer cannot attest itself",
        )

        for label, issuer_key in (
            ("EC", ec.generate_private_key(ec.SECP256R1())),
            ("RSA", rsa.generate_private_key(65537, 3072)),
        ):
            pgp.verify_admin("12345678")
            custom = own_issuer(issuer_key, label + " retained issuer")
            pgp.put_key(KEY_REF.ATT, issuer_key)
            pgp.put_certificate(KEY_REF.ATT, custom)
            pgp.set_fingerprint(KEY_REF.ATT, b"\xa5" * 20)
            pgp.set_generation_time(KEY_REF.ATT, 0x80000080)
            if pgp.get_uif(KEY_REF.ATT) != UIF.CACHED_FIXED:
                pgp.set_uif(KEY_REF.ATT, UIF.CACHED_FIXED)
            previous_attrs = bytes(pgp.get_algorithm_attributes(KEY_REF.ATT))
            pgp.reset()
            connection = fixture.restart()
            pgp = OpenPgpSession(connection)
            check(
                der(pgp.get_certificate(KEY_REF.ATT)) == der(custom)
                and public(pgp.get_public_key(KEY_REF.ATT))
                == public(issuer_key.public_key()),
                label
                + " replacement issuer certificate/private-key identity survives reset/restart",
            )
            check(
                bytes(pgp.get_algorithm_attributes(KEY_REF.ATT)) == previous_attrs
                and pgp.get_fingerprints()[KEY_REF.ATT] == b"\xa5" * 20
                and pgp.get_generation_times()[KEY_REF.ATT] == 0x80000080
                and pgp.get_uif(KEY_REF.ATT) == UIF.CACHED_FIXED,
                label
                + " retained issuer preserves own attributes/fingerprint/date/fixed UIF model",
            )
            pgp.verify_admin("12345678")
            user = pgp.generate_ec_key(KEY_REF.AUT, OID.SECP256R1)
            pgp.verify_pin("123456", extended=True)
            proof = pgp.attest_key(KEY_REF.AUT)
            proof.verify_directly_issued_by(custom)
            check(
                public(proof.public_key()) == public(user)
                and proof.not_valid_before_utc == custom.not_valid_before_utc
                and proof.not_valid_after_utc == custom.not_valid_after_utc,
                label
                + " retained private issuer independently signs new key with copied expired-template dates",
            )
            check(
                proof.signature_algorithm_oid.dotted_string
                == (
                    "1.2.840.10045.4.3.2" if label == "EC" else "1.2.840.113549.1.1.11"
                ),
                label + " issuer selects published SHA256 signature encoding",
            )

        # Wrong or malformed template stays opaque; failed attestation never
        # repairs it, rotates the issuer or overwrites a user's certificate.
        pgp.verify_admin("12345678")
        original = pgp.get_certificate(KEY_REF.ATT)
        wrong = own_issuer(
            ec.generate_private_key(ec.SECP256R1()), "mismatched template"
        )
        pgp.put_certificate(KEY_REF.ATT, wrong)
        denied(
            0x6A80,
            lambda: pgp.attest_key(KEY_REF.AUT),
            "mismatched template refuses attestation and retains existing user certificate",
        )
        pgp.reset()
        pgp = OpenPgpSession(connection)
        check(
            der(pgp.get_certificate(KEY_REF.ATT)) == der(wrong)
            and public(pgp.get_public_key(KEY_REF.ATT))
            == public(issuer_key.public_key()),
            "reset retains opaque mismatched template instead of regenerating issuer",
        )
        pgp.verify_admin("12345678")
        pgp.put_data(DO.ATT_CERTIFICATE, b"malformed own template")
        pgp.generate_ec_key(KEY_REF.AUT, OID.SECP256R1)
        pgp.verify_pin("123456", extended=True)
        denied(
            0x6A80,
            lambda: pgp.attest_key(KEY_REF.AUT),
            "malformed template cannot issue certificate and leaves persistent state unchanged",
        )
        pgp.reset()
        connection = fixture.restart()
        pgp = OpenPgpSession(connection)
        check(
            pgp.get_data(DO.ATT_CERTIFICATE) == b"malformed own template",
            "malformed stored template survives reset/restart without silent repair",
        )
        pgp.verify_admin("12345678")
        pgp.put_certificate(KEY_REF.ATT, original)

        # Deliberate certificate/key deletions survive repeated reset/restart.
        pgp.put_data(DO.ATT_CERTIFICATE, b"")
        pgp.reset()
        connection = fixture.restart()
        pgp = OpenPgpSession(connection)
        check(
            pgp.get_data(DO.ATT_CERTIFICATE) == b""
            and public(pgp.get_public_key(KEY_REF.ATT))
            == public(issuer_key.public_key()),
            "deleted issuer certificate stays deleted while private issuer remains after reset/restart",
        )
        pgp.verify_admin("12345678")
        pgp.generate_ec_key(KEY_REF.SIG, OID.Ed25519)
        pgp.verify_pin("123456", extended=True)
        denied(
            0x6A88,
            lambda: pgp.attest_key(KEY_REF.SIG),
            "deleted template never silently returns during attestation",
        )
        pgp.delete_key(KEY_REF.ATT)
        pgp.reset()
        connection = fixture.restart()
        pgp = OpenPgpSession(connection)
        check(
            int(pgp.get_key_information()[KEY_REF.ATT]) == 0
            and pgp.get_data(DO.ATT_CERTIFICATE) == b"",
            "deliberately deleted issuer key and certificate are not resurrected by reset/restart",
        )
        denied(
            0x6A88,
            lambda: pgp.get_public_key(KEY_REF.ATT),
            "deleted own issuer has no public key after reset",
        )

        # A valid stored issuer can still create a leaf exceeding the advertised
        # certificate budget. That failure must preserve the prior user object.
        pgp.verify_admin("12345678")
        large_key = ec.generate_private_key(ec.SECP256R1())
        candidates = []
        for count in range(1, 25):
            subject = x509.Name(
                [
                    x509.NameAttribute(x509.NameOID.COMMON_NAME, "L" * 64)
                    for _ in range(count)
                ]
            )
            candidate = own_issuer(large_key, "long issuer", subject)
            if len(der(candidate)) <= 2048:
                candidates.append(candidate)
        huge = candidates[-1]
        pgp.put_key(KEY_REF.ATT, large_key)
        pgp.put_certificate(KEY_REF.ATT, huge)
        pgp.generate_rsa_key(KEY_REF.SIG, 4096)
        pgp.protocol.send_apdu(0, 0xA5, 2, 4, bytes.fromhex("60045c027f21"))
        pgp.put_data(DO.CARDHOLDER_CERTIFICATE, b"retained previous user certificate")
        pgp.verify_pin("123456", extended=True)
        denied(
            0x6A84,
            lambda: pgp.attest_key(KEY_REF.SIG),
            "oversized generated attestation refuses before overwriting user certificate",
        )
        check(
            pgp.get_data(DO.CARDHOLDER_CERTIFICATE) == b"retained previous user certificate",
            "certificate-budget failure retains previous selected certificate occurrence",
        )
        passed = True
    finally:
        fixture.stop()
        report.write_text(
            json.dumps(
                {
                    "passed": passed,
                    "tests": checks,
                    "scope": "fresh software cards; independent SDK/crypto over direct IFD ABI"
                    if ifd_driver
                    else "fresh software cards; independent SDK/crypto over private CCID socket",
                    "physical_device_access_in_this_verifier": False,
                    "public_reference": "openpgp-reference-observation.json; template firmware extension wrapper measured, generated leaf extensions unmeasured",
                    "manufacturer_trust_reproduced": False,
                    "software_labels_own_serial_and_uncertified_flags": True,
                    "hardware_reset_metadata_uif_or_attestation_rejection_verified": False,
                    "unverified": [
                        "exact physical generated-leaf extension presence/order/encoding and certificate parsing/rejection rules",
                        "exact physical retention/reset of issuer fingerprint/date/UIF metadata",
                        "actual modified-emulator OS enumeration and physical attestation timing",
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
        prefix="ske-pgpatt-", dir=args.work_dir or "/tmp"
    ) as directory:
        run(
            Path(__file__).resolve().parents[1],
            Path(directory),
            args.report.resolve(),
            args.ifd_driver,
        )


if __name__ == "__main__":
    main()
