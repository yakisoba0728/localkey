#!/usr/bin/env python3
"""Exercise every captured public OpenPGP algorithm on fresh software cards.

All generation/import/PIN/crypto commands target opted-in software fixtures.
No physical reader is accessed by this verifier. SDK and cryptography provide
independent algorithm parsing, private keys, signatures and shared secrets.
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
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, x25519
from verify_smartcard import Fixture
from yubikit.core import Tlv
from yubikit.core.smartcard import ApduError
from yubikit.openpgp import KEY_REF, OID, EcAttributes, OpenPgpSession, RsaAttributes


def public(key):
    return key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def wrapped(crt, fields):
    parts = [Tlv(tag, value) for tag, value in fields]
    return Tlv(
        0x4D,
        crt
        + Tlv(0x7F48, b"".join(item[: -item.length] for item in parts))
        + Tlv(0x5F48, b"".join(item.value for item in parts)),
    )


def rsa_fields(key):
    numbers = key.private_numbers()
    size = key.key_size // 16
    return [
        (0x91, b"\x01\0\x01"),
        (0x92, numbers.p.to_bytes(size, "big")),
        (0x93, numbers.q.to_bytes(size, "big")),
    ]


def own_template(pub):
    # A local test root signs a certificate for the unknown generated issuer's
    # public key. Attestation then proves possession without exporting that key.
    root = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [x509.NameAttribute(x509.NameOID.COMMON_NAME, "Local software test issuer")]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
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
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .sign(root, hashes.SHA256())
    )


def run(root, directory, report, ifd_driver=None):
    fixture = Fixture(root, directory, ifd_driver)
    checks, generation, imports = [], [], []
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
            raise AssertionError("accepted forbidden key request: " + name)

    try:
        connection = fixture.start()
        pgp = OpenPgpSession(connection)
        reference = json.loads(
            (root / "openpgp-reference-observation.json").read_text()
        )
        raw = pgp.protocol.send_apdu(0, 0xCA, 0, 0xFA)
        check(
            raw.hex() == reference["algorithm_information"] and len(raw) == 421,
            "complete 421-byte FA response matches saved physical public reference",
        )
        advertised = pgp.get_algorithm_information()
        reference_rows = Tlv.parse_list(
            Tlv.unpack(0xFA, bytes.fromhex(reference["algorithm_information"]))
        )
        check(
            [
                (slot.algorithm_attributes_do, bytes(attr))
                for slot, attrs in advertised.items()
                for attr in attrs
            ]
            == [(row.tag, row.value) for row in reference_rows],
            "independent SDK decodes all captured attributes in their measured order",
        )
        check(
            {slot.name: len(attrs) for slot, attrs in advertised.items()}
            == {"SIG": 11, "DEC": 11, "AUT": 11, "ATT": 10},
            "inventory covers every 43-slot algorithm variant",
        )
        support = pgp.protocol.send_apdu(0, 0xCA, 0, 0x7A)
        support_fields = Tlv.parse_dict(Tlv.unpack(0x7A, support))
        check(
            {
                "outer_tag": "7a",
                "value_lengths": {
                    f"{tag:x}": len(value) for tag, value in support_fields.items()
                },
                "counter_payload_retained": False,
            }
            == reference["security_support_template_layout"]
            and pgp.get_signature_counter() == 0,
            "7A outer wrapper and three-byte counter schema match measured reference; software counter starts at zero",
        )
        pgp.verify_admin("12345678")
        message = b"independent software OpenPGP algorithm verification"

        def exercise(slot, pub, label):
            previous = pgp.get_signature_counter()
            if slot in (KEY_REF.SIG, KEY_REF.AUT):
                pgp.verify_pin("123456", extended=slot == KEY_REF.AUT)
                operation = pgp.sign if slot == KEY_REF.SIG else pgp.authenticate
                signature = operation(message, hashes.SHA256())
                if isinstance(pub, rsa.RSAPublicKey):
                    pub.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
                elif isinstance(pub, ed25519.Ed25519PublicKey):
                    pub.verify(signature, message)
                else:
                    pub.verify(signature, message, ec.ECDSA(hashes.SHA256()))
                check(True, label + " signature independently verifies")
            elif slot == KEY_REF.DEC:
                pgp.verify_pin("123456", extended=True)
                if isinstance(pub, rsa.RSAPublicKey):
                    result = pgp.decrypt(pub.encrypt(message, padding.PKCS1v15()))
                    expected = message
                else:
                    peer = (
                        x25519.X25519PrivateKey.generate()
                        if isinstance(pub, x25519.X25519PublicKey)
                        else ec.generate_private_key(pub.curve)
                    )
                    expected = (
                        peer.exchange(pub)
                        if isinstance(peer, x25519.X25519PrivateKey)
                        else peer.exchange(ec.ECDH(), pub)
                    )
                    result = pgp.decrypt(peer.public_key())
                check(
                    result == expected,
                    label + " decryption/shared secret independently matches",
                )
            else:
                template = own_template(pub)
                pgp.put_certificate(KEY_REF.ATT, template)
                pgp.verify_pin("123456", extended=True)
                leaf = pgp.attest_key(KEY_REF.SIG)
                leaf.verify_directly_issued_by(template)
                check(
                    public(leaf.public_key())
                    == public(pgp.get_public_key(KEY_REF.SIG)),
                    label
                    + " own attestation signature independently verifies without exporting issuer",
                )
            check(
                pgp.get_signature_counter() == previous + (slot == KEY_REF.SIG),
                label + " changes only the digital-signature counter for SIG",
            )

        for slot, variants in advertised.items():
            for attr in variants:
                label = f"generated {slot.name} {bytes(attr).hex()}"
                previous_counter = pgp.get_signature_counter()
                pub = (
                    pgp.generate_rsa_key(slot, attr.n_len)
                    if isinstance(attr, RsaAttributes)
                    else pgp.generate_ec_key(
                        slot, next(oid for oid in OID if bytes(oid) == attr.oid)
                    )
                )
                check(
                    public(pgp.get_public_key(slot)) == public(pub)
                    and int(pgp.get_key_information()[slot]) == 1
                    and pgp.get_signature_counter()
                    == (0 if slot == KEY_REF.SIG else previous_counter),
                    label + " public key/status/counter decoded by independent SDK",
                )
                exercise(slot, pub, label)
                generation.append({"slot": slot.name, "attributes": bytes(attr).hex()})

        private_cache = {}
        for slot, variants in advertised.items():
            if slot == KEY_REF.ATT:
                # An attestation issuer proves a generated user key. Imported
                # user keys must remain ineligible for this generated-key proof.
                pgp.generate_ec_key(KEY_REF.SIG, OID.Ed25519)
            for attr in variants:
                cache_key = (
                    bytes(attr)[1:] if isinstance(attr, EcAttributes) else bytes(attr)
                )
                if cache_key not in private_cache:
                    if isinstance(attr, RsaAttributes):
                        key = rsa.generate_private_key(65537, attr.n_len)
                    elif attr.oid == OID.Ed25519:
                        key = ed25519.Ed25519PrivateKey.generate()
                    elif attr.oid == OID.X25519:
                        key = x25519.X25519PrivateKey.generate()
                    else:
                        oid = next(oid for oid in OID if bytes(oid) == attr.oid)
                        # A leading-zero P-521 scalar makes the 66-byte standard
                        # width explicit instead of depending on random bit size.
                        key = (
                            ec.derive_private_key(1, ec.SECP521R1())
                            if oid == OID.SECP521R1
                            else ec.generate_private_key(getattr(ec, oid.name)())
                        )
                    private_cache[cache_key] = key
                key = private_cache[cache_key]
                previous_counter = pgp.get_signature_counter()
                if (
                    isinstance(key, ec.EllipticCurvePrivateKey)
                    and key.curve.name == "secp521r1"
                ):
                    pgp.set_algorithm_attributes(slot, attr)
                    private = key.private_numbers().private_value.to_bytes(66, "big")
                    pgp.protocol.send_apdu(
                        0, 0xDB, 0x3F, 0xFF, wrapped(slot.crt, [(0x92, private)])
                    )
                else:
                    pgp.put_key(slot, key)
                label = f"imported {slot.name} {bytes(attr).hex()}"
                check(
                    public(pgp.get_public_key(slot)) == public(key.public_key())
                    and int(pgp.get_key_information()[slot]) == 2
                    and pgp.get_signature_counter()
                    == (0 if slot == KEY_REF.SIG else previous_counter),
                    label
                    + " retains independent private key and resets only SIG counter",
                )
                exercise(slot, key.public_key(), label)
                imports.append({"slot": slot.name, "attributes": bytes(attr).hex()})

        pgp.verify_admin("12345678")
        # Raw APDUs bypass the SDK's preflight, so the actual card parser rejects
        # wrong-role/unadvertised attributes without erasing existing keys.
        for slot, invalid in (
            (KEY_REF.SIG, b"\x12" + bytes(OID.SECP256R1)),
            (KEY_REF.AUT, b"\x12" + bytes(OID.SECP256R1)),
            (KEY_REF.ATT, b"\x12" + bytes(OID.SECP256R1)),
            (KEY_REF.DEC, b"\x13" + bytes(OID.SECP256R1)),
            (KEY_REF.SIG, b"\x12" + bytes(OID.X25519)),
            (KEY_REF.AUT, b"\x12" + bytes(OID.X25519)),
            (KEY_REF.ATT, b"\x12" + bytes(OID.X25519)),
            (KEY_REF.DEC, b"\x16" + bytes(OID.Ed25519)),
            (KEY_REF.ATT, b"\x16" + bytes(OID.Ed25519)),
            (KEY_REF.SIG, b"\x13" + bytes(OID.Ed25519)),
            (KEY_REF.DEC, b"\x12" + bytes(OID.Ed25519)),
            (KEY_REF.SIG, b"\x16" + bytes(OID.X25519)),
        ):
            denied(
                0x6A80,
                lambda slot=slot, invalid=invalid: pgp.put_data(
                    slot.algorithm_attributes_do, invalid
                ),
                f"wrong-role {slot.name} attributes {invalid.hex()}",
            )
        for invalid in (
            b"",
            bytes.fromhex("010400001100"),
            bytes.fromhex("010800000000"),
            bytes.fromhex("010800002000"),
            bytes.fromhex("010800001101"),
            bytes.fromhex("010800001102"),
            bytes.fromhex("010800001103"),
            bytes.fromhex("010800001104"),
            bytes.fromhex("01080000110000"),
            b"\x13" + bytes(OID.SECP256R1) + b"\xff",
            b"\x13" + bytes(OID.SECP256R1) + b"\0",
            b"\x13\x2a",
            b"\xff",
        ):
            denied(
                0x6A80,
                lambda invalid=invalid: pgp.put_data(0xC1, invalid),
                f"unadvertised attributes {invalid.hex() or 'empty'}",
            )

        # Rejected imports must preserve an existing same-attribute key: using
        # raw PUT DB avoids the SDK's separate, destructive attribute update.
        rsa_key = private_cache[bytes.fromhex("010800001100")]
        pgp.put_key(KEY_REF.SIG, rsa_key)
        fields = rsa_fields(rsa_key)
        for name, malformed in (
            ("duplicate exponent", [fields[0], *fields]),
            ("wrong field order", [fields[1], fields[0], fields[2]]),
            ("unknown field", [*fields, (0x98, b"x")]),
            (
                "unexpected modulus",
                [
                    *fields,
                    (
                        0x97,
                        rsa_key.private_numbers().public_numbers.n.to_bytes(256, "big"),
                    ),
                ],
            ),
            ("missing prime", fields[:2]),
            ("short prime", [fields[0], (0x92, fields[1][1][1:]), fields[2]]),
            (
                "padded extra prime byte",
                [fields[0], (0x92, b"\0" + fields[1][1]), fields[2]],
            ),
            ("unsupported exponent", [(0x91, b"\0\0\3"), *fields[1:]]),
            ("extra exponent byte", [(0x91, b"\0\x01\0\x01"), *fields[1:]]),
            ("undersized modulus", [fields[0], (0x92, bytes(128)), (0x93, bytes(128))]),
        ):
            denied(
                0x6A80,
                lambda malformed=malformed: pgp.protocol.send_apdu(
                    0, 0xDB, 0x3F, 0xFF, wrapped(KEY_REF.SIG.crt, malformed)
                ),
                "RSA standard import rejects " + name,
            )
        for name, headers, values in (
            ("truncated header", b"\x91", b"x"),
            ("indefinite header", b"\x91\x80", b"x"),
            ("truncated long length", b"\x91\x82\x01", b"x"),
            ("zero length", b"\x91\0", b""),
            ("unconsumed value", b"\x91\x03", b"\x01\0\x01x"),
            ("value underflow", b"\x91\x03", b"x"),
        ):
            data = Tlv(
                0x4D, KEY_REF.SIG.crt + Tlv(0x7F48, headers) + Tlv(0x5F48, values)
            )
            denied(
                0x6A80,
                lambda data=data: pgp.protocol.send_apdu(0, 0xDB, 0x3F, 0xFF, data),
                "import parser rejects " + name,
            )
        denied(
            0x6A86,
            lambda: pgp.protocol.send_apdu(0, 0x47, 0x80, 1, KEY_REF.SIG.crt),
            "key generation rejects nonzero P2",
        )
        denied(
            0x6A86,
            lambda: pgp.protocol.send_apdu(0, 0x47, 0x81, 1, KEY_REF.SIG.crt),
            "public key read rejects nonzero P2",
        )
        pgp.verify_pin("123456")
        rsa_key.public_key().verify(
            pgp.sign(message, hashes.SHA256()),
            message,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        check(
            True,
            "retained RSA key independently signs after all rejected imports and headers",
        )

        # Extended CRT forms are specified for SIG/DEC/AUT; mismatches are invalid.
        ec_key = ec.generate_private_key(ec.SECP256R1())
        scalar = ec_key.private_numbers().private_value.to_bytes(32, "big")
        for slot, tag in (
            (KEY_REF.SIG, 0xB6),
            (KEY_REF.DEC, 0xB8),
            (KEY_REF.AUT, 0xA4),
        ):
            attr = EcAttributes.create(slot, OID.SECP256R1)
            pgp.set_algorithm_attributes(slot, attr)
            crt = Tlv(tag, Tlv(0x84, bytes([slot])))
            pgp.protocol.send_apdu(0, 0xDB, 0x3F, 0xFF, wrapped(crt, [(0x92, scalar)]))
            response = pgp.protocol.send_apdu(0, 0x47, 0x81, 0, crt)
            check(
                Tlv.parse_dict(Tlv.unpack(0x7F49, response))[0x86]
                == ec_key.public_key().public_bytes(
                    serialization.Encoding.X962,
                    serialization.PublicFormat.UncompressedPoint,
                ),
                f"extended CRT {slot.name} imports and reads matching public key",
            )
            denied(
                0x6A80,
                lambda tag=tag, slot=slot: pgp.protocol.send_apdu(
                    0,
                    0xDB,
                    0x3F,
                    0xFF,
                    wrapped(
                        Tlv(tag, Tlv(0x84, bytes([slot % 3 + 1]))), [(0x92, scalar)]
                    ),
                ),
                f"extended CRT {slot.name} rejects mismatched key reference",
            )
        for length in (31, 33):
            denied(
                0x6A80,
                lambda length=length: pgp.protocol.send_apdu(
                    0,
                    0xDB,
                    0x3F,
                    0xFF,
                    wrapped(KEY_REF.SIG.crt, [(0x92, bytes(length))]),
                ),
                f"EC private scalar rejects wrong {length}-byte width",
            )
        for name, value in (("zero", bytes(32)), ("out-of-range", b"\xff" * 32)):
            denied(
                0x6A80,
                lambda value=value: pgp.protocol.send_apdu(
                    0, 0xDB, 0x3F, 0xFF, wrapped(KEY_REF.SIG.crt, [(0x92, value)])
                ),
                "EC scalar rejects " + name,
            )
        pgp.set_algorithm_attributes(
            KEY_REF.SIG, EcAttributes.create(KEY_REF.SIG, OID.SECP521R1)
        )
        denied(
            0x6A80,
            lambda: pgp.protocol.send_apdu(
                0,
                0xDB,
                0x3F,
                0xFF,
                wrapped(KEY_REF.SIG.crt, [(0x92, (1).to_bytes(65, "big"))]),
            ),
            "P-521 scalar requires adjusted 66-byte standard field width",
        )
        pgp.protocol.send_apdu(
            0,
            0xDB,
            0x3F,
            0xFF,
            wrapped(KEY_REF.SIG.crt, [(0x92, (1).to_bytes(66, "big"))]),
        )
        p521_public = public(pgp.get_public_key(KEY_REF.SIG))
        connection = fixture.restart()
        pgp = OpenPgpSession(connection)
        check(
            public(pgp.get_public_key(KEY_REF.SIG)) == p521_public,
            "P-521 imported key persists and public read needs no PIN after restart",
        )
        pgp.verify_pin("123456")
        ec.derive_private_key(1, ec.SECP521R1()).public_key().verify(
            pgp.sign(message, hashes.SHA256()), message, ec.ECDSA(hashes.SHA256())
        )
        check(
            True,
            "retained P-521 private key independently verifies SDK signature after restart",
        )
        passed = True
    finally:
        fixture.stop()
        report.write_text(
            json.dumps(
                {
                    "passed": passed,
                    "tests": checks,
                    "generation_matrix": generation,
                    "import_matrix": imports,
                    "scope": "fresh software cards; independent SDK/crypto over direct IFD ABI"
                    if ifd_driver
                    else "fresh software cards; independent SDK/crypto over private CCID socket",
                    "public_algorithm_inventory_reference": "openpgp-reference-observation.json; GET DATA FA only; no physical key writes",
                    "physical_device_access_in_this_verifier": False,
                    "manufacturer_trust_reproduced": False,
                    "physical_algorithm_write_import_rejection_or_counter_boundaries_measured": False,
                    "sdk_notes": [
                        "pinned SDK EC import uses floor key_size/8; P-521 fixed standard width is sent as raw SDK APDU with 66-byte zero padding"
                    ],
                    "unverified": [
                        "physical acceptance/rejection tolerance of unadvertised attributes and malformed import layouts",
                        "physical key replacement/extended CRT and digital-signature counter behavior",
                        "actual modified-emulator OS discovery and reference crypto/touch timing",
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
        prefix="ske-pgpalgo-", dir=args.work_dir or "/tmp"
    ) as directory:
        run(
            Path(__file__).resolve().parents[1],
            Path(directory),
            args.report.resolve(),
            args.ifd_driver,
        )


if __name__ == "__main__":
    main()
