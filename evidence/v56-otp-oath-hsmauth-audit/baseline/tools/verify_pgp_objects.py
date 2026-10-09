#!/usr/bin/env python3
"""Verify OpenPGP public profile, storage boundaries and access on fresh cards.

Independent SDK/crypto and saved read-only reference bytes. All writes and PIN
commands target fresh software fixtures; never a physical reader.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from emucard.core import EncryptedState, dump_key
from verify_smartcard import Fixture, certificate
from yubikit.core import Tlv
from yubikit.core.smartcard import ApduError
from yubikit.openpgp import KEY_REF, OpenPgpSession


def encoded(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def public(key):
    return key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def run(root, directory, report, ifd_driver=None):
    fixture = Fixture(root, directory, ifd_driver)
    checks = []
    passed = False
    reference = json.loads((root / "openpgp-reference-observation.json").read_text())

    def check(condition, name):
        if not condition:
            raise AssertionError(name)
        checks.append({"name": name, "passed": True})
        print("PASS", name, flush=True)

    def denied(sw, operation, name, state_dir=directory):
        before = (state_dir / "state.bin").read_bytes()
        try:
            operation()
        except ApduError as error:
            check(
                error.sw == sw and (state_dir / "state.bin").read_bytes() == before,
                name + "; persistent state unchanged",
            )
        else:
            raise AssertionError("accepted forbidden OpenPGP request: " + name)

    try:
        connection = fixture.start()
        pgp = OpenPgpSession(connection)

        def get(oid):
            return pgp.protocol.send_apdu(0, 0xCA, oid >> 8, oid & 255)

        def put(oid, value):
            return pgp.protocol.send_apdu(0, 0xDA, oid >> 8, oid & 255, value)

        app = Tlv.parse_dict(Tlv.unpack(0x6E, get(0x6E)))
        discretionary = Tlv.parse_dict(app[0x73])
        check(
            discretionary[0xC0].hex() == reference["public_objects"]["c0"],
            "extended capability bytes exactly match saved public firmware-5.7.4 reference",
        )
        actual_layout = {
            "top_level_value_lengths": {
                f"{tag:x}": len(value) for tag, value in app.items()
            },
            "discretionary_value_lengths": {
                f"{tag:x}": len(value) for tag, value in discretionary.items()
            },
        }
        check(
            actual_layout == reference["application_related_layout"],
            "fresh application template tag placement and lengths match measured reference schema",
        )
        for oid in (0x5F52, 0x7F66, 0x7F74):
            check(
                get(oid).hex() == reference["public_objects"][f"{oid:x}"],
                f"direct public object {oid:x} bytes exactly match saved reference",
            )
        check(
            app[0x5F52].hex() == reference["application_related_public_fields"]["5f52"]
            and app[0x7F74].hex()
            == reference["application_related_public_fields"]["7f74"]
            and discretionary[0x7F66].hex()
            == reference["application_related_public_fields"]["discretionary_7f66"],
            "nested public capability fields match captured reference bytes",
        )
        for oid in (0xC1, 0xC2, 0xC3, 0xDA):
            check(
                discretionary[oid].hex()
                == reference["algorithm_attributes"][f"{oid:x}"],
                f"fresh algorithm attributes {oid:x} match observed RSA2048 profile",
            )
        check(
            discretionary[0xDE] == bytes.fromhex("0100020003008101"),
            "key information includes all three empty user keys and own generated attestation key",
        )
        metadata = pgp.get_application_related_data()
        caps = metadata.discretionary.extended_capabilities
        check(
            caps.challenge_max_length == 3070
            and caps.certificate_max_length == 2048
            and caps.special_do_max_length == 255,
            "independent SDK decodes measured 3070/2048/255 capability ceilings",
        )
        check(
            int(metadata.general_feature_management) == 0x20
            and metadata.extended_length_info is None,
            "SDK observes button flag and firmware-specific discretionary extended-length placement",
        )
        own_issuer = pgp.get_certificate(KEY_REF.ATT)
        check(
            isinstance(own_issuer.public_key(), rsa.RSAPublicKey)
            and own_issuer.public_key().key_size == 2048
            and "Local software" in own_issuer.subject.rfc4514_string(),
            "own attestation issuer uses observed RSA2048 profile without factory trust",
        )
        denied(
            0x6B00,
            lambda: get(0xC0),
            "direct C0 query matches measured reference 6B00 response",
        )

        for size in (1, 256, 2048, 3070):
            check(
                len(pgp.get_challenge(size)) == size,
                f"SDK GET CHALLENGE returns complete requested {size}-byte response",
            )
        denied(
            0x6700,
            lambda: pgp.protocol.send_apdu(0, 0x84, 0, 0, le=3071),
            "GET CHALLENGE rejects beyond declared maximum",
        )
        denied(
            0x6700,
            lambda: pgp.protocol.send_apdu(0, 0x84, 0, 0),
            "GET CHALLENGE requires Le",
        )
        denied(
            0x6A86,
            lambda: pgp.protocol.send_apdu(0, 0x84, 1, 0, le=8),
            "GET CHALLENGE rejects malformed header",
        )

        for oid in (0x101, 0x102, 0x103, 0x104):
            denied(
                0x6982,
                lambda oid=oid: put(oid, b"unauthorized"),
                f"private object {oid:x} write requires its specific verified PIN",
            )
        pgp.verify_pin("123456")
        for oid in (0x101, 0x103):
            denied(
                0x6982,
                lambda oid=oid: put(oid, b"wrong PIN reference"),
                f"signature-only PIN 81 cannot authorize object {oid:x} writes",
            )
        pgp.verify_pin("123456", extended=True)
        for oid in (0x101, 0x103):
            value = bytes([oid & 255]) * 255
            put(oid, value)
            check(
                get(oid) == value,
                f"PW1 reference 82 authorizes complete 255-byte object {oid:x}",
            )
            denied(
                0x6A84,
                lambda oid=oid: put(oid, bytes(256)),
                f"object {oid:x} rejects 256-byte replacement",
            )
        for oid in (0x102, 0x104):
            denied(
                0x6982,
                lambda oid=oid: put(oid, b"no administrator"),
                f"user PIN 82 cannot authorize administrator object {oid:x}",
            )
        pgp.verify_admin("12345678")
        for oid in (0x102, 0x104):
            value = bytes([oid & 255]) * 255
            put(oid, value)
            check(
                get(oid) == value,
                f"administrator authorizes complete 255-byte object {oid:x}",
            )
            denied(
                0x6A84,
                lambda oid=oid: put(oid, bytes(256)),
                f"object {oid:x} rejects 256-byte replacement",
            )
        connection = fixture.restart()
        pgp = OpenPgpSession(connection)
        for oid in (0x101, 0x102):
            check(
                get(oid) == bytes([oid & 255]) * 255,
                f"public private-use object {oid:x} persists and is readable without PIN",
            )
        for oid in (0x103, 0x104):
            denied(
                0x6982,
                lambda oid=oid: get(oid),
                f"protected private-use object {oid:x} remains PIN protected after restart",
            )
        pgp.verify_pin("123456", extended=True)
        check(get(0x103) == b"\x03" * 255, "private-use object 103 read accepts PIN 82")
        denied(
            0x6982,
            lambda: get(0x104),
            "user PIN never unlocks administrator-only object 104 read",
        )
        pgp.verify_admin("12345678")
        check(
            get(0x104) == b"\x04" * 255,
            "administrator private-use object survives restart",
        )

        for oid, limit, byte in (
            (0x5B, 39, b"N"),
            (0x5E, 255, b"L"),
            (0x5F50, 255, b"U"),
        ):
            value = byte * limit
            put(oid, value)
            check(
                get(oid) == value,
                f"data object {oid:x} accepts its {limit}-byte ceiling",
            )
            denied(
                0x6A84,
                lambda oid=oid, limit=limit: put(oid, bytes(limit + 1)),
                f"object {oid:x} rejects value one byte over declared ceiling",
            )
            put(oid, b"")
            check(get(oid) == b"", f"empty PUT clears variable object {oid:x}")
        put(0x5F2D, b"endeesfr")
        put(0x5F35, b"9")
        put(0x5B, b"LOCAL<<SOFTWARE")
        cardholder = Tlv.parse_dict(Tlv.unpack(0x65, get(0x65)))
        check(
            cardholder == {0x5B: b"LOCAL<<SOFTWARE", 0x5F2D: b"endeesfr", 0x5F35: b"9"},
            "cardholder template reflects bounded name, language pairs and ASCII sex value",
        )
        for size in (1, 3):
            denied(
                0x6A80,
                lambda size=size: put(0x5F2D, bytes(size)),
                f"language preference rejects unpaired {size}-byte value",
            )
        denied(
            0x6A84,
            lambda: put(0x5F2D, b"endeesfrit"),
            "language preference rejects over eight bytes",
        )
        for value in (b"", b"01", b"3", b"\x01"):
            denied(
                0x6A80,
                lambda value=value: put(0x5F35, value),
                f"sex data rejects noncanonical {value.hex() or 'empty'} value",
            )

        for oid in (0xC7, 0xC8, 0xC9, 0xDB, 0xCA, 0xCB, 0xCC, 0xDC):
            value = bytes([oid]) * 20
            put(oid, value)
            check(get(oid) == value, f"fingerprint {oid:x} stores exact 20-byte value")
        for size in (19, 21):
            denied(
                0x6A80,
                lambda size=size: put(0xC7, bytes(size)),
                f"fingerprint rejects {size}-byte value",
            )
        for oid in (0xCE, 0xCF, 0xD0, 0xDD):
            value = (oid * 1000).to_bytes(4, "big")
            put(oid, value)
            check(
                get(oid) == value,
                f"generation time {oid:x} stores exact four-byte value",
            )
        for size in (3, 5):
            denied(
                0x6A80,
                lambda size=size: put(0xCE, bytes(size)),
                f"generation time rejects {size}-byte value",
            )
        denied(
            0x6A80,
            lambda: put(0xD6, b"\x01\0"),
            "UIF write cannot change button feature identifier",
        )
        for oid in (0xC1, 0xF9):
            denied(
                0x6A84,
                lambda oid=oid: put(oid, bytes(256)),
                f"special object {oid:x} enforces 255-byte outer ceiling before parsing",
            )
        for oid in (
            0x4F,
            0x5F52,
            0x6E,
            0x7F66,
            0x7F74,
            0xC0,
            0x7A,
            0x93,
            0xDE,
            0xFA,
            0xD1,
            0xD2,
            0xD5,
            0x1234,
        ):
            denied(
                0x6B00,
                lambda oid=oid: put(oid, b"overwrite"),
                f"read-only or unsupported object {oid:x} refuses silent PUT success",
            )
        pgp.set_reset_code("87654321")
        denied(
            0x6B00,
            lambda: get(0xD3),
            "Resetting Code is write-only even for verified administrator",
        )

        for index in range(4):
            pgp.protocol.send_apdu(0, 0xA5, index, 4, bytes.fromhex("60045c027f21"))
            value = bytes([index + 1]) * 2048
            put(0x7F21, value)
            check(
                get(0x7F21) == value,
                f"certificate occurrence {index} accepts opaque 2048-byte value",
            )
            denied(
                0x6A84,
                lambda: put(0x7F21, bytes(2049)),
                f"certificate occurrence {index} rejects 2049-byte replacement",
            )
            put(0x7F21, b"")
            check(
                get(0x7F21) == b"",
                f"certificate occurrence {index} clears with empty PUT",
            )
        connection = fixture.restart()
        pgp = OpenPgpSession(connection)
        check(
            get(0xFC) == b"",
            "deliberately cleared own attestation certificate is not regenerated on restart",
        )
        check(
            get(0x5F35) == b"9"
            and get(0x5F2D) == b"endeesfr"
            and get(0xC7) == b"\xc7" * 20
            and get(0xCE) == (0xCE * 1000).to_bytes(4, "big"),
            "bounded fields and fixed metadata persist through restart",
        )
        pgp.verify_pin("123456", extended=True)
        for oid in (0x101, 0x103):
            put(oid, b"")
            check(get(oid) == b"", f"user can clear protected variable object {oid:x}")
        fixture.stop()

        legacy_dir = directory / "legacy"
        legacy_dir.mkdir()
        state = EncryptedState(legacy_dir / "state.bin")
        d = state.data["openpgp"]
        legacy_root = ec.generate_private_key(ec.SECP256R1())
        legacy_user = ec.generate_private_key(ec.SECP256R1())
        root_certificate = certificate(legacy_root)
        d["keys"].update(
            {
                "129": {"key": dump_key(legacy_root), "generated": True},
                "1": {"key": dump_key(legacy_user), "generated": True},
            }
        )
        d["objects"].update(
            {
                str(0xDA): "132a8648ce3d030107",
                str(0xC1): "132a8648ce3d030107",
                str(0xFC): encoded(root_certificate).hex(),
                str(0x5F50): (b"legacy URL" * 100).hex(),
                str(0x101): (b"legacy private value" * 20).hex(),
                str(0xD1): b"previous unsupported write".hex(),
            }
        )
        state.flush()
        old_url, old_private = (
            bytes.fromhex(d["objects"][str(0x5F50)]),
            bytes.fromhex(d["objects"][str(0x101)]),
        )
        legacy_fixture = Fixture(root, legacy_dir, ifd_driver)
        try:
            connection = legacy_fixture.start()
            pgp = OpenPgpSession(connection)
            check(
                get(0x5F50) == old_url and get(0x101) == old_private,
                "legacy oversized values remain readable without truncation or deletion",
            )
            check(
                encoded(pgp.get_certificate(KEY_REF.ATT)) == encoded(root_certificate),
                "existing ECC own attestation issuer is preserved instead of replaced by new RSA default",
            )
            denied(
                0x6B00,
                lambda: get(0xD1),
                "legacy unsupported write cannot expose write-only key material",
                legacy_dir,
            )
            pgp.verify_pin("123456")
            message = b"preserved legacy OpenPGP user key"
            legacy_user.public_key().verify(
                pgp.sign(message, hashes.SHA256()), message, ec.ECDSA(hashes.SHA256())
            )
            check(
                True,
                "legacy user private key preserved and independently verifies a fresh SDK signature",
            )
            pgp.verify_pin("123456", extended=True)
            leaf = pgp.attest_key(KEY_REF.SIG)
            leaf.verify_directly_issued_by(root_certificate)
            check(
                public(leaf.public_key()) == public(legacy_user.public_key()),
                "legacy own issuer private key independently verifies retained user-key attestation",
            )
            pgp.verify_admin("12345678")
            denied(
                0x6A84,
                lambda: put(0x5F50, old_url),
                "new oversized replacement remains rejected without damaging legacy URL",
                legacy_dir,
            )
            put(0x5F50, b"https://example.test/own-key")
            put(0x101, b"")
            check(
                get(0x5F50) == b"https://example.test/own-key" and get(0x101) == b"",
                "legacy oversized objects can recover through bounded replacement and deletion",
            )
        finally:
            legacy_fixture.stop()
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
                    "reference": "openpgp-reference-observation.json; only captured public metadata compared",
                    "physical_device_access_in_this_verifier": False,
                    "manufacturer_trust_reproduced": False,
                    "reference_storage_write_pin_or_challenge_boundaries_measured": False,
                    "sdk_notes": [
                        "pinned yubikit.openpgp.DO.LANGUAGE is EF2D; correct ISO 5F2D uses raw SDK APDU path"
                    ],
                    "unverified": [
                        "exact firmware storage/rejection/header/SCP allocation boundaries",
                        "reference data-content parsing tolerance and constructed/aggregate PUT behavior",
                        "actual modified-emulator OS enumeration, crypto and touch timing on reference",
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
        prefix="ske-pgpdo-", dir=args.work_dir or "/tmp"
    ) as directory:
        run(
            Path(__file__).resolve().parents[1],
            Path(directory),
            args.report.resolve(),
            args.ifd_driver,
        )


if __name__ == "__main__":
    main()
