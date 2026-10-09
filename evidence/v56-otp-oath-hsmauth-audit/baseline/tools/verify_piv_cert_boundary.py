#!/usr/bin/env python3
"""Check the documented PIV certificate byte limit through the stock SDK.

The 3052-byte limit is public Yubico documentation. The rejection status is a
software model pending a physical differential test. This opens no OS reader.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from yubikit.core import Tlv
from yubikit.core.smartcard import ApduError, SmartCardProtocol
from yubikit.piv import DEFAULT_MANAGEMENT_KEY, OBJECT_ID, SLOT, PivSession

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from emucard.core import Card, EmulatorConnection, EncryptedState


def run(work_dir: Path, report: Path) -> None:
    checks: list[dict[str, object]] = []

    def check(condition: bool, name: str) -> None:
        if not condition:
            raise AssertionError(name)
        checks.append({"name": name, "passed": True})
        print("PASS", name, flush=True)

    def denied(action, name: str) -> None:
        try:
            action()
        except ApduError as error:
            check(error.sw == 0x6A80, name)
        else:
            raise AssertionError("oversized certificate accepted: " + name)

    def encoded_object(size: int) -> bytes:
        return Tlv(0x70, b"x" * size) + Tlv(0x71, b"\0") + Tlv(0xFE)

    signer = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "own-boundary")])

    def certificate(extension_size: int) -> x509.Certificate:
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(signer.public_key())
            .serial_number(1)
            .not_valid_before(datetime.datetime(2025, 1, 1))
            .not_valid_after(datetime.datetime(2035, 1, 1))
            .add_extension(
                x509.UnrecognizedExtension(
                    x509.ObjectIdentifier("1.3.6.1.4.1.55555.1"),
                    b"x" * extension_size,
                ),
                critical=False,
            )
            .sign(signer, None)
        )

    work_dir.mkdir(parents=True, exist_ok=True)
    state_path = work_dir / "piv-cert-boundary.bin"
    connection = EmulatorConnection(Card(EncryptedState(state_path), lambda _: True))
    piv = PivSession(connection)
    piv.authenticate(DEFAULT_MANAGEMENT_KEY)
    piv.protocol = SmartCardProtocol(connection)
    piv.protocol.configure(piv.version, force_short=True)

    accepted = encoded_object(3052)
    piv.put_object(OBJECT_ID.AUTHENTICATION, accepted)
    check(piv.get_object(OBJECT_ID.AUTHENTICATION) == accepted,
          "SDK accepts a 3052-byte certificate in the authentication object")
    old_state = hashlib.sha256(state_path.read_bytes()).digest()
    denied(lambda: piv.put_object(OBJECT_ID.AUTHENTICATION, encoded_object(3053)),
           "SDK rejects a 3053-byte certificate in the authentication object")
    check(hashlib.sha256(state_path.read_bytes()).digest() == old_state,
          "rejected replacement leaves encrypted state unchanged")
    check(piv.get_object(OBJECT_ID.AUTHENTICATION) == accepted,
          "rejected replacement retains the accepted certificate")

    piv.put_object(OBJECT_ID.RETIRED20, accepted)
    check(piv.get_object(OBJECT_ID.RETIRED20) == accepted,
          "retired certificate object accepts 3052 bytes")
    denied(lambda: piv.put_object(OBJECT_ID.RETIRED20, encoded_object(3053)),
           "retired certificate object rejects 3053 bytes")

    ordinary = encoded_object(3053)
    piv.put_object(0x5FFF05, ordinary)
    check(piv.get_object(0x5FFF05) == ordinary,
          "ordinary data objects retain their existing buffer limit")

    valid = certificate(2802)
    oversized = certificate(2803)
    der = valid.public_bytes(serialization.Encoding.DER)
    check(len(der) == 3052 and len(oversized.public_bytes(serialization.Encoding.DER)) == 3053,
          "independent valid X.509 DER reaches both sides of the byte boundary")
    piv.put_certificate(SLOT.SIGNATURE, valid)
    check(piv.get_certificate(SLOT.SIGNATURE).public_bytes(serialization.Encoding.DER) == der,
          "stock SDK stores and reloads a valid 3052-byte certificate")
    denied(lambda: piv.put_certificate(SLOT.SIGNATURE, oversized),
           "stock SDK rejects a valid 3053-byte certificate")
    check(piv.get_certificate(SLOT.SIGNATURE).public_bytes(serialization.Encoding.DER) == der,
          "rejected X.509 replacement retains the accepted certificate")

    reopened = PivSession(EmulatorConnection(Card(EncryptedState(state_path), lambda _: True)))
    check(reopened.get_object(OBJECT_ID.AUTHENTICATION) == accepted
          and reopened.get_object(OBJECT_ID.RETIRED20) == accepted,
          "accepted certificate objects survive encrypted-state reload")

    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps({
        "passed": True,
        "count": len(checks),
        "tests": checks,
        "documented_certificate_limit": 3052,
        "reference": "https://docs.yubico.com/yesdk/users-manual/application-piv/cert-size.html",
        "physical_device_access": False,
        "exact_firmware_rejection_status_verified": False,
    }, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    run(args.work_dir, args.report)
