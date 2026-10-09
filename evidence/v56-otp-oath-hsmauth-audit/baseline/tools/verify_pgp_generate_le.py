#!/usr/bin/env python3
"""Check malformed OpenPGP GENERATE APDUs against fresh software cards."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from emucard.core import Apdu
from verify_smartcard import Fixture
from yubikit.core.smartcard import ApduError, ExtendedApduFormatter
from yubikit.openpgp import KEY_REF, OID, OpenPgpSession


def public_der(key):
    return key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def status(operation):
    try:
        operation()
    except ApduError as error:
        return error.sw
    return 0x9000


def capture(connection):
    sent = []
    original = connection.send_and_receive

    def send(apdu):
        sent.append(bytes(apdu))
        return original(apdu)

    connection.send_and_receive = send
    return sent


def run(root, expect, ifd_driver):
    observations = {}
    formatter = ExtendedApduFormatter(65535)
    with tempfile.TemporaryDirectory(prefix="ske-pgp-gen-", dir="/tmp") as base:
        for le in (1, 16):
            label = f"le{le}"
            directory = Path(base) / label
            directory.mkdir()
            fixture = Fixture(root, directory, ifd_driver)
            try:
                connection = fixture.start()
                sent = capture(connection)
                pgp = OpenPgpSession(connection)
                pgp.verify_admin("12345678")
                original_key = pgp.generate_ec_key(KEY_REF.SIG, OID.SECP256R1)
                original_public = public_der(original_key)
                normal_generate = next(item for item in reversed(sent) if item[1] == 0x47)
                observations[label + "_normal_sdk_le_absent"] = (
                    Apdu.decode(normal_generate).le is None
                )
                pgp.verify_pin("123456")
                message = b"OpenPGP GENERATE Le boundary"
                signature = pgp.sign(message, hashes.SHA256())
                original_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
                observations[label + "_initial_signature_verified"] = True
                observations[label + "_initial_counter"] = pgp.get_signature_counter()

                crt = bytes(KEY_REF.SIG.crt)
                wire = formatter.format_apdu(0, 0x47, 0x80, 0, crt, le)
                observations[label + "_decoded_le"] = Apdu.decode(wire).le
                before = (directory / "state.bin").read_bytes()
                observations[label + "_sw"] = status(
                    lambda: pgp.protocol.send_apdu(0, 0x47, 0x80, 0, crt, le=le)
                )
                sent_generate = next(item for item in reversed(sent) if item[1] == 0x47)
                observations[label + "_sent_wire_matches"] = sent_generate == wire
                observations[label + "_state_unchanged"] = (
                    directory / "state.bin"
                ).read_bytes() == before

                pgp = OpenPgpSession(fixture.restart())
                observed_public = public_der(pgp.get_public_key(KEY_REF.SIG))
                observations[label + "_original_key_persists"] = (
                    observed_public == original_public
                )
                observations[label + "_counter_after_restart"] = (
                    pgp.get_signature_counter()
                )

                connection = fixture.connection
                sent_normal = capture(connection)
                pgp.verify_admin("12345678")
                new_key = pgp.generate_ec_key(KEY_REF.SIG, OID.SECP256R1)
                normal_regenerate = next(
                    item for item in reversed(sent_normal) if item[1] == 0x47
                )
                observations[label + "_normal_regenerate_le_absent"] = (
                    Apdu.decode(normal_regenerate).le is None
                )
                observations[label + "_normal_new_key_differs"] = (
                    public_der(new_key) != observed_public
                )
                observations[label + "_normal_counter_reset"] = (
                    pgp.get_signature_counter() == 0
                )
                pgp.verify_pin("123456")
                signature = pgp.sign(message, hashes.SHA256())
                new_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
                observations[label + "_normal_signature_verified"] = True
                pgp = OpenPgpSession(fixture.restart())
                observations[label + "_normal_key_persists"] = (
                    public_der(pgp.get_public_key(KEY_REF.SIG)) == public_der(new_key)
                )
                observations[label + "_normal_counter_persists"] = (
                    pgp.get_signature_counter() == 1
                )

                # Accept both maximum-length forms alongside the SDK's absent Le.
                pgp.verify_admin("12345678")
                before_max = public_der(pgp.get_public_key(KEY_REF.SIG))
                observations[label + "_max256_sw"] = status(
                    lambda: pgp.protocol.send_apdu(0, 0x47, 0x80, 0, crt, le=256)
                )
                after_max256 = public_der(pgp.get_public_key(KEY_REF.SIG))
                observations[label + "_max256_replaces_key"] = after_max256 != before_max
                observations[label + "_max256_resets_counter"] = (
                    pgp.get_signature_counter() == 0
                )
                max65536_wire = b"\x00\x47\x80\x00\x00\x00\x02" + crt + b"\x00\x00"
                observations[label + "_max65536_decoded_le"] = Apdu.decode(
                    max65536_wire
                ).le
                _response, max65536_sw = fixture.connection.send_and_receive(
                    max65536_wire
                )
                observations[label + "_max65536_sw"] = max65536_sw
                after_max65536 = public_der(pgp.get_public_key(KEY_REF.SIG))
                observations[label + "_max65536_replaces_key"] = (
                    after_max65536 != after_max256
                )
                observations[label + "_max65536_resets_counter"] = (
                    pgp.get_signature_counter() == 0
                )
            finally:
                fixture.stop()

    expected = {}
    for le in (1, 16):
        label = f"le{le}"
        expected.update(
            {
                label + "_normal_sdk_le_absent": True,
                label + "_initial_signature_verified": True,
                label + "_initial_counter": 1,
                label + "_decoded_le": le,
                label + "_sw": 0x9000 if expect == "baseline" else 0x6700,
                label + "_sent_wire_matches": True,
                label + "_state_unchanged": expect == "guarded",
                label + "_original_key_persists": expect == "guarded",
                label + "_counter_after_restart": 0 if expect == "baseline" else 1,
                label + "_normal_regenerate_le_absent": True,
                label + "_normal_new_key_differs": True,
                label + "_normal_counter_reset": True,
                label + "_normal_signature_verified": True,
                label + "_normal_key_persists": True,
                label + "_normal_counter_persists": True,
                label + "_max256_sw": 0x9000,
                label + "_max256_replaces_key": True,
                label + "_max256_resets_counter": True,
                label + "_max65536_decoded_le": 65536,
                label + "_max65536_sw": 0x9000,
                label + "_max65536_replaces_key": True,
                label + "_max65536_resets_counter": True,
            }
        )
    mismatches = {
        name: {"expected": value, "actual": observations.get(name)}
        for name, value in expected.items()
        if observations.get(name) != value
    }
    return {
        "passed": not mismatches,
        "count": len(expected),
        "tests": [
            {"name": name, "passed": name not in mismatches} for name in expected
        ],
        "expect": expect,
        "transport": "direct IFD ABI" if ifd_driver else "private CCID socket",
        "observations": observations,
        "mismatches": mismatches,
        "physical_key_accessed": False,
        "source": "OpenPGP Smart Card Application 3.4.1 section 7.2.14",
        "note": "6700 is an emulator choice; exact physical 5.7.4 Le tolerance/status unmeasured",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--expect", required=True, choices=("baseline", "guarded"))
    parser.add_argument("--ifd-driver", type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    result = run(args.root.resolve(), args.expect, args.ifd_driver)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"passed": result["passed"], "checks": result["count"]}))
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
