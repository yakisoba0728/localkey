#!/usr/bin/env python3
"""Compare malformed OpenPGP PUT DATA APDUs on isolated software cards."""

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
from yubikit.core import InvalidPinError, Tlv
from yubikit.core.smartcard import ApduError, ExtendedApduFormatter
from yubikit.openpgp import DO, KEY_REF, OID, OpenPgpSession


def status(operation):
    try:
        operation()
    except ApduError as error:
        return error.sw
    return 0x9000


def accepted(operation):
    try:
        operation()
    except (ApduError, InvalidPinError):
        return False
    return True


def public_der(key):
    return key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def captured(connection):
    sent = []
    original = connection.send_and_receive

    def send(apdu):
        sent.append(bytes(apdu))
        return original(apdu)

    connection.send_and_receive = send
    return sent


def run(root, expect, ifd_driver):
    formatter = ExtendedApduFormatter(65535)
    observations = {}
    with tempfile.TemporaryDirectory(prefix="ske-pgp-put-", dir="/tmp") as base:
        for kind in ("name", "reset_code", "aut_key"):
            for le in (1, 256):
                label = f"{kind}_le{le}"
                directory = Path(base) / label
                directory.mkdir()
                fixture = Fixture(root, directory, ifd_driver)
                try:
                    connection = fixture.start()
                    sent = captured(connection)
                    pgp = OpenPgpSession(connection)
                    pgp.verify_admin("12345678")
                    if kind == "name":
                        ins, p1, p2, data = 0xDA, 0, 0x5B, b"BAD<<NAME"
                        original_object = pgp.get_data(DO.NAME)
                    elif kind == "reset_code":
                        ins, p1, p2, data = 0xDA, 0, 0xD3, b"87654321"
                    else:
                        ins, p1, p2 = 0xDB, 0x3F, 0xFF
                        data = bytes(Tlv(0x4D, Tlv(0xA4)))
                        original_key = public_der(
                            pgp.generate_ec_key(KEY_REF.AUT, OID.SECP256R1)
                        )

                    wire = formatter.format_apdu(0, ins, p1, p2, data, le)
                    observations[label + "_decoded_le"] = Apdu.decode(wire).le
                    before = (directory / "state.bin").read_bytes()
                    observations[label + "_sw"] = status(
                        lambda: pgp.protocol.send_apdu(0, ins, p1, p2, data, le=le)
                    )
                    observations[label + "_sent_wire_matches"] = sent[-1] == wire
                    observations[label + "_state_unchanged"] = (
                        directory / "state.bin"
                    ).read_bytes() == before

                    connection = fixture.restart()
                    sent_normal = captured(connection)
                    pgp = OpenPgpSession(connection)
                    if kind == "name":
                        observed = pgp.get_data(DO.NAME)
                        observations[label + "_malformed_value_persists"] = (
                            observed == data
                        )
                        observations[label + "_original_value_persists"] = (
                            observed == original_object
                        )
                        pgp.verify_admin("12345678")
                        pgp.put_data(DO.NAME, b"GOOD<<NAME")
                        normal_ins = 0xDA
                    elif kind == "reset_code":
                        observations[label + "_malformed_value_persists"] = accepted(
                            lambda: pgp.reset_pin("654321", reset_code="87654321")
                        )
                        observations[label + "_original_value_persists"] = not observations[
                            label + "_malformed_value_persists"
                        ]
                        pgp.verify_admin("12345678")
                        pgp.set_reset_code("12345678")
                        pgp.reset_pin("111111", reset_code="12345678")
                        normal_ins = 0xDA
                    else:
                        try:
                            observed = public_der(pgp.get_public_key(KEY_REF.AUT))
                        except ApduError:
                            observed = None
                        observations[label + "_malformed_value_persists"] = (
                            observed is None
                        )
                        observations[label + "_original_value_persists"] = (
                            observed == original_key
                        )
                        pgp.verify_admin("12345678")
                        new_key = ec.generate_private_key(ec.SECP256R1())
                        pgp.put_key(KEY_REF.AUT, new_key)
                        normal_ins = 0xDB

                    normal_apdu = next(
                        item for item in reversed(sent_normal) if item[1] == normal_ins
                    )
                    observations[label + "_normal_sdk_le_absent"] = (
                        Apdu.decode(normal_apdu).le is None
                    )
                    pgp = OpenPgpSession(fixture.restart())
                    if kind == "name":
                        observations[label + "_normal_sdk_persists"] = (
                            pgp.get_data(DO.NAME) == b"GOOD<<NAME"
                        )
                    elif kind == "reset_code":
                        observations[label + "_normal_sdk_persists"] = accepted(
                            lambda: pgp.verify_pin("111111")
                        )
                    else:
                        pub = pgp.get_public_key(KEY_REF.AUT)
                        observations[label + "_normal_sdk_persists"] = (
                            public_der(pub) == public_der(new_key.public_key())
                        )
                        pgp.verify_pin("123456", extended=True)
                        message = b"PUT DATA odd key import survives"
                        signature = pgp.authenticate(message, hashes.SHA256())
                        pub.verify(signature, message, ec.ECDSA(hashes.SHA256()))
                        observations[label + "_normal_crypto_works"] = True
                finally:
                    fixture.stop()

    expected = {}
    for kind in ("name", "reset_code", "aut_key"):
        for le in (1, 256):
            label = f"{kind}_le{le}"
            expected[label + "_decoded_le"] = le
            expected[label + "_sw"] = 0x9000 if expect == "baseline" else 0x6700
            expected[label + "_sent_wire_matches"] = True
            expected[label + "_state_unchanged"] = expect == "guarded"
            expected[label + "_malformed_value_persists"] = expect == "baseline"
            expected[label + "_original_value_persists"] = expect == "guarded"
            expected[label + "_normal_sdk_le_absent"] = True
            expected[label + "_normal_sdk_persists"] = True
            if kind == "aut_key":
                expected[label + "_normal_crypto_works"] = True
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
        "source": "OpenPGP Smart Card Application 3.4.1 section 7.2.8",
        "note": "6700 is an emulator choice; physical 5.7.4 malformed-command status/tolerance unmeasured",
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
