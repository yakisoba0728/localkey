#!/usr/bin/env python3
"""Audit PSO SIGN and INTERNAL AUTHENTICATE APDU boundaries in software."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from emucard.core import Apdu
from verify_smartcard import Fixture
from yubikit.core.smartcard import ApduError
from yubikit.openpgp import KEY_REF, OID, OpenPgpSession


MESSAGE = b"OpenPGP malformed signing APDU audit"
DIGEST = hashlib.sha256(MESSAGE).digest()


def public_der(key):
    return key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def status(operation):
    try:
        return operation(), 0x9000
    except ApduError as error:
        return b"", error.sw


def verify_raw(key, raw):
    if len(raw) != 64:
        return False
    signature = utils.encode_dss_signature(
        int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    )
    key.verify(signature, DIGEST, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    return True


def capture(connection):
    sent = []
    original = connection.send_and_receive

    def send(apdu):
        sent.append(bytes(apdu))
        return original(apdu)

    connection.send_and_receive = send
    return sent


def raw_max65536(ins, p1, p2, data):
    return bytes((0, ins, p1, p2, 0)) + len(data).to_bytes(2, "big") + data + b"\0\0"


def run(root, expect, ifd_driver):
    observations = {}
    with tempfile.TemporaryDirectory(prefix="ske-pgp-crypto-", dir="/tmp") as base:
        for operation in ("sig", "aut"):
            ins = 0x2A if operation == "sig" else 0x88
            key_ref = KEY_REF.SIG if operation == "sig" else KEY_REF.AUT
            pin_ref = 0x81 if operation == "sig" else 0x82
            p1, p2 = ((0x9E, 0x9A) if operation == "sig" else (0, 0))
            variants = (
                ("le1", p1, p2, DIGEST, 1),
                ("le16", p1, p2, DIGEST, 16),
                ("max256", p1, p2, DIGEST, 256),
                ("max65536", p1, p2, DIGEST, 65536),
                ("lc_empty", p1, p2, b"", None),
                ("lc_one", p1, p2, b"x", None),
                ("bad_p1", p1 + 1, p2, DIGEST, None),
                ("bad_p2", p1, p2 + 1, DIGEST, None),
            )
            for name, q1, q2, data, le in variants:
                label = f"{operation}_{name}"
                directory = Path(base) / label
                directory.mkdir()
                fixture = Fixture(root, directory, ifd_driver)
                try:
                    connection = fixture.start()
                    sent = capture(connection)
                    pgp = OpenPgpSession(connection)
                    pgp.verify_admin("12345678")
                    key = pgp.generate_ec_key(key_ref, OID.SECP256R1)
                    original_key = public_der(key)
                    pgp.verify_pin("123456", extended=operation == "aut")
                    before = (directory / "state.bin").read_bytes()
                    if le == 65536:
                        wire = raw_max65536(ins, q1, q2, data)
                        response, sw = fixture.connection.send_and_receive(wire)
                    else:
                        response, sw = status(
                            lambda: pgp.protocol.send_apdu(
                                0, ins, q1, q2, data, le=le or 0
                            )
                        )
                    observations[label + "_sw"] = sw
                    observations[label + "_signature_valid"] = (
                        verify_raw(key, response) if sw == 0x9000 else False
                    )
                    command = next(item for item in reversed(sent) if item[1] == ins)
                    parsed = Apdu.decode(command)
                    observations[label + "_decoded_le"] = parsed.le
                    observations[label + "_decoded_lc"] = len(parsed.data)
                    observations[label + "_header_matches"] = (
                        parsed.p1 == q1 and parsed.p2 == q2
                    )
                    observations[label + "_state_unchanged"] = (
                        directory / "state.bin"
                    ).read_bytes() == before
                    observations[label + "_counter_after"] = pgp.get_signature_counter()
                    _response, auth_sw = status(
                        lambda: pgp.protocol.send_apdu(0, 0x20, 0, pin_ref)
                    )
                    observations[label + "_auth_status_after"] = auth_sw
                    if auth_sw != 0x9000:
                        pgp.verify_pin("123456", extended=operation == "aut")
                    signed = (
                        pgp.sign(MESSAGE, hashes.SHA256())
                        if operation == "sig"
                        else pgp.authenticate(MESSAGE, hashes.SHA256())
                    )
                    key.verify(signed, MESSAGE, ec.ECDSA(hashes.SHA256()))
                    observations[label + "_normal_sdk_verified"] = True
                    pgp = OpenPgpSession(fixture.restart())
                    observations[label + "_key_persists"] = (
                        public_der(pgp.get_public_key(key_ref)) == original_key
                    )
                    observations[label + "_counter_final"] = pgp.get_signature_counter()
                finally:
                    fixture.stop()

    expected = {}
    for operation in ("sig", "aut"):
        p1, p2 = ((0x9E, 0x9A) if operation == "sig" else (0, 0))
        variants = (
            ("le1", 32, 1),
            ("le16", 32, 16),
            ("max256", 32, 256),
            ("max65536", 32, 65536),
            ("lc_empty", 0, None),
            ("lc_one", 1, None),
            ("bad_p1", 32, None),
            ("bad_p2", 32, None),
        )
        for name, lc, le in variants:
            label = f"{operation}_{name}"
            malformed_le = name in ("le1", "le16")
            max_le = name in ("max256", "max65536")
            accepted = max_le or (malformed_le and expect == "baseline")
            expected.update(
                {
                    label + "_sw": (
                        0x9000
                        if accepted
                        else 0x6700
                        if malformed_le
                        else 0x6A80
                        if name.startswith("lc_")
                        else 0x6A86
                    ),
                    label + "_signature_valid": accepted,
                    label + "_decoded_le": le,
                    label + "_decoded_lc": lc,
                    label + "_header_matches": True,
                    label + "_state_unchanged": not accepted,
                    label + "_counter_after": int(operation == "sig" and accepted),
                    label + "_auth_status_after": (
                        0x63C3 if operation == "sig" and accepted else 0x9000
                    ),
                    label + "_normal_sdk_verified": True,
                    label + "_key_persists": True,
                    label + "_counter_final": (
                        int(operation == "sig" and accepted)
                        + int(operation == "sig")
                    ),
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
        "source": "OpenPGP Smart Card Application 3.4.1 sections 7.2.10 and 7.2.13",
        "note": "6700 is the emulator's status choice; physical 5.7.4 tolerance/status unmeasured",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--expect", required=True, choices=("baseline", "guarded"))
    parser.add_argument("--ifd-driver", type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    report = run(args.root.resolve(), args.expect, args.ifd_driver)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "checks": report["count"]}))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
