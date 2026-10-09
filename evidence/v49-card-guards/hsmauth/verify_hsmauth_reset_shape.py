#!/usr/bin/env python3
"""Check YubiHSM Auth RESET APDU shape against private software transports."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from emucard.core import Apdu
from verify_smartcard import Fixture
from yubikit.core import Tlv
from yubikit.core.smartcard import ApduError
from yubikit.hsmauth import HsmAuthSession


def status(operation):
    try:
        operation()
    except ApduError as error:
        return error.sw
    return 0x9000


def setup_credential(connection):
    session = HsmAuthSession(connection)
    session.put_credential_symmetric(
        bytes(16), "survivor", b"a" * 16, b"b" * 16, "password"
    )
    return session


def list_labels(session):
    return [credential.label for credential in session.list_credentials()]


def run(root: Path, expect: str, ifd_driver: Path | None):
    observations = {}
    expected = {}
    cases = {
        "extra_data": (Tlv(0x71, b"x"), None),
        "explicit_le1": (b"", 1),
        "extended_le256": (b"", 256),
    }
    with tempfile.TemporaryDirectory(prefix="ske-hsmauth-reset-", dir="/tmp") as base:
        for label, (data, le) in cases.items():
            directory = Path(base) / label
            directory.mkdir()
            fixture = Fixture(root, directory, ifd_driver)
            try:
                conn = fixture.start()
                sent = []
                original = conn.send_and_receive

                def capture(apdu):
                    sent.append(bytes(apdu))
                    return original(apdu)

                conn.send_and_receive = capture
                h = setup_credential(conn)
                before = (directory / "state.bin").read_bytes()
                observations[label + "_sw"] = status(
                    lambda: h.protocol.send_apdu(0, 0x06, 0xDE, 0xAD, data, le=le)
                )
                wire = sent[-1]
                observations[label + "_wire"] = wire.hex()
                observations[label + "_decoded_data"] = Apdu.decode(wire).data.hex()
                observations[label + "_decoded_le"] = Apdu.decode(wire).le
                observations[label + "_state_unchanged"] = (
                    directory / "state.bin"
                ).read_bytes() == before
                observations[label + "_labels"] = list_labels(h)
                observations[label + "_restart_labels"] = list_labels(
                    HsmAuthSession(fixture.restart())
                )
                expected[label + "_sw"] = 0x9000 if expect == "baseline" else 0x6700
                expected[label + "_decoded_data"] = bytes(data).hex()
                expected[label + "_decoded_le"] = le
                expected[label + "_state_unchanged"] = expect == "guarded"
                expected[label + "_labels"] = [] if expect == "baseline" else ["survivor"]
                expected[label + "_restart_labels"] = expected[label + "_labels"]
            finally:
                fixture.stop()

        for label, short_zero in (("normal_sdk", False), ("short_zero", True)):
            directory = Path(base) / label
            directory.mkdir()
            fixture = Fixture(root, directory, ifd_driver)
            try:
                conn = fixture.start()
                sent = []
                original = conn.send_and_receive

                def capture(apdu):
                    sent.append(bytes(apdu))
                    return original(apdu)

                conn.send_and_receive = capture
                h = setup_credential(conn)
                if short_zero:
                    wire = bytes.fromhex("0006dead00")
                    observations[label + "_sw"] = conn.send_and_receive(wire)[1]
                else:
                    observations[label + "_sw"] = status(h.reset)
                observations[label + "_wire"] = sent[-1].hex()
                observations[label + "_restart_labels"] = list_labels(
                    HsmAuthSession(fixture.restart())
                )
                expected[label + "_sw"] = 0x9000
                expected[label + "_restart_labels"] = []
                expected[label + "_wire"] = (
                    "0006dead00" if short_zero else "0006dead"
                )
            finally:
                fixture.stop()

    mismatches = {
        key: {"expected": value, "actual": observations.get(key)}
        for key, value in expected.items()
        if observations.get(key) != value
    }
    return {
        "passed": not mismatches,
        "count": len(expected),
        "expect": expect,
        "transport": "direct IFD ABI" if ifd_driver else "private CCID socket",
        "core_sha256": hashlib.sha256((root / "emucard/core.py").read_bytes()).hexdigest(),
        "observations": observations,
        "mismatches": mismatches,
        "physical_key_accessed": False,
        "source": "Yubico YubiHSM Auth Reset application command APDU",
        "note": "6700 is the software model's status; physical firmware 5.7.4 tolerance unmeasured",
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
