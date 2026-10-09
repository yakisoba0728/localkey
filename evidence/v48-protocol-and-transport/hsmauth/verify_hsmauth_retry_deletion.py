#!/usr/bin/env python3
"""Compare YubiHSM Auth credential exhaustion using the unmodified YubiKit SDK."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives.asymmetric import ec
from verify_smartcard import Fixture
from yubikit.core import InvalidPinError
from yubikit.core.smartcard import ApduError
from yubikit.hsmauth import HsmAuthSession


MGMT = bytes(16)
PASSWORD = "correct password"
BAD_PASSWORD = "wrong password"
CONTEXT = bytes(range(16))


def status(operation):
    try:
        operation()
    except ApduError as error:
        return error.sw
    return 0x9000


def labels(session):
    return {credential.label: credential.counter for credential in session.list_credentials()}


def run(root: Path, expect: str, ifd_driver: Path | None):
    observations = {}
    expected = {}
    with tempfile.TemporaryDirectory(prefix="ske-hsmauth-retry-", dir="/tmp") as base:
        for kind in ("symmetric", "asymmetric"):
            directory = Path(base) / kind
            directory.mkdir()
            fixture = Fixture(root, directory, ifd_driver)
            try:
                h = HsmAuthSession(fixture.start())
                if kind == "symmetric":
                    h.put_credential_symmetric(MGMT, "victim", b"a" * 16, b"b" * 16, PASSWORD)
                else:
                    h.put_credential_asymmetric(
                        MGMT, "victim", ec.generate_private_key(ec.SECP256R1()), PASSWORD
                    )
                h.put_credential_symmetric(MGMT, "peer", b"c" * 16, b"d" * 16, PASSWORD)

                def wrong():
                    if kind == "symmetric":
                        try:
                            h.calculate_session_keys_symmetric("victim", CONTEXT, BAD_PASSWORD)
                        except InvalidPinError as error:
                            return error.attempts_remaining
                        return -1
                    sw = status(lambda: h.get_challenge("victim", BAD_PASSWORD))
                    return sw & 0xF if sw & 0xFFF0 == 0x63C0 else -1

                def valid():
                    if kind == "symmetric":
                        return len(h.calculate_session_keys_symmetric("victim", CONTEXT, PASSWORD).key_senc) == 16
                    return len(h.get_challenge("victim", PASSWORD)) == 65

                observations[kind + "_initial"] = labels(h)
                observations[kind + "_first_seven"] = [wrong() for _ in range(7)]
                observations[kind + "_one_retry_left"] = labels(h).get("victim")
                observations[kind + "_correct_password_works"] = valid()
                observations[kind + "_retries_restored"] = labels(h).get("victim")
                observations[kind + "_final_eight"] = [wrong() for _ in range(8)]
                observations[kind + "_after_exhaustion"] = labels(h)
                observations[kind + "_management_retries"] = h.get_management_key_retries()
                observations[kind + "_peer_derivation"] = (
                    len(h.calculate_session_keys_symmetric("peer", CONTEXT, PASSWORD).key_senc) == 16
                )
                h = HsmAuthSession(fixture.restart())
                observations[kind + "_after_restart"] = labels(h)
                if kind == "symmetric":
                    observations[kind + "_readd_sw"] = status(
                        lambda: h.put_credential_symmetric(
                            MGMT, "victim", b"e" * 16, b"f" * 16, PASSWORD
                        )
                    )
                else:
                    observations[kind + "_readd_sw"] = status(
                        lambda: h.put_credential_asymmetric(
                            MGMT, "victim", ec.generate_private_key(ec.SECP256R1()), PASSWORD
                        )
                    )
                observations[kind + "_readd_retries"] = labels(h).get("victim")

                expected[kind + "_initial"] = {"victim": 8, "peer": 8}
                expected[kind + "_first_seven"] = [7, 6, 5, 4, 3, 2, 1]
                expected[kind + "_one_retry_left"] = 1
                expected[kind + "_correct_password_works"] = True
                expected[kind + "_retries_restored"] = 8
                expected[kind + "_final_eight"] = [7, 6, 5, 4, 3, 2, 1, 0]
                expected[kind + "_after_exhaustion"] = (
                    {"victim": 0, "peer": 8}
                    if expect == "baseline"
                    else {"peer": 8}
                )
                expected[kind + "_management_retries"] = 8
                expected[kind + "_peer_derivation"] = True
                expected[kind + "_after_restart"] = expected[kind + "_after_exhaustion"]
                expected[kind + "_readd_sw"] = 0x6985 if expect == "baseline" else 0x9000
                expected[kind + "_readd_retries"] = 0 if expect == "baseline" else 8
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
        "source": "Yubico YubiHSM Auth Credential and Get AES-128 Session Keys documentation",
        "note": "Exact final-failure status and firmware 5.7.4 persistence were not physically measured",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--expect", required=True, choices=("baseline", "fixed"))
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
