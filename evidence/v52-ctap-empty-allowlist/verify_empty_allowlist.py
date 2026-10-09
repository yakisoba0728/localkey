#!/usr/bin/env python3
"""Compare absent and explicitly empty CTAP allowList over private CTAPHID."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

from fido2.ctap import CtapError


def count(assertion) -> int:
    return int.from_bytes(bytes(assertion.auth_data)[33:37], "big")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--expect", choices=("baseline", "fixed"), required=True)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    sys.path.insert(0, str(args.root.resolve() / "tools"))
    from verify_ctap import Fixture

    with tempfile.TemporaryDirectory(prefix="ske-empty-allow-", dir="/tmp") as temp:
        fixture = Fixture(args.binary.resolve(), Path(temp))
        try:
            ctap = fixture.start()
            att = ctap.make_credential(
                hashlib.sha256(b"empty allowList registration").digest(),
                {"id": "allow.example", "name": "Allow fixture"},
                {"id": b"account-1", "name": "Account"},
                [{"type": "public-key", "alg": -7}],
                options={"rk": True},
            )
            cred_id = att.auth_data.credential_data.credential_id
            remaining = ctap.get_info().remaining_disc_creds
            base_hash = hashlib.sha256(b"allow assertion").digest()
            first = ctap.get_assertion("allow.example", base_hash)
            first_count = count(first)
            try:
                empty = ctap.get_assertion("allow.example", base_hash, allow_list=[])
            except CtapError as error:
                empty_status = int(error.code)
                empty_count = None
            else:
                empty_status = 0
                empty_count = count(empty)
            nonmatch_status = None
            try:
                ctap.get_assertion(
                    "allow.example", base_hash,
                    allow_list=[{"type": "public-key", "id": b"not-the-credential"}],
                )
            except CtapError as error:
                nonmatch_status = int(error.code)
            explicit = ctap.get_assertion(
                "allow.example", base_hash,
                allow_list=[{"type": "public-key", "id": cred_id}],
            )
            explicit_count = count(explicit)
            absent_again = ctap.get_assertion("allow.example", base_hash)
            final_count = count(absent_again)
            remaining_after = ctap.get_info().remaining_disc_creds
        finally:
            fixture.stop()

    expected_empty_status = 0 if args.expect == "baseline" else 0x2E
    expected_final_delta = 3 if args.expect == "baseline" else 2
    passed = (
        first_count > 0
        and empty_status == expected_empty_status
        and (empty_count == first_count + 1 if args.expect == "baseline" else empty_count is None)
        and nonmatch_status == 0x2E
        and explicit_count == first_count + (2 if args.expect == "baseline" else 1)
        and final_count == first_count + expected_final_delta
        and remaining == remaining_after
    )
    report = {
        "passed": passed,
        "expect": args.expect,
        "first_count": first_count,
        "empty_status": empty_status,
        "empty_count": empty_count,
        "nonmatch_status": nonmatch_status,
        "explicit_count": explicit_count,
        "final_count": final_count,
        "remaining_before": remaining,
        "remaining_after": remaining_after,
        "transport": "unmodified python-fido2 over private Unix CTAPHID",
        "physical_device_access": False,
        "spec": "https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#ga-allowlist",
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
