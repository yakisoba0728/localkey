#!/usr/bin/env python3
"""Exercise the CTAP hmac-secret/up=false boundary over private CTAPHID."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

from fido2.ctap import CtapError


def sign_count(assertion) -> int:
    return int.from_bytes(bytes(assertion.auth_data)[33:37], "big")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--expect", required=True, choices=("baseline", "fixed"))
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    sys.path.insert(0, str(args.root.resolve() / "tools"))
    from verify_ctap import Fixture

    with tempfile.TemporaryDirectory(prefix="ske-hmac-upfalse-", dir="/tmp") as temp:
        fixture = Fixture(args.binary.resolve(), Path(temp))
        try:
            ctap = fixture.start()
            att = ctap.make_credential(
                hashlib.sha256(b"hmac-upfalse-registration").digest(),
                {"id": "hmac.example", "name": "HMAC fixture"},
                {"id": b"account", "name": "Account"},
                [{"type": "public-key", "alg": -7}],
                options={"rk": True},
            )
            credential_id = att.auth_data.credential_data.credential_id
            challenge = hashlib.sha256(b"hmac-upfalse-assertion").digest()
            before = ctap.get_assertion("hmac.example", challenge, options={"up": False})
            count_before = sign_count(before)
            try:
                bad = ctap.get_assertion(
                    "hmac.example", challenge,
                    allow_list=[{"type": "public-key", "id": credential_id}],
                    extensions={"hmac-secret": {}},
                    options={"up": False},
                )
            except CtapError as error:
                status = int(error.code)
                bad_count = None
            else:
                status = 0
                bad_count = sign_count(bad)
            after = ctap.get_assertion("hmac.example", challenge, options={"up": False})
            count_after = sign_count(after)
            normal = ctap.get_assertion("hmac.example", challenge)
            count_normal = sign_count(normal)
        finally:
            fixture.stop()

    expected = 0 if args.expect == "baseline" else 0x2B
    passed = (
        count_before >= 1
        and status == expected
        and (bad_count == count_before if args.expect == "baseline" else bad_count is None)
        and count_after == count_before
        and count_normal == count_before + 1
    )
    report = {
        "passed": passed,
        "expect": args.expect,
        "hmac_upfalse_status": status,
        "hmac_upfalse_count": bad_count,
        "before_count": count_before,
        "after_count": count_after,
        "normal_count": count_normal,
        "transport": "unmodified python-fido2 over private Unix CTAPHID",
        "physical_device_access": False,
        "spec": "https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-hmac-secret-extension",
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
