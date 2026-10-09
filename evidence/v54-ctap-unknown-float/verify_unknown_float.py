#!/usr/bin/env python3
"""Probe unknown canonical CBOR float values over private CTAPHID."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

from fido2 import cbor
from fido2.hid import CTAPHID


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--expected", required=True, type=lambda s: int(s, 0))
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    sys.path.insert(0, str(args.root.resolve() / "tools"))
    from verify_ctap import Fixture

    values = {
        "integer_control": bytes.fromhex("01"),
        "half_zero": bytes.fromhex("f90000"),
        "half_one": bytes.fromhex("f93c00"),
        "float_one": bytes.fromhex("fa3f800000"),
        "double_one": bytes.fromhex("fb3ff0000000000000"),
    }
    with tempfile.TemporaryDirectory(prefix="ske-unknown-float-") as tmp:
        fixture = Fixture(args.binary.resolve(), Path(tmp))
        try:
            fixture.start()
            rows = []
            for name, value in values.items():
                payload = (
                    b"\x02\xa3\x01"
                    + cbor.encode("unknown.example")
                    + b"\x02"
                    + cbor.encode(hashlib.sha256(b"canonical-float-probe").digest())
                    + b"\x08"
                    + value
                )
                reply = fixture.device.call(CTAPHID.CBOR, payload)
                rows.append({"name": name, "status": reply[0], "reply_length": len(reply)})
        finally:
            fixture.stop()

    passed = all(
        row["status"] == (0x2E if row["name"] == "integer_control" else args.expected)
        for row in rows
    )
    report = {
        "passed": passed,
        "expected_float_status": args.expected,
        "rows": rows,
        "transport": "private Unix CTAPHID over unmodified python-fido2",
        "physical_device_access": False,
        "spec": "https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#message-encoding",
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
