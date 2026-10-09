#!/usr/bin/env python3
"""Check unknown CTAP option values over a private pyfido2 CTAPHID socket."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

from fido2 import cbor
from fido2.hid import CTAPHID

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
if not (TOOLS / "verify_ctap.py").is_file():
    TOOLS = ROOT / "outputs/security-key-emulator/tools"
sys.path.insert(0, str(TOOLS))
from verify_ctap import Fixture


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--expect-fixed", action="store_true")
    args = parser.parse_args()
    digest = hashlib.sha256(b"v56-unknown-options").digest()
    cases = {
        "get_normal_missing_credential": (2, {1: "example.test", 2: digest}),
        "get_unknown_boolean": (2, {1: "example.test", 2: digest, 5: {"xFuture": True}}),
        "get_unknown_integer": (2, {1: "example.test", 2: digest, 5: {"xFuture": 7}}),
        "get_unknown_nested_map": (2, {1: "example.test", 2: digest, 5: {"xFuture": {"nested": [1, 2]}}}),
        "get_known_up_wrong_type": (2, {1: "example.test", 2: digest, 5: {"up": 7}}),
        "make_unknown_integer_missing_parameters": (1, {7: {"xFuture": 7}}),
    }
    result = {}
    with tempfile.TemporaryDirectory(prefix="v56-ctap-options-") as directory:
        fixture = Fixture(args.binary.resolve(), Path(directory))
        fixture.start()
        try:
            for name, (command, params) in cases.items():
                response = fixture.device.call(CTAPHID.CBOR, bytes([command]) + cbor.encode(params))
                result[name] = f"0x{response[0]:02x}"
        finally:
            fixture.stop()
    expected = {
        "get_normal_missing_credential": "0x2e",
        "get_unknown_boolean": "0x2e",
        "get_unknown_integer": "0x2e" if args.expect_fixed else "0x11",
        "get_unknown_nested_map": "0x2e" if args.expect_fixed else "0x11",
        "get_known_up_wrong_type": "0x11",
        "make_unknown_integer_missing_parameters": "0x14" if args.expect_fixed else "0x11",
    }
    assert result == expected, (result, expected)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({"passed": True, "expect_fixed": args.expect_fixed,
                                       "statuses": result, "tests": list(result),
                                       "physical_device_access": False}, indent=2) + "\n")
    print(args.report.read_text())


if __name__ == "__main__":
    main()
