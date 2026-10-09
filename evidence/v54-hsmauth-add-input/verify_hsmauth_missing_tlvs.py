#!/usr/bin/env python3
"""Probe missing YubiHSM Auth ADD CREDENTIAL fields over private CCID."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--root", required=True, type=Path)
args = parser.parse_args()
root = args.root.resolve()
sys.path.insert(0, str(root / "tools"))
sys.path.insert(0, str(root))

from yubikit.core import Tlv  # noqa: E402
from yubikit.hsmauth import HsmAuthSession  # noqa: E402
from verify_smartcard import Fixture  # noqa: E402


def transmit_add(conn, fields: list[tuple[int, bytes]]) -> int:
    payload = b"".join(Tlv(tag, value) for tag, value in fields)
    assert len(payload) <= 255
    response, sw = conn.send_and_receive(bytes([0, 1, 0, 0, len(payload)]) + payload)
    assert not response
    return sw


with tempfile.TemporaryDirectory(prefix="v54-hsmauth-missing-") as tmp:
    fixture = Fixture(root, Path(tmp))
    conn = fixture.start()
    try:
        sdk = HsmAuthSession(conn)
        symmetric = [
            (0x7B, bytes(16)), (0x71, b"symmetric"), (0x74, b"\x26"),
            (0x75, b"a" * 16), (0x76, b"b" * 16), (0x73, b"p" * 16),
            (0x7A, b"\0"),
        ]
        missing_symmetric = {}
        for tag in (0x71, 0x74, 0x73, 0x75, 0x76):
            fields = [(t, b"test-" + bytes([tag]) if t == 0x71 else v)
                      for t, v in symmetric if t != tag]
            missing_symmetric[f"{tag:02X}"] = transmit_add(conn, fields)
        asymmetric = [
            (0x7B, bytes(16)), (0x71, b"asymmetric"), (0x74, b"\x27"),
            (0x7D, b""), (0x73, b"p" * 16), (0x7A, b"\0"),
        ]
        missing_asymmetric_key = transmit_add(
            conn, [(tag, value) for tag, value in asymmetric if tag != 0x7D]
        )
        zero_length_asymmetric_key = transmit_add(conn, asymmetric)
        valid_symmetric = transmit_add(conn, symmetric)
        labels = sorted(c.label for c in sdk.list_credentials())
        retries = sdk.get_management_key_retries()
        result = {
            "root": str(root),
            "missing_symmetric_status": missing_symmetric,
            "missing_asymmetric_7D_status": missing_asymmetric_key,
            "zero_length_asymmetric_7D_status": zero_length_asymmetric_key,
            "valid_symmetric_status": valid_symmetric,
            "stored_labels": labels,
            "management_retries": retries,
        }
        assert set(missing_symmetric.values()) == {0x6A80}
        assert missing_asymmetric_key == 0x6A80
        assert zero_length_asymmetric_key == valid_symmetric == 0x9000
        assert labels == ["asymmetric", "symmetric"] and retries == 8
        print(json.dumps(result, indent=2))
    finally:
        fixture.stop()
