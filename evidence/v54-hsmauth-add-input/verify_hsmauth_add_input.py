#!/usr/bin/env python3
"""Private CCID-socket YubiHSM Auth ADD CREDENTIAL input boundary probe."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--root", type=Path, required=True)
parser.add_argument("--expect", choices=("baseline", "corrected"), required=True)
args = parser.parse_args()
root = args.root.resolve()
sys.path.insert(0, str(root / "tools"))
sys.path.insert(0, str(root))

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from yubihsm.core import _derive  # noqa: E402
from yubikit.core import Tlv  # noqa: E402
from yubikit.core.smartcard import ApduError  # noqa: E402
from yubikit.hsmauth import HsmAuthSession  # noqa: E402
from verify_smartcard import Fixture  # noqa: E402


def add_payload(label: bytes, alg: bytes = b"\x26") -> bytes:
    return (
        Tlv(0x7B, bytes(16))
        + Tlv(0x71, label)
        + Tlv(0x74, alg)
        + Tlv(0x75, b"a" * 16)
        + Tlv(0x76, b"b" * 16)
        + Tlv(0x73, b"p" * 16)
        + Tlv(0x7A, b"\0")
    )


def raw_add(conn, data: bytes) -> int:
    assert len(data) < 256
    response, sw = conn.send_and_receive(bytes([0, 1, 0, 0, len(data)]) + data)
    assert not response
    return sw


with tempfile.TemporaryDirectory(prefix="v54-hsmauth-") as tmp:
    fixture = Fixture(root, Path(tmp))
    conn = fixture.start()
    try:
        sdk = HsmAuthSession(conn)
        sdk.put_credential_symmetric(bytes(16), "alpha", b"a" * 16, b"b" * 16, "password")
        normal_initial = [r.label for r in sdk.list_credentials()]
        try:
            sdk.put_credential_symmetric(bytes(16), "alpha", b"a" * 16, b"b" * 16, "password")
        except ApduError as exc:
            duplicate_status = exc.sw
        else:
            duplicate_status = 0x9000
        count_after_duplicate = len(sdk.list_credentials())
        overlong_algorithm_status = raw_add(conn, add_payload(b"beta", b"\x26\x00"))
        invalid_utf8_status = raw_add(conn, add_payload(b"\xff"))
        raw_list, list_status = conn.send_and_receive(bytes.fromhex("00050000"))
        sdk_list_exception = None
        try:
            sdk_labels = [r.label for r in sdk.list_credentials()]
        except UnicodeDecodeError as exc:
            sdk_list_exception = type(exc).__name__
            sdk_labels = None
        sdk.put_credential_asymmetric(
            bytes(16), "한국어", ec.generate_private_key(ec.SECP256R1()), "password"
        )
        context = bytes(range(16))
        keys = sdk.calculate_session_keys_symmetric("alpha", context, "password")
        independently_derived = (
            keys.key_senc == _derive(b"a" * 16, 4, context)
            and keys.key_smac == _derive(b"b" * 16, 6, context)
            and keys.key_srmac == _derive(b"b" * 16, 7, context)
        )
        result = {
            "root": str(root),
            "normal_initial_labels": normal_initial,
            "duplicate_status": duplicate_status,
            "count_after_duplicate": count_after_duplicate,
            "overlong_algorithm_status": overlong_algorithm_status,
            "invalid_utf8_status": invalid_utf8_status,
            "raw_list_status": list_status,
            "raw_list_hex": raw_list.hex(),
            "sdk_list_exception_after_invalid_utf8": sdk_list_exception,
            "sdk_labels_after_invalid_utf8": sdk_labels,
            "asymmetric_utf8_sdk_add_accepted": True,
            "independent_symmetric_derivation_matches": independently_derived,
            "management_retries_after_inputs": sdk.get_management_key_retries(),
        }
        assert normal_initial == ["alpha"] and count_after_duplicate == 1
        assert list_status == 0x9000 and independently_derived
        assert result["management_retries_after_inputs"] == 8
        if args.expect == "baseline":
            assert (duplicate_status, overlong_algorithm_status, invalid_utf8_status) == (
                0x6985, 0x9000, 0x9000
            )
            assert sdk_list_exception == "UnicodeDecodeError"
        else:
            assert (duplicate_status, overlong_algorithm_status, invalid_utf8_status) == (
                0x6983, 0x6A80, 0x6A80
            )
            assert sdk_list_exception is None and sdk_labels == ["alpha"]
        print(json.dumps(result, ensure_ascii=False, indent=2))
    finally:
        fixture.stop()
