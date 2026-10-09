#!/usr/bin/env python3
"""Check YubiHSM Auth touch-policy byte using private CCID and YubiKit."""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tools.verify_smartcard import Fixture
from yubihsm.core import _derive
from yubikit.core import Tlv
from yubikit.core.smartcard import ApduError
from yubikit.hsmauth import HsmAuthSession


def run(root):
    checks = []

    def check(name, actual, expected):
        checks.append({"name": name, "actual": actual, "expected": expected, "matched": actual == expected})

    with tempfile.TemporaryDirectory(prefix="ske-hsmauth-touch-") as temp:
        directory = Path(temp)
        fixture = Fixture(root, directory)
        conn = fixture.start()
        try:
            sdk = HsmAuthSession(conn)
            management_key = bytes(16)
            key_enc, key_mac = b"a" * 16, b"b" * 16
            credential_password = b"p" * 16
            sdk.put_credential_symmetric(management_key, "normal", key_enc, key_mac, credential_password, touch_required=False)
            sdk.put_credential_symmetric(management_key, "touch", key_enc, key_mac, credential_password, touch_required=True)
            listed = {row.label: row.touch_required for row in sdk.list_credentials()}
            check("sdk_accepts_touch_0_and_1", listed, {"normal": False, "touch": True})
            context = bytes(range(16))
            keys = sdk.calculate_session_keys_symmetric("normal", context, credential_password)
            check("sdk_independent_aes_derivation", keys.key_senc.hex(), _derive(key_enc, 4, context).hex())
            touched_keys = sdk.calculate_session_keys_symmetric("touch", context, credential_password)
            check("sdk_touch_required_derivation", touched_keys.key_senc.hex(), _derive(key_enc, 4, context).hex())

            for label, touch_value in (
                ("invalid2", b"\x02"),
                ("invalid255", b"\xff"),
                ("invalidlen", b"\x01\x00"),
            ):
                data = (
                    Tlv(0x7B, management_key)
                    + Tlv(0x71, label.encode())
                    + Tlv(0x74, b"\x26")
                    + Tlv(0x75, key_enc)
                    + Tlv(0x76, key_mac)
                    + Tlv(0x73, credential_password)
                    + Tlv(0x7A, touch_value)
                )
                try:
                    sdk.protocol.send_apdu(0, 1, 0, 0, data)
                except ApduError as exc:
                    status = exc.sw
                else:
                    status = 0x9000
                check(f"{label}_status", status, 0x6A80)
                check(f"{label}_not_stored", label in {row.label for row in sdk.list_credentials()}, False)
            check("valid_credentials_remain", {row.label for row in sdk.list_credentials()}.issuperset({"normal", "touch"}), True)
        finally:
            fixture.stop()
    return checks


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    checks = run(args.root.resolve())
    result = {
        "passed": all(row["matched"] for row in checks),
        "matched": sum(row["matched"] for row in checks),
        "count": len(checks),
        "checks": checks,
        "physical_key_access": False,
        "host_pcsc_access": False,
        "firmware_5_7_4_differential_verified": False,
    }
    args.result.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: result[k] for k in ("passed", "matched", "count")}, indent=2))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
