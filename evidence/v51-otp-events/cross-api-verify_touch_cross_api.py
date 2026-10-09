#!/usr/bin/env python3
"""Cross-check legacy button opcodes against an active private touch session."""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from emucard.client import KeyboardSocketConnection
from tools.verify_smartcard import Fixture
from yubikit.core.otp import check_crc, modhex_decode
from yubikit.yubiotp import (
    SLOT,
    StaticPasswordSlotConfiguration,
    YubiOtpSlotConfiguration,
    YubiOtpSession,
)


def ticket(reports, key):
    letters = {4 + n: c for n, c in enumerate("abcdefghijklmnopqrstuvwxyz")}
    value = "".join(
        letters[bytes.fromhex(event["report"])[2]]
        for event in reports
        if bytes.fromhex(event["report"])[2] in letters
    )
    assert len(value) == 32, f"expected 32 modhex keystrokes; saw {len(value)}"
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return decryptor.update(modhex_decode(value)) + decryptor.finalize()


def attempt(fn):
    try:
        value = fn()
    except Exception as exc:
        return {"sw": getattr(exc, "sw", type(exc).__name__)}
    return {"event_count": len(value)}


def run(root):
    checks = []

    def check(name, actual, expected):
        if isinstance(actual, bytes):
            actual = actual.hex()
        if isinstance(expected, bytes):
            expected = expected.hex()
        checks.append({"name": name, "actual": actual, "expected": expected, "matched": actual == expected})

    with tempfile.TemporaryDirectory(prefix="ske-cross-api-") as directory_name:
        directory = Path(directory_name)
        fixture = Fixture(root, directory)
        conn = fixture.start()
        keyboard = KeyboardSocketConnection(directory / "s.sock")
        try:
            otp = YubiOtpSession(conn)
            otp.put_configuration(
                SLOT.ONE,
                StaticPasswordSlotConfiguration(bytes([0x84, 5, 30])).fast_trigger(False),
            )
            expected_slot1 = keyboard.press(1)
            check("legacy_press_before_touch", len(expected_slot1), 8)
            check("single_slot_down_emits", keyboard.touch_down(), expected_slot1)
            check("legacy_hold_denied_during_fast_touch", attempt(lambda: keyboard.hold(3500)), {"sw": 0x6985})
            check("legacy_press_denied_during_fast_touch", attempt(lambda: keyboard.press(1)), {"sw": 0x6985})
            check("single_slot_release_no_duplicate", keyboard.touch_up(3500), [])
            check("legacy_hold_after_release", keyboard.hold(3500), expected_slot1)
            check("legacy_press_after_release", keyboard.press(1), expected_slot1)

            otp.put_configuration(SLOT.TWO, StaticPasswordSlotConfiguration(b"\x06"))
            expected_slot2 = keyboard.press(2)
            check("two_slot_down_deferred", keyboard.touch_down(), [])
            check("legacy_press_denied_during_deferred_touch", attempt(lambda: keyboard.press(1)), {"sw": 0x6985})
            check("legacy_hold_denied_during_deferred_touch", attempt(lambda: keyboard.hold(3500)), {"sw": 0x6985})
            check("two_slot_release_selects_slot2", keyboard.touch_up(3500), expected_slot2)
            check("two_slot_legacy_hold_after_release", keyboard.hold(3500), expected_slot2)

            otp.delete_slot(SLOT.TWO)
            uid, key = bytes.fromhex("010203040506"), bytes.fromhex("11" * 16)
            otp.put_configuration(SLOT.ONE, YubiOtpSlotConfiguration(b"", uid, key).fast_trigger(False))
            first = ticket(keyboard.touch_down(), key)
            check("first_ticket_aes_crc", first[:6] == uid and check_crc(first), True)
            check("ticket_hold_denied_during_touch", attempt(lambda: keyboard.hold(3500)), {"sw": 0x6985})
            check("ticket_press_denied_during_touch", attempt(lambda: keyboard.press(1)), {"sw": 0x6985})
            check("ticket_release_no_duplicate", keyboard.touch_up(3500), [])
            second = ticket(keyboard.touch_down(), key)
            check("second_ticket_aes_crc", second[:6] == uid and check_crc(second), True)
            check("ticket_session_ctr_same", second[6:8], first[6:8])
            check("ticket_usage_ctr_plus_one", second[11], first[11] + 1)
            check("second_ticket_release_no_duplicate", keyboard.touch_up(500), [])
        finally:
            keyboard.close()
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
        "host_hid_registration": False,
        "firmware_5_7_4_behavior_verified": False,
    }
    args.result.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: result[k] for k in ("passed", "matched", "count")}, indent=2))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
