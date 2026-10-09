#!/usr/bin/env python3
"""Test private software touch event timing; never registers a host HID device."""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[0]))
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from emucard.client import KeyboardSocketConnection
from tools.verify_smartcard import Fixture
from yubikit.core.otp import check_crc, modhex_decode
from yubikit.yubiotp import (
    HmacSha1SlotConfiguration,
    SLOT,
    StaticPasswordSlotConfiguration,
    StaticTicketSlotConfiguration,
    YubiOtpSlotConfiguration,
    YubiOtpSession,
)


def ticket_plain(reports, key):
    alphabet = {4 + n: char for n, char in enumerate("abcdefghijklmnopqrstuvwxyz")}
    text = "".join(
        alphabet[bytes.fromhex(event["report"])[2]]
        for event in reports
        if bytes.fromhex(event["report"])[2] in alphabet
    )
    assert len(text) == 32, f"wrong OTP keyboard length: {len(text)}"
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return decryptor.update(modhex_decode(text)) + decryptor.finalize()


def run(root: Path):
    checks = []

    def check(name, actual, expected):
        matched = actual == expected
        if isinstance(actual, bytes):
            actual = actual.hex()
        if isinstance(expected, bytes):
            expected = expected.hex()
        checks.append({"name": name, "actual": actual, "expected": expected, "matched": matched})

    with tempfile.TemporaryDirectory(prefix="ske-touch-api-") as tmp:
        directory = Path(tmp)
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
            check("legacy_single_slot1_hold", keyboard.hold(3500), expected_slot1)
            try:
                first_down = keyboard.touch_down()
            except Exception as exc:
                check("single_slot1_output_at_press", type(exc).__name__, "eight_reports")
                return checks
            check("single_slot1_output_at_press", len(first_down), 8)
            check("single_slot1_reports_at_press", first_down, expected_slot1)
            check("single_slot1_no_duplicate_at_release", keyboard.touch_up(3500), [])
            second_down = keyboard.touch_down()
            check("rearmed_after_release", second_down, expected_slot1)
            try:
                keyboard.touch_down()
                duplicate = "accepted"
            except Exception as exc:
                duplicate = getattr(exc, "sw", type(exc).__name__)
            check("duplicate_press_rejected", duplicate, 0x6985)
            check("release_after_duplicate_press", keyboard.touch_up(500), [])
            try:
                keyboard.touch_up(500)
                duplicate = "accepted"
            except Exception as exc:
                duplicate = getattr(exc, "sw", type(exc).__name__)
            check("duplicate_release_rejected", duplicate, 0x6985)
            check("press_before_cross_session_probe", keyboard.touch_down(), expected_slot1)
            other_keyboard = KeyboardSocketConnection(directory / "s.sock")
            try:
                try:
                    other_keyboard.touch_up(3500)
                    cross_session = "accepted"
                except Exception as exc:
                    cross_session = getattr(exc, "sw", type(exc).__name__)
                check("other_session_cannot_release_touch", cross_session, 0x6985)
            finally:
                other_keyboard.close()
            check("original_session_can_release_touch", keyboard.touch_up(3500), [])
            otp.put_configuration(SLOT.TWO, StaticPasswordSlotConfiguration(b"\x06"))
            expected_slot2 = keyboard.press(2)
            check("two_slots_press_deferred", keyboard.touch_down(), [])
            check("two_slots_long_release_slot2", keyboard.touch_up(3500), expected_slot2)
            check("two_slots_second_press_deferred", keyboard.touch_down(), [])
            check("two_slots_short_release_slot1", keyboard.touch_up(2000), expected_slot1)
            check("legacy_two_slot_hold", keyboard.hold(3500), expected_slot2)
            otp.delete_slot(SLOT.TWO)
            uid, key = bytes.fromhex("010203040506"), bytes.fromhex("11" * 16)
            otp.put_configuration(
                SLOT.ONE,
                YubiOtpSlotConfiguration(b"", uid, key).fast_trigger(False),
            )
            first_ticket = ticket_plain(keyboard.touch_down(), key)
            check("ticket_at_press_valid", first_ticket[:6] == uid and check_crc(first_ticket), True)
            check("ticket_not_duplicated_at_release", keyboard.touch_up(3500), [])
            second_ticket = ticket_plain(keyboard.touch_down(), key)
            check("second_ticket_at_next_press_valid", second_ticket[:6] == uid and check_crc(second_ticket), True)
            check("session_counter_unchanged_on_release", second_ticket[6:8], first_ticket[6:8])
            check("usage_counter_advances_only_next_press", second_ticket[11], first_ticket[11] + 1)
            check("second_ticket_not_duplicated_at_release", keyboard.touch_up(500), [])
            otp.put_configuration(
                SLOT.ONE,
                StaticTicketSlotConfiguration(b"", b"\0" * 6, bytes(16)).manual_update(True),
            )
            check("manual_update_press_defers", keyboard.touch_down(), [])
            check("manual_update_long_release_arms", keyboard.touch_up(10000), [])
            check("manual_update_confirmation_press_defers", keyboard.touch_down(), [])
            check("manual_update_confirmation_release_outputs", bool(keyboard.touch_up(500)), True)
            otp.put_configuration(
                SLOT.ONE,
                StaticPasswordSlotConfiguration(bytes([0x84, 5, 30])).fast_trigger(True),
            )
            check("explicit_fast_flag_still_outputs_at_press", keyboard.touch_down(), expected_slot1)
            check("explicit_fast_flag_no_release_duplicate", keyboard.touch_up(3500), [])
            otp.put_configuration(SLOT.ONE, HmacSha1SlotConfiguration(bytes(range(20))))
            check("challenge_response_slot_no_keyboard_at_press", keyboard.touch_down(), [])
            check("challenge_response_slot_no_keyboard_at_release", keyboard.touch_up(3500), [])
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
        "passed": bool(checks) and all(row["matched"] for row in checks),
        "count": len(checks),
        "matched": sum(row["matched"] for row in checks),
        "checks": checks,
        "transport": "private Unix keyboard socket and independent YubiKit configuration",
        "physical_device_access": False,
        "host_hid_registration": False,
        "firmware_5_7_4_touch_timing_verified": False,
    }
    args.result.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in ("passed", "matched", "count")}, indent=2))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
