#!/usr/bin/env python3
"""Two private socket clients share one emulated OTP touch owner."""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from emucard.client import KeyboardSocketConnection
from tools.verify_smartcard import Fixture
from yubikit.core.otp import check_crc, modhex_decode
from yubikit.management import ManagementSession
from yubikit.yubiotp import SLOT, StaticPasswordSlotConfiguration, YubiOtpSlotConfiguration, YubiOtpSession


def ticket(reports, key):
    letters = {4 + n: c for n, c in enumerate("abcdefghijklmnopqrstuvwxyz")}
    chars = "".join(
        letters[bytes.fromhex(row["report"])[2]]
        for row in reports
        if bytes.fromhex(row["report"])[2] in letters
    )
    assert len(chars) == 32, len(chars)
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return decryptor.update(modhex_decode(chars)) + decryptor.finalize()


def attempt(fn):
    try:
        result = fn()
    except Exception as exc:
        return {"sw": getattr(exc, "sw", type(exc).__name__)}
    return {"events": len(result)}


def run(root):
    checks = []

    def check(name, actual, expected):
        if isinstance(actual, bytes):
            actual = actual.hex()
        if isinstance(expected, bytes):
            expected = expected.hex()
        checks.append({"name": name, "actual": actual, "expected": expected, "matched": actual == expected})

    with tempfile.TemporaryDirectory(prefix="ske-shared-touch-") as temp:
        directory = Path(temp)
        fixture = Fixture(root, directory)
        conn = fixture.start()
        a = KeyboardSocketConnection(directory / "s.sock")
        b = KeyboardSocketConnection(directory / "s.sock")
        try:
            otp = YubiOtpSession(conn)
            otp.put_configuration(SLOT.ONE, StaticPasswordSlotConfiguration(bytes([0x84, 5, 30])).fast_trigger(False))
            expected = a.press(1)
            check("normal_press_before_touch", len(expected), 8)
            check("owner_a_down_outputs", a.touch_down(), expected)
            check("other_b_press_denied", attempt(lambda: b.press(1)), {"sw": 0x6985})
            check("other_b_hold_denied", attempt(lambda: b.hold(3500)), {"sw": 0x6985})
            check("other_b_down_denied", attempt(b.touch_down), {"sw": 0x6985})
            check("other_b_up_denied", attempt(lambda: b.touch_up(3500)), {"sw": 0x6985})
            b.close()
            b = KeyboardSocketConnection(directory / "s.sock")
            check("other_client_close_does_not_release_owner", attempt(lambda: b.press(1)), {"sw": 0x6985})
            check("owner_a_up_no_duplicate", a.touch_up(3500), [])
            check("b_press_after_owner_release", b.press(1), expected)
            check("b_hold_after_owner_release", b.hold(3500), expected)
            check("a_down_before_disconnect", a.touch_down(), expected)
            a.close()
            a = None
            # Handler cleanup follows EOF; wait for that event rather than assuming
            # a scheduling order between close() and the other client request.
            deadline = time.monotonic() + 2
            while True:
                result = attempt(b.touch_down)
                if result != {"sw": 0x6985} or time.monotonic() >= deadline:
                    break
                time.sleep(0.01)
            check("owner_disconnect_releases_touch", result, {"events": 8})
            check("new_owner_up_no_duplicate", b.touch_up(3500), [])
            a = KeyboardSocketConnection(directory / "s.sock")
            check("a_down_before_management_reboot", a.touch_down(), expected)
            ManagementSession(conn).write_device_config(reboot=True)
            check("committed_reboot_clears_shared_touch", b.press(1), expected)
            check("old_owner_up_after_reboot_denied", attempt(lambda: a.touch_up(3500)), {"sw": 0x6985})

            otp = YubiOtpSession(conn)
            uid, key = bytes.fromhex("010203040506"), bytes.fromhex("11" * 16)
            otp.put_configuration(SLOT.ONE, YubiOtpSlotConfiguration(b"", uid, key).fast_trigger(False))
            first = ticket(a.touch_down(), key)
            check("first_a_ticket_aes_crc", first[:6] == uid and check_crc(first), True)
            check("b_hold_cannot_consume_ticket", attempt(lambda: b.hold(3500)), {"sw": 0x6985})
            check("b_press_cannot_consume_ticket", attempt(lambda: b.press(1)), {"sw": 0x6985})
            check("a_release_no_ticket", a.touch_up(3500), [])
            second = ticket(b.touch_down(), key)
            check("second_b_ticket_aes_crc", second[:6] == uid and check_crc(second), True)
            check("shared_session_counter_unchanged", second[6:8], first[6:8])
            check("shared_usage_counter_plus_one", second[11], first[11] + 1)
            check("b_release_no_ticket", b.touch_up(3500), [])
        finally:
            if a is not None:
                a.close()
            b.close()
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
        "firmware_5_7_4_cross_client_behavior_verified": False,
    }
    args.result.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: result[k] for k in ("passed", "matched", "count")}, indent=2))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
