#!/usr/bin/env python3
"""Check one-slot FAST_TRIG output across simulated hold/release requests."""

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from yubikit.core.smartcard import ApduError
from yubikit.yubiotp import SLOT, StaticPasswordSlotConfiguration, YubiOtpSession


def observed_events(events):
    usages = [bytes.fromhex(row["report"])[2] for row in events]
    return {"kind": "typed", "usages": [usage for usage in usages if usage]}


def observed_wire_response(raw):
    status = int.from_bytes(raw[:2], "big")
    if status != 0x9000:
        return {"kind": "denied", "status": f"SW={status:04x}"}
    count = int.from_bytes(raw[2:4], "big")
    if len(raw) != 4 + count * 10:
        raise ValueError("invalid private native keyboard frame")
    return observed_events(
        {"report": raw[4 + n * 10 : 12 + n * 10].hex()}
        for n in range(count)
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    parser.add_argument("--native-binary", required=True, type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    native_binary = args.native_binary.resolve()
    sys.path.insert(0, str(root))
    from emucard import Card, EmulatorConnection, EncryptedState
    from emucard.client import KeyboardSocketConnection, OtpSocketConnection
    from emucard.core import CardError

    rows = []

    def check(name, actual, expected):
        rows.append({"name": name, "actual": actual, "expected": expected,
                     "matched": actual == expected})

    def press(card, duration):
        try:
            return observed_events(card.otp_button_events(duration))
        except CardError as exc:
            return {"kind": "denied", "status": f"SW={exc.sw:04x}"}

    def card_with_slots(slot1=True, slot2=False, fast=False):
        card = Card(EncryptedState(), lambda _: True)
        sdk = YubiOtpSession(EmulatorConnection(card))
        if slot1:
            sdk.put_configuration(
                SLOT.ONE, StaticPasswordSlotConfiguration(b"\x04").fast_trigger(fast)
            )
        if slot2:
            sdk.put_configuration(SLOT.TWO, StaticPasswordSlotConfiguration(b"\x05"))
        return card

    first = {"kind": "typed", "usages": [4, 40]}
    second = {"kind": "typed", "usages": [5, 40]}
    denied = {"kind": "denied", "status": "SW=6985"}
    for fast in (False, True):
        card = card_with_slots(fast=fast)
        label = "flag_on" if fast else "flag_off"
        check(f"one_slot1_{label}_500ms", press(card, 500), first)
        check(f"one_slot1_{label}_2750ms", press(card, 2750), first)
        check(f"one_slot1_{label}_3500ms", press(card, 3500), first)

    card = card_with_slots(slot1=True, slot2=True, fast=True)
    check("two_slots_2000ms", press(card, 2000), first)
    check("two_slots_2750ms", press(card, 2750), denied)
    check("two_slots_3500ms", press(card, 3500), second)
    card = card_with_slots(slot1=False, slot2=True)
    check("only_slot2_500ms", press(card, 500), denied)
    check("only_slot2_3500ms", press(card, 3500), second)

    with tempfile.TemporaryDirectory(prefix="ske-v50-otp-", dir="/tmp") as temp:
        directory = Path(temp)
        sock = directory / "s.sock"
        with (directory / "service.log").open("wb") as log:
            process = subprocess.Popen(
                [sys.executable, "-m", "emucard.service", "--testing",
                 "--state", str(directory / "state.bin"), "--socket", str(sock)],
                cwd=root, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 5
                while True:
                    if process.poll() is not None:
                        raise RuntimeError("private service exited")
                    if sock.exists():
                        try:
                            otp = OtpSocketConnection(sock)
                            break
                        except ConnectionRefusedError:
                            pass
                    if time.monotonic() >= deadline:
                        raise TimeoutError("private service did not start")
                    time.sleep(0.02)
                try:
                    sdk = YubiOtpSession(otp)
                    sdk.put_configuration(SLOT.ONE, StaticPasswordSlotConfiguration(b"\x04"))
                finally:
                    otp.close()
                button = KeyboardSocketConnection(sock)
                try:
                    for duration, expected in ((500, first), (3500, first)):
                        try:
                            actual = observed_events(button.hold(duration))
                        except ApduError as exc:
                            actual = {"kind": "denied", "status": f"SW={exc.sw:04x}"}
                        check(f"private_socket_single_slot1_{duration}ms", actual, expected)
                finally:
                    button.close()
                native = subprocess.run(
                    [str(native_binary), "--wire-test", str(sock), "--hold-ms", "3500"],
                    check=True, capture_output=True, text=True,
                )
                raw = bytes.fromhex(json.loads(native.stdout)["keyboard_events"])
                check("native_wire_test_single_slot1_3500ms",
                      observed_wire_response(raw), first)
            finally:
                process.terminate()
                process.wait(5)

    report = {"passed": all(row["matched"] for row in rows),
              "count": len(rows), "checks": rows,
              "physical_device_access": False,
              "firmware_5_7_4_timing_verified": False,
              "transport": "YubiKit OTP configuration over in-memory and private OTP HID socket; private software button reports"}
    args.result.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
