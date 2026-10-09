#!/usr/bin/env python3
"""Check OTP touch-status bits through official SDK APDU and OTP HID clients."""

import argparse
import hmac
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from yubikit.yubiotp import (
    HmacSha1SlotConfiguration,
    SLOT,
    StaticPasswordSlotConfiguration,
    YubiOtpSession,
)


KEY = bytes(range(20))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    sys.path.insert(0, str(root))
    from emucard.client import CcidSocketConnection, OtpSocketConnection

    rows = []

    def check(name, actual, expected):
        rows.append({"name": name, "actual": actual, "expected": expected,
                     "matched": actual == expected})

    def observe(sock, name, expected_flags):
        ccid = CcidSocketConnection(sock)
        try:
            apdu_sdk = YubiOtpSession(ccid)
            apdu_state = apdu_sdk.get_config_state()
            status, sw = ccid.send_and_receive(b"\0\x03\0\0")
        finally:
            ccid.close()
        hid = OtpSocketConnection(sock)
        try:
            hid_sdk = YubiOtpSession(hid)
            hid_state = hid_sdk.get_config_state()
            report = hid.receive()
        finally:
            hid.close()
        expected = {
            "apdu_sw": "0x9000",
            "apdu_flags": expected_flags,
            "hid_flags": expected_flags,
            "apdu_configured": [bool(expected_flags & 1), bool(expected_flags & 2)],
            "hid_configured": [bool(expected_flags & 1), bool(expected_flags & 2)],
            "apdu_touch": [bool(expected_flags & 4), bool(expected_flags & 8)],
            "hid_touch": [bool(expected_flags & 4), bool(expected_flags & 8)],
        }
        actual = {
            "apdu_sw": hex(sw),
            "apdu_flags": int.from_bytes(status[4:6], "little"),
            "hid_flags": int.from_bytes(report[5:7], "little"),
            "apdu_configured": [apdu_state.is_configured(slot) for slot in SLOT],
            "hid_configured": [hid_state.is_configured(slot) for slot in SLOT],
            "apdu_touch": [apdu_state.is_touch_triggered(slot) for slot in SLOT],
            "hid_touch": [hid_state.is_touch_triggered(slot) for slot in SLOT],
        }
        check(name, actual, expected)

    with tempfile.TemporaryDirectory(prefix="ske-v45-touch-", dir="/tmp") as tmp:
        directory = Path(tmp)
        sock = directory / "s.sock"
        state = directory / "state.bin"

        def start(index):
            log_path = directory / f"service-{index}.log"
            log = log_path.open("wb")
            process = subprocess.Popen(
                [sys.executable, "-m", "emucard.service", "--testing",
                 "--state", str(state), "--socket", str(sock)],
                cwd=root, stdout=log, stderr=log)
            deadline = time.monotonic() + 5
            try:
                while True:
                    if process.poll() is not None:
                        raise RuntimeError(log_path.read_text())
                    if sock.exists():
                        try:
                            ready = CcidSocketConnection(sock)
                            ready.close()
                            return process, log
                        except ConnectionRefusedError:
                            pass
                    if time.monotonic() >= deadline:
                        raise TimeoutError(log_path.read_text())
                    time.sleep(0.02)
            except BaseException:
                process.terminate()
                process.wait(5)
                log.close()
                raise

        def stop(process, log):
            process.terminate()
            process.wait(5)
            log.close()
            if sock.exists():
                raise AssertionError("private service left its socket")

        process, log = start(1)
        try:
            ccid = CcidSocketConnection(sock)
            try:
                sdk = YubiOtpSession(ccid)
                sdk.put_configuration(
                    SLOT.ONE, StaticPasswordSlotConfiguration(b"\x04"))
                observe(sock, "static_slot1_is_touch_triggered", 0x05)
                sdk.put_configuration(SLOT.TWO, HmacSha1SlotConfiguration(KEY))
                observe(sock, "static_slot1_hmac_slot2", 0x07)
                sdk.swap_slots()
                observe(sock, "swap_moves_touch_bit_to_slot2", 0x0B)
            finally:
                ccid.close()
        finally:
            stop(process, log)

        process, log = start(2)
        try:
            observe(sock, "touch_bits_survive_restart", 0x0B)
            ccid = CcidSocketConnection(sock)
            try:
                sdk = YubiOtpSession(ccid)
                response = sdk.calculate_hmac_sha1(SLOT.ONE, b"abc")
                check("challenge_slot_still_works", response.hex(),
                      hmac.digest(KEY, b"abc", "sha1").hex())
                sdk.delete_slot(SLOT.TWO)
            finally:
                ccid.close()
            observe(sock, "delete_clears_slot2_touch_bit", 0x01)
        finally:
            stop(process, log)

    result = {"passed": all(row["matched"] for row in rows),
              "count": len(rows), "checks": rows, "physical_device_access": False,
              "firmware_5_7_4_differential_verified": False}
    args.result.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
