#!/usr/bin/env python3
"""Decrypt SDK-configured Yubico OTP tickets across select, reconnect, restart."""

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from yubikit.core.otp import check_crc
from yubikit.yubiotp import SLOT, YubiOtpSession, YubiOtpSlotConfiguration


KEY = bytes(range(16))
UID = bytes(range(16, 22))
MODHEX = "cbdefghijklnrtuv"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    sys.path.insert(0, str(root))
    from emucard import Card, EmulatorConnection, EncryptedState
    from emucard.client import CcidSocketConnection, KeyboardSocketConnection

    rows = []

    def check(name, actual, expected):
        rows.append({"name": name, "actual": actual, "expected": expected,
                     "matched": actual == expected})

    def decrypt(text):
        raw = bytes((MODHEX.index(text[i]) << 4) | MODHEX.index(text[i + 1])
                    for i in range(0, len(text), 2))
        ctx = Cipher(algorithms.AES(KEY), modes.ECB()).decryptor()
        ticket = ctx.update(raw) + ctx.finalize()
        return {"uid": ticket[:6].hex(),
                "use_counter": int.from_bytes(ticket[6:8], "little"),
                "session_counter": ticket[11],
                "crc_valid": check_crc(ticket)}

    def expected(use_counter, session_counter):
        return {"uid": UID.hex(), "use_counter": use_counter,
                "session_counter": session_counter, "crc_valid": True}

    state = EncryptedState()
    card = Card(state, lambda _: True)
    YubiOtpSession(EmulatorConnection(card)).put_configuration(
        SLOT.ONE, YubiOtpSlotConfiguration(b"", UID, KEY))
    check("in_memory_first", decrypt(card.otp_keypress(1)["text"]), expected(1, 0))
    # SELECT is a logical APDU session transition; device power remains present.
    YubiOtpSession(EmulatorConnection(card))
    check("in_memory_after_select", decrypt(card.otp_keypress(1)["text"]), expected(1, 1))
    other_card = Card(state, lambda _: True)
    check("in_memory_new_connection", decrypt(other_card.otp_keypress(1)["text"]), expected(1, 2))

    def typed(keyboard):
        chars = []
        for event in keyboard.press(1):
            report = bytes.fromhex(event["report"])
            usage = report[2]
            if 4 <= usage <= 29:
                chars.append(chr(ord("a") + usage - 4))
        return "".join(chars)

    with tempfile.TemporaryDirectory(prefix="ske-v46-ticket-", dir="/tmp") as tmp:
        directory = Path(tmp)
        sock = directory / "s.sock"
        state_path = directory / "state.bin"

        def start(index):
            log_path = directory / f"service-{index}.log"
            log = log_path.open("wb")
            process = subprocess.Popen(
                [sys.executable, "-m", "emucard.service", "--testing",
                 "--state", str(state_path), "--socket", str(sock)],
                cwd=root, stdout=log, stderr=log)
            deadline = time.monotonic() + 5
            try:
                while True:
                    if process.poll() is not None:
                        raise RuntimeError(log_path.read_text())
                    if sock.exists():
                        try:
                            conn = CcidSocketConnection(sock)
                            conn.close()
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
            conn = CcidSocketConnection(sock)
            try:
                YubiOtpSession(conn).put_configuration(
                    SLOT.ONE, YubiOtpSlotConfiguration(b"", UID, KEY))
            finally:
                conn.close()
            keyboard = KeyboardSocketConnection(sock)
            try:
                check("socket_first", decrypt(typed(keyboard)), expected(1, 0))
                check("socket_same_connection", decrypt(typed(keyboard)), expected(1, 1))
            finally:
                keyboard.close()
            keyboard = KeyboardSocketConnection(sock)
            try:
                check("socket_reconnect", decrypt(typed(keyboard)), expected(1, 2))
            finally:
                keyboard.close()
        finally:
            stop(process, log)
        process, log = start(2)
        try:
            keyboard = KeyboardSocketConnection(sock)
            try:
                check("process_restart", decrypt(typed(keyboard)), expected(2, 0))
            finally:
                keyboard.close()
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
