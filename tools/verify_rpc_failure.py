#!/usr/bin/env python3
"""Exercise private management-RPC flush rollback and decrypted OTP counters."""

import argparse
import hashlib
import json
import socket
import struct
import sys
import tempfile
import threading
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
    sys.path.insert(0, str(args.root.resolve()))
    from emucard import EncryptedState
    from emucard.client import CcidSocketConnection, KeyboardSocketConnection
    from emucard.service import Server, receive

    rows = []

    def check(name, actual, expected):
        rows.append({"name": name, "actual": actual, "expected": expected,
                     "matched": actual == expected})

    def rpc(conn, payload):
        packet = bytes([5, 0x43]) + len(payload).to_bytes(2, "big")
        packet += bytes(5) + payload
        conn.sendall(struct.pack(">I", len(packet)) + packet)
        return receive(conn, struct.unpack(">I", receive(conn, 4))[0]).hex()

    def ticket(keyboard):
        chars = []
        for event in keyboard.press(1):
            usage = bytes.fromhex(event["report"])[2]
            if 4 <= usage <= 29:
                chars.append(chr(ord("a") + usage - 4))
        text = "".join(chars)
        raw = bytes((MODHEX.index(text[i]) << 4) | MODHEX.index(text[i + 1])
                    for i in range(0, len(text), 2))
        ctx = Cipher(algorithms.AES(KEY), modes.ECB()).decryptor()
        plain = ctx.update(raw) + ctx.finalize()
        return {"uid": plain[:6].hex(),
                "use_counter": int.from_bytes(plain[6:8], "little"),
                "session_counter": plain[11], "crc_valid": check_crc(plain)}

    def expected(use_counter, session_counter):
        return {"uid": UID.hex(), "use_counter": use_counter,
                "session_counter": session_counter, "crc_valid": True}

    with tempfile.TemporaryDirectory(prefix="ske-v48-rpc-", dir="/tmp") as tmp:
        directory = Path(tmp)
        state = EncryptedState(directory / "state.bin")
        sock = directory / "s.sock"
        with Server(sock, state, lambda *_: True) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                conn = CcidSocketConnection(sock)
                try:
                    YubiOtpSession(conn).put_configuration(
                        SLOT.ONE, YubiOtpSlotConfiguration(b"", UID, KEY))
                finally:
                    conn.close()
                keyboard = KeyboardSocketConnection(sock)
                try:
                    check("first_ticket", ticket(keyboard), expected(1, 0))
                finally:
                    keyboard.close()

                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as manager:
                    manager.connect(str(sock))
                    generation = int.from_bytes(server.read_usb_state()[1:9], "big")
                    disk = state.path.read_bytes()
                    original = state.flush

                    def fail():
                        raise OSError("fixture persistence failure")

                    state.flush = fail
                    try:
                        check("failed_reboot_status", rpc(manager, b"\x02\x0c\x00"),
                              "6581")
                    finally:
                        state.flush = original
                    check("failed_reboot_keeps_generation",
                          int.from_bytes(server.read_usb_state()[1:9], "big"),
                          generation)
                    check("failed_reboot_keeps_disk",
                          hashlib.sha256(state.path.read_bytes()).hexdigest(),
                          hashlib.sha256(disk).hexdigest())
                    # This same-connection commit catches a stale reset flag.
                    check("unrelated_commit_status", rpc(manager, b"\x00"), "9000")
                    keyboard = KeyboardSocketConnection(sock)
                    try:
                        check("failure_keeps_otp_session", ticket(keyboard),
                              expected(1, 1))
                    finally:
                        keyboard.close()
                    check("successful_reboot_status", rpc(manager, b"\x02\x0c\x00"),
                          "9000")
                    check("successful_reboot_advances_generation",
                          int.from_bytes(server.read_usb_state()[1:9], "big"),
                          generation + 1)
                    keyboard = KeyboardSocketConnection(sock)
                    try:
                        check("successful_reboot_resets_otp_session", ticket(keyboard),
                              expected(2, 0))
                    finally:
                        keyboard.close()
            finally:
                server.shutdown()
                thread.join(5)

    result = {"passed": all(row["matched"] for row in rows),
              "count": len(rows), "checks": rows,
              "physical_device_access": False,
              "firmware_5_7_4_differential_verified": False}
    args.result.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
