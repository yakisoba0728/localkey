#!/usr/bin/env python3
"""Exercise management reboot and OTP counters over private SDK sockets."""

import argparse
import json
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from yubikit.core.otp import check_crc
from yubikit.management import ManagementSession
from yubikit.yubiotp import SLOT, YubiOtpSession, YubiOtpSlotConfiguration


KEY = bytes(range(16))
UID = bytes(range(16, 22))
MODHEX = "cbdefghijklnrtuv"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    parser.add_argument("--management-transport", choices=("ccid", "otp", "rpc"),
                        default="ccid")
    args = parser.parse_args()
    root = args.root.resolve()
    sys.path.insert(0, str(root))
    from emucard.client import (CcidSocketConnection, KeyboardSocketConnection,
                                OtpSocketConnection)
    from emucard.service import receive

    rows = []

    def check(name, actual, expected):
        rows.append({"name": name, "actual": actual, "expected": expected,
                     "matched": actual == expected})

    def typed(keyboard):
        chars = []
        for event in keyboard.press(1):
            usage = bytes.fromhex(event["report"])[2]
            if 4 <= usage <= 29:
                chars.append(chr(ord("a") + usage - 4))
        return "".join(chars)

    def decrypt(text):
        raw = bytes((MODHEX.index(text[i]) << 4) | MODHEX.index(text[i + 1])
                    for i in range(0, len(text), 2))
        decryptor = Cipher(algorithms.AES(KEY), modes.ECB()).decryptor()
        plain = decryptor.update(raw) + decryptor.finalize()
        return {"uid": plain[:6].hex(),
                "use_counter": int.from_bytes(plain[6:8], "little"),
                "session_counter": plain[11], "crc_valid": check_crc(plain)}

    def expected(use_counter, session_counter):
        return {"uid": UID.hex(), "use_counter": use_counter,
                "session_counter": session_counter, "crc_valid": True}

    with tempfile.TemporaryDirectory(prefix="ske-v47-reboot-", dir="/tmp") as tmp:
        directory = Path(tmp)
        sock = directory / "s.sock"
        log_path = directory / "service.log"
        with log_path.open("wb") as log:
            process = subprocess.Popen(
                [sys.executable, "-m", "emucard.service", "--testing",
                 "--state", str(directory / "state.bin"), "--socket", str(sock)],
                cwd=root, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 5
                while True:
                    if process.poll() is not None:
                        raise RuntimeError(log_path.read_text())
                    if sock.exists():
                        try:
                            conn = CcidSocketConnection(sock)
                            conn.close()
                            break
                        except ConnectionRefusedError:
                            pass
                    if time.monotonic() >= deadline:
                        raise TimeoutError(log_path.read_text())
                    time.sleep(0.02)

                conn = CcidSocketConnection(sock)
                try:
                    YubiOtpSession(conn).put_configuration(
                        SLOT.ONE, YubiOtpSlotConfiguration(b"", UID, KEY))
                finally:
                    conn.close()
                keyboard = KeyboardSocketConnection(sock)
                try:
                    check("socket_first", decrypt(typed(keyboard)), expected(1, 0))
                    check("socket_next", decrypt(typed(keyboard)), expected(1, 1))
                finally:
                    keyboard.close()

                if args.management_transport == "rpc":
                    # Private service management frame used by FIDO routing.
                    payload = b"\x02\x0c\x00"
                    packet = bytes([5, 0x43]) + len(payload).to_bytes(2, "big")
                    packet += bytes(5) + payload
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                        conn.connect(str(sock))
                        conn.sendall(struct.pack(">I", len(packet)) + packet)
                        size = struct.unpack(">I", receive(conn, 4))[0]
                        check("rpc_management_success", receive(conn, size).hex(),
                              "9000")
                else:
                    conn = (CcidSocketConnection if args.management_transport == "ccid"
                            else OtpSocketConnection)(sock)
                    try:
                        ManagementSession(conn).write_device_config(reboot=True)
                    finally:
                        conn.close()
                keyboard = KeyboardSocketConnection(sock)
                try:
                    check("management_reboot", decrypt(typed(keyboard)), expected(2, 0))
                    check("after_management_reboot", decrypt(typed(keyboard)), expected(2, 1))
                finally:
                    keyboard.close()
            finally:
                process.terminate()
                process.wait(5)

    result = {"passed": all(row["matched"] for row in rows),
              "count": len(rows), "checks": rows,
              "physical_device_access": False,
              "firmware_5_7_4_differential_verified": False}
    args.result.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
