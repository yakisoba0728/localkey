#!/usr/bin/env python3
"""Exercise CTAPHID WINK framing over the daemon's private test socket."""

import argparse
import hashlib
import json
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path


def exchange(connection, cid, cmd, payload):
    frame = cid + bytes([0x80 | cmd, len(payload) >> 8, len(payload) & 0xFF]) + payload
    connection.sendall(frame.ljust(64, b"\0"))
    result = bytearray()
    while len(result) < 64:
        block = connection.recv(64 - len(result))
        if not block:
            raise EOFError("daemon closed FIDO socket")
        result.extend(block)
    return bytes(result)


def run(binary, expect_fixed):
    with tempfile.TemporaryDirectory(prefix="ske59-wink-", dir="/tmp") as temporary:
        work = Path(temporary)
        path = work / "h.sock"
        with (work / "daemon.log").open("wb") as log:
            process = subprocess.Popen(
                [str(binary), "--testing", "--dek-file", "--key-backend=software",
                 "--store", str(work / "state.bin"), "--ctl-socket", str(work / "c.sock")],
                env={**os.environ, "SWPASSKEY_HID_SOCKET": str(path), "SWPASSKEY_LOG": "warn"},
                stdout=log, stderr=log,
            )
            connection = None
            try:
                for _ in range(100):
                    if process.poll() is not None:
                        raise RuntimeError("daemon exited before FIDO socket was ready")
                    if path.exists():
                        try:
                            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                            connection.settimeout(5)
                            connection.connect(str(path))
                        except ConnectionRefusedError:
                            connection.close()
                            connection = None
                        else:
                            break
                    time.sleep(0.05)
                if connection is None:
                    raise TimeoutError("FIDO socket did not start")
                nonce = b"wink-v59"
                init = exchange(connection, b"\xff" * 4, 0x06, nonce)
                assert init[:4] == b"\xff" * 4 and init[4] == 0x86
                assert init[5:7] == b"\x00\x11" and init[7:15] == nonce
                cid = init[15:19]
                assert cid not in (b"\x00" * 4, b"\xff" * 4)
                malformed = exchange(connection, cid, 0x08, b"\x01")
                if expect_fixed:
                    assert malformed[:5] == cid + b"\xbf" and malformed[5:8] == b"\x00\x01\x03"
                else:
                    assert malformed[:5] == cid + b"\x88" and malformed[5:7] == b"\x00\x00"
                valid = exchange(connection, cid, 0x08, b"")
                assert valid[:7] == cid + b"\x88\x00\x00"
                ping = exchange(connection, cid, 0x01, b"still-alive")
                assert ping[:7 + 11] == cid + b"\x81\x00\x0b" + b"still-alive"
                return {"passed": True, "expect_fixed": expect_fixed,
                        "malformed_reply_cmd": malformed[4],
                        "malformed_reply_payload_hex": malformed[7:8].hex() if expect_fixed else "",
                        "valid_wink": True, "fresh_ping": True,
                        "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                        "physical_device_access": False}
            finally:
                if connection is not None:
                    connection.close()
                process.terminate()
                try:
                    process.wait(5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--expect-fixed", action="store_true")
    arguments = parser.parse_args()
    result = run(arguments.binary, arguments.expect_fixed)
    arguments.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
