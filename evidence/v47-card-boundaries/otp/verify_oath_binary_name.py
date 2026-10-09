#!/usr/bin/env python3
"""Check byte-string OATH names through YubiKit APDUs and independent HMAC."""

import argparse
import hmac
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from yubikit.core import Tlv
from yubikit.core.smartcard import ApduError
from yubikit.oath import OathSession


SECRET = b"Yubico OATH binary name fixture"
CHALLENGE = bytes.fromhex("0000000000000001")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    sys.path.insert(0, str(root))
    from emucard import Card, EmulatorConnection, EncryptedState
    from emucard.client import CcidSocketConnection

    rows = []
    labels = []
    card = Card(EncryptedState(), lambda label: labels.append(label) or True)
    session = OathSession(EmulatorConnection(card))

    def check(name, actual, expected):
        rows.append({"name": name, "actual": actual, "expected": expected,
                     "matched": actual == expected})

    def put(name, target=None):
        target = target or session
        payload = bytes(Tlv(0x71, name))
        payload += bytes(Tlv(0x73, b"\x21\x06" + SECRET)) + b"\x78\x02"
        target.protocol.send_apdu(0, 1, 0, 0, payload)

    def calculate(name):
        payload = bytes(Tlv(0x71, name)) + bytes(Tlv(0x74, CHALLENGE))
        try:
            return session.protocol.send_apdu(0, 0xA2, 0, 0, payload).hex()
        except ApduError as exc:
            return f"SW={exc.sw:04x}"

    expected = bytes(Tlv(0x75, b"\x06" + hmac.digest(SECRET, CHALLENGE, "sha1"))).hex()
    text_name = "한글 계정".encode()
    binary_name = b"\xff\x00binary"
    put(text_name)
    check("utf8_touch_calculation", calculate(text_name), expected)
    put(binary_name)
    listed = session.protocol.send_apdu(0, 0xA1, 0, 0)
    check("binary_name_listed", bytes(Tlv(0x72, b"\x21" + binary_name)) in listed,
          True)
    check("binary_touch_calculation", calculate(binary_name), expected)
    try:
        sdk_digest = session.calculate(binary_name, CHALLENGE).hex()
    except ApduError as exc:
        sdk_digest = f"SW={exc.sw:04x}"
    check("high_level_sdk_binary_calculation", sdk_digest,
          hmac.digest(SECRET, CHALLENGE, "sha1").hex())
    check("binary_touch_label_lossless", labels[-1] if labels else "", "OATH \\xff\\x00binary")
    card.touch = lambda _: False
    try:
        session.calculate(binary_name, CHALLENGE)
    except ApduError as exc:
        denied_status = f"SW={exc.sw:04x}"
    else:
        denied_status = "success"
    check("binary_name_still_requires_touch", denied_status, "SW=6985")

    with tempfile.TemporaryDirectory(prefix="ske-v47-oath-", dir="/tmp") as tmp:
        directory = Path(tmp)
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
                            conn = CcidSocketConnection(sock)
                            break
                        except ConnectionRefusedError:
                            pass
                    if time.monotonic() >= deadline:
                        raise TimeoutError("private service did not start")
                    time.sleep(0.02)
                try:
                    socket_session = OathSession(conn)
                    put(binary_name, socket_session)
                    try:
                        digest = socket_session.calculate(binary_name, CHALLENGE).hex()
                    except ApduError as exc:
                        digest = f"SW={exc.sw:04x}"
                    check("socket_sdk_binary_calculation", digest,
                          hmac.digest(SECRET, CHALLENGE, "sha1").hex())
                finally:
                    conn.close()
            finally:
                process.terminate()
                process.wait(5)

    result = {"passed": all(row["matched"] for row in rows), "count": len(rows),
              "checks": rows, "physical_device_access": False,
              "firmware_5_7_4_differential_verified": False,
              "sdk": "YubiKit SmartCardProtocol over in-memory EmulatorConnection"}
    args.result.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
