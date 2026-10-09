#!/usr/bin/env python3
"""Check Yubico's 14-byte OATH PUT key boundary with independent YubiKit."""

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
from yubikit.oath import CredentialData, HASH_ALGORITHM, OATH_TYPE, OathSession


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
    challenge = b"\0" * 7 + b"\1"
    short = b"S" * 13
    minimum = b"M" * 14

    def check(name, actual, expected):
        rows.append({"name": name, "actual": actual, "expected": expected,
                     "matched": actual == expected})

    def raw_put(session, name, secret):
        data = bytes(Tlv(0x71, name)) + bytes(Tlv(0x73, b"\x21\x06" + secret))
        try:
            session.protocol.send_apdu(0, 1, 0, 0, data)
        except ApduError as exc:
            return f"SW={exc.sw:04x}"
        return "SW=9000"

    card = Card(EncryptedState(), lambda _: True)
    session = OathSession(EmulatorConnection(card))
    before = dict(card.state.data["oath"]["credentials"])
    result = raw_put(session, b"short13", short)
    check("raw_13_byte_key_rejected_without_mutation",
          {"status": result, "unchanged": card.state.data["oath"]["credentials"] == before},
          {"status": "SW=6a80", "unchanged": True})
    check("raw_14_byte_key_accepted", raw_put(session, b"minimum14", minimum),
          "SW=9000")
    check("raw_14_byte_key_hmac",
          session.calculate(b"minimum14", challenge).hex(),
          hmac.digest(minimum, challenge, "sha1").hex())
    check("64_byte_name_accepted", raw_put(session, b"N" * 64, minimum),
          "SW=9000")
    before = dict(card.state.data["oath"]["credentials"])
    result = raw_put(session, b"N" * 65, minimum)
    check("65_byte_name_rejected_without_mutation",
          {"status": result, "unchanged": card.state.data["oath"]["credentials"] == before},
          {"status": "SW=6a80", "unchanged": True})
    sdk_credential = session.put_credential(CredentialData(
        "sdk one byte", OATH_TYPE.TOTP, HASH_ALGORITHM.SHA1, b"\x01"))
    check("sdk_short_key_is_padded_to_14_bytes",
          len(bytes.fromhex(card.state.data["oath"]["credentials"][sdk_credential.id.hex()]["secret"])),
          14)
    check("sdk_short_key_hmac",
          session.calculate(sdk_credential.id, challenge).hex(),
          hmac.digest(b"\x01", challenge, "sha1").hex())
    check("zero_length_challenge_hmac",
          session.calculate(b"minimum14", b"").hex(),
          hmac.digest(minimum, b"", "sha1").hex())
    check("64_byte_challenge_hmac",
          session.calculate(b"minimum14", bytes(range(64))).hex(),
          hmac.digest(minimum, bytes(range(64)), "sha1").hex())

    with tempfile.TemporaryDirectory(prefix="ske-v49-oath-", dir="/tmp") as temp:
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
                            connection = CcidSocketConnection(sock)
                            break
                        except ConnectionRefusedError:
                            pass
                    if time.monotonic() >= deadline:
                        raise TimeoutError("private service did not start")
                    time.sleep(0.02)
                try:
                    socket_session = OathSession(connection)
                    check("socket_raw_13_byte_key_rejected",
                          raw_put(socket_session, b"socket13", short), "SW=6a80")
                    credential = socket_session.put_credential(CredentialData(
                        "socket sdk short", OATH_TYPE.TOTP, HASH_ALGORITHM.SHA1,
                        b"\x02"))
                    check("socket_sdk_short_key_hmac",
                          socket_session.calculate(credential.id, challenge).hex(),
                          hmac.digest(b"\x02", challenge, "sha1").hex())
                finally:
                    connection.close()
            finally:
                process.terminate()
                process.wait(5)

    report = {"passed": all(row["matched"] for row in rows),
              "count": len(rows), "checks": rows,
              "physical_device_access": False,
              "firmware_5_7_4_differential_verified": False,
              "transport": "YubiKit OathSession and SmartCardProtocol over in-memory card and private Unix CCID"}
    args.result.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
