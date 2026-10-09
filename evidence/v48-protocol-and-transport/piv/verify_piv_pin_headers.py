#!/usr/bin/env python3
"""Check documented PIV PIN-command headers over software YubiKit transports."""

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from yubikit.core.smartcard import ApduError
from yubikit.piv import PivSession


def block(value):
    return value.encode("ascii").ljust(8, b"\xff")


def status(protocol, ins, p1, p2, data, le=0):
    try:
        protocol.send_apdu(0, ins, p1, p2, data, le)
    except ApduError as error:
        return f"SW={error.sw:04x}"
    return "SW=9000"


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

    def check(name, actual, expected):
        rows.append({"name": name, "actual": actual, "expected": expected,
                     "matched": actual == expected})

    def fixture():
        card = Card(EncryptedState(), lambda _: True)
        return card, PivSession(EmulatorConnection(card))

    invalid = (
        ("verify_p1_success", 0x20, 1, 0x80, block("123456"), 0),
        ("verify_p1_wrong_pin", 0x20, 1, 0x80, block("999999"), 0),
        ("verify_explicit_le", 0x20, 0, 0x80, block("123456"), 1),
        ("change_p1_success", 0x24, 1, 0x80,
         block("123456") + block("654321"), 0),
        ("change_explicit_le", 0x24, 0, 0x80,
         block("123456") + block("654321"), 1),
        ("reset_retry_p1", 0x2C, 1, 0x80,
         block("12345678") + block("654321"), 0),
        ("reset_retry_p2", 0x2C, 0, 0x81,
         block("12345678") + block("654321"), 0),
        ("reset_retry_explicit_le", 0x2C, 0, 0x80,
         block("12345678") + block("654321"), 1),
    )
    for name, ins, p1, p2, data, le in invalid:
        card, session = fixture()
        before = (card.state.data["piv"]["pin"],
                  card.state.data["piv"]["pin_retries"],
                  card.state.data["piv"]["puk_retries"])
        actual_status = status(session.protocol, ins, p1, p2, data, le)
        after = (card.state.data["piv"]["pin"],
                 card.state.data["piv"]["pin_retries"],
                 card.state.data["piv"]["puk_retries"])
        expected_status = "SW=6700" if le else "SW=6a86"
        check(name, {"status": actual_status, "persistent_unchanged": before == after,
                     "pin_authorized": ("piv", "pin") in card.verified},
              {"status": expected_status, "persistent_unchanged": True,
               "pin_authorized": False})

    card, session = fixture()
    session.verify_pin("123456")
    check("sdk_verify_pin_normal", ("piv", "pin") in card.verified, True)
    card, session = fixture()
    session.change_pin("123456", "654321")
    check("sdk_change_pin_normal", card.state.data["piv"]["pin"], "654321")
    card, session = fixture()
    session.change_puk("12345678", "87654321")
    check("sdk_change_puk_normal", card.state.data["piv"]["puk"], "87654321")
    card, session = fixture()
    session.unblock_pin("12345678", "654321")
    check("sdk_reset_retry_normal", card.state.data["piv"]["pin"], "654321")

    with tempfile.TemporaryDirectory(prefix="ske-v48-piv-", dir="/tmp") as temp:
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
                    session = PivSession(connection)
                    actual = status(session.protocol, 0x2C, 0, 0x81,
                                    block("12345678") + block("654321"))
                    check("socket_reset_retry_wrong_p2", actual, "SW=6a86")
                    session.unblock_pin("12345678", "654321")
                    session.verify_pin("654321")
                    check("socket_sdk_normal_after_rejection", True, True)
                finally:
                    connection.close()
            finally:
                process.terminate()
                process.wait(5)

    report = {"passed": all(row["matched"] for row in rows),
              "count": len(rows), "checks": rows,
              "physical_device_access": False,
              "firmware_5_7_4_differential_verified": False,
              "transport": "YubiKit PivSession and SmartCardProtocol over in-memory card and private Unix CCID"}
    args.result.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
