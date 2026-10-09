#!/usr/bin/env python3
"""Verify exhausted HOTP over a private CCID socket and a service restart."""

import argparse
import hashlib
import hmac
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--root", required=True, type=Path)
parser.add_argument("--report", required=True, type=Path)
args = parser.parse_args()
root = args.root.resolve()
sys.path.insert(0, str(root))

from emucard.client import CcidSocketConnection  # noqa: E402
from emucard.core import EncryptedState, Tlv  # noqa: E402
from yubikit.core.smartcard import AID  # noqa: E402

secret = b"12345678901234567890"
terminal = (1 << 64) - 1
checks = []


def check(name, passed, observed):
    checks.append({"name": name, "passed": bool(passed), "observed": observed})


with tempfile.TemporaryDirectory(prefix="ske-oath-socket-", dir="/tmp") as tmp:
    directory = Path(tmp)
    state_path = directory / "card.bin"
    socket_path = directory / "card.sock"
    state = EncryptedState(state_path)
    state.data["oath"]["credentials"]["01"] = {
        "secret": secret.hex(),
        "type": 0x10,
        "hash": 1,
        "digits": 6,
        "counter": terminal - 1,
        "touch": False,
        "increasing": False,
    }
    state.flush()
    aid = bytes(AID.OATH)
    select = b"\0\xa4\x04\0" + bytes([len(aid)]) + aid
    data = Tlv(0x71, b"\x01") + Tlv(0x74, bytes(8))
    calculate = b"\0\xa2\0\0" + bytes([len(data)]) + data

    def start(index):
        log = (directory / f"service-{index}.log").open("wb")
        process = subprocess.Popen(
            [sys.executable, "-m", "emucard.service", "--state", str(state_path),
             "--socket", str(socket_path)],
            cwd=root, stdout=log, stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f"card service exited; see {log.name}")
            if socket_path.is_socket():
                return process, log
            time.sleep(0.02)
        raise TimeoutError("card service did not open private socket")

    def stop(process, log):
        process.terminate()
        process.wait(timeout=5)
        log.close()
        socket_path.unlink(missing_ok=True)

    process, log = start(1)
    try:
        connection = CcidSocketConnection(socket_path)
        try:
            _, sw = connection.send_and_receive(select)
            check("socket selects OATH", sw == 0x9000, hex(sw))
            for counter in (terminal - 1, terminal):
                response, sw = connection.send_and_receive(calculate)
                expected = Tlv(
                    0x75,
                    b"\x06" + hmac.digest(secret, counter.to_bytes(8, "big"), "sha1"),
                )
                check(
                    f"socket HOTP at {counter} uses exact counter",
                    sw == 0x9000 and response == expected,
                    {"sw": hex(sw), "response": response.hex()},
                )
        finally:
            connection.close()
    finally:
        stop(process, log)

    check(
        "next-counter sentinel persists across service restart",
        EncryptedState(state_path).data["oath"]["credentials"]["01"]["counter"]
        == 1 << 64,
        EncryptedState(state_path).data["oath"]["credentials"]["01"]["counter"],
    )
    process, log = start(2)
    try:
        connection = CcidSocketConnection(socket_path)
        try:
            _, sw = connection.send_and_receive(select)
            check("restarted socket selects OATH", sw == 0x9000, hex(sw))
            before = hashlib.sha256(state_path.read_bytes()).hexdigest()
            try:
                response, sw = connection.send_and_receive(calculate)
                observed = {"sw": hex(sw), "response": response.hex()}
                rejected = sw == 0x6581 and response == b""
            except Exception as error:
                observed = {"exception": type(error).__name__, "message": str(error)}
                rejected = False
            check("exhausted socket HOTP rejects without transport failure", rejected, observed)
            check(
                "exhausted socket rejection keeps ciphertext unchanged",
                hashlib.sha256(state_path.read_bytes()).hexdigest() == before,
                hashlib.sha256(state_path.read_bytes()).hexdigest(),
            )
            try:
                listing, sw = connection.send_and_receive(b"\0\xa1\0\0")
                alive = sw == 0x9000 and bytes(Tlv(0x72, b"\x11\x01")) in listing
                observed = {"sw": hex(sw), "listing": listing.hex()}
            except Exception as error:
                alive = False
                observed = {"exception": type(error).__name__, "message": str(error)}
            check("service remains usable for LIST after exhaustion", alive, observed)
        finally:
            try:
                connection.close()
            except Exception:
                pass
    finally:
        stop(process, log)

result = {
    "passed": all(row["passed"] for row in checks),
    "test_count": len(checks),
    "tests": checks,
    "transport": "private CCID socket",
    "physical_device_access": False,
    "physical_firmware_5_7_4_exhaustion_response_measured": False,
}
args.report.write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps({"passed": result["passed"], "checks": len(checks)}))
if not result["passed"]:
    raise SystemExit(1)
