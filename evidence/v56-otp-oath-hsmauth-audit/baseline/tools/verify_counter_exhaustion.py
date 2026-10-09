#!/usr/bin/env python3
"""Check 64-bit HOTP terminal-counter behavior on a private software card."""

import argparse
import hashlib
import hmac
import json
import sys
import tempfile
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--root", required=True, type=Path)
parser.add_argument("--report", required=True, type=Path)
args = parser.parse_args()
sys.path.insert(0, str(args.root.resolve()))

from emucard.core import Card, EncryptedState, Tlv  # noqa: E402
from yubikit.core.smartcard import AID  # noqa: E402

secret = b"12345678901234567890"
terminal = (1 << 64) - 1
checks = []


def check(name, condition, observed):
    checks.append({"name": name, "passed": bool(condition), "observed": observed})


with tempfile.TemporaryDirectory(prefix="ske-oath-exhaust-", dir="/tmp") as tmp:
    path = Path(tmp) / "card.bin"
    state = EncryptedState(path)
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
    card = Card(state)
    aid = bytes(AID.OATH)
    select = b"\0\xa4\x04\0" + bytes([len(aid)]) + aid
    data = Tlv(0x71, b"\x01") + Tlv(0x74, bytes(8))
    calculate = b"\0\xa2\0\0" + bytes([len(data)]) + data
    _, sw = card.transmit(select)
    check("select OATH", sw == 0x9000, hex(sw))

    for counter in (terminal - 1, terminal):
        response, sw = card.transmit(calculate)
        expected = Tlv(
            0x75, b"\x06" + hmac.digest(secret, counter.to_bytes(8, "big"), "sha1")
        )
        check(
            f"HOTP at {counter} uses the exact 8-byte counter",
            sw == 0x9000 and response == expected,
            {"sw": hex(sw), "response": response.hex()},
        )
    check(
        "next counter is an exhausted sentinel after the final valid HOTP",
        state.data["oath"]["credentials"]["01"]["counter"] == 1 << 64,
        state.data["oath"]["credentials"]["01"]["counter"],
    )
    state = EncryptedState(path)
    card = Card(state)
    _, sw = card.transmit(select)
    check("restart preserves OATH selection", sw == 0x9000, hex(sw))
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    try:
        response, sw = card.transmit(calculate)
        observed = {"sw": hex(sw), "response": response.hex()}
        rejected = sw == 0x6581 and response == b""
    except Exception as error:
        observed = {"exception": type(error).__name__, "message": str(error)}
        rejected = False
    check("exhausted HOTP returns generic error without crashing", rejected, observed)
    check(
        "exhausted rejection leaves encrypted state unchanged",
        hashlib.sha256(path.read_bytes()).hexdigest() == before,
        hashlib.sha256(path.read_bytes()).hexdigest(),
    )

result = {
    "passed": all(row["passed"] for row in checks),
    "test_count": len(checks),
    "tests": checks,
    "physical_device_access": False,
    "physical_firmware_5_7_4_exhaustion_response_measured": False,
}
args.report.write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps({"passed": result["passed"], "checks": len(checks)}))
if not result["passed"]:
    raise SystemExit(1)
