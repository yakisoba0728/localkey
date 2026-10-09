#!/usr/bin/env python3
"""Check documented two-slot OTP touch windows with SDK-written settings."""

import argparse
import json
import sys
from pathlib import Path

from yubikit.yubiotp import SLOT, StaticPasswordSlotConfiguration, YubiOtpSession

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from emucard import Card, EmulatorConnection, EncryptedState
from emucard.core import CardError


def press(card, duration_ms):
    try:
        reports = card.otp_button_events(duration_ms)
    except CardError as exc:
        return {"kind": "denied", "status": hex(exc.sw)}
    usages = [bytes.fromhex(row["report"])[2] for row in reports]
    usages = [usage for usage in usages if usage]
    return {"kind": "typed", "usages": usages}


card = Card(EncryptedState(), lambda _: True)
sdk = YubiOtpSession(EmulatorConnection(card))
sdk.put_configuration(SLOT.ONE, StaticPasswordSlotConfiguration(b"\x04"))
cases = [("one_slot_500ms", 500, {"kind": "typed", "usages": [4, 40]})]
observed = []
for label, ms, expected in cases:
    actual = press(card, ms)
    observed.append({"name": label, "actual": actual, "expected": expected, "matched": actual == expected})

sdk.put_configuration(SLOT.TWO, StaticPasswordSlotConfiguration(b"\x05"))
assert set(card.state.data["otp"]["slots"]) == {"1", "2"}
assert bytes.fromhex(card.state.data["otp"]["slots"]["1"]["config"])[45] & 0x10
cases = [
    ("two_slots_500ms", 500, {"kind": "denied", "status": "0x6985"}),
    ("two_slots_2000ms", 2000, {"kind": "typed", "usages": [4, 40]}),
    ("two_slots_2750ms", 2750, {"kind": "denied", "status": "0x6985"}),
    ("two_slots_3500ms", 3500, {"kind": "typed", "usages": [5, 40]}),
]
for label, ms, expected in cases:
    actual = press(card, ms)
    observed.append({"name": label, "actual": actual, "expected": expected, "matched": actual == expected})
result = {"passed": all(row["matched"] for row in observed),
          "count": len(observed),
          "tests": [{"name": row["name"], "passed": row["matched"]} for row in observed],
          "observations": observed,
          "physical_device_access": False, "exact_firmware_timing_verified": False}
parser = argparse.ArgumentParser()
parser.add_argument("--report", type=Path, required=True)
args = parser.parse_args()
args.report.parent.mkdir(parents=True, exist_ok=True)
args.report.write_text(json.dumps(result, indent=2) + "\n")
for row in observed:
    print(("PASS" if row["matched"] else "FAIL"), row["name"], flush=True)
raise SystemExit(0 if result["passed"] else 1)
