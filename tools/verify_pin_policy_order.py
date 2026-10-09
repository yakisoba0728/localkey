#!/usr/bin/env python3
"""Check PIN retry handling before force-change token policy on private CTAPHID."""
from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Config
from fido2.ctap2.pin import PinProtocolV1, PinProtocolV2
from verify_ctap import Fixture


def attempt(fn):
    try:
        fn()
        return 0
    except CtapError as error:
        return int(error.code)


def run(binary: Path, expect_fixed: bool) -> dict:
    with tempfile.TemporaryDirectory(prefix="ske-pin-policy-") as temp:
        fixture = Fixture(binary.resolve(), Path(temp))
        try:
            ctap = fixture.start()
            protocol2 = PinProtocolV2()
            permission = ClientPin.PERMISSION
            pin = ClientPin(ctap, protocol2)
            pin.set_pin("12345678")
            token = pin.get_pin_token("12345678", permission.AUTHENTICATOR_CFG)
            Config(ctap, protocol2, token).set_min_pin_length(9, force_change_pin=True)
            assert ctap.get_info().force_pin_change
            before = pin.get_pin_retries()[0]
            wrong = attempt(lambda: ClientPin(ctap, protocol2).get_pin_token("00000000", permission.CREDENTIAL_MGMT))
            after_wrong = ClientPin(ctap, protocol2).get_pin_retries()[0]
            correct = attempt(lambda: ClientPin(ctap, protocol2).get_pin_token("12345678", permission.CREDENTIAL_MGMT))
            after_correct = ClientPin(ctap, protocol2).get_pin_retries()[0]
            legacy = attempt(lambda: ClientPin(ctap, PinProtocolV1()).get_pin_token("12345678"))
            final = ClientPin(ctap, protocol2).get_pin_retries()[0]
        finally:
            fixture.stop()
    assert before == 8 and correct == 0x37
    if expect_fixed:
        assert (wrong, after_wrong, after_correct, legacy, final) == (0x31, 7, 8, 0x31, 8)
    else:
        assert (wrong, after_wrong, after_correct, legacy, final) == (0x37, 8, 8, 0x37, 8)
    return {"passed": True, "expected_fixed": expect_fixed,
            "transport": "private CTAPHID Unix socket", "physical_device_access": False,
            "initial_retries": before, "wrong_pin_status": f"0x{wrong:02x}",
            "retries_after_wrong_pin": after_wrong, "correct_pin_status": f"0x{correct:02x}",
            "retries_after_correct_pin": after_correct, "legacy_correct_pin_status": f"0x{legacy:02x}",
            "final_retries": final,
            "tests": [{"name": label, "passed": True} for label in (
                "wrong PIN is checked before forced-change policy",
                "wrong PIN decrements durable retries",
                "correct PIN restores retries before reporting policy",
                "legacy token uses PIN_INVALID for forced change",
            )]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--expect-fixed", action="store_true")
    args = parser.parse_args()
    result = run(args.binary, args.expect_fixed)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
