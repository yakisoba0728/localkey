#!/usr/bin/env python3
"""Malformed pinHashEnc must consume a durable PIN retry before decryption."""
from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin
from fido2.ctap2.pin import PinProtocolV2
from verify_ctap import Fixture


def attempt(ctap, protocol):
    authenticator_key = ctap.client_pin(2, 2)[1]
    platform_key, _ = protocol.encapsulate(authenticator_key)
    try:
        ctap.client_pin(2, 9, platform_key, pin_hash_enc=b"\x01", permissions=4)
        return 0
    except CtapError as error:
        return int(error.code)


def valid_attempt(pin, text):
    try:
        pin.get_pin_token(text)
        return 0
    except CtapError as error:
        return int(error.code)


def run(binary: Path, expect_fixed: bool) -> dict:
    with tempfile.TemporaryDirectory(prefix="ske-pin-malformed-") as temp:
        fixture = Fixture(binary.resolve(), Path(temp))
        try:
            ctap = fixture.start()
            protocol = PinProtocolV2()
            client = ClientPin(ctap, protocol)
            client.set_pin("1234")
            statuses = []
            retries = []
            for _ in range(4):
                statuses.append(attempt(ctap, protocol))
                retries.append(ClientPin(ctap, protocol).get_pin_retries())
            correct_before_cycle = valid_attempt(ClientPin(ctap, protocol), "1234")
            ctap = fixture.restart()
            after_cycle = ClientPin(ctap, protocol).get_pin_retries()
            correct_after_cycle = valid_attempt(ClientPin(ctap, protocol), "1234")
            final = ClientPin(ctap, protocol).get_pin_retries()
        finally:
            fixture.stop()
    if expect_fixed:
        assert statuses == [0x31, 0x31, 0x34, 0x34], statuses
        assert retries == [(7, None), (6, None), (5, True), (5, True)], retries
        assert correct_before_cycle == 0x34 and after_cycle == (5, None)
    else:
        assert statuses == [0x33] * 4 and retries == [(8, None)] * 4
        assert correct_before_cycle == 0 and after_cycle == (8, None)
    assert correct_after_cycle == 0 and final == (8, None)
    return {"passed": True, "expected_fixed": expect_fixed,
            "transport": "private CTAPHID Unix socket", "physical_device_access": False,
            "malformed_statuses": [f"0x{x:02x}" for x in statuses],
            "retry_states": retries,
            "correct_before_power_cycle_status": f"0x{correct_before_cycle:02x}",
            "retries_after_power_cycle": after_cycle,
            "correct_after_power_cycle_status": f"0x{correct_after_cycle:02x}",
            "final_retries": final,
            "tests": [{"name": label, "passed": True} for label in (
                "malformed encrypted PIN proof consumes durable retry",
                "third malformed proof triggers PIN_AUTH_BLOCKED",
                "fourth malformed proof consumes no additional retry while softblocked",
                "correct PIN remains blocked until power cycle",
                "correct PIN after power cycle restores eight retries",
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
