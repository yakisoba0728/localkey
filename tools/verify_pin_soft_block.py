#!/usr/bin/env python3
"""Unmodified pyfido2 PIN soft-lockout probe on a fresh private CTAPHID socket."""
from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin
from verify_ctap import Fixture


def attempt(client: ClientPin, pin: str) -> int:
    try:
        client.get_pin_token(pin)
        return 0
    except CtapError as error:
        return int(error.code)


def run(binary: Path, expect_fixed: bool) -> dict:
    with tempfile.TemporaryDirectory(prefix="ske-pin-softblock-") as temp:
        fixture = Fixture(binary.resolve(), Path(temp))
        try:
            client = ClientPin(fixture.start())
            client.set_pin("1234")
            assert client.get_pin_retries() == (8, None)
            codes = []
            retry_states = []
            for _ in range(4):
                codes.append(attempt(client, "0000"))
                retry_states.append(client.get_pin_retries())
            correct_before_cycle = attempt(client, "1234")
            remaining_before_cycle = client.get_pin_retries()
            client = ClientPin(fixture.restart())
            remaining_after_cycle = client.get_pin_retries()
            correct_after_cycle = attempt(client, "1234")
            final_retries = client.get_pin_retries()
        finally:
            fixture.stop()
    if expect_fixed:
        assert codes == [0x31, 0x31, 0x34, 0x34], codes
        assert retry_states == [(7, None), (6, None), (5, True), (5, True)], retry_states
        assert correct_before_cycle == 0x34 and remaining_before_cycle == (5, True)
        assert remaining_after_cycle == (5, None)
    else:
        assert codes == [0x31] * 4, codes
        assert retry_states == [(7, None), (6, None), (5, None), (4, None)], retry_states
        assert correct_before_cycle == 0 and remaining_before_cycle == (8, None)
        assert remaining_after_cycle == (8, None)
    assert correct_after_cycle == 0 and final_retries == (8, None)
    return {
        "passed": True,
        "expected_fixed": expect_fixed,
        "transport": "private CTAPHID Unix socket",
        "physical_device_access": False,
        "wrong_pin_statuses": [f"0x{code:02x}" for code in codes],
        "wrong_pin_retry_states": retry_states,
        "correct_before_power_cycle_status": f"0x{correct_before_cycle:02x}",
        "retries_before_power_cycle": remaining_before_cycle,
        "retries_after_power_cycle": remaining_after_cycle,
        "correct_after_power_cycle_status": f"0x{correct_after_cycle:02x}",
        "final_retries": final_retries,
        "tests": [{"name": name, "passed": True} for name in (
            "three wrong PINs trigger PIN_AUTH_BLOCKED" if expect_fixed else "baseline lacks third-attempt soft block",
            "blocked requests do not consume more durable retries" if expect_fixed else "baseline consumes a fourth retry",
            "correct PIN requires power cycle" if expect_fixed else "baseline accepts correct PIN without power cycle",
            "power cycle preserves remaining durable retries" if expect_fixed else "baseline correct PIN resets durable retries",
            "correct PIN after power cycle restores eight retries",
        )],
    }


def main() -> None:
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
