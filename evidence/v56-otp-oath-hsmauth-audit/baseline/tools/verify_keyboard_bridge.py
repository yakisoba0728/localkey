#!/usr/bin/env python3
"""Verify keyboard socket and compiled native bridge without OS keyboard input."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from emucard.client import KeyboardSocketConnection
from verify_smartcard import Fixture
from yubikit.management import ManagementSession
from yubikit.yubiotp import (
    SLOT,
    StaticPasswordSlotConfiguration,
    StaticTicketSlotConfiguration,
    YubiOtpSession,
)


def run(root, directory, binary, report):
    fixture = Fixture(root, directory)
    checks = []
    completed = False

    def check(value, name):
        if not value:
            raise AssertionError(name)
        checks.append({"name": name, "passed": True})
        print("PASS", name, flush=True)

    try:
        conn = fixture.start()
        serial = ManagementSession(conn).read_device_info().serial
        YubiOtpSession(conn).put_configuration(
            SLOT.ONE, StaticPasswordSlotConfiguration(bytes([0x84, 5, 30]))
        )
        keyboard = KeyboardSocketConnection(directory / "s.sock")
        try:
            expected = keyboard.press(1)
        finally:
            keyboard.close()
        check(
            len(expected) == 8
            and bytes.fromhex(expected[0]["report"])[0:3] == b"\x02\0\x04",
            "serialized keyboard socket press, modifier and release reports",
        )
        result = subprocess.run(
            [str(binary), "--wire-test", str(directory / "s.sock")],
            check=True,
            capture_output=True,
            text=True,
        )
        data = json.loads(result.stdout)
        check(
            data["serial"] == serial,
            "compiled macOS bridge reads shared CCID device identity",
        )
        check(
            len(bytes.fromhex(data["status"])) == 8,
            "compiled macOS bridge gets eight-byte OTP feature report",
        )
        raw = bytes.fromhex(data["keyboard_events"])
        check(
            raw[:4] == b"\x90\0\0\x08",
            "compiled macOS bridge reads successful software button response",
        )
        actual = [
            {
                "report": raw[i : i + 8].hex(),
                "delay_ms": int.from_bytes(raw[i + 8 : i + 10], "big"),
            }
            for i in range(4, len(raw), 10)
        ]
        check(
            actual == expected,
            "compiled macOS bridge keyboard records match independent socket client",
        )
        YubiOtpSession(conn).put_configuration(
            SLOT.TWO, StaticPasswordSlotConfiguration(b"\x06")
        )
        result = subprocess.run(
            [
                str(binary),
                "--wire-test",
                str(directory / "s.sock"),
                "--hold-ms",
                "3500",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        raw = bytes.fromhex(json.loads(result.stdout)["keyboard_events"])
        check(
            raw[:4] == b"\x90\0\0\x04" and raw[4:7] == b"\0\0\x06",
            "compiled native bridge hold/release request selects slot 2",
        )
        denied = subprocess.run(
            [str(binary), "--wire-test", str(directory / "s.sock"), "--hold-ms", "-1"],
            capture_output=True,
            check=False,
        )
        check(
            denied.returncode != 0, "native bridge rejects out-of-range hold duration"
        )
        otp = YubiOtpSession(conn)
        otp.put_configuration(
            SLOT.ONE,
            StaticTicketSlotConfiguration(b"", b"\0" * 6, bytes(16)).manual_update(
                True
            ),
        )
        keyboard = KeyboardSocketConnection(directory / "s.sock")
        try:
            original = keyboard.press(1)
            check(
                keyboard.hold(10000) == [],
                "socket long hold arms update without emitting reports",
            )
            updated = keyboard.hold(500)
            check(
                updated != original and keyboard.press(1) == updated,
                "socket short confirmation changes and persists static password output",
            )
        finally:
            keyboard.close()
        denied = subprocess.run(
            [str(binary), "--wire-test", str(directory / "missing.sock")],
            capture_output=True,
            check=False,
        )
        check(denied.returncode != 0, "native bridge rejects absent backend socket")
        (directory / "s.sock").chmod(0o666)
        denied = subprocess.run(
            [str(binary), "--wire-test", str(directory / "s.sock")],
            capture_output=True,
            check=False,
        )
        check(denied.returncode != 0, "native bridge rejects shared-access socket")
        (directory / "s.sock").chmod(0o600)
        completed = True
    finally:
        fixture.stop()
        report.write_text(
            json.dumps(
                {
                    "passed": completed,
                    "tests": checks,
                    "physical_key_accessed": False,
                    "os_keyboard_events": False,
                    "native_hid_registration_verified": False,
                },
                indent=2,
            )
            + "\n"
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, default=Path(tempfile.gettempdir()))
    args = parser.parse_args()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="ske-keyboard-", dir=args.work_dir
    ) as directory:
        run(
            Path(__file__).resolve().parents[1],
            Path(directory),
            args.binary.resolve(),
            args.report,
        )


if __name__ == "__main__":
    main()
