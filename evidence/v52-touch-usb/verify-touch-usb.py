#!/usr/bin/env python3
"""Private no-NIC dummy_hcd proof: software touch RPC reaches guest evdev."""

import json
import os
import select
import struct
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, "/opt")
sys.path.insert(0, "/opt/verification")

from emucard.client import KeyboardSocketConnection
from verify_composite import wait_for
from verify_composite_extra import UsbPcscFixture
from ykman.hid.linux import list_devices as list_otp
from yubikit.core.otp import OtpConnection
from yubikit.yubiotp import (
    HmacSha1SlotConfiguration,
    SLOT,
    StaticPasswordSlotConfiguration,
    YubiOtpSession,
)


def read_keys(fd, seconds):
    item = struct.Struct("@llHHi")
    pending = bytearray()
    keys = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not select.select([fd], [], [], 0.05)[0]:
            if len([e for e in keys if e[1] == 0]) >= 5:
                break
            continue
        pending.extend(os.read(fd, item.size * 64))
        while len(pending) >= item.size:
            _, _, kind, code, value = item.unpack(pending[: item.size])
            del pending[: item.size]
            if kind == 1:
                keys.append((code, value))
    return keys


report = {
    "passed": False,
    "checks": [],
    "software_touch_input": True,
    "physical_touch_sensor": False,
    "guest_network_devices": False,
    "host_usb_passthrough": False,
    "physical_device_access": False,
}


def check(condition, name):
    if not condition:
        raise AssertionError(name)
    report["checks"].append(name)
    print("PASS", name, flush=True)


try:
    assert Path("/opt/isolated-ske-usb-guest").exists()
    with tempfile.TemporaryDirectory(prefix="touch-usb-", dir="/guest-state") as path:
        fixture = UsbPcscFixture(Path(path))
        keyboard = otp_connection = None
        event_fd = None
        try:
            card = fixture.start()
            card.close()
            fixture.connection = None
            devices = list_otp()
            check(len(devices) == 1, "stock SDK finds own USB OTP HID interface")
            otp_connection = devices[0].open_connection(OtpConnection)
            otp = YubiOtpSession(otp_connection)
            otp.put_configuration(
                SLOT.ONE, StaticPasswordSlotConfiguration(bytes([0x84, 5, 30]))
            )
            event_path = wait_for(
                lambda: next(iter(Path("/dev/input").glob("event*")), None),
                "USB keyboard input event missing",
            )
            event_fd = os.open(event_path, os.O_RDONLY | os.O_NONBLOCK)
            hidraw_path = (
                Path("/sys/class/hidraw") / Path(devices[0].path).name / "device"
            ).resolve()
            check(
                "dummy_hcd" in str(hidraw_path),
                "observed keyboard belongs to private dummy_hcd",
            )
            keyboard = KeyboardSocketConnection(fixture.card_socket)
            down = keyboard.touch_down()
            check(len(down) > 0, "single-slot touch-down produces reports")
            first = read_keys(event_fd, 3)
            check(
                [c for c, v in first if v == 1] == [42, 30, 48, 2, 28],
                "touch-down emits Shift+A, b, 1, Enter over USB",
            )
            check(
                sorted(c for c, v in first if v == 0)
                == sorted(c for c, v in first if v == 1),
                "touch-down releases every key and modifier",
            )
            check(keyboard.touch_up(500) == [], "fast-trigger touch-up has no duplicate reports")
            check(read_keys(event_fd, 0.3) == [], "fast-trigger touch-up emits no duplicate USB keys")

            otp.put_configuration(
                SLOT.TWO, HmacSha1SlotConfiguration(b"own usb fixture key!")
            )
            check(keyboard.touch_down() == [], "dual-slot touch-down defers output")
            check(read_keys(event_fd, 0.3) == [], "deferred touch-down emits no USB keys")
            up = keyboard.touch_up(1500)
            check(len(up) > 0, "dual-slot touch-up selects slot one")
            second = read_keys(event_fd, 3)
            check(
                [c for c, v in second if v == 1] == [42, 30, 48, 2, 28],
                "touch-up emits Shift+A, b, 1, Enter over USB",
            )
            check(
                sorted(c for c, v in second if v == 0)
                == sorted(c for c, v in second if v == 1),
                "touch-up releases every key and modifier",
            )
            report["first_evdev_keys"] = first
            report["second_evdev_keys"] = second
            report["returned_down_reports"] = len(down)
            report["returned_up_reports"] = len(up)
            report["hidraw_path"] = str(hidraw_path)
            report["evdev_path"] = str(event_path.resolve())
            report["passed"] = True
        finally:
            if keyboard is not None:
                keyboard.close()
            if otp_connection is not None:
                otp_connection.close()
            if event_fd is not None:
                os.close(event_fd)
            fixture.stop()
except Exception as exc:
    report["error"] = f"{type(exc).__name__}: {exc}"
    raise
finally:
    report["test_count"] = len(report["checks"])
    print("SKE_TOUCH_USB_BEGIN", flush=True)
    print(json.dumps(report), flush=True)
    print("SKE_TOUCH_USB_END", flush=True)
