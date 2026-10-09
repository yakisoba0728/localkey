#!/usr/bin/env python3
"""No-NIC dummy_hcd probe for OTP IN backpressure with guest usbhid unbound."""

import json
import os
import re
import select
import struct
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, "/opt")
sys.path.insert(0, "/opt/verification")

from emucard.client import KeyboardSocketConnection
from verify_composite_extra import UsbPcscFixture
from ykman.hid.linux import list_devices as list_otp
from yubikit.core.otp import OtpConnection
from yubikit.yubiotp import SLOT, StaticPasswordSlotConfiguration, YubiOtpSession


class KeyWatcher:
    def __init__(self):
        self.events = []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        item = struct.Struct("@llHHi")
        fd = None
        pending = bytearray()
        try:
            while not self.stop.is_set():
                if fd is None:
                    path = next(iter(Path("/dev/input").glob("event*")), None)
                    if path is None:
                        time.sleep(0.002)
                        continue
                    try:
                        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
                    except OSError:
                        time.sleep(0.002)
                        continue
                if not select.select([fd], [], [], 0.01)[0]:
                    continue
                try:
                    pending.extend(os.read(fd, item.size * 64))
                except OSError:
                    os.close(fd)
                    fd = None
                    pending.clear()
                    continue
                while len(pending) >= item.size:
                    _, _, kind, code, value = item.unpack(pending[: item.size])
                    del pending[: item.size]
                    if kind == 1:
                        self.events.append((code, value))
        finally:
            if fd is not None:
                os.close(fd)

    def close(self):
        self.stop.set()
        self.thread.join(2)


mode = sys.argv[1] if len(sys.argv) == 2 else ""
assert mode in ("baseline", "fixed")
report = {
    "passed": False,
    "mode": mode,
    "guest_network_devices": False,
    "host_usb_passthrough": False,
    "physical_device_access": False,
    "software_touch_input": True,
}

try:
    assert Path("/opt/isolated-ske-usb-guest").exists()
    os.environ["SKE_TRACE_USB"] = "1"
    with tempfile.TemporaryDirectory(prefix="otp-backpressure-", dir="/guest-state") as path:
        fixture = UsbPcscFixture(Path(path))
        keyboard = otp_connection = None
        watcher = None
        try:
            card = fixture.start()
            card.close()
            fixture.connection = None
            devices = list_otp()
            assert len(devices) == 1
            otp_connection = devices[0].open_connection(OtpConnection)
            otp = YubiOtpSession(otp_connection)
            otp.put_configuration(
                SLOT.ONE, StaticPasswordSlotConfiguration(bytes([0x84, 5, 30]))
            )
            otp_connection.close()
            otp_connection = None
            keyboard = KeyboardSocketConnection(fixture.card_socket)
            hid_device = (
                Path("/sys/class/hidraw") / Path(devices[0].path).name / "device"
            ).resolve()
            interface = next(
                parent.name for parent in hid_device.parents
                if re.fullmatch(r"\d+-\d+(?:\.\d+)?:\d+\.\d+", parent.name)
                and (parent / "bInterfaceClass").exists()
            )
            driver = Path("/sys/bus/usb/drivers/usbhid")
            assert (driver / interface).exists()
            (driver / "unbind").write_text(interface)
            deadline = time.monotonic() + 5
            while list(Path("/dev/input").glob("event*")) and time.monotonic() < deadline:
                time.sleep(0.01)
            assert not list(Path("/dev/input").glob("event*"))
            report["guest_unbound_interface"] = interface
            report["own_hidraw_sysfs"] = str(hid_device)
            report["touch_report_counts"] = []
            for index in range(40):
                down = keyboard.touch_down()
                assert down
                assert keyboard.touch_up(500) == []
                report["touch_report_counts"].append(len(down))
                if fixture.bridge.poll() is not None:
                    report["bridge_failed_after_touch"] = index + 1
                    break
            deadline = time.monotonic() + 1
            while fixture.bridge.poll() is None and mode == "baseline" and time.monotonic() < deadline:
                time.sleep(0.01)
            report["bridge_returncode_after_flood"] = fixture.bridge.poll()
            if mode == "fixed" and fixture.bridge.poll() is None:
                watcher = KeyWatcher()
                (driver / "bind").write_text(interface)
                deadline = time.monotonic() + 12
                while time.monotonic() < deadline:
                    if len([1 for _, value in watcher.events if value == 1]) >= 40 * 5:
                        break
                    time.sleep(0.05)
                down_codes = [code for code, value in watcher.events if value == 1]
                up_codes = [code for code, value in watcher.events if value == 0]
                report["observed_down_count"] = len(down_codes)
                report["observed_up_count"] = len(up_codes)
                report["observed_first_down"] = down_codes[:5]
                report["observed_last_down"] = down_codes[-5:]
                report["bridge_alive_after_rebind"] = fixture.bridge.poll() is None
                before_fresh = len(down_codes)
                assert keyboard.touch_down()
                assert keyboard.touch_up(500) == []
                fresh_deadline = time.monotonic() + 3
                while time.monotonic() < fresh_deadline:
                    if len([1 for _, value in watcher.events if value == 1]) >= before_fresh + 5:
                        break
                    time.sleep(0.02)
                after_fresh = [code for code, value in watcher.events if value == 1]
                report["fresh_after_backpressure_down"] = after_fresh[before_fresh:]
                report["endpoint_otp_in_submissions"] = (
                    (fixture.directory / "usb.log").read_text().count(
                        "functionfs_async_queued address=129"
                    )
                )
                report["passed"] = (
                    len(report["touch_report_counts"]) == 40
                    and report["bridge_alive_after_rebind"]
                    and len(down_codes) >= 150
                    and len(up_codes) >= 150
                    and report["fresh_after_backpressure_down"][-5:] == [42,30,48,2,28]
                    and report["endpoint_otp_in_submissions"] >= 320
                )
            elif mode == "baseline":
                report["passed"] = (
                    report["bridge_returncode_after_flood"] not in (None, 0)
                    and len(report["touch_report_counts"]) >= 30
                )
        finally:
            usb_log = fixture.directory / "usb.log"
            if usb_log.exists():
                report["bridge_log_tail"] = usb_log.read_text(errors="replace")[-1800:]
            if watcher is not None:
                watcher.close()
            if keyboard is not None:
                keyboard.close()
            if otp_connection is not None:
                otp_connection.close()
            if fixture.bridge is not None and fixture.bridge.poll() is not None:
                fixture.bridge.stdin.close()
                fixture.bridge = None
            fixture.stop()
except Exception as exc:
    report["error"] = f"{type(exc).__name__}: {exc}"
    raise
finally:
    report["test_count"] = len(report.get("touch_report_counts", []))
    print("SKE_OTP_BACKPRESSURE_BEGIN", flush=True)
    print(json.dumps(report), flush=True)
    print("SKE_OTP_BACKPRESSURE_END", flush=True)
if not report["passed"]:
    raise SystemExit(1)
