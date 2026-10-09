#!/usr/bin/env python3
"""Probe CCID bulk OUT flood while owned guest USB bulk IN is unread."""

import json
import os
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

import usb.backend.libusb1
import usb.core
import usb.util
import verify_composite


mode = sys.argv[1] if len(sys.argv) == 2 else ""
assert mode in ("baseline", "fixed")
report = {
    "passed": False,
    "mode": mode,
    "guest_network_devices": False,
    "host_usb_passthrough": False,
    "physical_device_access": False,
    "owned_guest_dummy_hcd": True,
    "test_count": 0,
}
fixture = None
device = None
try:
    assert Path("/opt/isolated-ske-usb-guest").exists()
    os.environ["SKE_TRACE_USB"] = "1"
    with tempfile.TemporaryDirectory(prefix="v54-ccid-backpressure-", dir="/guest-state") as directory:
        fixture = verify_composite.CompositeFixture(Path("/opt/swpasskeyd"), Path(directory))
        try:
            fixture.start()
            backend = usb.backend.libusb1.get_backend(
                find_library=lambda name: "/usr/lib/aarch64-linux-gnu/libusb-1.0.so.0"
            )
            matches = list(usb.core.find(
                find_all=True, idVendor=0x1050, idProduct=0x0407, backend=backend
            ))
            assert len(matches) == 1 and matches[0].serial_number == fixture.serial
            device = matches[0]
            usb.util.claim_interface(device, 2)
            report["own_usb_address"] = device.address
            report["own_usb_serial"] = fixture.serial
            report["sent_sequences"] = []
            for index in range(310):
                packet = bytes([0x65, 0, 0, 0, 0, 0, index & 255, 0, 0, 0])
                try:
                    written = device.write(0x02, packet, timeout=1000)
                except usb.core.USBError as error:
                    report["write_error"] = f"{type(error).__name__}: {error}"
                    break
                assert written == 10
                report["sent_sequences"].append(index & 255)
                if fixture.bridge.poll() is not None:
                    report["bridge_failed_after_send"] = index + 1
                    break
                time.sleep(0.004)
            deadline = time.monotonic() + 1
            while mode == "baseline" and fixture.bridge.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            report["bridge_returncode_after_flood"] = fixture.bridge.poll()
            if mode == "fixed" and fixture.bridge.poll() is None:
                replies = []
                deadline = time.monotonic() + 12
                while len(replies) < len(report["sent_sequences"]) and time.monotonic() < deadline:
                    try:
                        packet = bytes(device.read(0x82, 64, timeout=500))
                    except usb.core.USBError as error:
                        report["read_error"] = f"{type(error).__name__}: {error}"
                        break
                    if len(packet) == 10:
                        replies.append((packet[0], packet[6], packet[7], packet[8]))
                report["reply_count"] = len(replies)
                report["reply_types"] = sorted(set(row[0] for row in replies))
                report["reply_sequences_match"] = (
                    Counter(row[1] for row in replies)
                    == Counter(report["sent_sequences"])
                )
                fresh = bytes([0x65, 0, 0, 0, 0, 0, 0xEE, 0, 0, 0])
                report["fresh_write_count"] = device.write(0x02, fresh, timeout=1000)
                fresh_reply = bytes(device.read(0x82, 64, timeout=2000))
                report["fresh_reply"] = [fresh_reply[0], fresh_reply[6]] if len(fresh_reply) >= 7 else []
                report["bridge_alive_after_drain"] = fixture.bridge.poll() is None
                report["passed"] = (
                    len(report["sent_sequences"]) == 310
                    and len(replies) == 310
                    and all(row[0] == 0x81 for row in replies)
                    and report["reply_sequences_match"]
                    and report["fresh_write_count"] == 10
                    and report["fresh_reply"] == [0x81, 0xEE]
                    and report["bridge_alive_after_drain"]
                )
        finally:
            if device is not None:
                usb.util.dispose_resources(device)
            if fixture is not None:
                usb_log = fixture.directory / "usb.log"
                if usb_log.exists():
                    report["bridge_log_tail"] = usb_log.read_text(errors="replace")[-1800:]
                if fixture.bridge is not None and fixture.bridge.poll() is not None:
                    fixture.bridge.stdin.close()
                    fixture.bridge = None
                fixture.stop()
except Exception as exc:
    report["error"] = f"{type(exc).__name__}: {exc}"
    raise
finally:
    report["test_count"] = len(report.get("sent_sequences", []))
    if mode == "baseline":
        report["passed"] = (
            len(report.get("sent_sequences", [])) >= 257
            and report.get("bridge_returncode_after_flood") not in (None, 0)
            and "USB input queue overflow" in report.get("bridge_log_tail", "")
        )
    print("SKE_V54_CCID_BACKPRESSURE_BEGIN", flush=True)
    print(json.dumps(report), flush=True)
    print("SKE_V54_CCID_BACKPRESSURE_END", flush=True)
if not report["passed"]:
    raise SystemExit(1)
