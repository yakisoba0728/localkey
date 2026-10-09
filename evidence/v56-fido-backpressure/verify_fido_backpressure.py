#!/usr/bin/env python3
"""Exercise FIDO interrupt IN backpressure through private dummy_hcd USB."""

import hashlib
import json
import os
import sys
import tempfile
import time
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
    "scope": "owned no-NIC dummy_hcd FIDO HID interrupt OUT/IN with host IN unread",
    "guest_network_devices": False,
    "host_usb_passthrough": False,
    "physical_device_access": False,
    "ping_payload_length": 7609,
    "request_count": 4,
}
fixture = device = None


def send_message(dev, cid, command, payload):
    header = cid + bytes([0x80 | command, len(payload) >> 8, len(payload) & 255])
    packets = [(header + payload[:57]).ljust(64, b"\0")]
    for sequence, offset in enumerate(range(57, len(payload), 59)):
        packets.append((cid + bytes([sequence]) + payload[offset:offset + 59]).ljust(64, b"\0"))
    for packet in packets:
        assert dev.write(0x04, packet, timeout=5000) == 64
    return len(packets)


def receive_message(dev, cid):
    first = bytes(dev.read(0x84, 64, timeout=5000))
    assert len(first) == 64 and first[:4] == cid
    command = first[4] & 0x7F
    length = (first[5] << 8) | first[6]
    data = bytearray(first[7:7 + min(length, 57)])
    count = 1
    while len(data) < length:
        packet = bytes(dev.read(0x84, 64, timeout=5000))
        assert len(packet) == 64 and packet[:4] == cid and packet[4] == count - 1
        data.extend(packet[5:5 + min(length - len(data), 59)])
        count += 1
    return command, bytes(data), count


try:
    assert Path("/opt/isolated-ske-usb-guest").exists()
    os.environ["SKE_TRACE_USB"] = "1"
    with tempfile.TemporaryDirectory(prefix="v56-fido-pressure-", dir="/guest-state") as directory:
        fixture = verify_composite.CompositeFixture(Path("/opt/swpasskeyd"), Path(directory))
        try:
            fixture.start()
            fixture.device.close()
            fixture.device = None
            backend = usb.backend.libusb1.get_backend(
                find_library=lambda name: "/usr/lib/aarch64-linux-gnu/libusb-1.0.so.0"
            )
            matches = list(usb.core.find(find_all=True, idVendor=0x1050, idProduct=0x0407, backend=backend))
            assert len(matches) == 1 and matches[0].serial_number == fixture.serial
            device = matches[0]
            report["own_usb_address"] = device.address
            report["own_usb_serial"] = fixture.serial
            if device.is_kernel_driver_active(1):
                device.detach_kernel_driver(1)
            usb.util.claim_interface(device, 1)
            nonce = b"v56-own!"
            assert send_message(device, b"\xff" * 4, 0x06, nonce) == 1
            init = bytes(device.read(0x84, 64, timeout=5000))
            assert init[:7] == b"\xff" * 4 + b"\x86\x00\x11" and init[7:15] == nonce
            cid = init[15:19]
            report["assigned_cid_hex"] = cid.hex()
            control = b"positive-v56"
            assert send_message(device, cid, 0x01, control) == 1
            command, response, count = receive_message(device, cid)
            report["positive_control"] = command == 1 and response == control and count == 1
            assert report["positive_control"]
            payloads = [bytes((i + j * 29) & 255 for i in range(7609)) for j in range(4)]
            sent = []
            try:
                for value in payloads:
                    sent.append(send_message(device, cid, 0x01, value))
            except usb.core.USBError as error:
                if mode == "fixed":
                    raise
                report["send_error"] = f"{type(error).__name__}: {error}"
            report["sent_reports"] = sent
            if mode == "fixed":
                assert sent == [129] * 4
            time.sleep(1.5)
            report["bridge_alive_after_unread"] = fixture.bridge.poll() is None
            if mode == "fixed":
                replies = [receive_message(device, cid) for _ in payloads]
                report["received_reports"] = [entry[2] for entry in replies]
                report["echo_matches"] = [entry[0] == 1 and entry[1] == payloads[i]
                                           for i, entry in enumerate(replies)]
                followup = b"after-pressure"
                assert send_message(device, cid, 0x01, followup) == 1
                command, response, count = receive_message(device, cid)
                report["followup_echo"] = command == 1 and response == followup and count == 1
                report["bridge_alive_after_drain"] = fixture.bridge.poll() is None
                report["passed"] = (report["bridge_alive_after_unread"]
                                    and report["received_reports"] == [129] * 4
                                    and report["echo_matches"] == [True] * 4
                                    and report["followup_echo"] and report["bridge_alive_after_drain"])
            else:
                # Baseline is successful only if the documented overflow is observed.
                log = (fixture.directory / "usb.log").read_text(errors="replace")
                report["overflow_observed"] = "USB input queue overflow" in log
                report["passed"] = (not report["bridge_alive_after_unread"]
                                    and report["overflow_observed"])
        finally:
            if device is not None:
                usb.util.dispose_resources(device)
            if fixture is not None:
                usb_log = fixture.directory / "usb.log"
                if usb_log.exists():
                    log = usb_log.read_text(errors="replace")
                    report["bridge_log_tail"] = log[-1500:]
                    report["overflow_observed"] = "USB input queue overflow" in log
                if fixture.bridge is not None and fixture.bridge.poll() is not None:
                    fixture.bridge.stdin.close()
                    fixture.bridge = None
                fixture.stop()
except Exception as exc:
    report["error"] = f"{type(exc).__name__}: {exc}"
    raise
finally:
    print("SKE_V56_FIDO_PRESSURE_BEGIN", flush=True)
    print(json.dumps(report), flush=True)
    print("SKE_V56_FIDO_PRESSURE_END", flush=True)
if not report["passed"]:
    raise SystemExit(1)
