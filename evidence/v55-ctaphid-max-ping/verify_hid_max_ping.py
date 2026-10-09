#!/usr/bin/env python3
"""CTAPHID final-continuation boundary through owned no-NIC USB hidraw bus."""

import hashlib
import json
import os
import sys
import tempfile
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
    "test_count": 4,
    "transport": "actual no-NIC guest USB FIDO HID interrupt endpoints / FunctionFS",
    "guest_network_devices": False,
    "host_usb_passthrough": False,
    "physical_device_access": False,
    "spec_max_ping_payload": 7609,
    "spec_url": "https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-hid-message-and-packet-structure",
}
fixture = device = None


def send_message(dev, cid, command, payload):
    header = cid + bytes([0x80 | command, len(payload) >> 8, len(payload) & 255])
    packets = [(header + payload[:57]).ljust(64, b"\0")]
    for sequence, offset in enumerate(range(57, len(payload), 59)):
        packets.append((cid + bytes([sequence]) + payload[offset:offset + 59]).ljust(64, b"\0"))
    for packet in packets:
        assert dev.write(0x04, packet, timeout=2000) == 64
    return len(packets)


def receive_message(dev, cid):
    first = bytes(dev.read(0x84, 64, timeout=3000))
    assert len(first) == 64 and first[:4] == cid
    command = first[4] & 0x7F
    length = (first[5] << 8) | first[6]
    data = bytearray(first[7:7 + min(length, 57)])
    count = 1
    while len(data) < length:
        packet = bytes(dev.read(0x84, 64, timeout=3000))
        assert len(packet) == 64 and packet[:4] == cid and packet[4] == count - 1
        data.extend(packet[5:5 + min(length - len(data), 59)])
        count += 1
    return command, bytes(data), count


try:
    assert Path("/opt/isolated-ske-usb-guest").exists()
    os.environ["SKE_TRACE_USB"] = "1"
    with tempfile.TemporaryDirectory(prefix="v55-max-ping-", dir="/guest-state") as directory:
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
            report["fido_kernel_driver_active_before_claim"] = device.is_kernel_driver_active(1)
            if report["fido_kernel_driver_active_before_claim"]:
                device.detach_kernel_driver(1)
            usb.util.claim_interface(device, 1)
            nonce = b"own-v55!"
            assert send_message(device, b"\xff" * 4, 0x06, nonce) == 1
            init = bytes(device.read(0x84, 64, timeout=3000))
            assert init[:7] == b"\xff" * 4 + b"\x86\x00\x11" and init[7:15] == nonce
            cid = init[15:19]
            assert len(cid) == 4 and cid != b"\0" * 4
            report["assigned_cid_hex"] = cid.hex()
            rows = []
            for size in (7550, 7551, 7609, 16):
                payload = bytes((index + size) & 255 for index in range(size))
                sent = send_message(device, cid, 0x01, payload)
                command, response, received = receive_message(device, cid)
                rows.append({
                    "size": size,
                    "sent_reports": sent,
                    "received_reports": received,
                    "response_command": command,
                    "response_error": response[0] if command == 0x3F and len(response) == 1 else None,
                    "echo_matches": command == 0x01 and response == payload,
                    "payload_sha256": hashlib.sha256(payload).hexdigest(),
                    "response_sha256": hashlib.sha256(response).hexdigest(),
                })
            report["rows"] = rows
            report["bridge_alive_after_boundary"] = fixture.bridge.poll() is None
            expected = [True, mode == "fixed", mode == "fixed", True]
            report["passed"] = (
                [row["echo_matches"] for row in rows] == expected
                and all(row["response_error"] == 3 for row in rows[1:3] if not row["echo_matches"])
                and [row["sent_reports"] for row in rows] == [128, 129, 129, 1]
                and report["bridge_alive_after_boundary"]
            )
        finally:
            if device is not None:
                usb.util.dispose_resources(device)
            if fixture is not None:
                usb_log = fixture.directory / "usb.log"
                if usb_log.exists():
                    report["bridge_log_tail"] = usb_log.read_text(errors="replace")[-1200:]
                if fixture.bridge is not None and fixture.bridge.poll() is not None:
                    fixture.bridge.stdin.close()
                    fixture.bridge = None
                fixture.stop()
except Exception as exc:
    report["error"] = f"{type(exc).__name__}: {exc}"
    raise
finally:
    print("SKE_V55_MAX_PING_BEGIN", flush=True)
    print(json.dumps(report), flush=True)
    print("SKE_V55_MAX_PING_END", flush=True)
if not report["passed"]:
    raise SystemExit(1)
