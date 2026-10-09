#!/usr/bin/env python3
"""Exercise allocated CTAPHID_INIT during real dummy_hcd FIDO user-presence wait."""

import errno
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

MODE = sys.argv[1]
assert MODE in ("baseline", "fixed")
MAKE_CREDENTIAL = bytes.fromhex(
    "01a5015820" + "11" * 32 +
    "02a26269646b6578616d706c652e636f6d646e616d65674578616d706c65"
    "03a36269644475736572646e616d6564557365726b646973706c61794e616d656455736572"
    "0481a263616c672664747970656a7075626c69632d6b6579"
    "07a262726bf4627570f5"
)
report = {
    "passed": False,
    "mode": MODE,
    "guest_network_devices": False,
    "host_usb_passthrough": False,
    "physical_device_access": False,
    "probe": "real dummy_hcd FIDO HID same-CID INIT during makeCredential presence wait",
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


def acquire(backend, serial):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        for found in usb.core.find(find_all=True, idVendor=0x1050, idProduct=0x0407, backend=backend):
            try:
                if found.serial_number != serial:
                    continue
                if found.is_kernel_driver_active(1):
                    found.detach_kernel_driver(1)
                usb.util.claim_interface(found, 1)
                return found
            except usb.core.USBError:
                usb.util.dispose_resources(found)
        time.sleep(.05)
    raise RuntimeError("owned FIDO USB interface did not enumerate")


def read_report(dev, timeout):
    try:
        return bytes(dev.read(0x84, 64, timeout=timeout))
    except usb.core.USBError as error:
        if error.errno == errno.ETIMEDOUT:
            return None
        raise


try:
    assert Path("/opt/isolated-ske-usb-guest").exists()
    assert not Path("/sys/class/net/eth0").exists()
    with tempfile.TemporaryDirectory(prefix="v58-fido-resync-", dir="/guest-state") as directory:
        fixture = verify_composite.CompositeFixture(Path("/opt/swpasskeyd"), Path(directory))
        try:
            fixture.start()
            fixture.device.close()
            fixture.device = None
            backend = usb.backend.libusb1.get_backend(
                find_library=lambda name: "/usr/lib/aarch64-linux-gnu/libusb-1.0.so.0")
            device = acquire(backend, fixture.serial)
            report["serial"] = fixture.serial
            nonce = b"v58-usb!"
            assert send_message(device, b"\xff" * 4, 0x06, nonce) == 1
            init = read_report(device, 5000)
            assert init and init[:7] == b"\xff" * 4 + b"\x86\x00\x11" and init[7:15] == nonce
            cid = init[15:19]
            report["cid_hex"] = cid.hex()
            report["make_credential_bytes"] = len(MAKE_CREDENTIAL)
            report["make_credential_reports"] = send_message(device, cid, 0x10, MAKE_CREDENTIAL)
            before = []
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                packet = read_report(device, 1000)
                assert packet is not None, "makeCredential did not enter presence wait"
                before.append(packet.hex())
                if packet[:4] == cid and packet[4] == 0xbb and packet[7] == 2:
                    break
                if packet[:4] == cid and packet[4] == 0x90:
                    raise AssertionError(f"makeCredential completed before presence wait: {packet.hex()}")
            else:
                raise AssertionError("UPNEEDED keepalive not observed")
            report["pre_resync_reports"] = before
            assert send_message(device, cid, 0x06, b"resync58") == 1
            after = []
            init_seen = False
            deadline = time.monotonic() + 1.5
            while time.monotonic() < deadline:
                packet = read_report(device, max(50, int((deadline - time.monotonic()) * 1000)))
                if packet is None:
                    break
                after.append(packet.hex())
                if packet[:4] == cid and packet[4] == 0x86:
                    assert packet[7:15] == b"resync58"
                    init_seen = True
            report["post_resync_reports"] = after
            report["init_seen"] = init_seen
            report["old_cbor_leaked"] = any(bytes.fromhex(value)[:4] == cid and
                                             bytes.fromhex(value)[4] == 0x90 for value in after)
            if init_seen and not report["old_cbor_leaked"]:
                assert send_message(device, cid, 0x01, b"fresh") == 1
                pong = read_report(device, 5000)
                report["fresh_ping"] = bool(pong and pong[:7] == cid + b"\x81\x00\x05" and pong[7:12] == b"fresh")
            report["passed"] = init_seen and (
                report["old_cbor_leaked"] if MODE == "baseline"
                else not report["old_cbor_leaked"] and report.get("fresh_ping", False))
        finally:
            if device is not None:
                usb.util.dispose_resources(device)
            if fixture is not None:
                daemon_log = fixture.directory / "daemon.log"
                if daemon_log.exists():
                    report["daemon_log_tail"] = daemon_log.read_text(errors="replace")[-1600:]
                if fixture.bridge is not None and fixture.bridge.poll() is not None:
                    fixture.bridge.stdin.close()
                    fixture.bridge = None
                fixture.stop()
except Exception as exc:
    report["error"] = f"{type(exc).__name__}: {exc}"
    raise
finally:
    print("SKE_V58_FIDO_RESYNC_BEGIN", flush=True)
    print(json.dumps(report), flush=True)
    print("SKE_V58_FIDO_RESYNC_END", flush=True)
if not report["passed"]:
    raise SystemExit(1)
