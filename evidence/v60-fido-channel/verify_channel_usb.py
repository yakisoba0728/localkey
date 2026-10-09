#!/usr/bin/env python3
"""No-NIC dummy_hcd FIDO channel prevalidation against the actual USB interface."""

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
report = {"passed": False, "mode": MODE,
          "guest_network_devices": False, "host_usb_passthrough": False,
          "physical_device_access": False,
          "scope": "owned dummy_hcd FunctionFS FIDO CID prevalidation"}
fixture = device = None


def send(dev, cid, command, payload=b"", declared=None):
    length = len(payload) if declared is None else declared
    packet = (cid + bytes([0x80 | command, length >> 8, length & 255]) + payload[:57]).ljust(64, b"\0")
    assert dev.write(0x04, packet, timeout=5000) == 64


def read(dev, timeout):
    try:
        return bytes(dev.read(0x84, 64, timeout=timeout))
    except usb.core.USBError as error:
        if error.errno == errno.ETIMEDOUT:
            return None
        raise


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
    raise RuntimeError("owned FIDO interface missing")


try:
    assert Path("/opt/isolated-ske-usb-guest").exists()
    assert not Path("/sys/class/net/eth0").exists()
    with tempfile.TemporaryDirectory(prefix="v60-fido-channel-", dir="/guest-state") as directory:
        fixture = verify_composite.CompositeFixture(Path("/opt/swpasskeyd"), Path(directory))
        try:
            fixture.start()
            fixture.device.close()
            fixture.device = None
            backend = usb.backend.libusb1.get_backend(
                find_library=lambda name: "/usr/lib/aarch64-linux-gnu/libusb-1.0.so.0")
            device = acquire(backend, fixture.serial)
            report["serial"] = fixture.serial
            nonce = b"v60-usb!"
            send(device, b"\xff" * 4, 0x06, nonce)
            init = read(device, 5000)
            assert init and init[:7] == b"\xff" * 4 + b"\x86\x00\x11" and init[7:15] == nonce
            valid = init[15:19]
            unknown = b"\x10\x20\x30\x40" if valid != b"\x10\x20\x30\x40" else b"\x20\x30\x40\x50"
            report["valid_cid_hex"] = valid.hex()
            report["unknown_cid_hex"] = unknown.hex()
            send(device, unknown, 0x01, b"X" * 57, declared=100)
            first = read(device, 150)
            report["unknown_initial_reply_hex"] = first and first.hex()
            send(device, valid, 0x01, b"okay")
            second = read(device, 1000)
            report["valid_ping_during_unknown_assembly_hex"] = second and second.hex()
            if MODE == "baseline":
                assert first is None
                assert second and second[:4] == valid and second[4] == 0xbf and second[7] == 0x06
                timeout = read(device, 1000)
                assert timeout and timeout[:4] == unknown and timeout[4] == 0xbf and timeout[7] == 0x05
                report["unknown_timeout_hex"] = timeout.hex()
            else:
                assert first and first[:4] == unknown and first[4] == 0xbf and first[7] == 0x0b
                assert second and second[:4] == valid and second[4] == 0x81 and second[7:11] == b"okay"
                report["unknown_timeout_hex"] = None
            assert device.write(0x04, unknown + b"\x00" + b"Y" * 59, timeout=5000) == 64
            orphan = read(device, 180)
            report["spurious_cont_reply_hex"] = orphan and orphan.hex()
            # USB scheduling can delay this optional baseline observation.
            # The socket A/B fixture is authoritative for the orphan reply.
            if MODE == "fixed":
                assert orphan is None
            assert device.write(0x04, b"\x00" * 5 + b"Z" * 59, timeout=5000) == 64
            zero_orphan = read(device, 180)
            report["zero_cid_spurious_cont_reply_hex"] = zero_orphan and zero_orphan.hex()
            if MODE == "fixed":
                assert zero_orphan is None
            send(device, valid, 0x01, b"fresh")
            late = []
            fresh = None
            for _ in range(12):
                candidate = read(device, 500)
                if candidate is None:
                    continue
                if candidate[:4] == valid and candidate[4] == 0x81 and candidate[7:12] == b"fresh":
                    fresh = candidate
                    break
                late.append(candidate.hex())
            report["late_reports_before_fresh"] = late
            if MODE == "fixed":
                assert not late
            assert fresh and fresh[:4] == valid and fresh[4] == 0x81 and fresh[7:12] == b"fresh"
            report["fresh_ping_hex"] = fresh.hex()
            report["passed"] = True
        finally:
            if device is not None:
                usb.util.dispose_resources(device)
            if fixture is not None:
                daemon_log = fixture.directory / "daemon.log"
                if daemon_log.exists():
                    report["daemon_log_tail"] = daemon_log.read_text(errors="replace")[-500:]
                if fixture.bridge is not None and fixture.bridge.poll() is not None:
                    fixture.bridge.stdin.close()
                    fixture.bridge = None
                fixture.stop()
except Exception as error:
    report["error"] = f"{type(error).__name__}: {error}"
    raise
finally:
    print("SKE_V60_FIDO_CHANNEL_BEGIN", flush=True)
    print(json.dumps(report), flush=True)
    print("SKE_V60_FIDO_CHANNEL_END", flush=True)
if not report["passed"]:
    raise SystemExit(1)
