#!/usr/bin/env python3
"""Stock SDK discovery and transactions on the guest's own virtual USB bus."""

import importlib.metadata
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, "/opt/verification")
sys.path.insert(0, "/opt")
import verify_ctap
import verify_smartcard
from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice
from fido2.hid.linux import list_descriptors
from yubikit.management import ManagementSession

checks = []
observations = []


def controller_provenance():
    """Verify the loaded test controller and the packaged patch, never a host UDC."""
    assert Path("/opt/isolated-ske-usb-guest").exists()
    mode = Path("/sys/module/dummy_hcd/parameters/requested_ep_addresses")
    assert mode.read_text().strip() == "Y", "requested address policy inactive"
    provenance = json.loads(Path("/opt/dummy-hcd-provenance.json").read_text())
    assert provenance["default_enabled"] is False
    assert provenance["optional_parameter"] == "requested_ep_addresses"
    for name, path in [
        ("dummy_hcd.ko", "/opt/dummy_hcd.ko"),
        ("dummy_hcd-addresses.patch", "/opt/dummy_hcd-addresses.patch"),
    ]:
        assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == provenance["files"][name]
    return {**provenance, "requested_ep_addresses_enabled": True}


def endpoint_addresses(configuration):
    """Read actual host descriptors independently of the emulator's descriptor builder."""
    assert len(configuration) >= 9 and configuration[:2] == b"\x09\x02"
    assert int.from_bytes(configuration[2:4], "little") == len(configuration)
    result, offset = [], 0
    while offset < len(configuration):
        size = configuration[offset]
        assert size >= 2 and offset + size <= len(configuration)
        if configuration[offset + 1] == 5:
            assert size >= 7
            result.append(configuration[offset + 2])
        offset += size
    return result


def expected_endpoint_addresses(bits):
    return (
        ([0x81] if bits & 1 else [])
        + ([0x04, 0x84] if bits & 2 else [])
        + ([0x02, 0x82, 0x83] if bits & 4 else [])
    )


def check(value, name):
    if not value:
        raise AssertionError(name)
    checks.append({"name": name, "passed": True})
    print("PASS", name, flush=True)


def wait_for(predicate, label):
    for _ in range(240):
        result = predicate()
        if result:
            return result
        time.sleep(0.05)
    raise AssertionError(label)


class CompositeFixture(verify_ctap.Fixture):
    def __init__(self, binary, directory):
        super().__init__(binary, directory)
        self.bridge = None
        (directory / "card").mkdir(exist_ok=True)
        self.card = verify_smartcard.Fixture(Path("/opt"), directory / "card", startup_timeout=30)

    def start(self):
        self.controller = controller_provenance()
        assert not list(Path("/dev").glob("hidraw*")), (
            "unexpected HID before own USB device"
        )
        connection = self.card.start()
        self.serial = str(ManagementSession(connection).read_device_info().serial)
        connection.close()
        self.card.connection = None
        self.card_socket = self.directory / "card/s.sock"
        super().start()
        self.device.close()
        self.device = None
        self.usb_log = (self.directory / "usb.log").open("ab")
        controllers = list(Path("/sys/class/udc").iterdir())
        assert len(controllers) == 1 and controllers[0].name.startswith("dummy_udc."), controllers
        self.bridge = subprocess.Popen(
            [
                "/opt/ske-usbd",
                "--card-socket",
                str(self.card_socket),
                "--fido-socket",
                str(self.socket_path),
                "--yubico-usb-ids",
                "--functionfs",
                "/dev/ffs-ske",
                "--configfs-gadget",
                "/sys/kernel/config/usb_gadget/ske",
                "--controller",
                controllers[0].name,
            ],
            stdin=subprocess.PIPE,
            stdout=self.usb_log,
            stderr=self.usb_log,
            text=True,
            env=dict(os.environ),
        )

        def discover():
            if self.bridge.poll() is not None:
                raise RuntimeError((self.directory / "usb.log").read_text())
            return next(
                (
                    d
                    for d in list_descriptors()
                    if (d.vid, d.pid, d.serial_number) == (0x1050, 0x0407, self.serial)
                ),
                None,
            )

        desc = wait_for(discover, "FIDO composite USB hidraw did not appear")
        own = [d for d in CtapHidDevice.list_devices() if d.descriptor == desc]
        assert len(own) == 1
        self.device = own[0]
        self.ctap = Ctap2(self.device)
        link = (Path("/sys/class/hidraw") / Path(desc.path).name / "device").resolve()
        assert "/usb" in str(link) and "dummy_hcd" in str(link), link
        usb_parent = next(parent for parent in link.parents if (parent / "descriptors").exists())
        raw_descriptors = (usb_parent / "descriptors").read_bytes()
        addresses = endpoint_addresses(raw_descriptors[18:])
        assert addresses == expected_endpoint_addresses(7), addresses
        observations.append(
            {
                "serial": self.serial,
                "path": desc.path,
                "vid": desc.vid,
                "pid": desc.pid,
                "kernel_link": str(link),
                "sdk_connection": type(self.device._connection).__name__,
                "userspace_usb_transport": "FunctionFS",
                "controller": self.controller,
                "host_visible_endpoint_addresses": addresses,
                "host_visible_device_descriptor_hex": raw_descriptors[:18].hex(),
                "host_visible_configuration_descriptor_hex": raw_descriptors[18:].hex(),
            }
        )
        return self.ctap

    def stop(self):
        if self.device:
            self.device.close()
            self.device = None
        if self.bridge:
            self.bridge.stdin.write("quit\n")
            self.bridge.stdin.flush()
            self.bridge.wait(10)
            assert self.bridge.returncode == 0, (self.directory / "usb.log").read_text()
            self.bridge.stdin.close()
            self.bridge = None
        if hasattr(self, "usb_log"):
            self.usb_log.close()
        super().stop()
        self.card.stop()
        wait_for(
            lambda: not list(Path("/dev").glob("hidraw*")),
            "USB HID persisted after teardown",
        )


def main():
    report = {
        "passed": False,
        "tests": checks,
        "kernel": platform.release(),
        "physical_device_access": False,
        "host_usb_passthrough": False,
        "guest_network_devices": False,
        "manufacturer_trust_reproduced": False,
        "browser_webauthn_verified": False,
        "native_macos_registration_verified": False,
        "native_linux_composite_usb_verified": False,
        "userspace_usb_transport": "FunctionFS",
        "discoveries": observations,
        "versions": {
            name: importlib.metadata.version(name)
            for name in ["fido2", "yubikey-manager", "pyscard", "pyusb"]
        },
    }
    try:
        assert Path("/opt/isolated-ske-usb-guest").exists()
        assert platform.release() == "6.8.0-146-generic"
        assert [p.name for p in Path("/sys/class/net").iterdir()] == ["lo"]
        verify_ctap.Fixture = CompositeFixture
        with tempfile.TemporaryDirectory(prefix="usb-", dir="/guest-state") as d:
            verify_ctap.run(Path("/opt/swpasskeyd"), Path(d), report)
            print("SKE_USB_DIAGNOSTIC", (Path(d) / "usb.log").read_text(), flush=True)
        check(len(observations) == 3, "three USB composite creation/restart cycles")
        check(
            len({d["serial"] for d in observations}) == 1,
            "own USB serial preserved across restarts",
        )
        report["native_linux_composite_usb_verified"] = True
        report["controller"] = controller_provenance()
        report["requested_endpoint_addresses_verified"] = True
        report["passed"] = True
        report["extra_checks"] = checks
        report["test_count"] = len(report["tests"])
    except Exception as exc:
        report.update(passed=False, error=f"{type(exc).__name__}: {exc}")
        raise
    finally:
        print("SKE_USB_RESULT_BEGIN", flush=True)
        print(
            json.dumps(
                report, default=lambda v: v.hex() if isinstance(v, bytes) else str(v)
            ),
            flush=True,
        )
        print("SKE_USB_RESULT_END", flush=True)


if __name__ == "__main__":
    main()
