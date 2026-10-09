#!/usr/bin/env python3
"""Run existing independent CTAP tests through stock SDK and real guest hidraw.

Only runs in the private, device-isolated test guest prepared by build-guest.py.
Creates new software credentials; the guest has no host USB or network devices.
"""

from __future__ import annotations

import importlib.metadata
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, "/opt/verification")

import verify_ctap
from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice
from fido2.hid.linux import LinuxCtapHidConnection, list_descriptors

observations = []


class NativeFixture(verify_ctap.Fixture):
    def start(self):
        assert not list(Path("/dev").glob("hidraw*")), "unexpected preexisting HID"
        self.log = (self.directory / "daemon.log").open("ab")
        env = {**os.environ, "SWPASSKEY_LOG": "debug"}
        env.pop("SWPASSKEY_HID_SOCKET", None)
        env.pop("SWPASSKEY_CARD_SOCKET", None)
        self.process = subprocess.Popen(
            [
                str(self.binary),
                "--testing",
                "--dek-file",
                "--key-backend=software",
                "--store",
                str(self.directory / "state.bin"),
                "--ctl-socket",
                str(self.directory / "c.sock"),
            ],
            env=env,
            stdout=self.log,
            stderr=self.log,
        )
        selected = None
        for _ in range(300):
            if self.process.poll() is not None:
                raise RuntimeError((self.directory / "daemon.log").read_text())
            serial_file = self.directory / "serial"
            if serial_file.exists():
                serial = serial_file.read_text().strip()
                matches = [
                    d
                    for d in list_descriptors()
                    if (d.vid, d.pid, d.serial_number) == (0x1209, 0xF1D0, serial)
                ]
                if len(matches) == 1:
                    selected = matches[0]
                    break
            time.sleep(0.05)
        assert selected is not None, "native UHID device never became discoverable"
        assert selected.path.startswith("/dev/hidraw")
        assert (selected.report_size_in, selected.report_size_out) == (64, 64)
        devices = list(CtapHidDevice.list_devices())
        own = [d for d in devices if d.descriptor == selected]
        assert len(own) == 1, "stock SDK did not enumerate the exact fresh device"
        self.device = own[0]
        assert isinstance(self.device._connection, LinuxCtapHidConnection)
        self.ctap = Ctap2(self.device)
        observations.append(
            {
                "path": selected.path,
                "vid": selected.vid,
                "pid": selected.pid,
                "name": selected.product_name,
                "serial": selected.serial_number,
                "report_size_in": selected.report_size_in,
                "report_size_out": selected.report_size_out,
                "sdk_transport": type(self.device._connection).__name__,
                "caps": int(self.device.capabilities),
                "kernel_device_link": str(
                    (
                        Path("/sys/class/hidraw") / Path(selected.path).name / "device"
                    ).resolve()
                ),
            }
        )
        return self.ctap

    def stop(self):
        super().stop()
        for _ in range(100):
            if not list(Path("/dev").glob("hidraw*")):
                return
            time.sleep(0.05)
        raise AssertionError("UHID device persisted after daemon teardown")


def main():
    report = {
        "subject": "modified software emulator, fresh private Linux guest",
        "transport": "Linux UHID -> kernel hidraw -> unmodified python-fido2",
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "sdk_version": importlib.metadata.version("fido2"),
        "physical_device_access": False,
        "host_usb_passthrough": False,
        "guest_network_devices": False,
        "manufacturer_trust_reproduced": False,
        "native_macos_registration_verified": False,
        "browser_webauthn_verified": False,
        "native_uhid_registration_verified": False,
        "test_presence": "explicit Debug auto-allow, not a physical touch",
        "real_os_keychain_tests_enabled": False,
        "native_discoveries": observations,
    }
    try:
        assert platform.system() == "Linux"
        assert Path("/opt/isolated-ske-test-guest").is_file()
        assert platform.release() == "6.8.0-146-generic"
        assert not os.environ.get("SWPASSKEY_HID_SOCKET")
        assert [p.name for p in Path("/sys/class/net").iterdir()] == ["lo"]
        assert Path("/dev/uhid").exists()
        verify_ctap.Fixture = NativeFixture
        with tempfile.TemporaryDirectory(prefix="own-", dir="/guest-state") as d:
            verify_ctap.run(Path("/opt/swpasskeyd"), Path(d), report)
            report["daemon_native_events"] = {
                event: (Path(d) / "daemon.log").read_text().count(event)
                for event in ["uhid_created", "uhid_start", "uhid_open", "uhid_close"]
            }
        assert len(observations) == 3, "expected initial creation and two restarts"
        assert len({d["serial"] for d in observations}) == 1
        report.update(
            native_uhid_registration_verified=True,
            native_sdk_ctap_verified=True,
            native_lifecycle_restart_teardown_verified=True,
            test_count=len(report["tests"]),
        )
    except Exception as exc:
        report.update(passed=False, error=f"{type(exc).__name__}: {exc}")
        raise
    finally:
        print("SKE_NATIVE_RESULT_BEGIN", flush=True)
        print(
            json.dumps(
                report,
                default=lambda v: v.hex() if isinstance(v, bytes) else str(v),
            ),
            flush=True,
        )
        print("SKE_NATIVE_RESULT_END", flush=True)


if __name__ == "__main__":
    main()
