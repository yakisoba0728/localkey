#!/usr/bin/env python3
"""Actual USB OTP, keyboard, stock libccid/pcscd and SDK grouping in private guest."""

import hmac
import hashlib
import json
import logging
import os
import select
import struct
import subprocess
import tempfile
import time
from pathlib import Path

import verify_composite
import verify_native_extra
from smartcard.pcsc.PCSCExceptions import (
    EstablishContextException,
    ListReadersException,
)
from smartcard.System import readers
from ykman.device import list_all_devices
from ykman.hid.linux import list_devices as list_otp
from ykman.pcsc import ScardSmartCardConnection
from ykman.pcsc import list_devices as list_pcsc
from yubikit.core import TRANSPORT
from yubikit.core.otp import CommandRejectedError, OtpConnection
from yubikit.yubiotp import (
    SLOT,
    HmacSha1SlotConfiguration,
    StaticPasswordSlotConfiguration,
    YubiOtpSession,
)

checks = []


def check(value, name):
    if not value:
        raise AssertionError(name)
    checks.append({"name": name, "passed": True})
    print("PASS", name, flush=True)


class UsbPcscFixture(verify_composite.CompositeFixture):
    def __init__(self, directory):
        super().__init__(Path("/opt/swpasskeyd"), directory)
        self.connection = self.manager = None

    def start(self):
        super().start()
        config = self.directory / "empty-readers"
        config.mkdir(exist_ok=True)
        self.manager_log = (self.directory / "pcscd.log").open("ab")
        self.manager = subprocess.Popen(
            [
                "/usr/sbin/pcscd",
                "--foreground",
                "--debug",
                "--disable-polkit",
                "--config",
                str(config),
            ],
            stdout=self.manager_log,
            stderr=self.manager_log,
        )

        def discover():
            if self.manager.poll() is not None:
                raise RuntimeError((self.directory / "pcscd.log").read_text())
            try:
                return next((r for r in readers() if self.serial in r.name), None)
            except (EstablishContextException, ListReadersException):
                return None

        reader = verify_composite.wait_for(
            discover, "stock libccid did not discover own USB reader"
        )
        self.reader_name = reader.name
        self.connection = ScardSmartCardConnection(reader.createConnection())
        assert self.connection.transport == TRANSPORT.USB, self.connection.transport
        assert self.connection.connection.getATR() == list(
            bytes.fromhex("3bf011000001e0")
        )
        driver_log = (self.directory / "pcscd.log").read_text()
        assert "libccid.so" in driver_log and "ske-ifd.so" not in driver_log, driver_log
        return self.connection

    def stop(self):
        if self.connection:
            self.connection.close()
            self.connection = None
        if self.manager:
            self.manager.terminate()
            self.manager.wait(10)
            self.manager = None
        if hasattr(self, "manager_log"):
            self.manager_log.close()
            print(
                "SKE_USB_PCSC_LOG",
                (self.directory / "pcscd.log").read_text(),
                flush=True,
            )
        super().stop()


def otp_keyboard(report):
    with tempfile.TemporaryDirectory(prefix="usb-otp-", dir="/guest-state") as d:
        fixture = UsbPcscFixture(Path(d))
        event_fd = None
        connection = None
        try:
            card = fixture.start()
            check(
                card.transport == TRANSPORT.USB,
                "stock PCSC SDK classifies independent software ATR as USB",
            )
            # Stock enumeration opens/closes its own PCSC handle with reset
            # disposition. Release our handle before that normal reader reset.
            card.close()
            fixture.connection = None
            discovered = list_all_devices()
            check(
                len(discovered) == 1 and str(discovered[0][1].serial) == fixture.serial,
                "stock ykman combines USB interfaces into one own device",
            )
            check(
                len(list_pcsc()) == 1, "stock ykman default smartcard reader discovery"
            )
            reader = next(r for r in readers() if fixture.serial in r.name)
            card = ScardSmartCardConnection(reader.createConnection())
            fixture.connection = card
            devices = list_otp()
            check(
                len(devices) == 1,
                "stock ykman enumerates native USB OTP keyboard interface",
            )
            connection = devices[0].open_connection(OtpConnection)
            otp = YubiOtpSession(connection)
            check(otp.version == (5, 7, 4), "stock USB OTP SDK reads feature version")
            try:
                otp.get_serial()
            except CommandRejectedError:
                check(
                    True, "fresh USB OTP keeps serial API disabled until configuration"
                )
            else:
                raise AssertionError("unconfigured OTP serial API")
            secret = b"own usb fixture key!"
            challenge = b"own USB challenge"
            otp.put_configuration(
                SLOT.TWO, HmacSha1SlotConfiguration(secret).serial_api_visible(True)
            )
            check(
                str(otp.get_serial()) == fixture.serial,
                "USB OTP and CCID serials identify the same own device",
            )
            expected = hmac.digest(secret, challenge, "sha1")
            check(
                otp.calculate_hmac_sha1(SLOT.TWO, challenge) == expected,
                "stock USB HID feature HMAC independently verified",
            )
            otp.put_configuration(SLOT.TWO, HmacSha1SlotConfiguration(secret).lt64(False).serial_api_visible(True))
            for index in range(128):
                full = hashlib.sha256(f"own USB request {index}".encode()).hexdigest().encode()
                assert otp.calculate_hmac_sha1(SLOT.TWO, full) == hmac.digest(secret, full, "sha1"), index
            report["consecutive_full_length_otp_hmac_requests"] = 128
            report["full_length_hmac_slot_uses_fixed_64_byte_mode"] = True
            check(True, "128 consecutive full-length USB OTP requests independently verify without SDK retries")
            otp.put_configuration(SLOT.TWO, HmacSha1SlotConfiguration(secret).serial_api_visible(True))
            check(
                YubiOtpSession(card).calculate_hmac_sha1(SLOT.TWO, challenge)
                == expected,
                "USB CCID and USB HID share programmed OTP state",
            )
            otp.put_configuration(
                SLOT.ONE, StaticPasswordSlotConfiguration(bytes([0x84, 5, 30]))
            )
            event_path = verify_composite.wait_for(
                lambda: next(iter(Path("/dev/input").glob("event*")), None),
                "USB keyboard input event missing",
            )
            event_fd = os.open(event_path, os.O_RDONLY | os.O_NONBLOCK)
            fixture.bridge.stdin.write("hold 500\n")
            fixture.bridge.stdin.flush()
            format = struct.Struct("@llHHi")
            pending = bytearray()
            events = []
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                if not select.select([event_fd], [], [], 0.1)[0]:
                    if len([e for e in events if e[1] == 0]) >= 5:
                        break
                    continue
                pending.extend(os.read(event_fd, format.size * 64))
                while len(pending) >= format.size:
                    _, _, kind, code, value = format.unpack(pending[: format.size])
                    del pending[: format.size]
                    if kind == 1:
                        events.append((code, value))
            down = [code for code, value in events if value == 1]
            up = [code for code, value in events if value == 0]
            report["observed_usb_keyboard_events"] = events
            check(
                down == [42, 30, 48, 2, 28],
                "actual USB keyboard Shift+A, b, 1, Enter events",
            )
            check(
                sorted(up) == sorted(down),
                "USB keyboard releases every key and modifier",
            )
            report["usb_otp"] = {
                "kernel_path": str(
                    (
                        Path("/sys/class/hidraw")
                        / Path(devices[0].path).name
                        / "device"
                    ).resolve()
                ),
                "sdk_connection": type(connection).__name__,
                "key_events": events,
                "host_keyboard_affected": False,
                "identity_and_keys": "fresh own software state",
            }
            check(
                "dummy_hcd" in report["usb_otp"]["kernel_path"],
                "OTP uses real guest USB controller and hidraw",
            )
            report["native_linux_usb_otp_sdk_verified"] = True
            report["native_linux_usb_keyboard_verified"] = True
        finally:
            if connection:
                connection.close()
            if event_fd is not None:
                os.close(event_fd)
            print(
                "SKE_USB_OTP_DIAGNOSTIC",
                (fixture.directory / "usb.log").read_text(),
                flush=True,
            )
            print(
                "SKE_USB_OTP_CARD_DIAGNOSTIC",
                (fixture.directory / "card/log.txt").read_text(),
                flush=True,
            )
            fixture.stop()
        check(
            not list(Path("/dev").glob("hidraw*"))
            and not list(Path("/dev/input").glob("event*")),
            "USB composite teardown removes HID and evdev devices",
        )


def main():
    # Record SDK feature-report traffic for any native timing failure.
    logging.basicConfig(level=logging.INFO)
    report = {
        "passed": False,
        "userspace_usb_transport": "FunctionFS",
        "control_transfer_diagnostic_tracing": bool(os.environ.get("SKE_TRACE_USB") or os.environ.get("SKE_TRACE_OTP_FRAMES")),
        "sdk_retry_or_explicit_transport_delay_added": False,
        "tests": checks,
        "physical_device_access": False,
        "host_usb_passthrough": False,
        "manufacturer_trust_reproduced": False,
        "native_linux_usb_otp_sdk_verified": False,
        "native_linux_usb_keyboard_verified": False,
        "native_linux_usb_ccid_pcsc_verified": False,
    }
    try:
        assert Path("/opt/isolated-ske-usb-guest").exists()
        otp_keyboard(report)
        verify_native_extra.PcscFixture = UsbPcscFixture
        verify_native_extra.checks = checks
        verify_native_extra.native_pcsc(report)
        report["native_pcsc"]["reader_provider"] = (
            "actual USB bus -> stock libccid -> actual pcscd -> stock PCSC SDK"
        )
        report["native_pcsc"]["physical_usb_bus_device"] = False
        report["native_pcsc"]["kernel_usb_bus_device"] = True
        for item in checks:
            item["name"] = (
                item["name"]
                .replace("native Linux IFD", "native USB CCID")
                .replace("native PCSC", "USB PCSC")
            )
        report.update(
            passed=True,
            native_linux_usb_ccid_pcsc_verified=True,
            test_count=len(checks),
        )
    except Exception as exc:
        report.update(error=f"{type(exc).__name__}: {exc}")
        raise
    finally:
        print("SKE_USB_EXTRA_BEGIN", flush=True)
        print(json.dumps(report), flush=True)
        print("SKE_USB_EXTRA_END", flush=True)


if __name__ == "__main__":
    main()
