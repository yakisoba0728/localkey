#!/usr/bin/env python3
"""Verify new Linux OTP and PCSC paths in the isolated guest only."""

from __future__ import annotations

import hmac
import json
import os
import select
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, "/opt/verification")
sys.path.insert(0, "/opt")

import verify_smartcard
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from smartcard.pcsc.PCSCExceptions import (
    EstablishContextException,
    ListReadersException,
)
from smartcard.System import readers
from ykman.hid.linux import HidrawConnection, get_info, get_usage
from ykman.pcsc import ScardSmartCardConnection
from yubikit.core.otp import CommandRejectedError
from yubikit.core.smartcard import ApduError
from yubikit.core.smartcard.scp import Scp03KeyParams
from yubikit.management import ManagementSession
from yubikit.oath import HASH_ALGORITHM, OATH_TYPE, CredentialData, OathSession
from yubikit.openpgp import OpenPgpSession
from yubikit.piv import DEFAULT_MANAGEMENT_KEY, KEY_TYPE, SLOT, PivSession
from yubikit.yubiotp import SLOT as OTP_SLOT
from yubikit.yubiotp import (
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


def wait_for(predicate, label):
    for _ in range(200):
        result = predicate()
        if result:
            return result
        time.sleep(0.05)
    raise AssertionError(label)


def native_otp(report):
    with tempfile.TemporaryDirectory(prefix="otp-", dir="/guest-state") as d:
        directory = Path(d)
        fixture = verify_smartcard.Fixture(Path("/opt"), directory, startup_timeout=30)
        bridge = connection = None
        event_fd = None
        log = (directory / "otp.log").open("wb")
        try:
            card = fixture.start()
            serial = ManagementSession(card).read_device_info().serial
            bridge = subprocess.Popen(
                ["/opt/ske-otpd", "--socket", str(directory / "s.sock")],
                stdin=subprocess.PIPE,
                stdout=log,
                stderr=log,
                text=True,
                env={**os.environ, "SKE_TRACE_UHID": "1"},
            )
            path = wait_for(
                lambda: next(iter(Path("/dev").glob("hidraw*")), None),
                "OTP hidraw did not appear",
            )
            with path.open("rb") as handle:
                check(
                    get_info(handle)[1:] == (0x1209, 0xF055), "native OTP ioctl VID/PID"
                )
                check(
                    get_usage(handle) == (1, 6), "native OTP keyboard usage descriptor"
                )
            connection = HidrawConnection(str(path))
            otp = YubiOtpSession(connection)
            check(otp.version == (5, 7, 4), "stock OTP SDK reads native feature report")
            try:
                otp.get_serial()
            except CommandRejectedError:
                check(
                    True, "native OTP denies serial until a slot enables API visibility"
                )
            else:
                raise AssertionError("fresh OTP exposed serial without slot visibility")
            secret = b"own native fixture!!".ljust(20, b"!")
            challenge = b"own native HID challenge"
            otp.put_configuration(
                OTP_SLOT.TWO, HmacSha1SlotConfiguration(secret).serial_api_visible(True)
            )
            check(
                otp.get_serial() == serial,
                "native OTP feature serial matches shared card after explicit visibility",
            )
            check(
                otp.calculate_hmac_sha1(OTP_SLOT.TWO, challenge)
                == hmac.digest(secret, challenge, "sha1"),
                "stock OTP SDK GET/SET_REPORT and independent HMAC",
            )
            check(
                YubiOtpSession(card).calculate_hmac_sha1(OTP_SLOT.TWO, challenge)
                == hmac.digest(secret, challenge, "sha1"),
                "native HID and CCID share programmed own OTP state",
            )
            otp.put_configuration(
                OTP_SLOT.ONE, StaticPasswordSlotConfiguration(bytes([0x84, 5, 30]))
            )
            event_path = wait_for(
                lambda: next(iter(Path("/dev/input").glob("event*")), None),
                "native evdev keyboard did not appear",
            )
            event_fd = os.open(event_path, os.O_RDONLY | os.O_NONBLOCK)
            bridge.stdin.write("1\n")
            bridge.stdin.flush()
            event_format = struct.Struct("@llHHi")
            pending = bytearray()
            events = []
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                if not select.select([event_fd], [], [], 0.1)[0]:
                    if len([e for e in events if e[1] == 0]) >= 5:
                        break
                    continue
                pending.extend(os.read(event_fd, event_format.size * 64))
                while len(pending) >= event_format.size:
                    _, _, kind, code, value = event_format.unpack(
                        pending[: event_format.size]
                    )
                    del pending[: event_format.size]
                    if kind == 1:
                        events.append((code, value))
            down = [code for code, value in events if value == 1]
            up = [code for code, value in events if value == 0]
            check(
                down == [42, 30, 48, 2, 28],
                "real evdev Shift+A, b, 1 and Enter presses",
            )
            check(
                sorted(up) == sorted(down), "real evdev releases every key and modifier"
            )
            report["native_otp"] = {
                "path": str(path),
                "event_path": str(event_path),
                "sdk_connection": type(connection).__name__,
                "evdev_key_events": events,
                "host_keyboard_affected": False,
                "software_presence": "Debug card --testing plus explicit bridge command",
            }
            connection.close()
            connection = None
            os.close(event_fd)
            event_fd = None
            bridge.stdin.write("quit\n")
            bridge.stdin.flush()
            check(bridge.wait(10) == 0, "native OTP bridge clean shutdown")
            bridge = None
            wait_for(
                lambda: not path.exists() and not event_path.exists(),
                "OTP teardown leaked device",
            )
            check(True, "native OTP removes hidraw and evdev on teardown")
            report["native_linux_otp_feature_verified"] = True
            report["native_linux_keyboard_evdev_verified"] = True
        finally:
            if connection:
                connection.close()
            if event_fd is not None:
                os.close(event_fd)
            if bridge:
                bridge.terminate()
                bridge.wait(10)
            log.close()
            print("SKE_OTP_DIAGNOSTIC", (directory / "otp.log").read_text(), flush=True)
            fixture.stop()


class PcscFixture(verify_smartcard.Fixture):
    def __init__(self, directory):
        super().__init__(Path("/opt"), directory, startup_timeout=30)
        self.manager = None

    def start(self):
        super().start().close()
        self.connection = None
        config = self.directory / "readers"
        config.mkdir(exist_ok=True)
        (config / "own.conf").write_text(
            "FRIENDLYNAME OwnSoftwareEmulator\n"
            f"DEVICENAME {self.directory / 's.sock'}\n"
            "LIBPATH /opt/ske-ifd.so\nCHANNELID 0\n"
        )
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
        found = None
        last_discovery = None
        for _ in range(200):
            if self.manager.poll() is not None:
                raise RuntimeError((self.directory / "pcscd.log").read_text())
            try:
                listed = readers()
                last_discovery = [str(r) for r in listed]
                matches = [
                    r for r in listed if r.name.startswith("OwnSoftwareEmulator")
                ]
            except (EstablishContextException, ListReadersException) as exc:
                last_discovery = repr(exc)
                matches = []
            if len(matches) == 1:
                found = matches[0]
                break
            time.sleep(0.05)
        if found is None:
            raise RuntimeError(
                f"PCSC reader not discoverable ({last_discovery}): "
                + (self.directory / "pcscd.log").read_text()
            )
        self.reader_name = found.name
        self.connection = ScardSmartCardConnection(found.createConnection())
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
        super().stop()


def native_pcsc(report):
    with tempfile.TemporaryDirectory(prefix="pcsc-", dir="/guest-state") as d:
        fixture = PcscFixture(Path(d))
        try:
            conn = fixture.start()
            check(
                len(readers()) == 1,
                "real pcscd enumerates exactly the own software reader",
            )
            check(
                conn.connection.getProtocol() == 2,
                "stock PCSC connection negotiates T=1",
            )
            serial = ManagementSession(conn).read_device_info().serial
            check(serial > 0, "stock management SDK over real PCSC resource manager")
            piv = PivSession(conn)
            check(piv.version == (5, 7, 4), "stock PIV SDK over native Linux IFD")
            try:
                piv.generate_key(SLOT.AUTHENTICATION, KEY_TYPE.ECCP256)
            except ApduError as exc:
                check(
                    exc.sw == 0x6982,
                    "native PCSC rejects unauthenticated key generation",
                )
            else:
                raise AssertionError("unauthenticated key generation")
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
            pub = piv.generate_key(SLOT.AUTHENTICATION, KEY_TYPE.ECCP256)
            piv.verify_pin("123456")
            msg = b"own native pcsc fixture signing challenge"
            pub.verify(
                piv.sign(SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, msg, hashes.SHA256()),
                msg,
                ec.ECDSA(hashes.SHA256()),
            )
            check(True, "native PCSC PIV signature independently verifies")
            payload = bytes(range(256)) * 8
            piv.put_object(0x5FFF05, payload)
            check(
                piv.get_object(0x5FFF05) == payload,
                "native PCSC long APDU command/response round trip",
            )
            oath = OathSession(conn)
            credential = oath.put_credential(
                CredentialData(
                    "own-pcsc-oath",
                    OATH_TYPE.TOTP,
                    HASH_ALGORITHM.SHA1,
                    secret=b"ownpcscfixturesecret",
                )
            )
            check(
                oath.calculate_code(credential, timestamp=1700000000).value.isdigit(),
                "stock OATH SDK over native PCSC",
            )
            check(
                OpenPgpSession(conn).version == (5, 7, 4),
                "stock OpenPGP SDK over native PCSC",
            )
            secure = PivSession(conn, Scp03KeyParams())
            secure.authenticate(DEFAULT_MANAGEMENT_KEY)
            secure.verify_pin("123456")
            pub.verify(
                secure.sign(
                    SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, msg, hashes.SHA256()
                ),
                msg,
                ec.ECDSA(hashes.SHA256()),
            )
            check(True, "native PCSC SCP03 encrypted signature and SDK response MAC")
            secure.put_object(0x5FFF05, payload[::-1])
            check(
                secure.get_object(0x5FFF05) == payload[::-1],
                "native PCSC encrypted long command/response chaining",
            )
            _, sw = conn.send_and_receive(bytes.fromhex("00fd000000"))
            check(
                sw == 0x6982,
                "native PCSC encrypted session rejects plaintext downgrade",
            )
            report["native_pcsc"] = {
                "reader_name": fixture.reader_name,
                "sdk_connection": type(conn).__name__,
                "atr": bytes(conn.connection.getATR()).hex(),
                "sdk_atr_transport_classification": str(conn.transport),
                "physical_usb_bus_device": False,
                "reader_provider": "actual pcscd -> compiled IFD -> private CCID card service",
            }
            conn = fixture.restart()
            check(
                ManagementSession(conn).read_device_info().serial == serial,
                "PCSC resource manager and card restart preserve own identity",
            )
            piv = PivSession(conn)
            piv.verify_pin("123456")
            pub.verify(
                piv.sign(SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, msg, hashes.SHA256()),
                msg,
                ec.ECDSA(hashes.SHA256()),
            )
            check(True, "PCSC restart preserves encrypted own credential and signature")
            report["native_linux_pcsc_resource_manager_verified"] = True
        finally:
            fixture.stop()


def main():
    report = {
        "passed": False,
        "physical_device_access": False,
        "host_usb_passthrough": False,
        "manufacturer_trust_reproduced": False,
        "native_macos_registration_verified": False,
        "native_composite_usb_bus_verified": False,
        "native_linux_otp_feature_verified": False,
        "native_linux_keyboard_evdev_verified": False,
        "native_linux_pcsc_resource_manager_verified": False,
        "tests": checks,
    }
    try:
        assert Path("/opt/isolated-ske-native-extra").exists()
        assert not list(Path("/dev").glob("hidraw*"))
        native_otp(report)
        native_pcsc(report)
        report.update(passed=True, test_count=len(checks))
    except Exception as exc:
        report.update(error=f"{type(exc).__name__}: {exc}")
        raise
    finally:
        print("SKE_NATIVE_EXTRA_BEGIN", flush=True)
        print(json.dumps(report), flush=True)
        print("SKE_NATIVE_EXTRA_END", flush=True)


if __name__ == "__main__":
    main()
