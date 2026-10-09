#!/usr/bin/env python3
"""SDK-driven hot reenumeration on the private guest's actual USB bus."""

import hmac
import json
import tempfile
import time
from pathlib import Path

import verify_composite
import verify_composite_extra
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin, PinProtocolV2
from fido2.hid import CtapHidDevice
from fido2.hid.linux import list_descriptors
from smartcard.pcsc.PCSCExceptions import (
    EstablishContextException,
    ListReadersException,
)
from smartcard.System import readers
from smartcard.scard import (
    SCARD_SCOPE_SYSTEM, SCARD_S_SUCCESS, SCARD_STATE_UNAWARE, SCARD_STATE_PRESENT,
    SCardEstablishContext, SCardGetStatusChange, SCardReleaseContext,
)
from ykman.hid.linux import list_devices as list_otp
from ykman.pcsc import ScardSmartCardConnection
from yubikit.core import TRANSPORT
from yubikit.core.otp import OtpConnection
from yubikit.management import CAPABILITY, DeviceConfig, ManagementSession
from yubikit.yubiotp import SLOT, HmacSha1SlotConfiguration, YubiOtpSession

checks, enumerations = [], []


def check(value, name):
    if not value:
        raise AssertionError(name)
    checks.append({"name": name, "passed": True})
    print("PASS", name, flush=True)


def snapshot(serial):
    for path in Path("/sys/bus/usb/devices").iterdir():
        try:
            if (path / "serial").read_text().strip() != serial:
                continue
            result = {
                "path": str(path.resolve()),
                "serial": serial,
                "vid": int((path / "idVendor").read_text().strip(), 16),
                "pid": int((path / "idProduct").read_text().strip(), 16),
                "address": int((path / "devnum").read_text()),
                "host_visible_configuration_descriptor_hex": (path / "descriptors").read_bytes()[18:].hex(),
                "classes": sorted(
                    int((interface / "bInterfaceClass").read_text().strip(), 16)
                    for interface in path.glob(path.name + ":*")
                ),
            }
            if result["classes"]:
                result["host_visible_endpoint_addresses"] = verify_composite.endpoint_addresses(
                    bytes.fromhex(result["host_visible_configuration_descriptor_hex"])
                )
                return result
        except (OSError, ValueError):
            continue
    return None


def connection(kind, serial):
    if kind == "FIDO":
        for device in CtapHidDevice.list_devices():
            if device.descriptor.serial_number == serial:
                return device
            device.close()
        raise AssertionError("own FIDO interface missing")
    if kind == "OTP":
        devices = list_otp()
        assert len(devices) == 1
        return devices[0].open_connection(OtpConnection)

    def discover():
        try:
            reader = next((reader for reader in readers() if serial in reader.name), None)
            if reader is None:
                return None
            result, context = SCardEstablishContext(SCARD_SCOPE_SYSTEM)
            if result != SCARD_S_SUCCESS:
                return None
            try:
                result, states = SCardGetStatusChange(context, 0, [(reader.name, SCARD_STATE_UNAWARE)])
                return reader if result == SCARD_S_SUCCESS and states[0][1] & SCARD_STATE_PRESENT else None
            finally:
                SCardReleaseContext(context)
        except (EstablishContextException, ListReadersException):
            return None

    reader = verify_composite.wait_for(discover, "own hotplug CCID reader missing")
    return ScardSmartCardConnection(reader.createConnection())


def run(directory, report):
    fixture = verify_composite_extra.UsbPcscFixture(directory)
    try:
        fixture.start()
        fixture.connection.close()
        fixture.connection = None
        serial = fixture.serial
        ctap = fixture.ctap
        digest = bytes(range(32))
        att = ctap.make_credential(
            digest,
            {"id": "localhost"},
            {"id": b"own-native-reboot"},
            [{"type": "public-key", "alg": -7}],
        )
        credential = att.auth_data.credential_data
        protocol = PinProtocolV2()
        ClientPin(ctap, protocol).set_pin("123456")
        old_token = ClientPin(ctap, protocol).get_pin_token(
            "123456", ClientPin.PERMISSION.GET_ASSERTION, "localhost"
        )
        old_agreement = ctap.client_pin(2, 2)[1]
        management = ManagementSession(fixture.device)
        original = snapshot(serial)
        assert original and original["pid"] == 0x407
        original["host_visible_endpoint_addresses"] = verify_composite.endpoint_addresses(
            bytes.fromhex(original["host_visible_configuration_descriptor_hex"])
        )
        check(original["host_visible_endpoint_addresses"] == verify_composite.expected_endpoint_addresses(7),
              "initial native USB composite preserves requested endpoint addresses")
        reference = json.loads(Path("/opt/usb-reference-observation.json").read_text())
        report["controller"] = fixture.controller
        enumerations.append(original)
        processes = (fixture.bridge.pid, fixture.process.pid, fixture.card.process.pid)

        management.write_device_config(DeviceConfig({TRANSPORT.USB: CAPABILITY.PIV}))
        time.sleep(0.4)
        check(
            snapshot(serial) == original,
            "settings write without reboot preserves live USB device",
        )
        check(
            management.read_device_info().config.enabled_capabilities[TRANSPORT.USB]
            == CAPABILITY.PIV,
            "pending USB configuration is readable through stock native SDK",
        )
        management.write_device_config(DeviceConfig({TRANSPORT.USB: CAPABILITY(0x33B)}))
        management.write_device_config(new_lock_code=b"L" * 16)
        for lock in [None, b"X" * 16]:
            try:
                management.write_device_config(reboot=True, cur_lock_code=lock)
            except CtapError as exc:
                check(
                    int(exc.code) == 0x7F,
                    "native FIDO rejects invalid configuration unlock",
                )
            else:
                raise AssertionError("invalid lock accepted")
        time.sleep(0.4)
        check(
            snapshot(serial) == original,
            "rejected reboot requests preserve live USB device",
        )
        management.write_device_config(cur_lock_code=b"L" * 16, new_lock_code=bytes(16))

        with connection("OTP", serial) as otp_connection:
            YubiOtpSession(otp_connection).put_configuration(
                SLOT.TWO,
                HmacSha1SlotConfiguration(b"own reboot fixture!!").serial_api_visible(
                    True
                ),
            )
        fixture.device.close()
        fixture.device = None
        current = original
        # Every public interface combination is activated without restarting any
        # emulator service. Writes traverse each of the three native SDK backends.
        for bits, mask, kind in [
            (1, 0x001, "FIDO"),
            (2, 0x202, "OTP"),
            (3, 0x203, "FIDO"),
            (4, 0x138, "OTP"),
            (5, 0x139, "CCID"),
            (6, 0x33A, "OTP"),
            (7, 0x33B, "CCID"),
            (7, 0x33B, "FIDO"),
        ]:
            with connection(kind, serial) as conn:
                ManagementSession(conn).write_device_config(
                    DeviceConfig({TRANSPORT.USB: CAPABILITY(mask)}), reboot=True
                )
            old_address = current["address"]

            def reappeared(bits=bits, old_address=old_address):
                if fixture.bridge.poll() is not None:
                    raise RuntimeError((directory / "usb.log").read_text())
                value = snapshot(serial)
                expected_classes = sorted(
                    ([3] if bits & 1 else [])
                    + ([3] if bits & 2 else [])
                    + ([11] if bits & 4 else [])
                )
                fido_paths = [
                    d for d in list_descriptors() if d.serial_number == serial
                ]
                hid_ready = bool(fido_paths) == bool(bits & 2) and all(
                    d.pid == 0x400 + bits for d in fido_paths
                )
                return (
                    value
                    if value
                    and value["address"] != old_address
                    and value["pid"] == 0x400 + bits
                    and value["classes"] == expected_classes
                    and hid_ready
                    else None
                )

            current = verify_composite.wait_for(
                reappeared, f"USB profile {bits} did not reenumerate"
            )
            actual = bytes.fromhex(current["host_visible_configuration_descriptor_hex"])
            current["host_visible_endpoint_addresses"] = verify_composite.endpoint_addresses(actual)
            check(current["host_visible_endpoint_addresses"] == verify_composite.expected_endpoint_addresses(bits),
                  f"native USB profile {bits} preserves every requested endpoint address")
            if bits == 6:
                check(actual == bytes.fromhex(reference["configuration_descriptor_hex"]),
                      "actual 125-byte FIDO+CCID configuration equals saved physical reference")
                fido_paths = [d for d in list_descriptors() if d.serial_number == serial]
                assert len(fido_paths) == 1, fido_paths
                link = (Path("/sys/class/hidraw") / Path(fido_paths[0].path).name / "device").resolve()
                current["host_visible_fido_report_descriptor_hex"] = (link / "report_descriptor").read_bytes().hex()
                check(current["host_visible_fido_report_descriptor_hex"] == reference["hid_report_descriptor_hex"],
                      "actual kernel FIDO report descriptor equals saved physical reference")
                report["reference_descriptor_equivalence_verified"] = True
            enumerations.append(current)
            check(
                current["vid"] == 0x1050 and "dummy_hcd" in current["path"],
                f"native USB profile {bits} has new address and expected interfaces",
            )
            check(
                processes
                == (fixture.bridge.pid, fixture.process.pid, fixture.card.process.pid)
                and all(
                    p.poll() is None
                    for p in [fixture.bridge, fixture.process, fixture.card.process]
                ),
                f"USB profile {bits} reenumerates within the same live processes",
            )
            fido_paths = [d for d in list_descriptors() if d.serial_number == serial]
            check(
                bool(fido_paths) == bool(bits & 2),
                f"kernel FIDO hidraw matches active USB profile {bits}",
            )

        with connection("FIDO", serial) as device:
            ctap = Ctap2(device)
            check(
                ctap.get_info().options["clientPin"],
                "native reboots preserve configured FIDO PIN",
            )
            check(
                ctap.client_pin(2, 2)[1] != old_agreement,
                "native reboot replaces FIDO key agreement",
            )
            try:
                ctap.get_assertion(
                    "localhost",
                    digest,
                    [{"type": "public-key", "id": credential.credential_id}],
                    pin_uv_protocol=2,
                    pin_uv_param=protocol.authenticate(old_token, digest),
                )
            except CtapError as exc:
                check(
                    int(exc.code) == 0x33, "native reboot rejects pre-reboot FIDO token"
                )
            else:
                raise AssertionError("old PIN token accepted after native reboot")
            token = ClientPin(ctap, protocol).get_pin_token(
                "123456", ClientPin.PERMISSION.GET_ASSERTION, "localhost"
            )
            result = ctap.get_assertion(
                "localhost",
                digest,
                [{"type": "public-key", "id": credential.credential_id}],
                pin_uv_protocol=2,
                pin_uv_param=protocol.authenticate(token, digest),
            )
            credential.public_key.verify(
                bytes(result.auth_data) + digest, result.signature
            )
            check(
                True,
                "same FIDO credential independently verifies after all USB reboots",
            )
        with connection("OTP", serial) as conn:
            otp = YubiOtpSession(conn)
            check(
                str(otp.get_serial()) == serial,
                "native reboots preserve own OTP serial visibility",
            )
            challenge = b"own reboot challenge"
            check(
                otp.calculate_hmac_sha1(SLOT.TWO, challenge)
                == hmac.digest(b"own reboot fixture!!", challenge, "sha1"),
                "native reboots preserve programmed OTP HMAC key",
            )
        with connection("CCID", serial) as conn:
            check(
                str(ManagementSession(conn).read_device_info().serial) == serial,
                "stock libccid hotplug returns same own CCID identity",
            )
        log = (directory / "usb.log").read_text()
        check(
            log.count("functionfs_reenumerated generation=") == 8,
            "eight acknowledged automatic USB reenumerations include unchanged profile",
        )
        report.update(
            native_linux_usb_configuration_reenumeration_verified=True,
            native_linux_usb_all_interface_combinations_verified=True,
            native_linux_usb_reboot_volatile_state_verified=True,
            requested_endpoint_addresses_all_profiles_verified=True,
        )
    finally:
        for name in ["usb.log", "pcscd.log"]:
            if not (directory / name).exists():
                continue
            print(
                "SKE_USB_REBOOT_DIAGNOSTIC", name,
                (directory / name).read_text(),
                flush=True,
            )
        fixture.stop()


def main():
    report = {
        "passed": False,
        "tests": checks,
        "enumerations": enumerations,
        "physical_device_access": False,
        "host_usb_passthrough": False,
        "manufacturer_trust_reproduced": False,
        "native_macos_registration_verified": False,
        "firmware_reboot_timing_measured": False,
        "userspace_usb_transport": "FunctionFS",
        "pcsc_presence_wait_before_sdk_connect": True,
    }
    try:
        assert Path("/opt/isolated-ske-usb-guest").exists()
        with tempfile.TemporaryDirectory(
            prefix="usb-reboot-", dir="/guest-state"
        ) as path:
            run(Path(path), report)
        check(
            not list(Path("/dev").glob("hidraw*")),
            "native reboot fixture teardown removes every own HID device",
        )
        report["passed"] = True
    except Exception as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        report["test_count"] = len(checks)
        print("SKE_USB_REBOOT_BEGIN", flush=True)
        print(json.dumps(report), flush=True)
        print("SKE_USB_REBOOT_END", flush=True)


if __name__ == "__main__":
    main()
