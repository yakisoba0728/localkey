#!/usr/bin/env python3
"""Test compiled USB control/endpoint routing without registering an OS device."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.attestation import PackedAttestation
from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice
from fido2.hid.base import CtapHidConnection, HidDescriptor
from verify_ctap import Fixture as FidoFixture
from verify_smartcard import Fixture as CardFixture
from yubikit.core import PID, TRANSPORT, USB_INTERFACE, YUBIKEY
from yubikit.core.otp import OtpConnection
from yubikit.core.smartcard import ApduError, SmartCardConnection
from yubikit.management import CAPABILITY, DeviceConfig, ManagementSession
from yubikit.oath import CredentialData, OathSession
from yubikit.piv import DEFAULT_MANAGEMENT_KEY, KEY_TYPE, SLOT, PivSession
from yubikit.yubiotp import SLOT as OTP_SLOT
from yubikit.yubiotp import (
    HmacSha1SlotConfiguration,
    StaticPasswordSlotConfiguration,
    YubiOtpSession,
)


class Wire:
    def __init__(self, binary, card_socket, fido_socket, log, compatibility_ids=False):
        self.process = subprocess.Popen(
            [
                str(binary),
                "--card-socket",
                str(card_socket),
                "--fido-socket",
                str(fido_socket),
                "--wire-test",
            ]
            + (["--yubico-usb-ids"] if compatibility_ids else []),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=log,
            text=True,
            bufsize=1,
        )

    def request(self, line):
        self.process.stdin.write(line + "\n")
        self.process.stdin.flush()
        data = self.process.stdout.readline()
        if not data:
            raise OSError(f"USB wire-test disconnected: {self.process.poll()}")
        result = json.loads(data)
        if "error" in result:
            raise OSError(result["error"])
        return result

    def control(self, kind, request, value=0, index=0, length=0, data=b""):
        setup = struct.pack("<BBHHH", kind, request, value, index, length)
        return self.request(f"control {setup.hex()} {data.hex()}")

    def receive(self, endpoint, capacity):
        until = time.monotonic() + 8
        while time.monotonic() < until:
            result = self.request(f"in {endpoint:02x} {capacity}")
            if result["stalled"]:
                raise OSError("USB endpoint stalled")
            if not result["pending"]:
                return bytes.fromhex(result["data"])
            time.sleep(0.005)
        raise TimeoutError("USB endpoint has no data")

    def output(self, endpoint, data):
        if self.request(f"out {endpoint:02x} {data.hex()}")["stalled"]:
            raise OSError("USB output stalled")

    def close(self):
        self.process.stdin.close()
        try:
            self.process.wait(5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(5)
        self.process.stdout.close()


class HidConnection(CtapHidConnection):
    def __init__(self, wire):
        self.wire = wire

    def read_packet(self):
        return self.wire.receive(0x84, 64)

    def write_packet(self, data):
        self.wire.output(0x04, data)

    def close(self):
        pass


class CardConnection(SmartCardConnection):
    def __init__(self, wire):
        self.wire, self.seq = wire, 0
        self.time_extensions = 0
        self.atr = self.command(0x62)

    @property
    def transport(self):
        return TRANSPORT.USB

    def command(self, kind, data=b""):
        if kind != 0x6F:
            return self.part(kind, data)[0]
        chunks = [data[i : i + 3062] for i in range(0, len(data), 3062)] or [b""]
        output = bytearray()
        for index, chunk in enumerate(chunks):
            level = (
                0
                if len(chunks) == 1
                else 1
                if index == 0
                else 2
                if index == len(chunks) - 1
                else 3
            )
            response, tail = self.part(kind, chunk, level)
            if index < len(chunks) - 1:
                if tail != 0x10 or response:
                    raise OSError("missing CCID command acknowledgement")
            else:
                if tail not in (0, 1):
                    raise OSError("invalid first CCID response part")
                output.extend(response)
        while tail in (1, 3):
            response, tail = self.part(kind, b"", 0x10)
            if (
                tail not in (2, 3)
                or not response
                or len(output) + len(response) > 65538
            ):
                raise OSError("invalid CCID response continuation")
            output.extend(response)
        return bytes(output)

    def part(self, kind, data=b"", level=0):
        self.seq = (self.seq + 1) & 255
        packet = (
            struct.pack("<BIBBBBB", kind, len(data), 0, self.seq, 0, level, 0) + data
        )
        for offset in range(0, len(packet), 64):
            self.wire.output(2, packet[offset : offset + 64])
        while True:
            response = self.wire.receive(0x82, 3072)
            reply, length, slot, seq, status, error, chain = struct.unpack(
                "<BIBBBBB", response[:10]
            )
            expected = {
                0x62: 0x80,
                0x6F: 0x80,
                0x69: 0x80,
                0x61: 0x82,
                0x6C: 0x82,
                0x6D: 0x82,
                0x6B: 0x83,
                0x73: 0x84,
            }.get(kind, 0x81)
            if (
                reply != expected
                or length != len(response) - 10
                or slot
                or seq != self.seq
            ):
                raise OSError("incorrect USB CCID response header")
            if status & 0xC0 == 0x80:
                if length or not error:
                    raise OSError("invalid waiting-time extension")
                self.time_extensions += 1
                continue
            if status & 0xC0:
                raise OSError(f"USB CCID reply failed {error}")
            if chain not in (
                (0, 1, 2, 3, 0x10)
                if reply == 0x80
                else (0, 1, 2, 3)
                if reply == 0x81
                else (0, 1)
                if reply == 0x82
                else (0,)
            ):
                raise OSError("invalid USB CCID tail")
            return response[10:], chain

    def send_and_receive(self, apdu):
        data = self.command(0x6F, apdu)
        if len(data) < 2:
            raise OSError("missing APDU status")
        return data[:-2], int.from_bytes(data[-2:], "big")

    def close(self):
        pass


class OtpHidConnection(OtpConnection):
    def __init__(self, wire, index):
        self.wire, self.index = wire, index

    def send(self, report):
        if self.wire.control(0x21, 9, 0x0300, self.index, 8, report)["stalled"]:
            raise OSError("OTP SET_REPORT stalled")

    def receive(self):
        result = self.wire.control(0xA1, 1, 0x0300, self.index, 8)
        if result["stalled"]:
            raise OSError("OTP GET_REPORT stalled")
        return bytes.fromhex(result["data"])

    def close(self):
        pass


def descriptors(data):
    offset, result = 0, []
    while offset < len(data):
        size = data[offset]
        if size < 2 or offset + size > len(data):
            raise ValueError("invalid USB descriptor length")
        result.append(data[offset : offset + size])
        offset += size
    return result


def run(root, directory, binary, fido_binary, report):
    card_dir, fido_dir = directory / "c", directory / "f"
    card_dir.mkdir()
    fido_dir.mkdir()
    card, fido = (
        CardFixture(root, card_dir),
        FidoFixture(fido_binary, fido_dir, card_dir / "s.sock"),
    )
    wire = None
    tests = []
    completed = False
    resume_observation = None

    def check(value, name):
        if not value:
            raise AssertionError(name)
        tests.append({"name": name, "passed": True})
        print("PASS", name, flush=True)

    try:
        original_card = card.start()
        serial = ManagementSession(original_card).read_device_info().serial
        fido.start()
        fido.device.close()
        fido.device = None
        with (directory / "usb.log").open("w") as log:
            wire = Wire(binary, card_dir / "s.sock", fido_dir / "h.sock", log)
            raw = bytes.fromhex(wire.control(0x80, 6, 0x0100, length=18)["data"])
            check(
                len(raw) == 18 and raw[7] == 64 and raw[17] == 1,
                "USB device descriptor, control packet size and configuration count",
            )
            check(
                struct.unpack("<HH", raw[8:12]) == (0x1209, 0xF1D0),
                "USB descriptor keeps independent software VID/PID",
            )
            check(
                len(bytes.fromhex(wire.control(0x80, 6, 0x0100, length=8)["data"]))
                == 8,
                "USB enumeration descriptor is truncated to requested length",
            )
            data = bytes.fromhex(wire.control(0x80, 6, 0x0200, length=255)["data"])
            rows = descriptors(data)
            check(
                len(data) == int.from_bytes(data[2:4], "little"),
                "USB configuration total length and every descriptor boundary",
            )
            interfaces = [row for row in rows if row[1] == 4]
            check(
                [row[5] for row in interfaces] == [3, 3, 11]
                and [row[2] for row in interfaces] == [0, 1, 2],
                "one configuration exposes keyboard OTP, FIDO HID and CCID interfaces",
            )
            endpoints = [row for row in rows if row[1] == 5]
            check(
                {row[2] for row in endpoints} == {0x81, 0x02, 0x82, 0x04, 0x83, 0x84},
                "USB endpoint addresses are unique across all interfaces",
            )
            ccid = next(row for row in rows if row[0] == 54)
            check(
                int.from_bytes(ccid[6:10], "little") == 2
                and int.from_bytes(ccid[40:44], "little") & 0x40000
                and int.from_bytes(ccid[44:48], "little") == 3072,
                "CCID descriptor advertises T=1, extended APDU exchange and bounded messages",
            )
            for index in (0, 1):
                report_bytes = bytes.fromhex(
                    wire.control(0x81, 6, 0x2200, index, 255)["data"]
                )
                hid = bytes.fromhex(wire.control(0x81, 6, 0x2100, index, 9)["data"])
                check(
                    len(report_bytes) == int.from_bytes(hid[7:9], "little"),
                    f"HID report descriptor length matches interface {index}",
                )
            text = bytes.fromhex(wire.control(0x80, 6, 0x0303, 0x0409, 255)["data"])[
                2:
            ].decode("utf-16le")
            check(
                text == str(serial),
                "USB string serial matches independent SDK device identity",
            )
            check(
                wire.control(0x80, 6, 0x0600, length=10)["stalled"],
                "unsupported device qualifier is stalled for full-speed device",
            )
            check(
                wire.control(0x80, 6, 0x0304, 0x0409, 255)["stalled"],
                "unknown USB string index is stalled",
            )
            check(
                wire.request("out 04 " + bytes(64).hex())["stalled"],
                "USB data endpoints reject traffic before SET_CONFIGURATION",
            )
            check(
                not wire.control(0, 5, 7)["stalled"],
                "USB SET_ADDRESS accepts valid address before configuration",
            )
            check(
                wire.control(0, 9, 2)["stalled"], "unknown USB configuration is stalled"
            )
            check(
                not wire.control(0, 9, 1)["stalled"]
                and wire.control(0x80, 8, length=1)["data"] == "01",
                "SET_CONFIGURATION enables interfaces and GET_CONFIGURATION reflects it",
            )
            check(
                wire.receive(0x83, 2) == b"\x50\x03",
                "CCID interrupt endpoint notifies present card at configuration",
            )
            check(
                wire.control(0x81, 10, index=1, length=1)["data"] == "00"
                and wire.control(1, 11, 1, 1)["stalled"],
                "only alternate interface zero is accepted",
            )
            check(
                wire.control(0xA1, 2, index=2, length=4)["data"] == "a00f0000"
                and wire.control(0xA1, 3, index=2, length=4)["data"] == "00b00400",
                "CCID class control clock and baud values match descriptor",
            )
            check(
                wire.control(0xA1, 3, index=0, length=1)["data"] == "01"
                and not wire.control(0x21, 11, index=0)["stalled"]
                and wire.control(0xA1, 3, index=0, length=1)["data"] == "00",
                "keyboard HID GET_PROTOCOL and SET_PROTOCOL",
            )
            check(
                wire.control(0x21, 11, 2, 0)["stalled"],
                "keyboard rejects invalid protocol",
            )
            check(
                not wire.control(0x21, 10, 5 << 8, 0)["stalled"]
                and wire.control(0xA1, 2, index=0, length=1)["data"] == "05",
                "keyboard HID idle duration round trip",
            )
            check(
                wire.receive(0x81, 8) == bytes(8),
                "keyboard idle timeout repeats current input report",
            )
            wire.control(0x21, 10, 0, 0)
            check(
                not wire.control(0x21, 9, 0x0200, 0, 1, b"\x13")["stalled"]
                and wire.control(0xA1, 1, 0x0200, 0, 1)["data"] == "13",
                "keyboard LED output report readback",
            )
            check(
                wire.control(0xA1, 1, 0x0301, 0, 8)["stalled"],
                "HID report IDs absent from descriptor are rejected",
            )
            wire.control(2, 3, 0, 0x84)
            check(
                wire.request("in 84 64")["stalled"],
                "halted USB IN endpoint responds with STALL rather than pending",
            )
            check(
                wire.control(0x82, 0, index=0x84, length=2)["data"] == "0100",
                "USB endpoint halt status is isolated to requested endpoint",
            )
            wire.control(2, 1, 0, 0x84)
            check(
                wire.control(0x82, 0, index=0x84, length=2)["data"] == "0000",
                "CLEAR_FEATURE releases endpoint halt",
            )
            check(
                wire.control(2, 3, 0, 0x89)["stalled"],
                "unknown endpoint cannot be halted",
            )
            check(
                wire.request("out 04 aa")["stalled"],
                "FIDO endpoint rejects reports of incorrect size",
            )
            device = CtapHidDevice(
                HidDescriptor(
                    "usb-wire", 0x1209, 0xF1D0, 64, 64, "software composite", text
                ),
                HidConnection(wire),
            )
            ctap = Ctap2(device)
            check(
                ctap.info.max_msg_size == 1536,
                "independent FIDO SDK GetInfo over compiled USB endpoints",
            )
            challenge = hashlib.sha256(b"USB composite fresh registration").digest()
            att = ctap.make_credential(
                challenge,
                {"id": "localhost"},
                {"id": b"usb-fixture"},
                [{"type": "public-key", "alg": -7}],
            )
            PackedAttestation().verify(att.att_stmt, att.auth_data, challenge)
            credential = att.auth_data.credential_data
            assertion = ctap.get_assertion(
                "localhost",
                challenge,
                [{"type": "public-key", "id": credential.credential_id}],
            )
            credential.public_key.verify(
                assertion.auth_data + challenge, assertion.signature
            )
            check(
                True,
                "FIDO registration and assertion signatures independently verified through USB routing",
            )
            usb_card = CardConnection(wire)
            check(
                usb_card.atr == bytes.fromhex("3bf011000001e0"),
                "CCID bulk power-up returns valid T=1 ATR",
            )
            check(
                ManagementSession(usb_card).read_device_info().serial == serial,
                "independent smartcard SDK uses same composite serial",
            )
            piv = PivSession(usb_card)
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
            public_key = piv.generate_key(SLOT.AUTHENTICATION, KEY_TYPE.ECCP256)
            piv.verify_pin("123456")
            signature = piv.sign(
                SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, challenge, hashes.SHA256()
            )
            public_key.verify(signature, challenge, ec.ECDSA(hashes.SHA256()))
            check(
                True,
                "PIV SDK generates key and verifies signature through segmented CCID USB transfers",
            )
            def raw_card(kind, payload=b""):
                usb_card.seq = (usb_card.seq + 1) & 255
                sequence = usb_card.seq
                wire.output(0x02, struct.pack("<BIBBBBB", kind, len(payload), 0, sequence, 0, 0, 0) + payload)
                packet = wire.receive(0x82, 3072)
                header = struct.unpack("<BIBBBBB", packet[:10])
                if header[1] != len(packet) - 10 or header[2] or header[3] != sequence:
                    raise AssertionError("resume test CCID header mismatch")
                return header, packet[10:]

            saved = (card_dir / "state.bin").read_bytes()
            usb_card.seq = (usb_card.seq + 1) & 255
            original_seq = usb_card.seq
            wire.output(0x02, struct.pack("<BIBBBBB", 0x65, 0, 0, original_seq, 0, 0, 0))
            # OUT queues an asynchronous request; its acknowledgement does
            # not prove the card reply committed. Read an actual prefix before
            # suspend, retaining the other nine original response bytes.
            original_prefix = wire.receive(0x82, 1)
            assert original_prefix == b"\x81", "original actual committed slot response prefix"
            wire.request("suspend")
            wire.request("resume")
            actual_tail = wire.receive(0x82, 3072)
            packet = original_prefix + actual_tail
            resume_observation = {"original_sequence":original_seq, "actual_prefix_hex":original_prefix.hex(),
                                  "actual_retained_tail_hex":actual_tail.hex(), "actual_whole_original_response_hex":packet.hex(),
                                  "commit_observed_before_suspend":True, "unread_whole_response_verified_by_this_wire_case":False}
            check(struct.unpack("<BIBBBBB", packet) == (0x81, 0, 0, original_seq, 0, 0, 0),
                  "compiled resume retains exact original committed slot response tail after prefix1")
            check(wire.receive(0x83, 2) == b"\x50\x03",
                  "compiled resume reports occupied slot insertion")
            inactive, data = raw_card(0x65)
            check(inactive[0] == 0x81 and inactive[4:] == (1, 0, 3) and not data,
                  "compiled resume leaves occupied inactive slot and stopped clock")
            denied, data = raw_card(0x6f, bytes.fromhex("00a4040007a0000005272101"))
            check(denied[0] == 0x80 and denied[4:] == (0x41, 0xfe, 0) and not data,
                  "compiled resumed card rejects APDU before explicit PowerOn")
            check((card_dir / "state.bin").read_bytes() == saved,
                  "compiled suspend resume and unpowered denial retain exact durable bytes")
            wire.request("resume")
            check(wire.request("in 83 2")["pending"],
                  "duplicate resume without new suspend emits no extra insertion")
            check(usb_card.command(0x62) == bytes.fromhex("3bf011000001e0"),
                  "compiled explicit resumed PowerOn returns original ATR")
            active, data = raw_card(0x65)
            check(active[4:] == (0, 0, 0) and not data,
                  "compiled resumed slot activates only after PowerOn")
            wire.request("resume")
            active, data = raw_card(0x65)
            check(active[4:] == (0, 0, 0) and wire.request("in 83 2")["pending"],
                  "unsolicited duplicate resume preserves newly activated card")
            try:
                piv.sign(SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, challenge, hashes.SHA256())
            except ApduError as error:
                check(error.sw == 0x6982, "compiled resume revokes previous PIV PIN verification")
            else:
                raise AssertionError("PIV PIN survived card resume")
            try:
                piv.generate_key(SLOT.SIGNATURE, KEY_TYPE.ECCP256)
            except ApduError as error:
                check(error.sw == 0x6982, "compiled resume revokes previous PIV management authentication")
            else:
                raise AssertionError("PIV administration survived card resume")
            piv.verify_pin("123456")
            signature = piv.sign(SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, challenge, hashes.SHA256())
            public_key.verify(signature, challenge, ec.ECDSA(hashes.SHA256()))
            check(True, "fresh PIV PIN enables original persisted key and independently verified signature after resume")
            assertion = ctap.get_assertion("localhost", challenge, [{"type":"public-key", "id":credential.credential_id}])
            credential.public_key.verify(assertion.auth_data + challenge, assertion.signature)
            check(True, "original FIDO credential independently signs after compiled card resume")
            oath = OathSession(usb_card)
            oath.put_credential(
                CredentialData.parse_uri(
                    "otpauth://totp/USB:fixture?secret=JBSWY3DPEHPK3PXP"
                )
            )
            check(
                len(oath.calculate_code(oath.list_credentials()[0], 1234567890).value)
                == 6,
                "OATH SDK provisioning and TOTP calculation over USB CCID",
            )
            otp_connection = OtpHidConnection(wire, 0)
            otp = YubiOtpSession(otp_connection)
            key = b"usb HMAC fixture key"
            otp.put_configuration(
                OTP_SLOT.ONE, HmacSha1SlotConfiguration(key).require_touch(False)
            )
            check(
                otp.calculate_hmac_sha1(OTP_SLOT.ONE, challenge)
                == hmac.new(key, challenge, "sha1").digest(),
                "OTP SDK writes and challenges slot through USB GET_REPORT and SET_REPORT",
            )
            check(otp.get_serial() == serial, "OTP HID and CCID share composite serial")
            otp.put_configuration(
                OTP_SLOT.ONE, StaticPasswordSlotConfiguration(b"\x04\x05")
            )
            wire.request("hold 500")
            reports = [wire.receive(0x81, 8) for _ in range(6)]
            check(
                reports[0] == b"\0\0\x04" + bytes(5)
                and reports[2] == b"\0\0\x05" + bytes(5)
                and reports[-1] == bytes(8),
                "button produces modifier/press/release keyboard USB reports in order",
            )
            check(
                wire.control(0xA1, 1, 0x0100, 0, 8)["data"] == bytes(8).hex(),
                "GET_REPORT returns most recently transmitted keyboard report",
            )
            wire.request("out 02 6f05000000000100000001")
            wire.request("reset")
            check(
                wire.control(0x80, 8, length=1)["data"] == "00"
                and wire.request("out 04 " + bytes(64).hex())["stalled"],
                "bus reset clears USB configuration and pending transfers",
            )
            wire.control(0, 9, 1)
            check(
                wire.receive(0x83, 2) == b"\x50\x03" and usb_card.command(0x62),
                "reconfiguration after reset restores CCID interface",
            )
            malformed = b"\x6f" + (3063).to_bytes(4, "little") + bytes(5)
            check(
                wire.request("out 02 " + malformed.hex())["stalled"],
                "CCID assembly rejects length beyond descriptor maximum",
            )
            check(
                usb_card.command(0x65) == b"",
                "CCID assembly recovers cleanly after oversized header rejection",
            )
            wire.close()
            wire = None
            # Public application settings determine which descriptors exist on reconnect.
            management = ManagementSession(original_card)
            for mask, expected in (
                (CAPABILITY.PIV, [11]),
                (CAPABILITY.FIDO2, [3]),
                (CAPABILITY.OTP, [3]),
            ):
                management.write_device_config(DeviceConfig({TRANSPORT.USB: mask}))
                wire = Wire(binary, card_dir / "s.sock", fido_dir / "h.sock", log)
                data = bytes.fromhex(wire.control(0x80, 6, 0x0200, length=255)["data"])
                check(
                    [row[5] for row in descriptors(data) if row[1] == 4] == expected
                    and data[4] == 1,
                    f"enabled USB application mask 0x{int(mask):x} creates only its interface",
                )
                wire.close()
                wire = None
            management.write_device_config(
                DeviceConfig({TRANSPORT.USB: CAPABILITY(0x33B)})
            )
            from ykman.pcsc import _pid_from_name

            for bits in range(1, 8):
                mask = CAPABILITY(0)
                if bits & 1:
                    mask |= CAPABILITY.OTP
                if bits & 2:
                    mask |= CAPABILITY.FIDO2
                if bits & 4:
                    mask |= CAPABILITY.PIV
                management.write_device_config(DeviceConfig({TRANSPORT.USB: mask}))
                wire = Wire(binary, card_dir / "s.sock", fido_dir / "h.sock", log, True)
                raw = bytes.fromhex(wire.control(0x80, 6, 0x0100, length=18)["data"])
                expected_pid = PID.of(YUBIKEY.YK4, USB_INTERFACE(bits))
                product = bytes.fromhex(
                    wire.control(0x80, 6, 0x0302, 0x0409, 255)["data"]
                )[2:].decode("utf-16le")
                check(
                    struct.unpack("<HH", raw[8:12]) == (0x1050, int(expected_pid))
                    and _pid_from_name(product) == expected_pid
                    and "software" in product.lower(),
                    f"optional USB matching IDs and software reader label pass SDK predicates for interface bits {bits}",
                )
                if bits == 7:
                    wire.control(0, 9, 1)
                    descriptor = HidDescriptor(
                        "compat-usb-wire",
                        0x1050,
                        int(expected_pid),
                        64,
                        64,
                        product,
                        str(serial),
                    )
                    compatible = Ctap2(CtapHidDevice(descriptor, HidConnection(wire)))
                    check(
                        str(compatible.info.aaguid)
                        == "6fb1dfdd-51c0-43a0-a6f2-f74812cbf8fb"
                        and compatible.info.firmware_version == 3,
                        "USB matching mode retains independent software AAGUID and firmware revision",
                    )
                wire.close()
                wire = None
            management.write_device_config(
                DeviceConfig({TRANSPORT.USB: CAPABILITY(0x33B)})
            )
            completed = True
    finally:
        if wire:
            wire.close()
        fido.stop()
        card.stop()
        report.write_text(
            json.dumps(
                {
                    "passed": completed,
                    "resume_commit_observation": resume_observation,
                    "tests": tests,
                    "physical_key_accessed": False,
                    "os_usb_controller_registered": False,
                    "os_keyboard_reports_injected": False,
                    "native_controller_source_compiled": True,
                    "transport": "compiled USB model and native executable --wire-test",
                },
                indent=2,
            )
            + "\n"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--fido-binary", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, default=Path("/tmp"))
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ske-usb-", dir=args.work_dir) as directory:
        run(
            Path(__file__).resolve().parents[1],
            Path(directory),
            args.binary.resolve(),
            args.fido_binary.resolve(),
            args.report,
        )


if __name__ == "__main__":
    main()
