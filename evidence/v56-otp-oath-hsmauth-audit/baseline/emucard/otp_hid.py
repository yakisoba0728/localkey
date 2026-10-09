"""Eight-byte OTP HID feature-report protocol, independent of the OS transport."""

import os
import struct

from yubikit.core.smartcard import AID

from .core import crc16


class OtpHidDevice:
    def __init__(self, card):
        self.card = card
        self.frame = bytearray(70)
        self.sequence = -1
        self.responses = []

    def status(self):
        return b"\0" + self.card.otp_status() + b"\0"

    def receive(self):
        return self.responses.pop(0) if self.responses else self.status()

    def send(self, report):
        if len(report) != 8:
            raise ValueError("OTP report must contain eight bytes")
        if os.environ.get("SKE_TRACE_OTP_FRAMES"):
            print(
                "otp_report",
                "flags",
                hex(report[-1]),
                "data_crc",
                crc16(report[:7]),
                flush=True,
            )
        if report[-1] in (0xFF, 0x8F):
            self.responses.clear()
            self.frame = bytearray(70)
            self.sequence = -1
            return
        if report[-1] & 0xE0 != 0x80:
            raise ValueError("invalid OTP write flags")
        sequence = report[-1] & 0x1F
        if sequence == 0:
            self.frame = bytearray(70)
            self.sequence = -1
            self.responses.clear()
        elif self.sequence < 0:
            # An aborted or completed frame must start again at sequence 0.
            return
        if not self.sequence < sequence <= 9:
            raise ValueError("invalid OTP sequence")
        self.frame[sequence * 7 : sequence * 7 + 7] = report[:7]
        self.sequence = sequence
        if sequence != 9:
            return
        payload = bytes(self.frame[:64])
        slot = self.frame[64]
        received_crc = int.from_bytes(self.frame[65:67], "little")
        self.frame = bytearray(70)
        self.sequence = -1
        valid_crc = crc16(payload) == received_crc
        if os.environ.get("SKE_TRACE_OTP_FRAMES"):
            print(
                "otp_frame_complete", "command", slot, "crc_ok", valid_crc, flush=True
            )
        if not valid_crc:
            return
        lengths = {
            1: 58,
            3: 58,
            4: 58,
            5: 58,
            6: 6,
            8: 62,
            9: 62,
            0x10: 0,
            0x12: 51,
            0x13: 1,
            0x20: 6,
            0x28: 6,
            0x30: 64,
            0x38: 64,
        }
        if slot == 0x15:
            if payload[0] > 63:
                return
            lengths[slot] = payload[0] + 1
        if slot not in lengths:
            return
        aid = bytes(AID.OTP)
        if self.card.selected != AID.OTP:
            _, sw = self.card.transmit(b"\0\xa4\x04\0" + bytes([len(aid)]) + aid)
            if sw != 0x9000:
                return
        data = payload[: lengths[slot]]
        request = bytes([0, 1, slot, 0]) + (
            bytes([len(data)]) + data if data else b"\0"
        )
        result, sw = self.card.transmit(request)
        if os.environ.get("SKE_TRACE_OTP_FRAMES"):
            print(
                "otp_command_complete", "command", slot, "status", hex(sw), flush=True
            )
        if sw != 0x9000:
            return
        if slot not in (0x10, 0x13, 0x20, 0x28, 0x30, 0x38):
            return
        result += struct.pack("<H", (~crc16(result)) & 0xFFFF)
        for i, start in enumerate(range(0, len(result), 7)):
            self.responses.append(
                result[start : start + 7].ljust(7, b"\0") + bytes([0x40 | i])
            )
        self.responses.append(bytes(7) + b"\x40")
