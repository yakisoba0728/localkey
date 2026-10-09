"""Yubico SDK smartcard connection through serialized CCID bulk frames."""

import socket
import struct
import time
from pathlib import Path

from yubikit.core import TRANSPORT
from yubikit.core.otp import OtpConnection
from yubikit.core.smartcard import ApduError, SmartCardConnection

from .profile import (
    CCID_PAYLOAD_LENGTH,
    MAX_COMMAND_APDU_LENGTH,
    MAX_RESPONSE_APDU_LENGTH,
)
from .service import receive


class CcidSocketConnection(SmartCardConnection):
    def __init__(self, path: Path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(15)
        self.seq = 0
        self.closed = False
        try:
            self.sock.connect(str(path))
            self.command(0x62, b"")
        except BaseException:
            self.closed = True
            self.sock.close()
            raise

    @property
    def transport(self):
        return TRANSPORT.USB

    def command(self, kind, data):
        if kind != 0x6F:
            return self._exchange(kind, data)[0]
        if len(data) > MAX_COMMAND_APDU_LENGTH:
            raise ValueError("APDU exceeds ISO 7816 extended command limit")
        chunks = [
            data[i : i + CCID_PAYLOAD_LENGTH]
            for i in range(0, len(data), CCID_PAYLOAD_LENGTH)
        ] or [b""]
        result = bytearray()
        tail = 0
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
            response, tail = self._exchange(kind, chunk, level)
            if index < len(chunks) - 1:
                if response or tail != 0x10:
                    raise OSError("invalid CCID command continuation acknowledgement")
            else:
                if tail not in (0, 1):
                    raise OSError("invalid CCID response start")
                result.extend(response)
        while tail in (1, 3):
            response, tail = self._exchange(kind, b"", 0x10)
            if (
                tail not in (2, 3)
                or not response
                or len(result) + len(response) > MAX_RESPONSE_APDU_LENGTH
            ):
                raise OSError("invalid CCID response continuation")
            result.extend(response)
        return bytes(result)

    def _exchange(self, kind, data, level=0):
        self.seq = (self.seq + 1) % 256
        packet = (
            struct.pack("<BIBBBBB", kind, len(data), 0, self.seq, 0, level, 0) + data
        )
        self.sock.sendall(struct.pack(">I", len(packet)) + packet)
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
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            n = struct.unpack(">I", receive(self.sock, 4))[0]
            if not 10 <= n <= CCID_PAYLOAD_LENGTH + 10:
                raise OSError("invalid CCID response length")
            reply = receive(self.sock, n)
            response, length, slot, seq, status, error, chain = struct.unpack(
                "<BIBBBBB", reply[:10]
            )
            valid_tail = (
                chain in (0, 1, 2, 3, 0x10)
                if response == 0x80
                else chain <= 3
                if response == 0x81
                else chain in (0, 1)
                if response == 0x82
                else chain == 0
            )
            if (
                response != expected
                or seq != self.seq
                or slot
                or length != len(reply) - 10
                or not valid_tail
            ):
                raise OSError("invalid CCID response header")
            if status & 0xC0 == 0x80:
                if length or not error:
                    raise OSError("invalid CCID time-extension reply")
                continue
            if status & 0xC0:
                raise OSError(f"CCID failure: status={status:02x}, error={error:02x}")
            return reply[10:], chain
        raise TimeoutError("CCID operation exceeded transport deadline")

    def send_and_receive(self, apdu):
        out = self.command(0x6F, apdu)
        if len(out) < 2:
            raise OSError("missing APDU status")
        return out[:-2], int.from_bytes(out[-2:], "big")

    def close(self):
        if not self.closed:
            try:
                self.command(0x63, b"")
            finally:
                self.closed = True
                self.sock.close()


class OtpSocketConnection(OtpConnection):
    """Serialized OTP HID reports on the emulator's private socket."""

    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(15)
        self.sock.connect(str(path))

    def exchange(self, kind, report):
        if len(report) != 8:
            raise ValueError("incorrect OTP report length")
        self.sock.sendall(struct.pack(">I", 9) + bytes([kind]) + report)
        n = struct.unpack(">I", receive(self.sock, 4))[0]
        if n != 8:
            raise OSError("incorrect OTP report response length")
        return receive(self.sock, n)

    def send(self, report):
        self.exchange(1, report)

    def receive(self):
        return self.exchange(2, bytes(8))

    def close(self):
        self.sock.close()


class KeyboardSocketConnection:
    """Software button requests; touch reports also reach a live USB bridge."""

    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(30)
        self.sock.connect(str(path))

    def press(self, slot):
        if slot not in (1, 2):
            raise ValueError("invalid OTP slot")
        packet = bytes([3, slot]) + bytes(7)
        return self._button_exchange(packet)

    def hold(self, duration_ms):
        if type(duration_ms) is not int or not 0 <= duration_ms <= 60000:
            raise ValueError("invalid hold duration")
        return self._button_exchange(
            bytes([6]) + duration_ms.to_bytes(2, "big") + bytes(6)
        )

    def touch_down(self):
        """Begin a touch; a single slot 1 can return reports immediately."""
        return self._button_exchange(bytes([10]) + bytes(8))

    def touch_up(self, duration_ms):
        """Release a touch; duration selects a slot when output was deferred."""
        if type(duration_ms) is not int or not 0 <= duration_ms <= 60000:
            raise ValueError("invalid hold duration")
        return self._button_exchange(
            bytes([11]) + duration_ms.to_bytes(2, "big") + bytes(6)
        )

    def _button_exchange(self, packet):
        self.sock.sendall(struct.pack(">I", len(packet)) + packet)
        n = struct.unpack(">I", receive(self.sock, 4))[0]
        if not 4 <= n <= 4096:
            raise OSError("invalid keyboard event response")
        data = receive(self.sock, n)
        sw, count = struct.unpack(">HH", data[:4])
        if sw != 0x9000:
            raise ApduError(b"", sw)
        if len(data) != 4 + count * 10:
            raise OSError("invalid keyboard event count")
        return [
            {
                "report": data[i : i + 8].hex(),
                "delay_ms": struct.unpack(">H", data[i + 8 : i + 10])[0],
            }
            for i in range(4, len(data), 10)
        ]

    def close(self):
        self.sock.close()
