"""Call the platform IFD Handler ABI; no system readers are enumerated.

This adapter lets independent smartcard SDKs test the compiled reader driver.
It does not register a reader in the operating system's PC/SC resource manager.
"""

from __future__ import annotations

import ctypes
import sys
import threading
from pathlib import Path

from yubikit.core import TRANSPORT
from yubikit.core.smartcard import SmartCardConnection

from .profile import MAX_COMMAND_APDU_LENGTH, MAX_RESPONSE_APDU_LENGTH

DWORD = ctypes.c_uint32 if sys.platform == "darwin" else ctypes.c_ulong
RESPONSECODE = ctypes.c_int32 if sys.platform == "darwin" else ctypes.c_long
BYTE = ctypes.c_uint8
BYTES = ctypes.POINTER(BYTE)
LENGTH = ctypes.POINTER(DWORD)


class Pci(ctypes.Structure):
    _fields_ = [("Protocol", DWORD), ("Length", DWORD)]


class IfdError(OSError):
    def __init__(self, code, operation):
        self.code = code
        super().__init__(f"IFD {operation} failed with code {code}")


class Driver:
    def __init__(self, path):
        if sys.platform not in ("darwin", "linux"):
            raise OSError("this adapter declares the macOS or Linux PC/SC IFD ABI")
        self.library = ctypes.CDLL(str(Path(path).resolve()))
        signatures = {
            "IFDHCreateChannelByName": [DWORD, ctypes.c_char_p],
            "IFDHCreateChannel": [DWORD, DWORD],
            "IFDHCloseChannel": [DWORD],
            "IFDHGetCapabilities": [DWORD, DWORD, LENGTH, BYTES],
            "IFDHSetCapabilities": [DWORD, DWORD, DWORD, BYTES],
            "IFDHSetProtocolParameters": [DWORD, DWORD, BYTE, BYTE, BYTE, BYTE],
            "IFDHPowerICC": [DWORD, DWORD, BYTES, LENGTH],
            "IFDHTransmitToICC": [
                DWORD,
                Pci,
                BYTES,
                DWORD,
                BYTES,
                LENGTH,
                ctypes.POINTER(Pci),
            ],
            "IFDHControl": [DWORD, DWORD, BYTES, DWORD, BYTES, DWORD, LENGTH],
            "IFDHICCPresence": [DWORD],
        }
        for name, args in signatures.items():
            method = getattr(self.library, name)
            method.argtypes = args
            method.restype = RESPONSECODE
            setattr(self, name, method)
        self.lock = threading.Lock()
        self.slots = set()

    def reserve(self):
        with self.lock:
            slot = next((n for n in range(16) if n not in self.slots), None)
            if slot is None:
                raise IfdError(612, "allocate reader")
            self.slots.add(slot)
            return slot << 16

    def release(self, lun):
        with self.lock:
            self.slots.discard(lun >> 16)


_drivers = {}
_drivers_lock = threading.Lock()


def load_driver(path):
    path = str(Path(path).resolve())
    with _drivers_lock:
        if path not in _drivers:
            _drivers[path] = Driver(path)
        return _drivers[path]


def require_success(code, operation):
    if code:
        raise IfdError(code, operation)


class IfdNativeConnection(SmartCardConnection):
    def __init__(self, driver_path, socket_path):
        self.driver = load_driver(driver_path)
        self.lun = self.driver.reserve()
        self.closed = True
        try:
            require_success(
                self.driver.IFDHCreateChannelByName(
                    self.lun, bytes(str(Path(socket_path).resolve()), "utf-8")
                ),
                "open",
            )
            self.closed = False
            self.atr = self.power(500)
            require_success(
                self.driver.IFDHSetProtocolParameters(self.lun, 2, 0, 0, 0, 0),
                "T=1 negotiation",
            )
        except Exception:
            if not self.closed:
                self.driver.IFDHCloseChannel(self.lun)
                self.closed = True
            self.driver.release(self.lun)
            raise

    @property
    def transport(self):
        return TRANSPORT.USB

    def power(self, action):
        data = (BYTE * 33)()
        length = DWORD(33)
        require_success(
            self.driver.IFDHPowerICC(self.lun, action, data, ctypes.byref(length)),
            "power",
        )
        return bytes(data[: length.value])

    def send_and_receive(self, apdu):
        if self.closed:
            raise IfdError(617, "transmit on closed reader")
        if not 1 <= len(apdu) <= MAX_COMMAND_APDU_LENGTH:
            raise ValueError("APDU exceeds the CCID transport bound")
        tx = (BYTE * len(apdu)).from_buffer_copy(apdu)
        rx = (BYTE * MAX_RESPONSE_APDU_LENGTH)()
        length = DWORD(len(rx))
        pci = Pci()
        require_success(
            self.driver.IFDHTransmitToICC(
                self.lun,
                Pci(1, ctypes.sizeof(Pci)),
                tx,
                len(tx),
                rx,
                ctypes.byref(length),
                ctypes.byref(pci),
            ),
            "transmit",
        )
        if length.value < 2 or length.value > len(rx) or pci.Protocol != 1:
            raise OSError("invalid IFD APDU response")
        data = bytes(rx[: length.value])
        return data[:-2], int.from_bytes(data[-2:], "big")

    def close(self):
        if not self.closed:
            try:
                self.power(501)
            finally:
                self.driver.IFDHCloseChannel(self.lun)
                self.driver.release(self.lun)
                self.closed = True
