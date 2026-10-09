#!/usr/bin/env python3
"""Exercise the compiled platform reader ABI using fresh private socket fixtures."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import plistlib
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from emucard.ifd import BYTE, DWORD, IfdNativeConnection, Pci, load_driver
from verify_smartcard import Fixture
from yubikit.core import InvalidPinError
from yubikit.core.smartcard import AID
from yubikit.management import ManagementSession
from yubikit.piv import PivSession


def run(root, directory, binary, report):
    tests = []
    fixture = Fixture(root, directory)
    driver = load_driver(binary)
    lun = 15 << 16
    opened = False
    completed = False

    def check(value, name):
        if not value:
            raise AssertionError(name)
        tests.append({"name": name, "passed": True})
        print("PASS", name, flush=True)

    def power(action, capacity=33):
        data = (BYTE * 40)(*([0xA5] * 40))
        size = DWORD(capacity)
        code = driver.IFDHPowerICC(lun, action, data, ctypes.byref(size))
        return code, size.value, bytes(data)

    def transmit(apdu, capacity=32786, protocol=1):
        tx = (BYTE * len(apdu)).from_buffer_copy(apdu)
        rx = (BYTE * 32790)(*([0xA5] * 32790))
        size, pci = DWORD(capacity), Pci(9, 9)
        code = driver.IFDHTransmitToICC(
            lun,
            Pci(protocol, ctypes.sizeof(Pci)),
            tx,
            len(tx),
            rx,
            ctypes.byref(size),
            ctypes.byref(pci),
        )
        return code, size.value, bytes(rx), pci

    try:
        conn = fixture.start()
        serial = ManagementSession(conn).read_device_info().serial
        check(
            driver.IFDHICCPresence(lun) == 617,
            "unopened native reader reports no such device",
        )
        check(
            driver.IFDHCreateChannelByName(1, os.fsencode(directory / "s.sock")) == 617,
            "single-slot driver rejects a nonzero slot index",
        )
        check(
            driver.IFDHCreateChannelByName(16 << 16, os.fsencode(directory / "s.sock"))
            == 617,
            "driver enforces reader-index capacity",
        )
        check(
            driver.IFDHCreateChannelByName(lun, os.fsencode(directory / "missing.sock"))
            == 617,
            "driver rejects missing CCID service",
        )
        (directory / "s.sock").chmod(0o666)
        check(
            driver.IFDHCreateChannelByName(lun, os.fsencode(directory / "s.sock"))
            == 617,
            "driver rejects a socket accessible to other users",
        )
        (directory / "s.sock").chmod(0o600)
        require = driver.IFDHCreateChannelByName(lun, os.fsencode(directory / "s.sock"))
        opened = require == 0
        check(opened, "native reader opens private CCID transport")
        check(
            driver.IFDHCreateChannelByName(lun, os.fsencode(directory / "s.sock"))
            == 612,
            "duplicate reader open preserves existing channel",
        )
        check(
            driver.IFDHICCPresence(lun) == 615,
            "unpowered but present virtual card is detected",
        )
        apdu = b"\0\xa4\x04\0" + bytes([len(AID.PIV)]) + bytes(AID.PIV)
        check(
            transmit(apdu)[0:2] == (616, 0),
            "unpowered card rejects transmit with zero response length",
        )
        code, size, data = power(500)
        check(
            code == 0
            and data[:size] == bytes.fromhex("3bf011000001e0")
            and data[size:] == b"\xa5" * (40 - size),
            "IFD power-up supplies valid T=1 ATR without overwriting buffer tail",
        )
        check(
            driver.IFDHSetProtocolParameters(lun, 2, 0, 0, 0, 0) == 0,
            "IFD negotiates the ATR's T=1 protocol",
        )
        check(
            driver.IFDHSetProtocolParameters(lun, 1, 0, 0, 0, 0) == 607
            and driver.IFDHSetProtocolParameters(lun, 2, 1, 0, 0, 0) == 605,
            "IFD rejects unsupported protocol and PTS negotiation",
        )
        code, size, data, pci = transmit(apdu)
        check(
            code == 0
            and data[:size][-2:] == b"\x90\0"
            and pci.Protocol == 1
            and pci.Length == ctypes.sizeof(Pci),
            "native IFD transmit carries ISO SELECT response and receive PCI",
        )
        code, size, data, _ = transmit(b"\0\xfd\0\0\0", capacity=1)
        check(
            code == 618 and size == 0 and data == b"\xa5" * len(data),
            "short receive buffer returns bounded error without copying partial response",
        )
        code, size, _, pci = transmit(apdu, protocol=0)
        check(
            code == 607 and size == 0 and pci.Protocol == 0,
            "wrong transmit PCI does not execute card command",
        )
        caps = (BYTE * 100)()
        length = DWORD(100)
        code = driver.IFDHGetCapabilities(lun, 0x0103, ctypes.byref(length), caps)
        check(
            code == 0
            and bytes(caps[: length.value]).rstrip(b"\0") == str(serial).encode(),
            "native driver serial matches shared management identity",
        )
        results = []
        for tag in (0x0FAC, 0x0FAD, 0x0FAE):
            length = DWORD(100)
            code = driver.IFDHGetCapabilities(lun, tag, ctypes.byref(length), caps)
            results.append(code == 0 and length.value == 1 and caps[0] == 1)
        check(
            all(results),
            "native driver advertises one slot and serialized thread-safe operations",
        )
        length = DWORD(100)
        code = driver.IFDHGetCapabilities(lun, 0xFFFF, ctypes.byref(length), caps)
        check(
            code == 600
            and length.value == 0
            and driver.IFDHSetCapabilities(lun, 0x303, 0, None) == 602,
            "unknown capability and read-only attribute errors follow IFD ABI",
        )
        length = DWORD(0)
        code = driver.IFDHGetCapabilities(lun, 0x303, ctypes.byref(length), caps)
        check(
            code == 618 and length.value == 0, "ATR capability respects caller capacity"
        )
        returned = DWORD(123)
        check(
            driver.IFDHControl(
                lun, 0x42000000 + 3400, None, 0, None, 0, ctypes.byref(returned)
            )
            == 0
            and returned.value == 0,
            "PC/SC feature request advertises no hardware PIN pad",
        )
        returned = DWORD(123)
        check(
            driver.IFDHControl(lun, 42, None, 0, None, 0, ctypes.byref(returned)) == 606
            and returned.value == 0,
            "unsupported control request yields empty error response",
        )
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: driver.IFDHICCPresence(lun), range(80)))
        check(
            results == [615] * 80,
            "parallel status calls preserve CCID sequence integrity",
        )
        check(power(9)[:2] == (608, 0), "invalid power action returns empty ABI error")
        check(
            power(501)[:2] == (0, 0) and driver.IFDHICCPresence(lun) == 615,
            "power-down clears ATR while card remains present",
        )
        check(
            driver.IFDHCloseChannel(lun) == 0 and driver.IFDHCloseChannel(lun) == 617,
            "native close releases channel and rejects double close",
        )
        opened = False
        native = IfdNativeConnection(binary, directory / "s.sock")
        try:
            piv = PivSession(native)
            piv.verify_pin("123456")
            check(
                driver.IFDHICCPresence(native.lun) == 615
                and piv.get_pin_attempts() == 3,
                "independent PIV SDK operates through compiled IFD driver",
            )
            native.power(502)
            # Read a protected object after reset: the proof must have been cleared.
            piv = PivSession(native)
            piv.verify_pin("123456")
            piv.protocol.send_apdu(0, 0x24, 0, 0x80, b"123456\xff\xff654321\xff\xff")
            native.power(502)
            try:
                piv.verify_pin("123456")
            except InvalidPinError as e:
                check(
                    e.attempts_remaining == 2,
                    "IFD warm reset preserves durable PIN changes",
                )
            else:
                raise AssertionError("PIN change lost at warm reset")
            piv.verify_pin("654321")
            check(True, "new PIN remains usable through native driver after reset")
        finally:
            native.close()
        plist = plistlib.loads(binary.parent.parent.joinpath("Info.plist").read_bytes())
        check(
            plist["CFBundleIdentifier"] == "local.ske.ifd"
            and plist["CFBundleExecutable"] == binary.name,
            "native reader bundle has loader identity and executable metadata",
        )
        check(
            not any(k in plist for k in ("ifdVendorID", "ifdProductID")),
            "reader bundle does not claim or bind to the physical YubiKey USB interfaces",
        )
        # The old channel must fail safely once the backend disappears.
        check(
            driver.IFDHCreateChannelByName(lun, os.fsencode(directory / "s.sock")) == 0,
            "driver channel can reopen after clean release",
        )
        opened = True
        fixture.stop()
        check(
            driver.IFDHICCPresence(lun) == 617,
            "backend disconnect reports reader removal without SIGPIPE",
        )
        completed = True
    finally:
        if opened:
            driver.IFDHCloseChannel(lun)
        fixture.stop()
        report.write_text(
            json.dumps(
                {
                    "passed": completed,
                    "tests": tests,
                    "physical_key_accessed": False,
                    "native_ifd_abi_verified": completed,
                    "system_pcsc_reader_registered": False,
                    "system_driver_installation_performed": False,
                },
                indent=2,
            )
            + "\n"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, default=Path("/tmp"))
    args = parser.parse_args()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ske-ifd-", dir=args.work_dir) as directory:
        run(
            Path(__file__).resolve().parents[1],
            Path(directory),
            args.driver.resolve(),
            args.report,
        )


if __name__ == "__main__":
    main()
