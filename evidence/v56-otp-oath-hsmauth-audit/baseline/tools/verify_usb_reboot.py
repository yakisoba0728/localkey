#!/usr/bin/env python3
"""SDK reboot, stale authorization and failed commit tests on own software state."""

from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives import hashes
from emucard.client import CcidSocketConnection
from emucard.core import EncryptedState
from emucard.service import Server, receive
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin, PinProtocolV2
from fido2.hid import CtapHidDevice
from fido2.hid.base import HidDescriptor
from verify_ctap import Fixture as FidoFixture
from verify_smartcard import Fixture as CardFixture
from verify_usb_bridge import HidConnection, Wire
from yubikit.core import TRANSPORT
from yubikit.core.smartcard import ApduError
from yubikit.management import CAPABILITY, DeviceConfig, ManagementSession
from yubikit.piv import DEFAULT_MANAGEMENT_KEY, KEY_TYPE, PIN_POLICY, SLOT, PivSession

checks = []


def check(value, name):
    if not value:
        raise AssertionError(name)
    checks.append({"name": name, "passed": True})
    print("PASS", name, flush=True)


def lifecycle(path):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(2)
        conn.connect(str(path))
        conn.sendall(struct.pack(">I", 9) + b"\x09" + bytes(8))
        result = receive(conn, struct.unpack(">I", receive(conn, 4))[0])
        assert len(result) == 11 and result[0] == 1
        return struct.unpack(">QH", result[1:])


def capabilities(path):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(2)
        conn.connect(str(path))
        conn.sendall(struct.pack(">I", 9) + b"\x05" + bytes(8))
        result = receive(conn, struct.unpack(">I", receive(conn, 4))[0])
        assert len(result) == 4 and result[:2] == b"\x90\0"
        return int.from_bytes(result[2:], "big")


def rejected(call, code, name):
    try:
        call()
    except ApduError as exc:
        check(exc.sw == code, name)
    else:
        raise AssertionError(name)


def fault_commit(directory):
    state = EncryptedState(directory / "fault.bin")
    path = directory / "fault.sock"
    with Server(path, state, lambda *_: True) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        connection = CcidSocketConnection(path)
        try:
            session = ManagementSession(connection)
            before = lifecycle(path)
            disk = state.path.read_bytes()
            original = state.flush
            during_failed_commit = []

            def fail_flush():
                during_failed_commit.append((
                    state.data["management"]["enabled"], capabilities(path)
                ))
                raise OSError("own fixture persistence failure")

            state.flush = fail_flush
            rejected(
                lambda: session.write_device_config(
                    DeviceConfig({TRANSPORT.USB: CAPABILITY.PIV}), reboot=True
                ),
                0x6581,
                "failed settings commit rejects the reboot request",
            )
            state.flush = original
            check(
                during_failed_commit == [(int(CAPABILITY.PIV), 0x33B)],
                "FIDO capability read returns committed mask during a failing settings transaction",
            )
            check(
                capabilities(path) == 0x33B,
                "failed settings transaction preserves committed FIDO capability snapshot",
            )
            check(
                lifecycle(path) == before,
                "failed commit publishes no reboot or USB mask",
            )
            check(
                state.path.read_bytes() == disk,
                "failed commit preserves encrypted file",
            )
            check(
                session.read_device_info().config.enabled_capabilities[TRANSPORT.USB]
                == CAPABILITY(0x33B),
                "failed commit restores public SDK configuration",
            )
            session.write_device_config(reboot=True)
            check(
                lifecycle(path)[0] == before[0] + 1,
                "recovered persistence permits reboot",
            )
            session.write_device_config(DeviceConfig({TRANSPORT.USB: CAPABILITY.PIV}))
            check(
                capabilities(path) == int(CAPABILITY.PIV),
                "successful settings commit publishes updated FIDO capability snapshot",
            )
        finally:
            connection.close()
            server.shutdown()
            thread.join(5)
    path.unlink()


def run(binary, fido_binary, directory):
    card_dir, fido_dir = directory / "card", directory / "fido"
    card_dir.mkdir()
    fido_dir.mkdir()
    root = Path(__file__).resolve().parents[1]
    card = CardFixture(root, card_dir)
    fido = FidoFixture(fido_binary, fido_dir)
    fido.card_socket = card_dir / "s.sock"
    wire = None
    try:
        connection = card.start()
        socket_path = card_dir / "s.sock"
        fido.start()
        fido.device.close()
        fido.device = None
        with (directory / "usb.log").open("w") as log:
            wire = Wire(binary, socket_path, fido.socket_path, log, True)
            wire.control(0, 9, 1)

            def open_fido():
                descriptor = HidDescriptor(
                    "own-software-wire",
                    0x1050,
                    0x407,
                    64,
                    64,
                    "own software",
                    str(serial),
                )
                return Ctap2(CtapHidDevice(descriptor, HidConnection(wire)))

            session = ManagementSession(connection)
            serial = session.read_device_info().serial
            ctap = open_fido()
            digest = bytes(range(32))
            att = ctap.make_credential(
                digest,
                {"id": "localhost"},
                {"id": b"own-reboot-user"},
                [{"type": "public-key", "alg": -7}],
            )
            credential = att.auth_data.credential_data
            protocol = PinProtocolV2()
            ClientPin(ctap, protocol).set_pin("123456")
            token = ClientPin(ctap, protocol).get_pin_token(
                "123456", ClientPin.PERMISSION.GET_ASSERTION, "localhost"
            )
            agreement = ctap.client_pin(2, 2)[1]
            initial = lifecycle(socket_path)
            session.write_device_config(DeviceConfig({TRANSPORT.USB: CAPABILITY.PIV}))
            wire.request("reenumerate")
            check(
                lifecycle(socket_path)[0] == initial[0],
                "write without reboot preserves lifecycle generation",
            )
            check(
                wire.control(0x80, 6, 0x0100, length=18)["data"][20:24] == "0704",
                "write without reboot preserves active USB PID",
            )
            check(
                wire.control(0x80, 8, length=1)["data"] == "01",
                "write without reboot preserves USB configuration",
            )
            session.write_device_config(
                DeviceConfig({TRANSPORT.USB: CAPABILITY(0x33B)})
            )
            session.write_device_config(new_lock_code=b"L" * 16)
            locked = lifecycle(socket_path)
            rejected(
                lambda: session.write_device_config(reboot=True),
                0x6982,
                "locked configuration rejects missing unlock and reboot",
            )
            rejected(
                lambda: session.write_device_config(
                    reboot=True, cur_lock_code=b"X" * 16
                ),
                0x6982,
                "wrong unlock code rejects reboot",
            )
            check(
                lifecycle(socket_path) == locked,
                "rejected lock requests publish no lifecycle change",
            )
            malformed = b"\x0b\x10" + b"L" * 16 + b"\x0c\0\x03\x01\x10"
            _, sw = connection.send_and_receive(
                b"\0\x1c\0\0" + bytes([len(malformed) + 1, len(malformed)]) + malformed
            )
            check(
                sw == 0x6A80 and lifecycle(socket_path) == locked,
                "malformed authenticated reboot configuration is rejected atomically",
            )
            session.write_device_config(
                cur_lock_code=b"L" * 16, new_lock_code=bytes(16)
            )
            second = CcidSocketConnection(socket_path)
            piv = PivSession(second)
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
            piv.generate_key(SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, PIN_POLICY.ONCE)
            piv.verify_pin("123456")
            piv.sign(SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, digest, hashes.SHA256())
            session.write_device_config(
                DeviceConfig({TRANSPORT.USB: CAPABILITY.PIV}), reboot=True
            )
            check(
                lifecycle(socket_path)[0] == initial[0] + 1,
                "successful SDK reboot is visible to USB backend",
            )
            wire.request("reenumerate")
            check(
                wire.control(0x80, 6, 0x0100, length=18)["data"][20:24] == "0404",
                "reboot adopts stored CCID-only USB PID",
            )
            check(
                wire.control(0x80, 8, length=1)["data"] == "00",
                "reboot clears USB configuration",
            )
            check(
                wire.request("out 04 " + bytes(64).hex())["stalled"],
                "removed FIDO interface rejects old endpoint",
            )
            rejected(
                lambda: piv.sign(
                    SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, digest, hashes.SHA256()
                ),
                0x6982,
                "reboot clears peer PIV authorization",
            )
            check(
                piv.get_pin_attempts() != 0,
                "persistent PIV PIN retry state remains available",
            )
            second.close()
            session.write_device_config(
                DeviceConfig({TRANSPORT.USB: CAPABILITY(0x33B)}), reboot=True
            )
            wire.request("reenumerate")
            wire.control(0, 9, 1)
            ctap = open_fido()
            check(
                ctap.get_info().options["clientPin"],
                "reboot preserves configured FIDO PIN",
            )
            check(
                ctap.client_pin(2, 2)[1] != agreement,
                "reboot replaces volatile FIDO key agreement",
            )
            try:
                ctap.get_assertion(
                    "localhost",
                    digest,
                    [{"type": "public-key", "id": credential.credential_id}],
                    pin_uv_protocol=2,
                    pin_uv_param=protocol.authenticate(token, digest),
                )
            except CtapError as exc:
                check(int(exc.code) == 0x33, "pre-reboot FIDO token is rejected")
            else:
                raise AssertionError("old FIDO token accepted")
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
                "same credential independently verifies after reboot with fresh token",
            )
            check(
                session.read_device_info().serial == serial,
                "reboots preserve own device serial",
            )
            wire.close()
            wire = None
    finally:
        if wire:
            wire.close()
        fido.stop()
        card.stop()
    fault_commit(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--fido-binary", required=True, type=Path)
    parser.add_argument("--work-dir", type=Path, default=Path(tempfile.gettempdir()))
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    report = {
        "passed": False,
        "tests": checks,
        "physical_key_accessed": False,
        "native_usb_reenumeration_verified": False,
    }
    try:
        with tempfile.TemporaryDirectory(
            prefix="ske-reboot-", dir=args.work_dir
        ) as directory:
            run(args.binary.resolve(), args.fido_binary.resolve(), Path(directory))
        report["passed"] = True
    except Exception as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        args.report.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
