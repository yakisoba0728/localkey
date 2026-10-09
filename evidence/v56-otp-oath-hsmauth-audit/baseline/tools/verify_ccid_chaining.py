#!/usr/bin/env python3
"""Verify measured USB profile, CCID APDU chaining, WTX and disconnect recovery.

Only fresh local software fixtures are opened. Reference metadata is read from
the saved public descriptor observation; this test never accesses physical USB.
"""

from __future__ import annotations

import argparse
import copy
import json
import struct
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from emucard.client import CcidSocketConnection
from emucard.core import Apdu, Card, CcidDevice, EmulatorConnection, EncryptedState
from emucard.service import Server
from verify_ccid import TouchGate, calculate, frame, unpack
from verify_ctap import Fixture as FidoFixture
from verify_smartcard import Fixture as CardFixture
from verify_usb_bridge import CardConnection, Wire
from yubikit.core import TRANSPORT, Tlv
from yubikit.management import CAPABILITY, DeviceConfig, ManagementSession
from yubikit.oath import CredentialData, OathSession
from yubikit.piv import DEFAULT_MANAGEMENT_KEY, PivSession

OID = 0x5FFF05


class TransportFixture:
    """Deterministic large APDUs for CCID framing, not a PIV implementation."""

    def __init__(self):
        self.calls = []
        self.response = bytes(range(256)) * 56

    def reset_session(self):
        pass

    def transmit(self, packet):
        self.calls.append(packet)
        Apdu.decode(packet)
        return self.response, 0x9000


class ApprovalGate(TouchGate):
    def __init__(self):
        super().__init__()
        self.approved = threading.Event()

    def __call__(self, label, cancelled):
        if not self.armed:
            return True
        self.entered.set()
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            if cancelled.wait(0.01):
                return False
            if self.approved.is_set():
                return True
        raise TimeoutError("test did not approve or cancel presence")


def extended(ins, data=b"", le=None):
    result = bytes([0, ins, 0x3F, 0xFF, 0])
    if data:
        result += len(data).to_bytes(2, "big") + data
        if le is not None:
            result += (le % 65536).to_bytes(2, "big")
    else:
        result += ((le or 65536) % 65536).to_bytes(2, "big")
    return result


def get_object():
    return extended(0xCB, Tlv(0x5C, OID.to_bytes(3, "big")), 65536)


def put_object(data):
    return extended(0xDB, Tlv(0x5C, OID.to_bytes(3, "big")) + Tlv(0x53, data))


def core_exchange(device, data, sizes=None):
    chunks = (
        [data[i : i + 3062] for i in range(0, len(data), 3062)]
        if sizes is None
        else sizes
    )
    out = None
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
        out = unpack(device.exchange(frame(0x6F, chunk, p2=level, seq=index & 255)))
        if index < len(chunks) - 1:
            assert out[0][4:7] == (0, 0, 0x10) and not out[1]
    return out


def run(root, directory, binary, fido_binary, driver, report):
    tests = []
    completed = False

    def check(value, name):
        if not value:
            raise AssertionError(name)
        tests.append({"name": name, "passed": True})
        print("PASS", name, flush=True)

    try:
        state = EncryptedState(directory / "core.bin")
        card = Card(state, lambda _: True)
        device = CcidDevice(card)
        device.exchange(frame(0x62))
        piv = PivSession(EmulatorConnection(card))
        piv.authenticate(DEFAULT_MANAGEMENT_KEY)
        value = bytes(range(256)) * 11 + bytes(range(247))
        packet = put_object(value)
        old_file = state.path.read_bytes()
        header, data = unpack(device.exchange(frame(0x6F, packet[:100], p2=1, seq=255)))
        check(
            header[3:7] == (255, 0, 0, 0x10) and not data,
            "CCID first command fragment acknowledges without APDU status",
        )
        check(
            str(OID) not in state.data["piv"]["objects"]
            and state.path.read_bytes() == old_file,
            "first fragment does not dispatch or persist incomplete PIV command",
        )
        middle = packet[100:1100]
        header, data = unpack(device.exchange(frame(0x6F, middle, p2=3, seq=0)))
        check(
            header[3:7] == (0, 0, 0, 0x10) and not data,
            "CCID middle command fragment preserves sequence wrap",
        )
        remaining = packet[1100:]
        while len(remaining) > 3062:
            header, data = unpack(device.exchange(frame(0x6F, remaining[:3062], p2=3)))
            assert header[6] == 0x10 and not data
            remaining = remaining[3062:]
        header, data = unpack(device.exchange(frame(0x6F, remaining, p2=2)))
        check(
            header[4:7] == (0, 0, 0) and data == b"\x90\0",
            "CCID final command fragment dispatches one complete extended APDU",
        )
        check(
            EncryptedState(state.path).data["piv"]["objects"][str(OID)] == value.hex(),
            "multi-frame PIV write commits its complete object",
        )
        header, data = core_exchange(device, get_object())
        check(
            header[1] == 3062 and header[6] == 1,
            "large response begins with one bounded CCID part",
        )
        result = bytearray(data)
        continuations = []
        while header[6] in (1, 3):
            header, data = unpack(device.exchange(frame(0x6F, p2=0x10)))
            continuations.append(header[6])
            assert len(data) <= 3062
            result.extend(data)
        check(
            continuations[-1] == 2 and all(t == 3 for t in continuations[:-1]),
            "PIV response ends with the final chain indicator",
        )
        check(
            result == Tlv(0x53, value) + b"\x90\0",
            "reassembled response preserves object bytes and final ISO status",
        )
        header, _ = unpack(device.exchange(frame(0x6F, p2=0x10)))
        check(header[5] == 8, "response continuation after completion is rejected")
        for level in (2, 3):
            header, _ = unpack(device.exchange(frame(0x6F, b"orphan", p2=level)))
            check(
                header[5] == 8, f"orphan command continuation level {level} is rejected"
            )
        for level in (4, 0x11, 0xFF):
            header, _ = unpack(device.exchange(frame(0x6F, b"invalid", p2=level)))
            check(header[5] == 8, f"reserved level parameter {level} is rejected")
        device.exchange(frame(0x6F, packet[:10], p2=1))
        header, _ = unpack(device.exchange(frame(0x6F, packet[:10], p2=1)))
        check(
            header[5] == 8 and not device.command_parts,
            "duplicate first fragment drops incomplete command without dispatch",
        )
        device.exchange(frame(0x6F, packet[:10], p2=1))
        header, _ = unpack(device.exchange(frame(0x6F, get_object())))
        check(
            header[5] == 8 and not device.command_parts,
            "whole APDU cannot silently replace a pending command fragment",
        )
        core_exchange(device, get_object())
        header, _ = unpack(device.exchange(frame(0x6F, b"not empty", p2=0x10)))
        check(
            header[5] == 1 and not device.response_parts,
            "response continuation requires an empty command body",
        )
        core_exchange(device, get_object())
        header, _ = unpack(device.exchange(frame(0x6F, get_object())))
        check(
            header[5] == 8 and not device.response_parts,
            "new command cannot silently consume pending response continuation",
        )
        device.exchange(frame(0x6F, b"x" * 3062, p2=1))
        for _ in range(20):
            header, _ = unpack(device.exchange(frame(0x6F, b"x" * 3062, p2=3)))
            assert header[6] == 0x10
        header, _ = unpack(device.exchange(frame(0x6F, b"x" * 3062, p2=3)))
        check(
            header[5] == 1 and not device.command_parts,
            "command accumulation rejects total size above 65544 bytes",
        )
        header, _ = unpack(device.exchange(frame(0x6F, b"x" * 3063)))
        check(
            header[5] == 1,
            "one CCID frame cannot exceed measured descriptor payload length",
        )
        maximum = extended(0xF0, b"x" * 65535, 65536)
        check(
            len(maximum) == 65544 and len(Apdu.decode(maximum).data) == 65535,
            "ISO decoder accepts the full extended APDU envelope",
        )
        header, data = core_exchange(device, maximum)
        check(
            header[4] == 0 and data == b"\x67\0",
            "maximum ISO command is carried by CCID but exceeds PIV application buffer",
        )
        before = copy.deepcopy(state.data)
        header, data = core_exchange(device, put_object(bytes(range(256)) * 56))
        check(
            data == b"\x67\0" and state.data == before,
            "14 KiB PIV write is rejected atomically at the application boundary",
        )
        transport_card = TransportFixture()
        transport_device = CcidDevice(transport_card)
        transport_device.exchange(frame(0x62))
        header, data = core_exchange(transport_device, maximum)
        check(
            transport_card.calls == [maximum] and header[6] == 1,
            "CCID transport fixture dispatches maximum ISO APDU exactly once",
        )
        reassembled = bytearray(data)
        levels = []
        while header[6] in (1, 3):
            header, data = unpack(transport_device.exchange(frame(0x6F, p2=0x10)))
            levels.append(header[6])
            assert len(data) <= 3062
            reassembled.extend(data)
        check(
            len(levels) > 1 and levels[-1] == 2 and set(levels[:-1]) == {3},
            "14 KiB transport fixture exercises actual middle and final response parts",
        )
        check(
            reassembled == transport_card.response + b"\x90\0",
            "large transport-only response preserves bytes and one final status",
        )
        device.exchange(frame(0x6F, packet[:10], p2=1))
        device.abort(0, 90)
        device.exchange(frame(0x72, seq=90))
        header, _ = unpack(device.exchange(frame(0x6F, packet[10:100], p2=2)))
        check(header[5] == 8, "completed ABORT discards incomplete command fragments")
        core_exchange(device, get_object())
        device.abort(0, 91)
        device.exchange(frame(0x72, seq=91))
        header, _ = unpack(device.exchange(frame(0x6F, p2=0x10)))
        check(header[5] == 8, "completed ABORT discards unread response fragments")
        core_exchange(device, get_object())
        device.exchange(frame(0x63))
        device.exchange(frame(0x62))
        header, _ = unpack(device.exchange(frame(0x6F, p2=0x10)))
        check(header[5] == 8, "power cycle discards outstanding CCID response chain")

        for transport in ("socket", "ifd"):
            target = directory / transport
            target.mkdir()
            fixture = CardFixture(root, target, driver if transport == "ifd" else None)
            try:
                connection = fixture.start()
                piv = PivSession(connection)
                piv.authenticate(DEFAULT_MANAGEMENT_KEY)
                data, sw = connection.send_and_receive(put_object(value))
                check(
                    sw == 0x9000 and not data,
                    f"{transport} client fragments bounded 3 KiB PIV extended write",
                )
                data, sw = connection.send_and_receive(get_object())
                check(
                    sw == 0x9000 and data == Tlv(0x53, value),
                    f"{transport} client collects all CCID response parts",
                )
                check(
                    piv.get_object(OID) == value,
                    f"independent SDK reads chained object over {transport}",
                )
                check(
                    connection.send_and_receive(maximum)[1] == 0x6700,
                    f"{transport} carries maximum ISO command to PIV buffer rejection",
                )
                check(
                    connection.send_and_receive(put_object(b"x" * 14336))[1] == 0x6700
                    and piv.get_object(OID) == value,
                    f"{transport} rejects oversized PIV replacement without data loss",
                )
            finally:
                fixture.stop()

        live_dir, fido_dir = directory / "live", directory / "fido"
        live_dir.mkdir()
        fido_dir.mkdir()
        live_state = EncryptedState(live_dir / "state.bin")
        gate = ApprovalGate()
        path = live_dir / "s.sock"
        fido = FidoFixture(fido_binary, fido_dir, path)
        wire = None
        with (
            Server(path, live_state, gate) as server,
            (directory / "usb.log").open("w") as log,
        ):
            thread = threading.Thread(
                target=server.serve_forever, kwargs={"poll_interval": 0.05}
            )
            thread.start()
            original = None
            try:
                original = CcidSocketConnection(path)
                management = ManagementSession(original)
                management.write_device_config(
                    DeviceConfig(
                        {
                            TRANSPORT.USB: CAPABILITY.FIDO2
                            | CAPABILITY.PIV
                            | CAPABILITY.OATH
                        }
                    )
                )
                fido.start()
                fido.device.close()
                fido.device = None
                wire = Wire(binary, path, fido.socket_path, log, True)
                reference = json.loads(
                    (root / "usb-reference-observation.json").read_text()
                )
                descriptor = bytes.fromhex(
                    wire.control(0x80, 6, 0x0200, length=255)["data"]
                )
                check(
                    descriptor
                    == bytes.fromhex(reference["configuration_descriptor_hex"]),
                    "FIDO+CCID USB configuration matches reference bytes exactly",
                )
                report_descriptor = wire.control(0x81, 6, 0x2200, index=0, length=255)[
                    "data"
                ]
                check(
                    report_descriptor == reference["hid_report_descriptor_hex"],
                    "FIDO HID report descriptor matches cached physical reference",
                )
                descriptor = bytes.fromhex(
                    wire.control(0x80, 6, 0x0100, length=18)["data"]
                )
                fields = reference["device_fields"]
                check(
                    int.from_bytes(descriptor[2:4], "little") == fields["bcdUSB"]
                    and int.from_bytes(descriptor[12:14], "little")
                    == fields["bcdDevice"]
                    and descriptor[4:8]
                    == bytes(
                        [
                            fields["bDeviceClass"],
                            fields["bDeviceSubClass"],
                            fields["bDeviceProtocol"],
                            fields["bMaxPacketSize0"],
                        ]
                    ),
                    "public USB release/class/control-size fields match reference metadata",
                )
                check(
                    struct.unpack("<HH", descriptor[8:12])
                    == (fields["idVendor"], fields["idProduct"]),
                    "optional USB matching IDs follow measured 1050:0406 profile",
                )
                product = bytes.fromhex(
                    wire.control(0x80, 6, 0x0302, 0x0409, 255)["data"]
                )[2:].decode("utf-16le")
                check(
                    "software" in product.lower(),
                    "matching public descriptors preserve explicit independent software identity",
                )
                wire.control(0, 9, 1)
                connection = CardConnection(wire)
                piv = PivSession(connection)
                piv.authenticate(DEFAULT_MANAGEMENT_KEY)
                check(
                    connection.send_and_receive(put_object(value))[1] == 0x9000,
                    "native USB routes a bounded multi-frame 3 KiB PIV write",
                )
                data, sw = connection.send_and_receive(get_object())
                check(
                    sw == 0x9000 and data == Tlv(0x53, value),
                    "native USB collects multi-frame PIV response with final status",
                )
                check(
                    piv.get_object(OID) == value,
                    "independent PIV SDK reads complete object over measured USB profile",
                )
                check(
                    connection.send_and_receive(put_object(b"x" * 14336))[1] == 0x6700
                    and piv.get_object(OID) == value,
                    "native USB rejects oversized PIV object and preserves stored data",
                )
                oath = OathSession(connection)
                credential = oath.put_credential(
                    CredentialData.parse_uri(
                        "otpauth://hotp/CCID:WTX?secret=JBSWY3DPEHPK3PXP&counter=0"
                    ),
                    touch_required=True,
                )
                previous = live_state.path.read_bytes()
                gate.armed = True
                wire.output(2, frame(0x6F, calculate(credential.id), seq=97))
                check(
                    gate.entered.wait(1),
                    "time-extension test reaches pending actual service touch",
                )
                time.sleep(0.55)
                header, data = unpack(wire.receive(0x82, 3072))
                check(
                    header[3:7] == (97, 0x80, 1, 0) and not data,
                    "native CCID sends bounded WTX multiplier with original sequence",
                )
                time.sleep(0.55)
                header, data = unpack(wire.receive(0x82, 3072))
                check(
                    header[3:7] == (97, 0x80, 1, 0) and not data,
                    "WTX repeats while operation remains pending",
                )
                wire.control(0x21, 1, 98 << 8, index=1)
                wire.output(2, frame(0x72, seq=98))
                responses = [unpack(wire.receive(0x82, 3072))[0] for _ in range(2)]
                check(
                    {h[3]: h[4] for h in responses} == {97: 0x40, 98: 0},
                    "ABORT completes after WTX without another successful APDU",
                )
                check(
                    live_state.path.read_bytes() == previous,
                    "waiting-time extensions and cancellation leave HOTP ciphertext unchanged",
                )
                gate.armed = False
                oath = OathSession(connection)
                gate.entered.clear()
                gate.approved.clear()
                gate.armed = True
                with ThreadPoolExecutor(max_workers=1) as executor:
                    pending = executor.submit(
                        oath.calculate_code, oath.list_credentials()[0]
                    )
                    check(
                        gate.entered.wait(1),
                        "independent SDK request enters delayed approval with WTX",
                    )
                    time.sleep(0.65)
                    check(
                        not pending.done() and connection.time_extensions >= 1,
                        "independent CCID client consumes WTX and keeps its SDK request pending",
                    )
                    gate.approved.set()
                    check(
                        len(pending.result(2).value) == 6,
                        "independent OATH SDK completes after time extension and approval",
                    )
                check(
                    EncryptedState(live_state.path).data["oath"]["credentials"][
                        credential.id.hex()
                    ]["counter"]
                    == 1,
                    "WTX followed by approval commits exactly one HOTP counter",
                )
                wire.close()
                wire = None
                gate.armed = False
                pending_connection = CcidSocketConnection(path)
                pending_oath = OathSession(pending_connection)
                pending_credential = pending_oath.list_credentials()[0]
                gate.entered.clear()
                gate.approved.clear()
                gate.armed = True
                previous = copy.deepcopy(live_state.data)
                old_file = live_state.path.read_bytes()

                def wait_for_disconnect():
                    try:
                        pending_oath.calculate_code(pending_credential)
                    except (OSError, EOFError):
                        return True
                    return False

                with ThreadPoolExecutor(max_workers=1) as executor:
                    pending = executor.submit(wait_for_disconnect)
                    check(
                        gate.entered.wait(1),
                        "disconnect test enters card presence wait",
                    )
                    pending_connection.sock.sendall(
                        struct.pack(">I", 10) + frame(0x65, seq=112)
                    )
                    pending_connection.sock.shutdown(2)
                    check(pending.result(2), "disconnect ends pending client request")
                    pending_connection.sock.close()
                    pending_connection.closed = True
                    gate.armed = False
                    started = time.monotonic()
                    recovered = CcidSocketConnection(path)
                    check(
                        time.monotonic() - started < 1,
                        "peer EOF releases shared state lock and allows a new reader",
                    )
                    check(
                        live_state.data == previous
                        and live_state.path.read_bytes() == old_file,
                        "disconnected operation rolls back without durable mutation",
                    )
                    check(
                        OathSession(recovered).list_credentials()[0].id
                        == credential.id,
                        "independent SDK resumes after disconnected presence request",
                    )
                    recovered.close()
            finally:
                if wire:
                    wire.close()
                if original:
                    original.close()
                fido.stop()
                server.shutdown()
                thread.join(2)
        path.unlink()
        completed = True
    finally:
        report.write_text(
            json.dumps(
                {
                    "passed": completed,
                    "tests": tests,
                    "scope": "fresh software fixtures; saved public USB metadata; no physical USB or OS registration",
                },
                indent=2,
            )
            + "\n"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--fido-binary", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(
        prefix="ske-chain-", dir=args.work_dir or "/tmp"
    ) as directory:
        run(
            Path(__file__).resolve().parents[1],
            Path(directory),
            args.binary.resolve(),
            args.fido_binary.resolve(),
            args.driver.resolve(),
            args.report.resolve(),
        )


if __name__ == "__main__":
    main()
