#!/usr/bin/env python3
"""CCID 1.1 framing, parameter atomicity and live cancellation on fresh state.

The native bridge runs only in wire-test mode. No OS USB device or physical card
is opened. Controlled synchronization exercises both sides of the commit race.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import select as select_io
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from emucard.client import CcidSocketConnection
from emucard.core import ATR, Card, CcidDevice, EncryptedState
from emucard.service import Server, receive
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2
from fido2.hid.base import HidDescriptor
from verify_ctap import Fixture as FidoFixture
from verify_usb_bridge import CardConnection, HidConnection, Wire
from yubikit.core import Tlv
from yubikit.core.smartcard import AID
from yubikit.oath import CredentialData, OathSession


def frame(kind, data=b"", slot=0, seq=0, p1=0, p2=0, p3=0, length=None):
    return (
        struct.pack(
            "<BIBBBBB",
            kind,
            len(data) if length is None else length,
            slot,
            seq,
            p1,
            p2,
            p3,
        )
        + data
    )


def unpack(packet):
    header = struct.unpack("<BIBBBBB", packet[:10])
    if header[1] != len(packet) - 10:
        raise AssertionError("CCID response length mismatch")
    return header, packet[10:]


def apdu(ins, data=b"", p1=0, p2=0):
    return bytes([0, ins, p1, p2]) + (bytes([len(data)]) + data if data else b"")


def select(aid):
    return apdu(0xA4, bytes(aid), p1=4)


def calculate(name):
    return apdu(0xA2, Tlv(0x71, name) + Tlv(0x74, bytes(8)), p2=1)


def rpc(sock, data):
    sock.sendall(struct.pack(">I", len(data)) + data)
    size = struct.unpack(">I", receive(sock, 4))[0]
    return receive(sock, size)


def wait_prompt(process):
    deadline = time.monotonic() + 2
    output = bytearray()
    while time.monotonic() < deadline:
        if select_io.select([process.stdout], [], [], 0.05)[0]:
            output.extend(os.read(process.stdout.fileno(), 256))
            if b"approve user presence" in output:
                return True
    return False


def provision(card, name=b"cancel"):
    assert card.transmit(select(AID.OATH))[1] == 0x9000
    data = Tlv(0x71, name) + Tlv(0x73, b"\x11\x06fixture secret") + b"\x78\x02"
    assert card.transmit(apdu(1, data))[1] == 0x9000
    return card.state.data["oath"]["credentials"][name.hex()]


class TouchGate:
    def __init__(self):
        self.armed = False
        self.entered = threading.Event()

    def __call__(self, label, cancelled):
        if not self.armed:
            return True
        self.entered.set()
        if not cancelled.wait(4):
            raise TimeoutError("test did not cancel pending presence request")
        return False


def run(root, directory, binary, fido_binary, report):
    tests = []
    completed = False

    def check(value, name):
        if not value:
            raise AssertionError(name)
        tests.append({"name": name, "passed": True})
        print("PASS", name, flush=True)

    def expect(device, kind, *, error=None, expected_data=None, tail=None, **kwargs):
        seq = kwargs.get("seq", 0)
        header, payload = unpack(device.exchange(frame(kind, **kwargs)))
        expected_type = {
            0x62: 0x80,
            0x6F: 0x80,
            0x69: 0x80,
            0x61: 0x82,
            0x6C: 0x82,
            0x6D: 0x82,
            0x6B: 0x83,
            0x73: 0x84,
        }.get(kind, 0x81)
        return (
            header[0] == expected_type
            and header[3] == seq
            and (header[4] & 0xC0) == (0x40 if error is not None else 0)
            and header[5] == (error or 0)
            and (expected_data is None or payload == expected_data)
            and (tail is None or header[6] == tail)
        )

    try:
        state = EncryptedState(directory / "core.bin")
        card = Card(state, lambda _: True)
        device = CcidDevice(card)
        check(
            expect(device, 0x65, tail=3), "inactive slot reports unknown stopped clock"
        )
        check(expect(device, 0x6F, error=0xFE), "unpowered transfer returns ICC_MUTE")
        check(
            expect(device, 0x62, expected_data=ATR, seq=255),
            "power-up ATR and full byte sequence echo",
        )
        defaults = bytes.fromhex("1110004d002000")
        check(
            expect(device, 0x6C, expected_data=defaults, tail=1),
            "T=1 default parameters match independent software ATR",
        )
        parameters = bytes.fromhex("1110ff9f02fe00")
        check(
            expect(device, 0x61, p1=1, data=parameters, expected_data=parameters),
            "T=1 parameter change accepts valid bounds",
        )
        check(
            expect(device, 0x6C, expected_data=parameters, tail=1),
            "GET_PARAMETERS preserves negotiated state",
        )
        for index, value, offset in (
            (0, 0, 10),
            (1, 0, 11),
            (3, 0xA0, 13),
            (4, 4, 14),
            (5, 255, 15),
            (6, 1, 16),
        ):
            invalid = bytearray(parameters)
            invalid[index] = value
            header, payload = unpack(
                device.exchange(frame(0x61, invalid, p1=1, seq=offset))
            )
            check(
                header[0] == 0x82
                and header[3] == offset
                and header[4] == 0x40
                and header[5] == offset
                and header[6] == 1
                and payload == parameters,
                f"invalid parameter offset {offset} returns unchanged current settings",
            )
        header, payload = unpack(device.exchange(frame(0x61, b"short", p1=1)))
        check(
            header[0] == 0x82 and header[5] == 1 and payload == parameters,
            "incorrect parameter size does not mutate negotiation",
        )
        header, payload = unpack(device.exchange(frame(0x61, parameters, p1=0)))
        check(
            header[5] == 7 and payload == parameters,
            "unsupported T=0 parameter request preserves T=1 settings",
        )
        direct = bytes.fromhex("1112004d032000")
        header, payload = unpack(device.exchange(frame(0x61, direct, p1=1)))
        check(
            header[4] == 0 and payload[1] == 0x10,
            "ATR convention controls T=1 inverse bit",
        )
        check(
            expect(device, 0x6E, p1=1, tail=1),
            "either-polarity clock stop selects low state",
        )
        check(expect(device, 0x6F, error=0xFE), "stopped clock rejects APDU transfer")
        check(
            expect(device, 0x6E, p1=0, tail=0), "clock restart restores running status"
        )
        check(
            expect(device, 0x6E, p1=2, error=7), "invalid clock operation is rejected"
        )
        check(
            expect(device, 0x6D, expected_data=defaults, tail=1),
            "RESET_PARAMETERS restores ATR defaults",
        )
        check(expect(device, 0x6E, p1=1, error=7), "default ATR forbids clock stop")
        for kind in (0x62, 0x63, 0x65, 0x6C, 0x6D, 0x6E):
            check(
                expect(device, kind, error=1, data=b"x"),
                f"command {kind:02x} rejects nonzero reserved payload",
            )
        for offset, values in ((7, {"p1": 1}), (8, {"p2": 1}), (9, {"p3": 1})):
            check(
                expect(device, 0x65, error=offset, **values),
                f"reserved header offset {offset} rejected before execution",
            )
        for kind in (0x62, 0x65, 0x61, 0x6B, 0x73):
            header, _ = unpack(device.exchange(frame(kind, slot=1, seq=77)))
            check(
                header[2:6] == (1, 77, 0x42, 5),
                f"nonexistent slot uses no-ICC status for reply {kind:02x}",
            )
        check(
            expect(device, 0x6F, error=1, length=5),
            "malformed declared length produces recoverable CCID error",
        )
        for kind in (0x69, 0x6A, 0x6B, 0x71, 0xFD):
            check(
                expect(device, kind, error=0),
                f"unadvertised command {kind:02x} uses its correct failed reply type",
            )
        rates = struct.pack("<II", 4000, 307200)
        header, payload = unpack(device.exchange(frame(0x73, rates)))
        check(
            header[0] == 0x84 and header[4] == 0 and payload == rates,
            "clock/rate negotiation reports active fixed values",
        )
        check(
            expect(device, 0x73, error=10, data=struct.pack("<II", 4001, 307200)),
            "unsupported clock frequency rejected at offset 10",
        )
        check(
            expect(device, 0x73, error=14, data=struct.pack("<II", 4000, 307201)),
            "unsupported bit rate rejected at offset 14",
        )
        check(not device.abort(1, 70), "control ABORT rejects nonexistent slot")
        check(device.abort(0, 70), "control ABORT accepts independent sequence number")
        check(
            expect(device, 0x6C, error=0xFF),
            "abort barrier fails new commands before matching bulk phase",
        )
        check(
            expect(device, 0x72, seq=71, error=0xFF),
            "mismatched bulk ABORT preserves barrier",
        )
        check(
            expect(device, 0x72, seq=70, tail=0),
            "matching bulk ABORT completes control-first pair",
        )
        check(
            expect(device, 0x65, tail=0),
            "completed abort pair reopens slot to commands",
        )
        with ThreadPoolExecutor(max_workers=2) as executor:
            pending = executor.submit(device.exchange, frame(0x72, seq=72))
            time.sleep(0.03)
            check(
                not pending.done(), "bulk-first ABORT defers reply until control phase"
            )
            device.abort(0, 72)
            header, _ = unpack(pending.result(2))
            check(
                header[3:6] == (72, 0, 0),
                "bulk-first ABORT resolves after matching control request",
            )
        check(expect(device, 0x63, tail=3), "power-off returns inactive clock state")
        check(
            expect(device, 0x62, expected_data=ATR),
            "power cycle restores clean T=1 card session",
        )

        # Force the race after a genuine HOTP counter mutation, before persistence.
        provision(card)
        original_commit = card.commit
        before_commit, release_commit = threading.Event(), threading.Event()

        def delayed_commit(*args, **kwargs):
            before_commit.set()
            if not release_commit.wait(2):
                raise TimeoutError("commit gate timed out")
            original_commit(*args, **kwargs)

        card.commit = delayed_commit
        previous = copy.deepcopy(state.data)
        old_file = state.path.read_bytes()
        with ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(
                device.exchange, frame(0x6F, calculate(b"cancel"), seq=91)
            )
            check(
                before_commit.wait(1),
                "HOTP cancellation race reaches pre-commit boundary",
            )
            device.abort(0, 92)
            release_commit.set()
            header, payload = unpack(pending.result(2))
            check(
                header[3:6] == (91, 0x40, 0xFF) and not payload,
                "cancellation before commit suppresses APDU success",
            )
        check(
            state.data == previous and state.path.read_bytes() == old_file,
            "cancelled counter mutation rolls back memory and leaves ciphertext unchanged",
        )
        card.commit = original_commit
        device.exchange(frame(0x72, seq=92))
        card.transmit(select(AID.OATH))
        original_flush = state.flush
        in_flush, release_flush, abort_entered = (
            threading.Event(),
            threading.Event(),
            threading.Event(),
        )

        def delayed_flush():
            in_flush.set()
            if not release_flush.wait(2):
                raise TimeoutError("flush gate timed out")
            original_flush()

        def concurrent_abort():
            abort_entered.set()
            return device.abort(0, 94)

        state.flush = delayed_flush
        with ThreadPoolExecutor(max_workers=2) as executor:
            pending = executor.submit(
                device.exchange, frame(0x6F, calculate(b"cancel"), seq=93)
            )
            check(in_flush.wait(1), "commit-first race reaches protected durable write")
            aborted = executor.submit(concurrent_abort)
            abort_entered.wait(1)
            time.sleep(0.03)
            check(
                not aborted.done(), "ABORT waits for an already-started commit boundary"
            )
            release_flush.set()
            header, payload = unpack(pending.result(2))
            check(
                aborted.result(2) and header[4] == 0 and payload[-2:] == b"\x90\0",
                "commit accepted before ABORT may complete successfully",
            )
        state.flush = original_flush
        check(
            EncryptedState(state.path).data["oath"]["credentials"][b"cancel".hex()][
                "counter"
            ]
            == 1,
            "commit-first operation persists exactly one HOTP increment",
        )
        device.exchange(frame(0x72, seq=94))

        # Authentication failures are durable even when their response is aborted.
        # Cancellation cannot be used to undo a PIN comparison already performed.
        card.transmit(select(AID.PIV))
        retries = state.data["piv"]["pin_retries"]
        before_commit.clear()
        release_commit.clear()
        card.commit = delayed_commit
        with ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(
                device.exchange,
                frame(0x6F, apdu(0x20, b"654321\xff\xff", p2=0x80), seq=95),
            )
            check(
                before_commit.wait(1),
                "failed PIN comparison reaches durable retry commit",
            )
            device.abort(0, 96)
            release_commit.set()
            header, payload = unpack(pending.result(2))
            check(
                header[4:6] == (0x40, 0xFF) and not payload,
                "ABORT suppresses a failed PIN response",
            )
        card.commit = original_commit
        check(
            EncryptedState(state.path).data["piv"]["pin_retries"] == retries - 1,
            "aborted response cannot erase a completed wrong-PIN attempt",
        )
        device.exchange(frame(0x72, seq=96))
        card.transmit(select(AID.PIV))
        check(
            card.transmit(apdu(0x20, b"123456\xff\xff", p2=0x80))[1] == 0x9000,
            "valid PIN works after retry-preserving cancellation",
        )

        live_dir = directory / "live"
        live_dir.mkdir()
        live_state = EncryptedState(live_dir / "state.bin")
        gate = TouchGate()
        path = live_dir / "s.sock"
        fido_dir = directory / "fido"
        fido_dir.mkdir()
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
            try:
                # Accelerate only the incomplete-frame deadline; exercise real
                # persistent server sessions and fragmented stream requests.
                server.rpc_frame_timeout = 0.25
                with CcidSocketConnection(path) as idle:
                    token = rpc(idle.sock, b"\x08" + bytes(8))
                    time.sleep(0.75)
                    check(
                        rpc(idle.sock, b"\x08" + bytes(8)) == token,
                        "idle private reader retains its session beyond the frame deadline",
                    )
                    check(
                        OathSession(idle).version == (5, 7, 4),
                        "independent OATH SDK resumes on the same idle reader",
                    )
                previous = copy.deepcopy(live_state.data)
                old_file = live_state.path.read_bytes()
                for label, fragment in (
                    ("header", b"\0"),
                    ("body", struct.pack(">I", 9) + b"\x09"),
                    ("oversized length", struct.pack(">I", 32787)),
                    ("capability padding", struct.pack(">I", 9) + b"\x05" + bytes(7) + b"\x01"),
                ):
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as partial:
                        partial.settimeout(2)
                        partial.connect(str(path))
                        partial.sendall(fragment)
                        check(
                            not partial.recv(1),
                            f"private RPC rejects malformed {label} without dispatch",
                        )
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as partial:
                    partial.settimeout(2)
                    partial.connect(str(path))
                    partial.sendall(struct.pack(">I", 9))
                    started = time.monotonic()
                    closed = False
                    for _ in range(6):
                        time.sleep(0.1)
                        try:
                            partial.sendall(b"\0")
                        except BrokenPipeError:
                            closed = True
                            break
                    check(
                        (closed or not partial.recv(1))
                        and time.monotonic() - started < 1,
                        "fragmented RPC body cannot extend the total frame deadline",
                    )
                deadline = time.monotonic() + 2
                while server.sessions and time.monotonic() < deadline:
                    time.sleep(0.01)
                check(
                    not server.sessions,
                    "closed and timed-out readers release private session capabilities",
                )
                check(
                    live_state.data == previous
                    and live_state.path.read_bytes() == old_file,
                    "malformed RPC requests preserve card data and encrypted state",
                )
                server.rpc_frame_timeout = 30
                fido.start()
                fido.device.close()
                fido.device = None
                wire = Wire(binary, path, fido.socket_path, log)
                wire.control(0, 9, 1)
                connection = CardConnection(wire)
                oath = OathSession(connection)
                credential = oath.put_credential(
                    CredentialData.parse_uri(
                        "otpauth://hotp/CCID:cancel?secret=JBSWY3DPEHPK3PXP&counter=0"
                    ),
                    touch_required=True,
                )
                hid = CtapHidDevice(
                    HidDescriptor(
                        "ccid-wire", 0x1209, 0xF1D0, 64, 64, "Software", None
                    ),
                    HidConnection(wire),
                )
                previous = copy.deepcopy(live_state.data)
                old_file = live_state.path.read_bytes()
                gate.armed = True
                wire.output(2, frame(0x6F, calculate(credential.id), seq=53))
                check(
                    gate.entered.wait(1),
                    "native USB bulk request enters real service presence wait",
                )
                check(
                    "FIDO_2_1" in Ctap2(hid).get_info().versions,
                    "independent FIDO SDK GetInfo completes during CCID presence wait",
                )
                check(
                    live_state.data == previous
                    and live_state.path.read_bytes() == old_file,
                    "concurrent FIDO capability reads leave pending card transaction untouched",
                )
                check(
                    hid.ping(b"CCID is pending") == b"CCID is pending",
                    "FIDO HID PING completes while CCID presence is pending",
                )
                check(
                    wire.control(0xA1, 2, index=2, length=2)["data"] == "a00f",
                    "USB CCID control list supports short reads during presence wait",
                )
                wire.output(2, frame(0x65, seq=54))
                header, _ = unpack(wire.receive(0x82, 3072))
                check(
                    header[3:6] == (54, 0x40, 0xE0),
                    "native USB rejects a second command to a busy slot",
                )
                check(
                    wire.control(0x21, 1, (80 << 8) | 1, index=2)["stalled"],
                    "USB ABORT with nonexistent slot stalls without cancelling request",
                )
                check(
                    not wire.control(0x21, 1, 80 << 8, index=2)["stalled"],
                    "USB control ABORT interrupts active CCID presence without waiting for state lock",
                )
                wire.output(2, frame(0x72, seq=80))
                replies = [unpack(wire.receive(0x82, 3072)) for _ in range(2)]
                by_seq = {header[3]: (header, payload) for header, payload in replies}
                check(
                    by_seq[53][0][4:6] == (0x40, 0xFF) and not by_seq[53][1],
                    "aborted native transfer returns CMD_ABORTED without APDU data",
                )
                check(
                    by_seq[80][0][0] == 0x81 and by_seq[80][0][4:6] == (0, 0),
                    "native matching bulk ABORT returns good slot status",
                )
                check(
                    live_state.data == previous
                    and live_state.path.read_bytes() == old_file,
                    "active transport cancellation preserves credentials, counters and encrypted state",
                )
                gate.armed = False
                oath = OathSession(connection)
                check(
                    len(oath.calculate_code(oath.list_credentials()[0]).value) == 6,
                    "independent OATH SDK resumes after native cancellation",
                )
                check(
                    EncryptedState(live_state.path).data["oath"]["credentials"][
                        credential.id.hex()
                    ]["counter"]
                    == 1,
                    "resumed request commits one HOTP result without cancellation replay",
                )
                wire.output(2, frame(0x72, seq=81))
                check(
                    wire.request("in 82 3072")["pending"],
                    "native bulk-first ABORT remains pending",
                )
                wire.control(0x21, 1, 81 << 8, index=2)
                header, _ = unpack(wire.receive(0x82, 3072))
                check(
                    header[3:6] == (81, 0, 0),
                    "native bulk-first ABORT completes across independent pipes",
                )
                OathSession(connection)
                for sequence in range(100, 140):
                    wire.output(2, frame(0x72, seq=sequence))
                    assert wire.request("in 82 3072")["pending"]
                    wire.control(0x21, 1, sequence << 8, index=2)
                    header, _ = unpack(wire.receive(0x82, 3072))
                    assert header[3:6] == (sequence, 0, 0)
                    assert OathSession(connection).version == (5, 7, 4)
                check(
                    True,
                    "forty immediate bulk-first ABORT completions each leave SDK requests usable",
                )
                gate.entered.clear()
                gate.armed = True
                old_file = live_state.path.read_bytes()
                wire.output(2, frame(0x6F, calculate(credential.id), seq=82))
                check(
                    gate.entered.wait(1),
                    "bus reset test reaches pending presence operation",
                )
                wire.request("reset")
                check(
                    live_state.path.read_bytes() == old_file,
                    "native bus reset cancels pending operation without counter commit",
                )
                wire.control(0, 9, 1)
                check(
                    wire.request("in 82 3072")["pending"],
                    "bus reset discards replies from the previous USB generation",
                )
                gate.armed = False
                connection.command(0x62)
                check(
                    OathSession(connection).list_credentials()[0].id == credential.id,
                    "native bus reset restores a usable fresh card session",
                )
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as control:
                    control.settimeout(2)
                    control.connect(str(path))
                    request = b"\x07" + bytes(16) + b"\0\x01"
                    control.sendall(struct.pack(">I", len(request)) + request)
                    size = struct.unpack(">I", receive(control, 4))[0]
                    check(
                        receive(control, size) == b"\x6a\x86",
                        "unknown private session capability cannot cancel another reader",
                    )
                wire.close()
                wire = None
            finally:
                if wire:
                    wire.close()
                fido.stop()
                server.shutdown()
                thread.join(2)
        path.unlink()

        # Exercise the actual terminal presence implementation, without --testing.
        prompt_dir = directory / "prompt"
        prompt_dir.mkdir()
        prompt_path = prompt_dir / "s.sock"
        with (prompt_dir / "stderr.log").open("wb") as log:
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "emucard.service",
                    "--state",
                    str(prompt_dir / "state.bin"),
                    "--socket",
                    str(prompt_path),
                ],
                cwd=root,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=log,
            )
            connection = None
            try:
                for _ in range(100):
                    if process.poll() is not None:
                        raise RuntimeError("non-testing card service exited")
                    if prompt_path.exists():
                        break
                    time.sleep(0.01)
                connection = CcidSocketConnection(prompt_path)
                oath = OathSession(connection)
                credential = oath.put_credential(
                    CredentialData.parse_uri(
                        "otpauth://hotp/CCID:prompt?secret=JBSWY3DPEHPK3PXP&counter=0"
                    ),
                    touch_required=True,
                )
                token = rpc(connection.sock, b"\x08" + bytes(8))[1:]
                previous = (prompt_dir / "state.bin").read_bytes()

                def pending_presence():
                    try:
                        connection.command(0x6F, calculate(credential.id))
                    except OSError as error:
                        return "error=ff" in str(error)
                    return False

                with ThreadPoolExecutor(max_workers=1) as executor:
                    pending = executor.submit(pending_presence)
                    check(
                        wait_prompt(process),
                        "non-testing service waits for explicit terminal approval",
                    )
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as control:
                        control.settimeout(2)
                        control.connect(str(prompt_path))
                        check(
                            rpc(control, b"\x07" + token + b"\0\x9a") == b"\x90\0",
                            "session control cancels actual stdin presence wait",
                        )
                    check(
                        pending.result(1),
                        "actual terminal wait ends promptly with CMD_ABORTED",
                    )
                check(
                    (prompt_dir / "state.bin").read_bytes() == previous,
                    "terminal cancellation preserves persistent HOTP state",
                )
                connection.seq = 0x99
                connection.command(0x72, b"")
                oath = OathSession(connection)
                with ThreadPoolExecutor(max_workers=1) as executor:
                    pending = executor.submit(
                        oath.calculate_code, oath.list_credentials()[0]
                    )
                    check(
                        wait_prompt(process),
                        "next operation requests fresh terminal approval",
                    )
                    process.stdin.write(b"y\n")
                    process.stdin.flush()
                    check(
                        len(pending.result(2).value) == 6,
                        "explicit terminal approval permits one resumed HOTP response",
                    )
                check(
                    EncryptedState(prompt_dir / "state.bin").data["oath"][
                        "credentials"
                    ][credential.id.hex()]["counter"]
                    == 1,
                    "terminal-approved operation persists exactly one counter increment",
                )
            finally:
                if connection:
                    connection.close()
                process.terminate()
                process.wait(3)
                process.stdin.close()
                process.stdout.close()
        check(
            not prompt_path.exists(),
            "non-testing service removes its owned socket on shutdown",
        )
        completed = True
    finally:
        report.write_text(
            json.dumps(
                {
                    "passed": completed,
                    "tests": tests,
                    "scope": "fresh software state; native USB wire model; no OS registration or physical key",
                    "specification": "https://www.usb.org/sites/default/files/DWG_Smart-Card_CCID_Rev110.pdf",
                },
                indent=2,
            )
            + "\n"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--fido-binary", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(
        prefix="ske-ccid-", dir=args.work_dir or "/tmp"
    ) as directory:
        run(
            Path(__file__).resolve().parents[1],
            Path(directory),
            args.binary.resolve(),
            args.fido_binary.resolve(),
            args.report.resolve(),
        )


if __name__ == "__main__":
    main()
