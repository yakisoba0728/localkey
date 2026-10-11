"""Engine backend: localkeyd's private wire socket (docs/PROGRAM.md "lk-wire").

One wire connection carries CCID and FIDO (the socket takes one client at a time), so
`WireLink` owns the socket and a reader thread that sorts device frames into queues.
`EngineCcid` and `EngineFido` present the same interface as the physical backends and
check every command with the same guard. `EngineSetup` is the only unguarded path; it is
used by `--engine-setup` and never by probes.
"""

from __future__ import annotations

import os
import queue
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time

from common import Cmd, fragment, parse_packet
from guard import CcidGuard, FidoGuard

FIDO_OUT = 0x01
CCID_BULK_OUT = 0x04
TOUCH = 0x06
BUS = 0x07
IDENTITY = 0x80
FIDO_IN = 0x81
OTP_KEYBOARD = 0x82
OTP_FEATURE = 0x83
CCID_BULK_IN = 0x84
CCID_INTERRUPT = 0x85
PRESENCE = 0x86
ERROR = 0xFF


class WireError(Exception):
    pass


def parse_identity(payload: bytes) -> dict:
    vendor, product, release, interfaces = struct.unpack(">HHHB", payload[:7])
    offset = 7
    fields = []
    for _ in range(7):
        (size,) = struct.unpack(">H", payload[offset : offset + 2])
        fields.append(payload[offset + 2 : offset + 2 + size])
        offset += 2 + size
    return {
        "vid": vendor,
        "pid": product,
        "release": release,
        "interfaces": [name for bit, name in ((1, "otp"), (2, "fido"), (4, "ccid")) if interfaces & bit],
        "manufacturer": fields[0].decode(errors="replace"),
        "product": fields[1].decode(errors="replace"),
        "serial": fields[2].decode(errors="replace"),
        "device_descriptor": fields[3].hex(),
        "configuration_descriptor": fields[4].hex(),
        "fido_report_descriptor": fields[5].hex(),
    }


class WireLink:
    """The single connection to localkeyd's wire socket."""

    def __init__(self, path: str, timeout: float = 10.0):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(timeout)
        self.sock.connect(path)
        self.sock.settimeout(None)
        self.ccid_q: queue.Queue = queue.Queue()
        self.fido_q: queue.Queue = queue.Queue()
        self.side: list = []
        self.identity = None
        self.identity_count = 0
        self.identity_cond = threading.Condition()
        self.error = None
        self.closed = threading.Event()
        self.send_lock = threading.Lock()
        self.thread = threading.Thread(target=self._reader, name="wire-reader", daemon=True)
        self.thread.start()
        self.wait_identity(0, timeout)

    def _read_exact(self, size: int) -> bytes:
        data = b""
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise EOFError
            data += chunk
        return data

    def _reader(self):
        try:
            while True:
                (length,) = struct.unpack(">I", self._read_exact(4))
                frame = self._read_exact(length)
                now = time.monotonic()
                kind, payload = frame[0], frame[1:]
                if kind == FIDO_IN:
                    self.fido_q.put((now, payload))
                elif kind == CCID_BULK_IN:
                    self.ccid_q.put(payload)
                elif kind == IDENTITY:
                    with self.identity_cond:
                        self.identity = parse_identity(payload)
                        self.identity_count += 1
                        self.identity_cond.notify_all()
                elif kind == ERROR:
                    self.error = payload.decode(errors="replace")
                    break
                else:
                    self.side.append((now, kind, payload))
        except (EOFError, OSError):
            pass
        finally:
            self.closed.set()
            with self.identity_cond:
                self.identity_cond.notify_all()

    def wait_identity(self, after: int, timeout: float = 10.0) -> dict:
        deadline = time.monotonic() + timeout
        with self.identity_cond:
            while self.identity_count <= after:
                left = deadline - time.monotonic()
                if left <= 0 or self.closed.is_set():
                    raise WireError(f"no IDENTITY frame (error: {self.error})")
                self.identity_cond.wait(left)
            return self.identity

    def send(self, kind: int, payload: bytes):
        if self.closed.is_set():
            raise WireError(f"wire connection closed (error: {self.error})")
        frame = struct.pack(">IB", 1 + len(payload), kind) + payload
        with self.send_lock:
            self.sock.sendall(frame)

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
        self.thread.join(2)


class CcidError(Exception):
    pass


class _CcidCore:
    """CCID message framing over the wire link (USB CCID Rev 1.1)."""

    def __init__(self, link: WireLink):
        self.link = link
        self.seq = 0
        self._atr = None

    def _next_seq(self) -> int:
        self.seq = (self.seq + 1) & 0xFF
        return self.seq

    def _drain(self):
        while True:
            try:
                self.link.ccid_q.get_nowait()
            except queue.Empty:
                return

    def _exchange(self, message_type: int, data: bytes, b7: int = 0, b8b9: bytes = b"\x00\x00", timeout: float = 60.0) -> tuple[int, int, int, bytes]:
        seq = self._next_seq()
        header = struct.pack("<BIBB", message_type, len(data), 0, seq) + bytes([b7]) + b8b9
        self.link.send(CCID_BULK_OUT, header + data)
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise CcidError("no CCID reply")
            try:
                reply = self.link.ccid_q.get(timeout=left)
            except queue.Empty:
                raise CcidError("no CCID reply") from None
            if len(reply) < 10 or reply[6] != seq:
                continue
            status, error, chain = reply[7], reply[8], reply[9]
            if status & 0xC0 == 0x80:  # time extension
                continue
            return status, error, chain, bytes(reply[10:])

    def power_on(self) -> bytes:
        self._drain()
        status, error, _, data = self._exchange(0x62, b"")
        if status & 0xC0:
            raise CcidError(f"IccPowerOn failed: status {status:02X} error {error:02X}")
        self._atr = data
        return data

    def atr(self) -> bytes:
        return self._atr

    def raw_transmit(self, command: bytes) -> tuple[bytes, int]:
        status, error, chain, data = self._exchange(0x6F, bytes(command))
        if status & 0xC0:
            raise CcidError(f"XfrBlock failed: status {status:02X} error {error:02X}")
        response = data
        while chain in (0x01, 0x03):
            status, error, chain, data = self._exchange(0x6F, b"", b8b9=b"\x10\x00")
            if status & 0xC0:
                raise CcidError(f"XfrBlock chain failed: status {status:02X} error {error:02X}")
            response += data
        if len(response) < 2:
            raise CcidError("response without a status word")
        return response[:-2], response[-2] << 8 | response[-1]


class EngineCcid:
    """Guarded CCID access to the engine (same interface as physical.PhysicalCcid)."""

    def __init__(self, link: WireLink):
        self._core = _CcidCore(link)
        self._guard = CcidGuard()
        self._core.power_on()

    def atr(self) -> bytes:
        return self._core.atr()

    def begin(self):
        pass

    def end(self):
        pass

    def transmit(self, command: bytes) -> tuple[bytes, int]:
        self._guard.check(command)
        try:
            data, sw = self._core.raw_transmit(command)
        except Exception:
            self._guard.observe(command, None)
            raise
        self._guard.observe(command, sw)
        return data, sw

    def close(self):
        pass


class EngineFido:
    """Guarded CTAPHID access to the engine (same interface as physical.PhysicalFido)."""

    def __init__(self, link: WireLink):
        self._link = link
        self._guard = FidoGuard()
        self._lock = threading.Lock()

    def send_packet(self, pkt: bytes) -> float:
        with self._lock:
            self._guard.check_packet(pkt)
            stamp = time.monotonic()  # taken just before the write
            self._link.send(FIDO_OUT, bytes(pkt))
            return stamp

    def send_message(self, cid: int, command: int, payload: bytes = b"") -> float:
        with self._lock:
            packets = self._guard.approve_message(cid, command, payload)
            first = None
            sent = 0
            try:
                for pkt in packets:
                    if len(packets) > 1:  # single packets were checked by approve_message
                        self._guard.check_packet(pkt)
                    if first is None:
                        first = time.monotonic()  # just before the first write
                    self._link.send(FIDO_OUT, pkt)
                    sent += 1
            finally:
                if sent < len(packets):
                    self._guard.abandon(cid)
            return first

    def recv_packet(self, timeout: float):
        try:
            return self._link.fido_q.get(timeout=max(timeout, 0))
        except queue.Empty:
            return None

    def drain(self):
        while True:
            try:
                self._link.fido_q.get_nowait()
            except queue.Empty:
                return

    def close(self):
        pass


class EngineSetup:
    """Unguarded engine-only state changes for `--engine-setup` (refused for physical)."""

    def __init__(self, link: WireLink):
        self.link = link

    # -- CTAPHID over the wire, for python-fido2's ClientPin
    def ctap_device(self):
        from fido2.ctap import CtapDevice, CtapError

        link = self.link

        class WireCtapDevice(CtapDevice):
            def __init__(self):
                self._cid = 0xFFFFFFFF
                nonce = os.urandom(8)
                response = self.call(Cmd.INIT, nonce)
                assert response[:8] == nonce
                self._cid = struct.unpack(">I", response[8:12])[0]
                self._caps = response[16]

            @property
            def capabilities(self):
                return self._caps

            def call(self, cmd, data=b"", event=None, on_keepalive=None):
                for pkt in fragment(self._cid, cmd, bytes(data)):
                    link.send(FIDO_OUT, pkt)
                payload, total, seq = b"", None, 0
                while True:
                    try:
                        _, pkt = link.fido_q.get(timeout=35)
                    except queue.Empty:
                        raise OSError("no CTAPHID reply") from None
                    p = parse_packet(pkt)
                    if p["cid"] != self._cid:
                        continue
                    if total is None:
                        if not p["init"]:
                            continue
                        if p["cmd"] == Cmd.KEEPALIVE:
                            continue
                        if p["cmd"] == Cmd.ERROR:
                            raise CtapError(p["data"][0])
                        total = p["bcnt"]
                        payload = p["data"]
                    else:
                        if p["init"] or p["seq"] != seq:
                            raise OSError("CTAPHID sequence error")
                        seq += 1
                        payload += p["data"]
                    if len(payload) >= total:
                        return payload[:total]

            @classmethod
            def list_devices(cls):
                return iter(())

        return WireCtapDevice()

    def set_fido_pin(self, pin: str):
        from fido2.ctap2 import Ctap2
        from fido2.ctap2.pin import ClientPin

        device = self.ctap_device()
        ClientPin(Ctap2(device)).set_pin(pin)

    # -- Management WRITE CONFIG with REBOOT over CCID
    def set_usb(self, interfaces: set[str] | None = None, enabled: int | None = None) -> dict:
        core = _CcidCore(self.link)
        core.power_on()
        data, sw = core.raw_transmit(bytes.fromhex("00A4040008A000000527471117"))
        if sw != 0x9000:
            raise WireError(f"SELECT Management: {sw:04X}")
        data, sw = core.raw_transmit(bytes.fromhex("001D0000"))
        if sw != 0x9000:
            raise WireError(f"READ CONFIG: {sw:04X}")
        from common import flat_tlvs

        info = flat_tlvs(data[1 : 1 + data[0]])
        supported = int.from_bytes(info.get(0x01, b"\x00\x00"), "big")
        if enabled is None:
            mask = 0
            if "otp" in interfaces:
                mask |= 0x0001
            if "fido" in interfaces:
                mask |= 0x0002 | 0x0200
            if "ccid" in interfaces:
                mask |= 0x0008 | 0x0010 | 0x0020 | 0x0100
            enabled = supported & mask
        tlvs = bytes([0x03, 0x02]) + enabled.to_bytes(2, "big") + bytes([0x0C, 0x00])
        before = self.link.identity_count
        data, sw = core.raw_transmit(bytes([0x00, 0x1C, 0x00, 0x00, len(tlvs) + 1, len(tlvs)]) + tlvs)
        if sw != 0x9000:
            raise WireError(f"WRITE CONFIG: {sw:04X}")
        identity = self.link.wait_identity(before, 10)
        return {"usb_enabled": f"0x{enabled:04X}", "identity_after": {k: identity[k] for k in ("vid", "pid", "interfaces", "product")}}


class Daemon:
    """A localkeyd process with a fresh state directory and storage key."""

    def __init__(self, binary: str, profile: str = "yubikey-5c-nano-5.7.4", base: str | None = None, verbose: bool = False):
        self.tmp = tempfile.mkdtemp(prefix="lkm", dir=base)  # short path: sun_path is 104 bytes
        self.state = os.path.join(self.tmp, "state")
        self.key = os.path.join(self.tmp, "key")
        self.wire = os.path.join(self.tmp, "wire.sock")
        self.control = os.path.join(self.tmp, "control.sock")
        self.log_path = os.path.join(self.tmp, "localkeyd.log")
        subprocess.run([binary, "keygen", "--key-file", self.key], check=True, capture_output=True)
        self.log = open(self.log_path, "wb")
        args = [binary, "run", "--state", self.state, "--key-file", self.key, "--transport", "wire", "--wire", self.wire, "--control", self.control, "--profile", profile, "--exit-on-stdin-eof"]
        if verbose:
            args.append("-v")
        self.proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=self.log, stderr=self.log)
        deadline = time.monotonic() + 15
        while not os.path.exists(self.wire):
            if self.proc.poll() is not None or time.monotonic() > deadline:
                raise WireError(f"localkeyd did not start (exit {self.proc.poll()}); log: {self.log_text()}")
            time.sleep(0.05)

    def log_text(self) -> str:
        try:
            with open(self.log_path, "rb") as f:
                return f.read().decode(errors="replace")
        except OSError:
            return ""

    def stop(self) -> int:
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            code = self.proc.wait(15)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            code = self.proc.wait(5)
        self.log.close()
        return code

    def cleanup(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class EngineTarget:
    """The engine as a measurement target: `.ccid`, `.fido`, `.info`."""

    name = "engine"

    def __init__(self, wire_path: str):
        self.link = WireLink(wire_path)
        self.info = {"identity": {k: self.link.identity[k] for k in ("vid", "pid", "release", "interfaces", "manufacturer", "product")}}
        self._ccid = None
        self._fido = None

    def setup(self) -> EngineSetup:
        # a setup may re-enumerate the device: the CCID slot must be powered on again
        self._ccid = None
        return EngineSetup(self.link)

    def refresh_info(self):
        self._ccid = None
        self.info["identity"] = {k: self.link.identity[k] for k in ("vid", "pid", "release", "interfaces", "manufacturer", "product")}

    @property
    def ccid(self) -> EngineCcid:
        if self._ccid is None:
            self._ccid = EngineCcid(self.link)
        return self._ccid

    @property
    def fido(self) -> EngineFido:
        if self._fido is None:
            self._fido = EngineFido(self.link)
        return self._fido

    def close(self):
        self.link.close()
