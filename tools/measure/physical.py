"""Physical backend: the inserted YubiKey through the host's PC/SC and HID stacks.

Read-only by construction: each backend creates its own guard (`guard.CcidGuard`,
`guard.FidoGuard`) in its constructor and keeps it and the device handle in name-mangled
attributes; the only methods that send are `transmit`, `send_packet` and
`send_message`, and each of them calls the guard before a byte leaves. There is no raw
send method, no IccPowerOn/Off, no card reset (disconnect leaves the card), no OTP HID.

The host libraries are imported lazily in the constructors so the unit tests can pass
fakes and never load the real backends.

CCID: pyscard's low-level `smartcard.scard` API on the system PC/SC service. The one
reader whose name contains "YubiKey" is opened with SCARD_SHARE_EXCLUSIVE and T=1; if
another client holds it, SCARD_SHARE_SHARED is used and every probe runs inside
SCardBeginTransaction/SCardEndTransaction (`begin`/`end`), with the guard's applet
tracking reset at each `begin` (another client may have selected something in between).
`transmit` is SCardTransmit: no automatic GET RESPONSE, so 61xx stays visible.

FIDO: python-fido2's HID backend. Descriptors come from `fido2.hid.list_descriptors()`
(FIDO usage page 0xF1D0 / usage 1 only) filtered to vendor 0x1050; the connection is
`fido2.hid.open_connection(descriptor)` and raw `write_packet`/`read_packet`. On macOS
`read_packet` runs a CFRunLoop for up to 4 s per attempt and raises OSError when nothing
came, so a reader thread loops on it and feeds a timestamped queue; the timestamp is
taken in the IOKit input-report callback by wrapping the connection's `read_queue.put`
when it exists (macOS), otherwise when `read_packet` returns. `close` stops the thread
(bounded join; the thread is a daemon).
"""

from __future__ import annotations

import importlib
import logging
import queue
import threading
import time

from guard import CcidGuard, FidoGuard

YUBICO_VID = 0x1050


class PhysicalError(Exception):
    pass


class PhysicalCcid:
    def __init__(self, scard=None, reader_match: str = "YubiKey"):
        self.__guard = CcidGuard()
        sc = scard if scard is not None else importlib.import_module("smartcard.scard")
        self.__sc = sc
        self.__card = None
        self.__in_tx = False
        hr, ctx = sc.SCardEstablishContext(sc.SCARD_SCOPE_USER)
        if hr != sc.SCARD_S_SUCCESS:
            raise PhysicalError(f"SCardEstablishContext: {hr:#x}")
        self.__ctx = ctx
        try:
            hr, readers = sc.SCardListReaders(ctx, [])
            if hr != sc.SCARD_S_SUCCESS:
                raise PhysicalError(f"SCardListReaders: {hr:#x}")
            matches = [r for r in readers if reader_match in r]
            if len(matches) != 1:
                raise PhysicalError(f"expected exactly one reader containing {reader_match!r}, found {len(matches)}")
            self.reader = matches[0]
            hr, card, proto = sc.SCardConnect(ctx, self.reader, sc.SCARD_SHARE_EXCLUSIVE, sc.SCARD_PROTOCOL_T1)
            self.mode = "exclusive"
            if hr != sc.SCARD_S_SUCCESS:
                hr, card, proto = sc.SCardConnect(ctx, self.reader, sc.SCARD_SHARE_SHARED, sc.SCARD_PROTOCOL_T1)
                self.mode = "shared"
            if hr != sc.SCARD_S_SUCCESS:
                raise PhysicalError(f"SCardConnect: {hr:#x}")
            self.__card = card
            if proto != sc.SCARD_PROTOCOL_T1:
                raise PhysicalError(f"active protocol {proto} is not T=1")
            hr, _reader, _state, _protocol, atr = sc.SCardStatus(card)
            if hr != sc.SCARD_S_SUCCESS:
                raise PhysicalError(f"SCardStatus: {hr:#x}")
            self.__atr = bytes(atr)
        except BaseException:
            self.close()
            raise

    def atr(self) -> bytes:
        return self.__atr

    def begin(self):
        """Start one probe sequence (a PC/SC transaction when shared)."""
        sc = self.__sc
        if self.mode == "shared" and not self.__in_tx:
            hr = sc.SCardBeginTransaction(self.__card)
            if hr != sc.SCARD_S_SUCCESS:
                raise PhysicalError(f"SCardBeginTransaction: {hr:#x}")
            self.__in_tx = True
        self.__guard.reset()

    def end(self):
        sc = self.__sc
        if self.__in_tx:
            self.__in_tx = False
            sc.SCardEndTransaction(self.__card, sc.SCARD_LEAVE_CARD)

    def transmit(self, command: bytes) -> tuple[bytes, int]:
        sc = self.__sc
        command = bytes(command)
        if self.mode == "shared" and not self.__in_tx:
            raise PhysicalError("shared reader: transmit only inside begin()/end()")
        self.__guard.check(command)  # raises GuardViolation before anything is sent
        hr, response = sc.SCardTransmit(self.__card, sc.SCARD_PCI_T1, list(command))
        if hr != sc.SCARD_S_SUCCESS or len(response) < 2:
            self.__guard.observe(command, None)
            raise PhysicalError(f"SCardTransmit: {hr:#x}")
        sw = response[-2] << 8 | response[-1]
        self.__guard.observe(command, sw)
        return bytes(response[:-2]), sw

    def close(self):
        sc = self.__sc
        self.end()
        if self.__card is not None:
            sc.SCardDisconnect(self.__card, sc.SCARD_LEAVE_CARD)
            self.__card = None
        if self.__ctx is not None:
            sc.SCardReleaseContext(self.__ctx)
            self.__ctx = None


class PhysicalFido:
    def __init__(self, hid=None, join_timeout: float = 10.0):
        self.__guard = FidoGuard()
        hid = hid if hid is not None else importlib.import_module("fido2.hid")
        # macOS read_packet logs every 4 s run-loop timeout at error level
        logging.getLogger("fido2.hid").setLevel(logging.CRITICAL)
        descriptors = [d for d in hid.list_descriptors() if d.vid == YUBICO_VID]
        if len(descriptors) != 1:
            raise PhysicalError(f"expected exactly one Yubico FIDO HID device, found {len(descriptors)}")
        descriptor = descriptors[0]
        if descriptor.report_size_in != 64 or descriptor.report_size_out != 64:
            raise PhysicalError("FIDO reports are not 64 bytes")
        self.info = {"vid": descriptor.vid, "pid": descriptor.pid, "product": descriptor.product_name}
        self.__conn = hid.open_connection(descriptor)
        self.__queue: queue.Queue = queue.Queue()
        self.__stop = threading.Event()
        self.__lock = threading.Lock()
        self.__join_timeout = join_timeout
        read_queue = getattr(self.__conn, "read_queue", None)
        if read_queue is not None and callable(getattr(read_queue, "put", None)):
            original_put = read_queue.put

            def stamped_put(item, *args, **kwargs):
                return original_put((time.monotonic(), item), *args, **kwargs)

            read_queue.put = stamped_put  # instance attribute: the IOKit callback looks it up
        self.__thread = threading.Thread(target=self.__reader, name="fido-reader", daemon=True)
        self.__thread.start()

    def __reader(self):
        while not self.__stop.is_set():
            try:
                item = self.__conn.read_packet()
            except OSError:
                continue  # macOS: no report within one run-loop pass
            except Exception:
                break
            if isinstance(item, tuple):
                stamp, pkt = item
            else:
                stamp, pkt = time.monotonic(), item
            if self.__stop.is_set():
                break
            self.__queue.put((stamp, bytes(pkt)))

    def send_packet(self, pkt: bytes) -> float:
        with self.__lock:
            self.__guard.check_packet(pkt)  # raises GuardViolation before anything is sent
            stamp = time.monotonic()  # taken just before the write
            self.__conn.write_packet(bytes(pkt))
            return stamp

    def send_message(self, cid: int, command: int, payload: bytes = b"") -> float:
        with self.__lock:
            packets = self.__guard.approve_message(cid, command, payload)
            first = None
            sent = 0
            try:
                for pkt in packets:
                    if len(packets) > 1:
                        self.__guard.check_packet(pkt)
                    if first is None:
                        first = time.monotonic()  # just before the first write
                    self.__conn.write_packet(pkt)
                    sent += 1
            finally:
                if sent < len(packets):
                    self.__guard.abandon(cid)
            return first

    def recv_packet(self, timeout: float):
        try:
            return self.__queue.get(timeout=max(timeout, 0))
        except queue.Empty:
            return None

    def drain(self):
        while True:
            try:
                self.__queue.get_nowait()
            except queue.Empty:
                return

    def close(self):
        self.__stop.set()
        self.__thread.join(self.__join_timeout)
        self.__conn.close()


class PhysicalTarget:
    """The physical key as a measurement target: `.ccid`, `.fido`, `.info`."""

    name = "physical"

    def __init__(self, scard=None, hid=None):
        self._scard = scard
        self._hid = hid
        self._ccid = None
        self._fido = None
        self.info = {}

    @property
    def ccid(self) -> PhysicalCcid:
        if self._ccid is None:
            self._ccid = PhysicalCcid(self._scard)
            self.info["ccid"] = {"reader": self._ccid.reader, "mode": self._ccid.mode}
        return self._ccid

    @property
    def fido(self) -> PhysicalFido:
        if self._fido is None:
            self._fido = PhysicalFido(self._hid)
            self.info["fido"] = self._fido.info
        return self._fido

    def close(self):
        for backend in (self._fido, self._ccid):
            if backend is not None:
                try:
                    backend.close()
                except Exception:
                    pass
