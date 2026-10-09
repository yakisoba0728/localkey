#!/usr/bin/env python3
"""Serve CCID frames on a private Unix socket; optional existing vpcd reader bridge."""

from __future__ import annotations

import argparse
from collections import deque
import copy
import fcntl
import os
import select
import signal
import socket
import socketserver
import struct
import sys
import threading
import time
from pathlib import Path

from .core import ATR, VERSION, Card, CardError, CcidDevice, EncryptedState
from .otp_hid import OtpHidDevice


def receive(sock, length, deadline=None):
    out = bytearray()
    while len(out) < length:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("incomplete RPC frame")
            sock.settimeout(remaining)
        chunk = sock.recv(length - len(out))
        if not chunk:
            raise EOFError()
        out.extend(chunk)
    return bytes(out)


def prompt_touch(label, cancelled=None):
    """Explicit presence approval; a CCID ABORT can interrupt the wait."""
    print(f"{label}: approve user presence [y/N] ", end="", flush=True)
    line = bytearray()
    try:
        while cancelled is None or not cancelled.is_set():
            if not select.select([sys.stdin], [], [], 0.05)[0]:
                continue
            value = os.read(sys.stdin.fileno(), 1)
            if not value:
                return False
            if value in (b"\n", b"\r"):
                return bytes(line).strip().lower() == b"y"
            if len(line) > 32:
                return False
            line.extend(value)
    except (OSError, ValueError):
        return False
    return False


class SocketCancellation(threading.Event):
    """Presence waits and commit checks also notice a disconnected requester."""

    def __init__(self, request):
        super().__init__()
        self.request = request
        self.poller = None
        if hasattr(select, "kqueue"):
            self.poller = select.kqueue()
            self.poller.control(
                [
                    select.kevent(
                        request.fileno(),
                        filter=select.KQ_FILTER_READ,
                        flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                    )
                ],
                0,
            )

    def is_set(self):
        if not super().is_set():
            try:
                if self.poller is not None:
                    if any(
                        event.flags & select.KQ_EV_EOF
                        for event in self.poller.control(None, 4, 0)
                    ):
                        self.set()
                elif select.select([self.request], [], [], 0)[
                    0
                ] and not self.request.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT):
                    self.set()
            except OSError:
                self.set()
        return super().is_set()

    def wait(self, timeout=None):
        deadline = None if timeout is None else time.monotonic() + timeout
        while not self.is_set():
            remaining = (
                0.05 if deadline is None else min(0.05, deadline - time.monotonic())
            )
            if remaining <= 0:
                return False
            super().wait(remaining)
        return True

    def close(self):
        if self.poller is not None:
            self.poller.close()


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    rpc_frame_timeout = 30

    def __init__(self, path, state, touch):
        self.state = state
        self.touch = touch
        self.lock = threading.Lock()
        self.sessions_lock = threading.Lock()
        self.sessions = {}
        self.usb_lock = threading.Lock()
        self.keyboard_lock = threading.Lock()
        self.keyboard_usb_events = deque()
        self.keyboard_last_poll = float("-inf")
        self.keyboard_subscriber = None
        self.publish_usb_state(Card(state))
        # A pre-existing socket must be handled by the caller, never unlinked blindly.
        super().__init__(str(path), Handler)
        Path(path).chmod(0o600)

    def publish_usb_state(self, card):
        """Publish only committed settings; polling must not wait for touch."""
        from .management import state as config_state

        config = config_state(card)
        snapshot = b"\x01" + struct.pack(
            ">QH", config.get("reboot_generation", 0), config["enabled"]
        )
        with self.usb_lock:
            previous = getattr(self, "usb_snapshot", None)
            self.usb_snapshot = snapshot
            if previous is not None and previous[1:9] != snapshot[1:9]:
                with self.keyboard_lock:
                    self.keyboard_usb_events.clear()

    def read_usb_state(self):
        with self.usb_lock:
            return self.usb_snapshot

    def check_keyboard_usb_capacity(self):
        # Only a live USB bridge subscribes. A software touch without a bridge
        # still returns its ordinary reports to the private-socket caller.
        with self.keyboard_lock:
            if time.monotonic() - self.keyboard_last_poll < 1.0:
                if len(self.keyboard_usb_events) >= 128:
                    raise CardError(0x6A84)

    def publish_keyboard_usb_events(self, response):
        if response[2:4] == b"\0\0":
            return
        with self.keyboard_lock:
            if time.monotonic() - self.keyboard_last_poll < 1.0:
                self.keyboard_usb_events.append(response)

    def drain_keyboard_usb_events(self, generation, capacity, subscriber):
        empty = struct.pack(">HH", 0x9000, 0)
        if generation != int.from_bytes(self.read_usb_state()[1:9], "big"):
            return empty
        with self.keyboard_lock:
            if self.keyboard_subscriber != subscriber:
                self.keyboard_usb_events.clear()
                self.keyboard_subscriber = subscriber
            self.keyboard_last_poll = time.monotonic()
            if not self.keyboard_usb_events:
                return empty
            if int.from_bytes(self.keyboard_usb_events[0][2:4], "big") > capacity:
                return empty
            return self.keyboard_usb_events.popleft()

    def end_keyboard_usb_subscriber(self, subscriber):
        with self.keyboard_lock:
            if self.keyboard_subscriber == subscriber:
                self.keyboard_usb_events.clear()
                self.keyboard_last_poll = float("-inf")
                self.keyboard_subscriber = None

    def pause_keyboard_usb_subscriber(self, subscriber):
        """Discard pending reports when the USB transport loses configuration."""
        self.end_keyboard_usb_subscriber(subscriber)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        card = Card(
            self.server.state,
            lambda label: self.server.touch(label, device.cancel_event),
        )
        cancellation = SocketCancellation(self.request)
        device = CcidDevice(card, cancellation)
        otp = OtpHidDevice(card)
        generation = int.from_bytes(self.server.read_usb_state()[1:9], "big")
        token = os.urandom(16)
        with self.server.sessions_lock:
            self.server.sessions[token] = device
        try:
            while True:
                # USB/PCSC clients keep sessions open while other interfaces
                # are active. Idle time is not an incomplete-frame timeout.
                self.request.settimeout(None)
                first = receive(self.request, 1)
                deadline = time.monotonic() + self.server.rpc_frame_timeout
                n = struct.unpack(
                    ">I", first + receive(self.request, 3, deadline)
                )[0]
                if not 9 <= n <= 32786:
                    return
                packet = receive(self.request, n, deadline)
                self.request.settimeout(30)
                # A separate same-user control connection may cancel a blocked
                # session. Never take the global state lock on this path.
                if packet[0] == 7:
                    if n != 19:
                        raise ValueError("invalid CCID control RPC frame")
                    with self.server.sessions_lock:
                        target = self.server.sessions.get(packet[1:17])
                        valid = target is not None and target.abort(
                            packet[17], packet[18]
                        )
                    response = b"\x90\0" if valid else b"\x6a\x86"
                    self.request.sendall(struct.pack(">I", len(response)) + response)
                    continue
                if n == 9 and packet[0] == 8:
                    if any(packet[1:]):
                        raise ValueError("invalid CCID session RPC frame")
                    response = b"\x01" + token
                    self.request.sendall(struct.pack(">I", len(response)) + response)
                    continue
                if n == 9 and packet[0] == 9:
                    if any(packet[1:]):
                        raise ValueError("invalid USB lifecycle RPC frame")
                    response = self.server.read_usb_state()
                    self.request.sendall(struct.pack(">I", len(response)) + response)
                    continue
                if n == 11 and packet[0] == 12:
                    capacity = int.from_bytes(packet[9:11], "big")
                    if capacity > 256:
                        raise ValueError("invalid USB keyboard queue capacity")
                    response = self.server.drain_keyboard_usb_events(
                        int.from_bytes(packet[1:9], "big"), capacity, token
                    )
                    self.request.sendall(struct.pack(">I", len(response)) + response)
                    continue
                if n == 9 and packet[0] == 13:
                    if any(packet[1:]):
                        raise ValueError("invalid USB keyboard reset RPC frame")
                    self.server.pause_keyboard_usb_subscriber(token)
                    response = struct.pack(">HH", 0x9000, 0)
                    self.request.sendall(struct.pack(">I", len(response)) + response)
                    continue
                if n == 9 and packet[:2] == b"\x05\0":
                    if any(packet[2:]):
                        raise ValueError("invalid capability request")
                    # FIDO checks this before dispatching every CTAP command.
                    # Read the committed mask, without waiting for another
                    # interface's presence prompt or flushing its transaction.
                    response = b"\x90\0" + self.server.read_usb_state()[9:11]
                    self.request.sendall(struct.pack(">I", len(response)) + response)
                    continue
                with self.server.lock:
                    current = int.from_bytes(self.server.read_usb_state()[1:9], "big")
                    if generation != current:
                        card.reset_session()
                        device.reset_transfer()
                        otp = OtpHidDevice(card)
                        generation = current
                    if n == 9 and packet[0] == 4:
                        if any(packet[1:]):
                            raise ValueError("invalid identity request")
                        response = VERSION + bytes.fromhex(card.state.data["serial"])
                    elif packet[0] == 5:
                        from .management import read_config, write_config
                        from .management import state as config_state

                        size = int.from_bytes(packet[2:4], "big")
                        if n != 9 + size or any(packet[4:9]):
                            raise ValueError("invalid configuration RPC frame")
                        previous = copy.deepcopy(card.state.data)
                        previous_otp_sessions = copy.deepcopy(card.otp_sessions)
                        previous_otp_reset = card.reset_otp_power_after_commit
                        try:
                            command, payload = packet[1], packet[9:]
                            if command == 0 and not payload:
                                result = config_state(card)["enabled"].to_bytes(
                                    2, "big"
                                )
                            elif command == 0x42 and len(payload) <= 1:
                                result = read_config(card, payload[0] if payload else 0)
                            elif command == 0x43:
                                write_config(card, payload)
                                result = b""
                            else:
                                raise CardError(0x6A86)
                            # This RPC has no CCID ABORT transaction. Keep its
                            # existing flush boundary without marking a CCID
                            # command committed, while applying OTP power reset.
                            card._flush_committed_state()
                            response = b"\x90\0" + result
                        except (CardError, OSError) as e:
                            card.state.data = previous
                            card.otp_sessions.clear()
                            card.otp_sessions.update(previous_otp_sessions)
                            card.reset_otp_power_after_commit = previous_otp_reset
                            response = struct.pack(
                                ">H", e.sw if isinstance(e, CardError) else 0x6581
                            )
                    elif n == 9 and packet[0] in (3, 6, 10, 11):
                        if packet[0] == 3 and (
                            packet[1] not in (1, 2) or any(packet[2:])
                        ):
                            raise ValueError("invalid software button request")
                        if packet[0] == 6 and any(packet[3:]):
                            raise ValueError("invalid hold/release request")
                        if packet[0] == 10 and any(packet[1:]):
                            raise ValueError("invalid touch-down request")
                        if packet[0] == 11 and any(packet[3:]):
                            raise ValueError("invalid touch-up request")
                        try:
                            if packet[0] in (10, 11):
                                self.server.check_keyboard_usb_capacity()
                            if packet[0] == 3:
                                events = card.otp_keyboard_events(packet[1])
                            elif packet[0] == 6:
                                events = card.otp_button_events(
                                    int.from_bytes(packet[1:3], "big")
                                )
                            elif packet[0] == 10:
                                events = card.otp_button_press_events()
                            else:
                                events = card.otp_button_release_events(
                                    int.from_bytes(packet[1:3], "big")
                                )
                            response = struct.pack(
                                ">HH", 0x9000, len(events)
                            ) + b"".join(
                                bytes.fromhex(e["report"])
                                + struct.pack(">H", e["delay_ms"])
                                for e in events
                            )
                            if packet[0] in (10, 11):
                                self.server.publish_keyboard_usb_events(response)
                        except CardError as e:
                            response = struct.pack(">HH", e.sw, 0)
                    elif n == 9 and packet[0] in (1, 2):
                        if packet[0] == 1:
                            otp.send(packet[1:])
                            response = otp.status()
                        else:
                            response = otp.receive()
                    else:
                        response = device.exchange(packet)
                    self.server.publish_usb_state(card)
                self.request.sendall(struct.pack(">I", len(response)) + response)
        except (EOFError, OSError, CardError, ValueError):
            return
        finally:
            self.server.end_keyboard_usb_subscriber(token)
            with self.server.sessions_lock:
                self.server.sessions.pop(token, None)
            # Touch ownership is device-wide; serialize disconnect cleanup
            # with other clients' button requests on the same device.
            with self.server.lock:
                card.reset_session()
            cancellation.close()


def bridge_vpcd(state, touch, port):
    """vsmartcard vpcd framing. Requires a separately installed virtual PC/SC reader."""
    card = Card(state, lambda label: touch(label, None))
    with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
        conn.settimeout(None)
        while True:
            n = struct.unpack(">H", receive(conn, 2))[0]
            if n > 32776:
                raise ValueError("oversized vpcd APDU")
            request = receive(conn, n)
            if n == 1:
                if request[0] in (0, 1, 2):
                    card.reset_session()
                    continue
                if request[0] == 4:
                    response = ATR
                else:
                    raise ValueError("unknown vpcd control")
            else:
                data, sw = card.transmit(request)
                response = data + struct.pack(">H", sw)
            conn.sendall(struct.pack(">H", len(response)) + response)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--state", required=True, type=Path)
    p.add_argument("--socket", type=Path)
    p.add_argument("--vpcd-port", type=int)
    p.add_argument(
        "--testing",
        action="store_true",
        help="explicitly simulate touch for local tests",
    )
    a = p.parse_args()
    if bool(a.socket) == bool(a.vpcd_port):
        p.error("choose exactly one of --socket or --vpcd-port")
    a.state.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(a.state) + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            p.error("state already in use by another card service")
        state = EncryptedState(a.state)
        touch = (lambda _, cancelled=None: True) if a.testing else prompt_touch
        if a.vpcd_port:
            bridge_vpcd(state, touch, a.vpcd_port)
            return
        a.socket.parent.mkdir(parents=True, exist_ok=True)
        # Server owns only the freshly created socket, and removes it on exit.
        if a.socket.exists() or a.socket.is_symlink():
            p.error("socket path already exists")
        with Server(a.socket, state, touch) as server:
            previous = signal.signal(
                signal.SIGTERM,
                lambda *_: threading.Thread(
                    target=server.shutdown, daemon=True
                ).start(),
            )
            try:
                server.serve_forever(poll_interval=0.2)
            finally:
                signal.signal(signal.SIGTERM, previous)
                if a.socket.exists() and a.socket.is_socket():
                    a.socket.unlink()
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
