#!/usr/bin/env python3
"""Reproduce stale software-touch replay across same-generation USB disconnect."""

import json
import os
import select
import socket
import struct
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, "/opt")
sys.path.insert(0, "/opt/verification")

from emucard.client import KeyboardSocketConnection
from verify_composite import wait_for
from verify_composite_extra import UsbPcscFixture
from ykman.hid.linux import list_devices as list_otp
from yubikit.core.otp import OtpConnection
from yubikit.yubiotp import SLOT, StaticPasswordSlotConfiguration, YubiOtpSession


class RawKeyboardRpc:
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        self.sock.connect(str(path))

    def exchange(self, packet):
        self.sock.sendall(struct.pack(">I", len(packet)) + packet)
        length = self.sock.recv(4)
        if not length:
            return b""
        size = struct.unpack(">I", length)[0]
        response = bytearray()
        while len(response) < size:
            part = self.sock.recv(size - len(response))
            if not part:
                break
            response.extend(part)
        return bytes(response)

    def close(self):
        self.sock.close()


def lifecycle(path):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(5)
        conn.connect(str(path))
        conn.sendall(struct.pack(">I", 9) + bytes([9]) + bytes(8))
        size = struct.unpack(">I", conn.recv(4))[0]
        data = bytearray()
        while len(data) < size:
            data.extend(conn.recv(size - len(data)))
        assert len(data) == 11 and data[0] == 1
        return int.from_bytes(data[1:9], "big")


class KeyWatcher:
    def __init__(self):
        self.events = []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        event = struct.Struct("@llHHi")
        fd = None
        pending = bytearray()
        try:
            while not self.stop.is_set():
                if fd is None:
                    path = next(iter(Path("/dev/input").glob("event*")), None)
                    if path is None:
                        time.sleep(0.002)
                        continue
                    try:
                        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
                    except OSError:
                        time.sleep(0.002)
                        continue
                if not select.select([fd], [], [], 0.01)[0]:
                    continue
                try:
                    pending.extend(os.read(fd, event.size * 64))
                except OSError:
                    os.close(fd)
                    fd = None
                    pending.clear()
                    continue
                while len(pending) >= event.size:
                    _, _, kind, code, value = event.unpack(pending[: event.size])
                    del pending[: event.size]
                    if kind == 1:
                        self.events.append((code, value))
        finally:
            if fd is not None:
                os.close(fd)

    def close(self):
        self.stop.set()
        self.thread.join(2)


mode = sys.argv[1] if len(sys.argv) == 2 else ""
assert mode in ("baseline", "fixed")
report = {
    "passed": False,
    "mode": mode,
    "software_touch_input": True,
    "guest_network_devices": False,
    "host_usb_passthrough": False,
    "physical_device_access": False,
}

try:
    assert Path("/opt/isolated-ske-usb-guest").exists()
    with tempfile.TemporaryDirectory(prefix="v53-touch-reset-", dir="/guest-state") as path:
        fixture = UsbPcscFixture(Path(path))
        keyboard = None
        watcher = None
        try:
            card = fixture.start()
            card.close()
            fixture.connection = None
            devices = list_otp()
            assert len(devices) == 1
            otp_connection = devices[0].open_connection(OtpConnection)
            otp = YubiOtpSession(otp_connection)
            otp.put_configuration(
                SLOT.ONE, StaticPasswordSlotConfiguration(bytes([0x84, 5, 30]))
            )
            otp_connection.close()
            keyboard = KeyboardSocketConnection(fixture.card_socket)
            generation_before = lifecycle(fixture.card_socket)
            udc = Path("/sys/kernel/config/usb_gadget/ske/UDC")
            controller = next(iter(Path("/sys/class/udc").iterdir())).name
            udc.write_text("\n")
            wait_for(lambda: not list(Path("/dev/input").glob("event*")),
                     "USB keyboard did not disconnect")
            disconnected_at = time.monotonic()
            assert keyboard.touch_down()
            assert keyboard.touch_up(500) == []
            report["touch_after_disconnect_ms"] = round(
                (time.monotonic() - disconnected_at) * 1000
            )
            watcher = KeyWatcher()
            udc.write_text(controller + "\n")
            wait_for(lambda: list(Path("/dev/input").glob("event*")),
                     "USB keyboard did not reconnect")
            time.sleep(0.5)
            stale = list(watcher.events)
            watcher.events.clear()
            report["stale_evdev_keys"] = stale
            report["generation_before"] = generation_before
            report["generation_after"] = lifecycle(fixture.card_socket)
            assert report["generation_after"] == generation_before

            # A new touch after reconnect must still type through FunctionFS.
            assert keyboard.touch_down()
            assert keyboard.touch_up(500) == []
            time.sleep(0.5)
            fresh = list(watcher.events)
            report["fresh_evdev_keys"] = fresh
            expected = [42, 30, 48, 2, 28]
            stale_down = [code for code, value in stale if value == 1]
            fresh_down = [code for code, value in fresh if value == 1]
            report["stale_down"] = stale_down
            report["fresh_down"] = fresh_down
            report["passed"] = (
                (bool(stale_down) and set(stale_down) <= set(expected)
                 if mode == "baseline" else stale_down == [])
                and fresh_down == expected
            )
            if mode == "fixed" and report["passed"]:
                report["passed"] = False
                # Reuse the card service after stopping the sole USB bridge.
                # This isolates token ownership and malformed-frame handling.
                bridge = fixture.bridge
                bridge.stdin.write("quit\n")
                bridge.stdin.flush()
                bridge.wait(10)
                assert bridge.returncode == 0
                bridge.stdin.close()
                fixture.bridge = None
                time.sleep(0.05)
                owner = RawKeyboardRpc(fixture.card_socket)
                other = RawKeyboardRpc(fixture.card_socket)
                try:
                    generation = lifecycle(fixture.card_socket)
                    poll_zero = bytes([12]) + generation.to_bytes(8, "big") + bytes(2)
                    poll_all = bytes([12]) + generation.to_bytes(8, "big") + b"\x01\x00"
                    pause = bytes([13]) + bytes(8)
                    empty = struct.pack(">HH", 0x9000, 0)
                    assert owner.exchange(poll_zero) == empty
                    assert keyboard.touch_down()
                    assert keyboard.touch_up(500) == []
                    assert other.exchange(pause) == empty
                    retained = owner.exchange(poll_all)
                    assert retained[:2] == b"\x90\0" and retained[2:4] != b"\0\0"
                    assert owner.exchange(poll_zero) == empty
                    assert keyboard.touch_down()
                    assert keyboard.touch_up(500) == []
                    assert owner.exchange(pause) == empty
                    assert owner.exchange(poll_all) == empty
                    malformed = RawKeyboardRpc(fixture.card_socket)
                    try:
                        try:
                            malformed_response = malformed.exchange(bytes([13, 1]) + bytes(7))
                        except (ConnectionResetError, BrokenPipeError):
                            malformed_response = b""
                        assert malformed_response == b""
                    finally:
                        malformed.close()
                    report["wrong_token_retained_report_count"] = int.from_bytes(
                        retained[2:4], "big"
                    )
                    report["owner_pause_cleared_queue"] = True
                    report["malformed_pause_frame_rejected"] = True
                    report["passed"] = True
                finally:
                    owner.close()
                    other.close()
        finally:
            if watcher is not None:
                watcher.close()
            if keyboard is not None:
                keyboard.close()
            fixture.stop()
except Exception as exc:
    report["error"] = f"{type(exc).__name__}: {exc}"
    raise
finally:
    print("SKE_TOUCH_RESET_BEGIN", flush=True)
    print(json.dumps(report), flush=True)
    print("SKE_TOUCH_RESET_END", flush=True)
if not report["passed"]:
    raise SystemExit(1)
