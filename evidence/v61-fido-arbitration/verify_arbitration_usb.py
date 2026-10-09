#!/usr/bin/env python3
"""Owned dummy_hcd FIDO endpoint arbitration with one delayed card RPC."""

import errno
import json
import os
import socket
import socketserver
import sys
import tempfile
import threading
import time
from pathlib import Path

import usb.backend.libusb1
import usb.core
import usb.util
import verify_composite
import verify_ctap

MODE = sys.argv[1]
assert MODE in ("baseline", "fixed")
report = {"passed": False, "mode": MODE, "guest_network_devices": False,
          "host_usb_passthrough": False, "physical_device_access": False,
          "transport": "owned dummy_hcd FunctionFS FIDO endpoint 0x04/0x84"}
armed = threading.Event()
profile_entered = threading.Event()
release_profile = threading.Event()
fixture = device = server = None


def receive_exact(connection, size):
    data = bytearray()
    while len(data) < size:
        piece = connection.recv(size - len(data))
        if not piece:
            raise RuntimeError("socket EOF")
        data.extend(piece)
    return bytes(data)


class Proxy(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    upstream = None


class ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        header = receive_exact(self.request, 4)
        body = receive_exact(self.request, int.from_bytes(header, "big"))
        if armed.is_set() and body[0] == 5 and body[1] == 0 and not profile_entered.is_set():
            profile_entered.set()
            if not release_profile.wait(1.5):
                raise RuntimeError("delayed profile RPC expired")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as upstream:
            upstream.connect(str(self.server.upstream))
            upstream.sendall(header + body)
            reply_header = receive_exact(upstream, 4)
            reply = receive_exact(upstream, int.from_bytes(reply_header, "big"))
        self.request.sendall(reply_header + reply)


def send(dev, cid, command, data=b""):
    packet = (cid + bytes([0x80 | command, len(data) >> 8, len(data) & 255]) + data[:57]).ljust(64, b"\0")
    assert dev.write(0x04, packet, timeout=5000) == 64


def read(dev, timeout):
    try:
        return bytes(dev.read(0x84, 64, timeout=timeout))
    except usb.core.USBError as error:
        if error.errno == errno.ETIMEDOUT:
            return None
        raise


def reply_for(dev, cid, timeout=1.2):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        candidate = read(dev, max(10, int((deadline - time.monotonic()) * 1000)))
        if candidate and candidate[:4] == cid and candidate[4] != 0xbb:
            return candidate
    raise RuntimeError(f"missing reply for CID {cid.hex()}")


def acquire(backend, serial):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        for found in usb.core.find(find_all=True, idVendor=0x1050, idProduct=0x0407, backend=backend):
            try:
                if found.serial_number != serial:
                    continue
                if found.is_kernel_driver_active(1):
                    found.detach_kernel_driver(1)
                usb.util.claim_interface(found, 1)
                return found
            except usb.core.USBError:
                usb.util.dispose_resources(found)
        time.sleep(.05)
    raise RuntimeError("owned FIDO USB interface missing")


original_start = verify_ctap.Fixture.start


try:
    assert Path("/opt/isolated-ske-usb-guest").exists()
    assert not Path("/sys/class/net/eth0").exists()
    with tempfile.TemporaryDirectory(prefix="v61-fido-usb-", dir="/guest-state") as directory:
        directory = Path(directory)
        proxy_path = directory / "card-proxy.sock"
        server = Proxy(str(proxy_path), ProxyHandler)
        os.chmod(proxy_path, 0o600)
        server.upstream = directory / "card/s.sock"
        threading.Thread(target=server.serve_forever, daemon=True).start()

        def daemon_uses_proxy(self):
            real = self.card_socket
            self.card_socket = proxy_path
            try:
                return original_start(self)
            finally:
                self.card_socket = real

        verify_ctap.Fixture.start = daemon_uses_proxy
        fixture = verify_composite.CompositeFixture(Path("/opt/swpasskeyd"), directory)
        try:
            fixture.start()
            verify_ctap.Fixture.start = original_start
            fixture.device.close()
            fixture.device = None
            backend = usb.backend.libusb1.get_backend(
                find_library=lambda name: "/usr/lib/aarch64-linux-gnu/libusb-1.0.so.0")
            device = acquire(backend, fixture.serial)
            report["serial"] = fixture.serial

            def allocate(nonce):
                send(device, b"\xff" * 4, 0x06, nonce)
                response = reply_for(device, b"\xff" * 4, 5)
                assert response[4] == 0x86 and response[7:15] == nonce
                return response[15:19]

            active = allocate(b"v61-usb1")
            other = allocate(b"v61-usb2")
            report["active_cid_hex"] = active.hex()
            report["other_cid_hex"] = other.hex()
            armed.set()
            send(device, active, 0x10, b"\x04")
            assert profile_entered.wait(1.0), "daemon did not enter delayed card RPC"
            report["worker_held_during_probes"] = True
            for name, cid, command, data in [
                ("ping", other, 0x01, b"ping"),
                ("broadcast_init", b"\xff" * 4, 0x06, b"newcid!!"),
            ]:
                send(device, cid, command, data)
                answer = reply_for(device, cid)
                report[name + "_reply_hex"] = answer.hex()
                if MODE == "fixed":
                    assert answer[4] == 0xbf and answer[7] == 0x06, name
                else:
                    assert answer[4] == 0x80 | command, name
            release_profile.set()
            response = reply_for(device, active, 3)
            assert response[4] == 0x90 and response[7] == 0
            report["active_cbor_first_hex"] = response.hex()
            remaining = max(0, int.from_bytes(response[5:7], "big") - 57)
            while remaining:
                continuation = read(device, 1000)
                assert continuation and continuation[:4] == active
                remaining -= min(59, remaining)
            send(device, other, 0x01, b"idle")
            idle = reply_for(device, other, 3)
            assert idle[4] == 0x81 and idle[7:11] == b"idle"
            report["idle_ping_hex"] = idle.hex()
            report["passed"] = True
        finally:
            release_profile.set()
            if device is not None:
                usb.util.dispose_resources(device)
            if fixture is not None:
                fixture.stop()
            if server is not None:
                server.shutdown()
                server.server_close()
except Exception as error:
    report["error"] = f"{type(error).__name__}: {error}"
    raise
finally:
    verify_ctap.Fixture.start = original_start
    print("SKE_V61_FIDO_ARBITRATION_BEGIN", flush=True)
    print(json.dumps(report), flush=True)
    print("SKE_V61_FIDO_ARBITRATION_END", flush=True)
if not report["passed"]:
    raise SystemExit(1)
