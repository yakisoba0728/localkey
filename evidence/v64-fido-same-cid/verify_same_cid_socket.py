#!/usr/bin/env python3
"""Same-CID CTAPHID transaction atomicity over a private Unix socket."""

import json
import os
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

binary = Path(sys.argv[1]).resolve()
mode = sys.argv[2]
result_path = Path(sys.argv[3]).resolve()
assert mode in ("baseline", "fixed")

report = {"passed": False, "mode": mode, "private_hid_socket": True,
          "fake_card_socket": True, "network_devices": False,
          "host_usb_access": False, "host_hid_access": False,
          "host_pcsc_access": False, "host_keychain_access": False,
          "physical_device_access": False}
profile_entered = threading.Event()
release_profile = threading.Event()


def receive_exact(connection, size):
    data = bytearray()
    while len(data) < size:
        piece = connection.recv(size - len(data))
        if not piece:
            raise RuntimeError("unexpected socket EOF")
        data.extend(piece)
    return bytes(data)


class CardServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class CardHandler(socketserver.BaseRequestHandler):
    def handle(self):
        header = receive_exact(self.request, 4)
        length = int.from_bytes(header, "big")
        request = receive_exact(self.request, length)
        if request[0] == 4:  # identity
            response = b"\x01\x00\x00\x00\x00\x00\x01"
        elif request[0] == 9:  # generation
            response = b"\x01" + b"\x00" * 10
        elif request[0] == 5 and request[1] == 0:  # enabled USB profile
            profile_entered.set()
            if not release_profile.wait(1.5):
                raise RuntimeError("profile hold timed out")
            response = b"\x90\x00\x02\x00"  # CTAP CBOR enabled
        else:
            response = b"\x90\x00"
        self.request.sendall(len(response).to_bytes(4, "big") + response)


def packet(cid, command, data=b""):
    return (cid + bytes([0x80 | command, len(data) >> 8, len(data) & 255]) + data[:57]).ljust(64, b"\0")


def read_packet(connection, timeout):
    connection.settimeout(timeout)
    try:
        return receive_exact(connection, 64)
    except socket.timeout:
        return None


def reply_for(connection, cid, deadline=1.0):
    until = time.monotonic() + deadline
    while time.monotonic() < until:
        response = read_packet(connection, max(.02, until - time.monotonic()))
        if response is None:
            continue
        if response[:4] == cid and response[4] != 0xbb:  # skip KEEPALIVE
            return response
    raise RuntimeError(f"response for CID {cid.hex()} missing")


with tempfile.TemporaryDirectory(prefix="ske-v61-arbitration-") as directory:
    base = Path(directory)
    card_path = base / "card.sock"
    server = CardServer(str(card_path), CardHandler)
    os.chmod(card_path, 0o600)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    env = dict(os.environ, SWPASSKEY_HID_SOCKET=str(base / "hid.sock"),
               SWPASSKEY_CARD_SOCKET=str(card_path), SWPASSKEY_PRESENCE="stdin",
               SWPASSKEY_TESTING="", SWPASSKEY_LOG="warn")
    with (result_path.parent / (result_path.stem + ".daemon.log")).open("wb") as log:
        daemon = subprocess.Popen([str(binary), "--dek-file", "--key-backend=software",
                                   "--store", str(base / "state.bin"),
                                   "--ctl-socket", str(base / "ctl.sock")],
                                  stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=env)
        connection = None
        try:
            for _ in range(100):
                if daemon.poll() is not None:
                    raise RuntimeError(f"daemon exited early: {daemon.returncode}")
                try:
                    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    connection.connect(str(base / "hid.sock"))
                    break
                except (FileNotFoundError, ConnectionRefusedError):
                    connection.close()
                    connection = None
                    time.sleep(.03)
            if connection is None:
                raise RuntimeError("private HID socket unavailable")

            def allocate(nonce):
                connection.sendall(packet(b"\xff" * 4, 0x06, nonce))
                response = reply_for(connection, b"\xff" * 4)
                assert response[4] == 0x86 and response[7:15] == nonce
                return response[15:19]

            active = allocate(b"v64-cid1")
            other = allocate(b"v64-cid2")
            assert active != other
            report["active_cid_hex"] = active.hex()
            report["other_cid_hex"] = other.hex()

            connection.sendall(packet(active, 0x10, b"\x04"))  # CBOR getInfo
            assert profile_entered.wait(1.0), "worker did not enter delayed profile RPC"
            report["worker_held_during_probes"] = True
            cases = [("same_cid_ping", active, 0x01, b"ping"),
                     ("same_cid_wink", active, 0x08, b"")]
            for name, cid, command, payload in cases:
                connection.sendall(packet(cid, command, payload))
                response = reply_for(connection, cid)
                report[name + "_reply_hex"] = response.hex()
                if mode == "fixed":
                    assert response[4] == 0xbf and response[7] == 0x06, name
                else:
                    assert response[4] == 0x80 | command, name
            release_profile.set()
            first = reply_for(connection, active, 2.0)
            assert first[4] == 0x90 and first[7] == 0, first.hex()
            report["active_cbor_first_hex"] = first.hex()
            remaining = max(0, int.from_bytes(first[5:7], "big") - 57)
            while remaining:
                continuation = read_packet(connection, 1.0)
                assert continuation and continuation[:4] == active
                remaining -= min(59, remaining)

            connection.sendall(packet(other, 0x01, b"idle"))
            idle = reply_for(connection, other)
            assert idle[4] == 0x81 and idle[7:11] == b"idle"
            report["idle_ping_hex"] = idle.hex()
            report["passed"] = True
        except Exception as error:
            report["error"] = f"{type(error).__name__}: {error}"
            raise
        finally:
            release_profile.set()
            if connection:
                connection.close()
            daemon.terminate()
            try:
                daemon.wait(timeout=3)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait(timeout=3)
            server.shutdown()
            server.server_close()
            report["daemon_exit_code"] = daemon.returncode
            result_path.write_text(json.dumps(report, indent=2) + "\n")
