#!/usr/bin/env python3
"""Private-socket CTAPHID_CANCEL during a delayed U2F REGISTER transaction."""

import hashlib
import json
import os
import pty
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
          "fake_card_socket": True, "software_presence_approval": True,
          "guest_network_devices": False, "host_usb_access": False,
          "host_hid_access": False, "host_pcsc_access": False,
          "host_keychain_access": False, "physical_device_access": False}
profile_entered = threading.Event()
release_profile = threading.Event()


def read_exact(conn, count):
    result = bytearray()
    while len(result) < count:
        chunk = conn.recv(count - len(result))
        if not chunk:
            raise RuntimeError("socket EOF")
        result.extend(chunk)
    return bytes(result)


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        head = read_exact(self.request, 4)
        request = read_exact(self.request, int.from_bytes(head, "big"))
        if request[0] == 4:  # shared card identity
            response = b"\x01\x00\x00\x00\x00\x00\x01"
        elif request[0] == 9:  # management generation
            response = b"\x01" + b"\x00" * 10
        elif request[0] == 5 and request[1] == 0:  # enabled transport profile
            profile_entered.set()
            if not release_profile.wait(1.5):
                raise RuntimeError("profile hold expired")
            response = b"\x90\x00\x00\x02"  # U2F enabled, CBOR disabled
        else:
            response = b"\x90\x00"
        self.request.sendall(len(response).to_bytes(4, "big") + response)


def frame(cid, command, payload):
    length = len(payload)
    first = (cid + bytes([0x80 | command, length >> 8, length & 255]) + payload[:57]).ljust(64, b"\0")
    yield first
    offset = 57
    sequence = 0
    while offset < length:
        yield (cid + bytes([sequence]) + payload[offset:offset + 59]).ljust(64, b"\0")
        offset += 59
        sequence += 1


def read_packet(conn, timeout):
    conn.settimeout(timeout)
    return read_exact(conn, 64)


def read_message(conn, cid, timeout=4):
    deadline = time.monotonic() + timeout
    while True:
        first = read_packet(conn, max(.05, deadline - time.monotonic()))
        if first[:4] == cid and first[4] != 0xbb:  # ignore KEEPALIVE
            break
        if time.monotonic() > deadline:
            raise RuntimeError("U2F reply timed out")
    length = int.from_bytes(first[5:7], "big")
    payload = bytearray(first[7:7 + min(length, 57)])
    sequence = 0
    while len(payload) < length:
        cont = read_packet(conn, max(.05, deadline - time.monotonic()))
        assert cont[:4] == cid and cont[4] == sequence, cont.hex()
        payload.extend(cont[5:5 + min(length - len(payload), 59)])
        sequence += 1
    return first[4], bytes(payload)


with tempfile.TemporaryDirectory(prefix="ske-v62-cancel-u2f-") as directory:
    base = Path(directory)
    card_path = base / "card.sock"
    server = Server(str(card_path), Handler)
    os.chmod(card_path, 0o600)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    master, slave = pty.openpty()
    env = dict(os.environ, SWPASSKEY_HID_SOCKET=str(base / "hid.sock"),
               SWPASSKEY_CARD_SOCKET=str(card_path), SWPASSKEY_PRESENCE="stdin",
               SWPASSKEY_TESTING="", SWPASSKEY_LOG="warn")
    with (result_path.parent / (result_path.stem + ".daemon.log")).open("wb") as log:
        daemon = subprocess.Popen([str(binary), "--dek-file", "--key-backend=software",
                                   "--store", str(base / "state.bin"),
                                   "--ctl-socket", str(base / "ctl.sock")],
                                  stdin=slave, stdout=log, stderr=log, env=env)
        os.close(slave)
        hid = None
        try:
            for _ in range(100):
                if daemon.poll() is not None:
                    raise RuntimeError(f"daemon exited early: {daemon.returncode}")
                try:
                    hid = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    hid.connect(str(base / "hid.sock"))
                    break
                except (FileNotFoundError, ConnectionRefusedError):
                    hid.close()
                    hid = None
                    time.sleep(.03)
            if hid is None:
                raise RuntimeError("private HID socket unavailable")

            nonce = b"u2fcanc!"
            hid.sendall(next(frame(b"\xff" * 4, 0x06, nonce)))
            command, data = read_message(hid, b"\xff" * 4)
            assert command == 0x86 and data[:8] == nonce
            cid = data[8:12]
            report["cid_hex"] = cid.hex()
            apdu = b"\x00\x01\x00\x00\x00\x00\x40" + b"\x11" * 32 + b"\x22" * 32 + b"\x00\x00"
            assert len(apdu) == 73
            for packet in frame(cid, 0x03, apdu):
                hid.sendall(packet)
            assert profile_entered.wait(1), "U2F worker did not enter delayed card RPC"
            hid.sendall(next(frame(cid, 0x11, b"")))
            report["cancel_sent_during_u2f"] = True
            # Allow the HID loop to consume CANCEL before unblocking the
            # worker; otherwise scheduling can make it arrive after the reply.
            time.sleep(.20)
            # The approval is an owned pseudo-terminal input, not a keyboard.
            os.write(master, b"y\n")
            release_profile.set()
            command, response = read_message(hid, cid)
            assert command == 0x83, command
            report["u2f_reply_length"] = len(response)
            report["u2f_reply_sha256"] = hashlib.sha256(response).hexdigest()
            report["u2f_status_hex"] = response[-2:].hex()
            report["u2f_registration_tag_hex"] = response[:1].hex()
            if mode == "baseline":
                assert response == b"\x69\x85"
            else:
                assert response[0] == 0x05 and response[-2:] == b"\x90\x00"
            hid.sendall(next(frame(cid, 0x01, b"fresh")))
            ping_command, ping_response = read_message(hid, cid)
            assert ping_command == 0x81 and ping_response == b"fresh"
            report["fresh_ping_ok"] = True
            report["passed"] = True
        except Exception as error:
            report["error"] = f"{type(error).__name__}: {error}"
            raise
        finally:
            release_profile.set()
            if hid:
                hid.close()
            daemon.terminate()
            try:
                daemon.wait(3)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait(3)
            os.close(master)
            server.shutdown()
            server.server_close()
            report["daemon_exit_code"] = daemon.returncode
            result_path.write_text(json.dumps(report, indent=2) + "\n")
