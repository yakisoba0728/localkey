#!/usr/bin/env python3
"""Private-socket CTAPHID channel state A/B; no HID/USB device is opened."""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

binary = Path(sys.argv[1]).resolve()
mode = sys.argv[2]
result_path = Path(sys.argv[3]).resolve()
assert mode in ("baseline", "fixed")
report = {"passed": False, "mode": mode, "physical_device_access": False,
          "host_usb_access": False, "host_hid_access": False, "host_keychain_access": False,
          "guest_network_devices": False}


def report_packet(cid, command, payload=b"", declared=None):
    length = len(payload) if declared is None else declared
    return (cid + bytes([0x80 | command, length >> 8, length & 255]) + payload[:57]).ljust(64, b"\0")


def read_packet(connection, timeout):
    connection.settimeout(timeout)
    data = bytearray()
    try:
        while len(data) < 64:
            piece = connection.recv(64 - len(data))
            if not piece:
                raise RuntimeError("daemon socket disconnected")
            data.extend(piece)
    except socket.timeout:
        if data:
            raise RuntimeError("partial daemon report")
        return None
    return bytes(data)


def expect(connection, cid, command, timeout=2):
    reply = read_packet(connection, timeout)
    if reply is None or reply[:4] != cid or reply[4] != 0x80 | command:
        raise AssertionError(f"expected CID {cid.hex()} command {command:02x}; got {reply and reply.hex()}")
    return reply


with tempfile.TemporaryDirectory(prefix="ske-v60-channel-", dir="/tmp") as directory:
    base = Path(directory)
    env = dict(os.environ, SWPASSKEY_HID_SOCKET=str(base / "h.sock"),
               SWPASSKEY_PRESENCE="stdin", SWPASSKEY_TESTING="", SWPASSKEY_LOG="warn")
    with (result_path.parent / (result_path.stem + ".daemon.log")).open("wb") as log:
        daemon = subprocess.Popen([str(binary), "--dek-file", "--key-backend=software",
                                   "--store", str(base / "state.bin"), "--ctl-socket", str(base / "c.sock")],
                                  stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=env)
        connection = None
        try:
            for _ in range(100):
                if daemon.poll() is not None:
                    raise RuntimeError(f"daemon exited early: {daemon.returncode}")
                if (base / "h.sock").exists():
                    try:
                        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                        connection.connect(str(base / "h.sock"))
                        break
                    except ConnectionRefusedError:
                        connection.close()
                        connection = None
                time.sleep(.05)
            if connection is None:
                raise RuntimeError("private socket did not listen")
            nonce = b"v60-cid!"
            connection.sendall(report_packet(b"\xff" * 4, 0x06, nonce))
            init = expect(connection, b"\xff" * 4, 0x06)
            assert init[7:15] == nonce
            valid = init[15:19]
            unknown = b"\x10\x20\x30\x40" if valid != b"\x10\x20\x30\x40" else b"\x20\x30\x40\x50"
            report["valid_cid_hex"] = valid.hex()
            report["unknown_cid_hex"] = unknown.hex()

            # An unallocated CID starts a 100-byte PING but omits the CONT.
            connection.sendall(report_packet(unknown, 0x01, b"X" * 57, declared=100))
            first = read_packet(connection, .12)
            report["unknown_initial_reply_hex"] = first and first.hex()
            connection.sendall(report_packet(valid, 0x01, b"okay"))
            second = read_packet(connection, 1.0)
            report["valid_ping_during_unknown_assembly_hex"] = second and second.hex()
            if mode == "baseline":
                assert first is None
                assert second and second[:4] == valid and second[4] == 0xbf and second[7] == 0x06
                timed_out = expect(connection, unknown, 0x3f, 1.0)
                assert timed_out[7] == 0x05
                report["unknown_timeout_hex"] = timed_out.hex()
            else:
                assert first and first[:4] == unknown and first[4] == 0xbf and first[7] == 0x0b
                assert second and second[:4] == valid and second[4] == 0x81 and second[7:11] == b"okay"
                report["unknown_timeout_hex"] = None

            # A CONT without a matching INIT is spurious and must be ignored.
            connection.sendall(unknown + b"\x00" + b"Y" * 59)
            spurious = read_packet(connection, .18)
            report["spurious_cont_reply_hex"] = spurious and spurious.hex()
            if mode == "baseline":
                assert spurious and spurious[:4] == unknown and spurious[4] == 0xbf and spurious[7] == 0x04
            else:
                assert spurious is None
            connection.sendall(b"\x00" * 5 + b"Z" * 59)
            zero_orphan = read_packet(connection, .18)
            report["zero_cid_spurious_cont_reply_hex"] = zero_orphan and zero_orphan.hex()
            if mode == "baseline":
                assert zero_orphan and zero_orphan[:4] == b"\x00" * 4 and zero_orphan[4] == 0xbf and zero_orphan[7] == 0x0b
            else:
                assert zero_orphan is None
            connection.sendall(report_packet(valid, 0x01, b"fresh"))
            pong = expect(connection, valid, 0x01)
            assert pong[7:12] == b"fresh"
            report["fresh_ping_hex"] = pong.hex()
            report["passed"] = True
        except Exception as error:
            report["error"] = f"{type(error).__name__}: {error}"
            raise
        finally:
            if connection is not None:
                connection.close()
            daemon.terminate()
            try:
                daemon.wait(5)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait(5)
            result_path.write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps({k: report[k] for k in ("passed", "mode", "unknown_initial_reply_hex",
                                              "valid_ping_during_unknown_assembly_hex",
                                              "spurious_cont_reply_hex",
                                              "zero_cid_spurious_cont_reply_hex")}, indent=2))
