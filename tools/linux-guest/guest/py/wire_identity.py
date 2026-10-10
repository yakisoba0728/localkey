#!/usr/bin/env python3
"""Print the engine's USB identity as localkeyd's wire transport sends it.

usage: wire_identity.py WIRE-SOCKET

Connects to the wire socket (docs/PROGRAM.md "lk-wire": connecting is a plug-in), reads the
IDENTITY frame (type 0x80) and prints key=value lines: vendor, product, release (4 hex
digits each), interfaces, manufacturer, product_name, serial, and the descriptors as
space-separated lowercase hex (device, configuration, fido_rd, otp_rd).
"""

import socket
import struct
import sys

IDENTITY = 0x80


def read_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise SystemExit("wire_identity: the connection ended")
        data += chunk
    return data


def spaced(data):
    return " ".join(f"{byte:02x}" for byte in data)


def main():
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(10)
        sock.connect(sys.argv[1])
        while True:
            (length,) = struct.unpack(">I", read_exact(sock, 4))
            frame = read_exact(sock, length)
            if frame[0] == IDENTITY:
                break
    payload = frame[1:]
    vendor, product, release, interfaces = struct.unpack(">HHHB", payload[:7])
    offset = 7
    fields = []
    for _ in range(7):
        (size,) = struct.unpack(">H", payload[offset : offset + 2])
        fields.append(payload[offset + 2 : offset + 2 + size])
        offset += 2 + size
    names = [name for bit, name in ((1, "otp"), (2, "fido"), (4, "ccid")) if interfaces & bit]
    print(f"vendor={vendor:04x}")
    print(f"product={product:04x}")
    print(f"release={release:04x}")
    print(f"interfaces={','.join(names)}")
    print(f"manufacturer={fields[0].decode()}")
    print(f"product_name={fields[1].decode()}")
    print(f"serial={fields[2].decode()}")
    print(f"device={spaced(fields[3])}")
    print(f"configuration={spaced(fields[4])}")
    print(f"fido_rd={spaced(fields[5])}")
    print(f"otp_rd={spaced(fields[6])}")


if __name__ == "__main__":
    main()
