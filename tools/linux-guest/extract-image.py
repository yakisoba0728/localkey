#!/usr/bin/env python3
"""Turn Ubuntu's arm64 vmlinuz into a raw arm64 Image that QEMU's -kernel boots directly.

Ubuntu 26.04 ships the arm64 kernel as a "Stubble" EFI application: a PE file whose
`.linux` section holds an upstream EFI zboot image (`MZ`, then `zimg` at offset 4), whose
payload is the zstd-compressed raw Image. QEMU's -kernel neither runs the stub (that needs
UEFI firmware) nor unpacks a zstd zboot payload, and jumps into the PE as if it were a raw
Image: the guest prints nothing at all. Layouts used: the PE/COFF section table, and the
zboot header of the kernel's drivers/firmware/efi/libstub/zboot-header.S (payload offset at
byte 8, payload size at byte 12, compression name at byte 24, all little-endian). The arm64
Image header has the magic "ARM\\x64" at byte 56 (Documentation/arch/arm64/booting.rst).

    extract-image.py VMLINUZ IMAGE

Standard library only; zstd payloads are decompressed with the `zstd` command.
"""

from __future__ import annotations

import struct
import subprocess
import sys


def pe_section(data: bytes, wanted: bytes) -> bytes | None:
    if data[:2] != b"MZ":
        return None
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        return None
    count = struct.unpack_from("<H", data, pe + 6)[0]
    optional = struct.unpack_from("<H", data, pe + 20)[0]
    table = pe + 24 + optional
    for i in range(count):
        name, _vsize, _vaddr, raw_size, raw_ptr = struct.unpack_from("<8sIIII", data, table + 40 * i)
        if name.rstrip(b"\0") == wanted:
            return data[raw_ptr:raw_ptr + raw_size]
    return None


def unzboot(data: bytes) -> bytes:
    if data[:2] != b"MZ" or data[4:8] != b"zimg":
        raise SystemExit("not an EFI zboot image")
    offset, size = struct.unpack_from("<II", data, 8)
    kind = data[24:32].rstrip(b"\0").decode("ascii")
    payload = data[offset:offset + size]
    if kind == "gzip":
        import gzip  # not in python3-minimal; only needed for a gzip payload

        return gzip.decompress(payload)
    if kind == "zstd":
        return subprocess.run(["zstd", "-dc"], input=payload, stdout=subprocess.PIPE, check=True).stdout
    raise SystemExit(f"unsupported zboot compression {kind!r}")


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: extract-image.py VMLINUZ IMAGE")
    data = open(sys.argv[1], "rb").read()
    inner = pe_section(data, b".linux")
    if inner is not None:
        print(f"Stubble image: .linux section of {len(inner)} bytes")
        data = inner
    if data[4:8] == b"zimg":
        data = unzboot(data)
        print(f"zboot payload: {len(data)} bytes")
    if data[56:60] != b"ARM\x64":
        raise SystemExit("result is not an arm64 Image (no ARM\\x64 magic at byte 56)")
    with open(sys.argv[2], "wb") as out:
        out.write(data)
    print(f"wrote {sys.argv[2]} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
