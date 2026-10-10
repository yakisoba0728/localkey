#!/usr/bin/env python3
"""What a hidraw client sees of a HID device, through the hidraw ioctls.

usage: hidraw_info.py NODE [--get-feature LEN]...

For NODE (/dev/hidrawN) prints key=value lines from HIDIOCGRAWINFO (bus, vendor, product),
HIDIOCGRAWNAME, HIDIOCGRAWPHYS, HIDIOCGRAWUNIQ and HIDIOCGRDESC (space-separated hex).
Each --get-feature LEN does HIDIOCGFEATURE(LEN) with buffer byte 0 = report number 0 and
prints the length the kernel returned and the buffer, or the error
(`Documentation/hid/hidraw.rst`; `include/uapi/linux/hidraw.h`).
"""

import argparse
import fcntl
import os
import struct

IOC_WRITE, IOC_READ = 1, 2


def ioc(direction, number, size):
    return (direction << 30) | (size << 16) | (ord("H") << 8) | number


HIDIOCGRDESCSIZE = ioc(IOC_READ, 0x01, 4)
HIDIOCGRDESC = ioc(IOC_READ, 0x02, 4 + 4096)
HIDIOCGRAWINFO = ioc(IOC_READ, 0x03, 8)


def raw_string(fd, number):
    buf = bytearray(256)
    length = fcntl.ioctl(fd, ioc(IOC_READ, number, len(buf)), buf, True)
    return bytes(buf[:length]).rstrip(b"\0").decode(errors="replace")


def spaced(data):
    return " ".join(f"{byte:02x}" for byte in data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("node")
    parser.add_argument("--get-feature", type=int, action="append", default=[])
    args = parser.parse_args()
    fd = os.open(args.node, os.O_RDWR)
    try:
        info = bytearray(8)
        fcntl.ioctl(fd, HIDIOCGRAWINFO, info, True)
        bus, vendor, product = struct.unpack("<IHH", info)
        print(f"bus={bus:04x}")
        print(f"vendor={vendor:04x}")
        print(f"product={product:04x}")
        print(f"name={raw_string(fd, 0x04)}")
        print(f"phys={raw_string(fd, 0x05)}")
        print(f"uniq={raw_string(fd, 0x08)}")
        size = bytearray(4)
        fcntl.ioctl(fd, HIDIOCGRDESCSIZE, size, True)
        (length,) = struct.unpack("<I", size)
        desc = bytearray(4 + 4096)
        struct.pack_into("<I", desc, 0, length)
        fcntl.ioctl(fd, HIDIOCGRDESC, desc, True)
        print(f"rdesc={spaced(desc[4 : 4 + length])}")
        for size in args.get_feature:
            buf = bytearray(size)
            try:
                got = fcntl.ioctl(fd, ioc(IOC_READ | IOC_WRITE, 0x07, size), buf, True)
                print(f"get_feature_{size}=returned {got}: {spaced(buf)}")
            except OSError as error:
                print(f"get_feature_{size}=error {error.errno} ({os.strerror(error.errno)})")
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
