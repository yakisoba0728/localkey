#!/usr/bin/env python3
"""Host-side requests to a USB device through usbfs (/dev/bus/usb/BBB/DDD).

usage: usbfs.py NODE reset
       usbfs.py NODE control REQTYPE REQUEST VALUE INDEX LENGTH [DATA-HEX]

reset    USBDEVFS_RESET: a port reset and re-enumeration of the same configuration.
control  USBDEVFS_CONTROL: one control transfer; numbers in any Python base (0x81).
         Prints "ok N: <hex>" with the bytes of an IN data stage, or "error E (name)";
         EPIPE is a stall. A request to an interface claims it (usbfs warns), which fails
         with EBUSY while a kernel driver holds it.

Sources: include/uapi/linux/usbdevice_fs.h (struct usbdevfs_ctrltransfer, the ioctl
numbers).
"""

import ctypes
import errno
import fcntl
import os
import sys


class CtrlTransfer(ctypes.Structure):
    _fields_ = [
        ("bRequestType", ctypes.c_uint8),
        ("bRequest", ctypes.c_uint8),
        ("wValue", ctypes.c_uint16),
        ("wIndex", ctypes.c_uint16),
        ("wLength", ctypes.c_uint16),
        ("timeout", ctypes.c_uint32),
        ("data", ctypes.c_void_p),
    ]


def ioc(direction, kind, number, size):
    return (direction << 30) | (size << 16) | (ord(kind) << 8) | number


USBDEVFS_CONTROL = ioc(3, "U", 0, ctypes.sizeof(CtrlTransfer))  # _IOWR('U', 0, ...)
USBDEVFS_RESET = ioc(0, "U", 20, 0)  # _IO('U', 20)


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    node, command = sys.argv[1], sys.argv[2]
    fd = os.open(node, os.O_RDWR)
    try:
        if command == "reset":
            fcntl.ioctl(fd, USBDEVFS_RESET, 0)
            print("ok reset")
            return 0
        if command != "control" or len(sys.argv) < 8:
            sys.exit(__doc__)
        reqtype, request, value, index, length = (int(a, 0) for a in sys.argv[3:8])
        payload = bytes.fromhex(sys.argv[8]) if len(sys.argv) > 8 else b""
        buffer = ctypes.create_string_buffer(payload, max(length, len(payload), 1))
        transfer = CtrlTransfer(reqtype, request, value, index, length, 2000,
                                ctypes.cast(buffer, ctypes.c_void_p))
        try:
            count = fcntl.ioctl(fd, USBDEVFS_CONTROL, transfer)
        except OSError as error:
            print(f"error {error.errno} ({errno.errorcode.get(error.errno, '?')})")
            return 1
        data = buffer.raw[:count] if reqtype & 0x80 else b""
        print(f"ok {count}: {data.hex(' ')}")
        return 0
    finally:
        os.close(fd)


if __name__ == "__main__":
    sys.exit(main())
