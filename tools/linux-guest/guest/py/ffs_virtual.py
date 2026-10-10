#!/usr/bin/env python3
"""FunctionFS experiment: present a configuration's interfaces as a gadget with chosen
descriptor flags, and report what the host sees.

usage: ffs_virtual.py --config HEX --udc NAME [--flags N] [--seconds S] [--name NAME]

--config is a whole configuration descriptor (as the engine produces it); its body (after
the 9-byte header) is written to ep0 as the full-speed descriptor list of a V2
descriptors blob with --flags (default 0x11 = FUNCTIONFS_HAS_FS_DESC |
FUNCTIONFS_VIRTUAL_ADDR, include/uapi/linux/usb/functionfs.h), followed by the empty
strings blob. The gadget (ConfigFS /sys/kernel/config/usb_gadget/<name>, idVendor 1050,
idProduct 0407, FunctionFS instance <name> at /dev/ffs-<name>) is bound to --udc; ep0 is
served for S seconds (every SETUP is stalled), and the script prints the endpoint files
f_fs created, the host's descriptors and configuration value, and the kernel log of the
run. Then it unbinds and removes everything it made. Needs root; nothing else may use
the UDC meanwhile.
"""

import argparse
import glob
import os
import struct
import subprocess
import threading
import time

CONFIGFS = "/sys/kernel/config/usb_gadget"


def write(path, value):
    with open(path, "w") as f:
        f.write(value + "\n")


def body_of(config):
    """The descriptors after the configuration header and how many there are."""
    body = config[9:]
    count, pos = 0, 0
    while pos < len(body):
        pos += body[pos]
        count += 1
    return body, count


def serve_ep0(fd, stop, log):
    while not stop.is_set():
        try:
            data = os.read(fd, 48)
        except OSError as error:
            log.append(f"ep0 read: {os.strerror(error.errno)}")
            time.sleep(0.05)
            continue
        for i in range(0, len(data) - 11, 12):
            event = data[i:i + 12]
            kind = event[8]
            name = ["BIND", "UNBIND", "ENABLE", "DISABLE", "SETUP", "SUSPEND", "RESUME"][kind] if kind < 7 else str(kind)
            if kind == 4:
                rtype, req, value, index, length = struct.unpack("<BBHHH", event[:8])
                log.append(f"SETUP {rtype:02x} {req:02x} value 0x{value:04x} index {index} length {length}: stalled")
                try:
                    if rtype & 0x80:
                        os.read(fd, 1)
                    else:
                        os.write(fd, b"\0")
                except OSError:
                    pass
            else:
                log.append(name)
            if kind == 1:
                return


def host_device(timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for dev in glob.glob("/sys/bus/usb/devices/*"):
            try:
                if open(f"{dev}/idVendor").read().strip() == "1050":
                    return dev
            except OSError:
                pass
        time.sleep(0.2)
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--udc", required=True)
    parser.add_argument("--flags", type=lambda s: int(s, 0), default=0x11)
    parser.add_argument("--seconds", type=float, default=6)
    parser.add_argument("--name", default="lkvirt")
    args = parser.parse_args()
    config = bytes.fromhex("".join(args.config.split()))
    body, count = body_of(config)
    gadget = f"{CONFIGFS}/{args.name}"
    function = f"{gadget}/functions/ffs.{args.name}"
    cfg = f"{gadget}/configs/c.1"
    mount = f"/dev/ffs-{args.name}"
    made = []
    fd = None
    stop = threading.Event()
    log = []
    server = None
    subprocess.run(["dmesg", "-C"], check=False)
    try:
        os.mkdir(gadget)
        made.append(gadget)
        for name, value in (("idVendor", "0x1050"), ("idProduct", "0x0407"), ("bcdDevice", "0x0574"),
                            ("bcdUSB", "0x0200"), ("max_speed", "full-speed")):
            write(f"{gadget}/{name}", value)
        os.mkdir(f"{gadget}/strings/0x409")
        made.append(f"{gadget}/strings/0x409")
        write(f"{gadget}/strings/0x409/manufacturer", "Yubico")
        write(f"{gadget}/strings/0x409/product", "ffs experiment")
        os.mkdir(function)
        made.append(function)
        os.mkdir(cfg)
        made.append(cfg)
        write(f"{cfg}/bmAttributes", f"0x{config[7]:02x}")
        write(f"{cfg}/MaxPower", str(config[8] * 2))
        os.makedirs(mount, exist_ok=True)
        subprocess.run(["mount", "-t", "functionfs", args.name, mount], check=True)
        made.append(("mount", mount))
        fd = os.open(f"{mount}/ep0", os.O_RDWR)
        blob = struct.pack("<IIII", 3, 16 + len(body), args.flags, count) + body
        try:
            os.write(fd, blob)
            print(f"descriptors blob (flags 0x{args.flags:02x}, {count} descriptors): accepted")
        except OSError as error:
            print(f"descriptors blob (flags 0x{args.flags:02x}): refused: {os.strerror(error.errno)}")
            return 1
        os.write(fd, struct.pack("<IIII", 2, 16, 0, 0))
        print(f"endpoint files: {' '.join(sorted(os.listdir(mount)))}")
        os.symlink(function, f"{cfg}/ffs.{args.name}")
        made.append(("link", f"{cfg}/ffs.{args.name}"))
        server = threading.Thread(target=serve_ep0, args=(fd, stop, log), daemon=True)
        server.start()
        write(f"{gadget}/UDC", args.udc)
        made.append(("udc", f"{gadget}/UDC"))
        dev = host_device(10)
        time.sleep(args.seconds)
        if dev is None:
            print("host: no 1050 device appeared")
        else:
            raw = open(f"{dev}/descriptors", "rb").read()
            print(f"host: {os.path.basename(dev)} descriptors: {raw.hex(' ')}")
            value = open(f"{dev}/bConfigurationValue").read().strip()
            print(f"host: bConfigurationValue '{value}' (empty: not configured)")
    finally:
        stop.set()
        for item in reversed(made):
            try:
                if isinstance(item, tuple) and item[0] == "udc":
                    write(item[1], "")
                    time.sleep(0.3)
                elif isinstance(item, tuple) and item[0] == "link":
                    os.remove(item[1])
                elif isinstance(item, tuple) and item[0] == "mount":
                    if fd is not None:
                        os.close(fd)
                        fd = None
                    time.sleep(0.2)
                    subprocess.run(["umount", item[1]], check=False)
                else:
                    os.rmdir(item)
            except OSError as error:
                print(f"cleanup {item}: {os.strerror(error.errno)}")
        if fd is not None:
            os.close(fd)
        print("ep0 events: " + "; ".join(log))
        kmsg = subprocess.run(["dmesg"], capture_output=True, text=True, check=False).stdout
        for line in kmsg.splitlines():
            print(f"kernel: {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
