#!/usr/bin/env python3
"""Capture what a keyboard types: the evdev key events and, optionally, the raw hidraw
input reports of the same HID device.

usage: evdev_keys.py --event /dev/input/eventN [--hidraw /dev/hidrawM] [--seconds S]

Prints "capturing" once both nodes are open, then reads until S seconds (default 10) have
passed, or 1 s after an Enter key was released. Then prints:
  hidraw: one line per input report read from the hidraw node (its size and bytes)
  keys=   the EV_KEY events in order (+NAME press, -NAME release; autorepeat ignored)
  typed=  the text they type on a US layout, as a Python repr (Enter is "\\n")
"""

import argparse
import os
import select
import struct
import time

EVENT = struct.Struct("llHHi")  # struct input_event on a 64-bit kernel
EV_KEY = 0x01

LETTERS = {
    16: "q", 17: "w", 18: "e", 19: "r", 20: "t", 21: "y", 22: "u", 23: "i", 24: "o", 25: "p",
    30: "a", 31: "s", 32: "d", 33: "f", 34: "g", 35: "h", 36: "j", 37: "k", 38: "l",
    44: "z", 45: "x", 46: "c", 47: "v", 48: "b", 49: "n", 50: "m",
}
# code: (unshifted, shifted) on a US layout (include/uapi/linux/input-event-codes.h)
KEYS = {code: (ch, ch.upper()) for code, ch in LETTERS.items()}
KEYS.update({2 + i: (str((i + 1) % 10), "!@#$%^&*()"[i]) for i in range(10)})
KEYS.update({
    12: ("-", "_"), 13: ("=", "+"), 26: ("[", "{"), 27: ("]", "}"), 39: (";", ":"),
    40: ("'", '"'), 41: ("`", "~"), 43: ("\\", "|"), 51: (",", "<"), 52: (".", ">"),
    53: ("/", "?"), 57: (" ", " "), 28: ("\n", "\n"), 15: ("\t", "\t"),
})
NAMES = {code: f"KEY_{pair[0].upper()}" for code, pair in KEYS.items() if pair[0].isalnum()}
NAMES.update({28: "KEY_ENTER", 57: "KEY_SPACE", 15: "KEY_TAB", 42: "KEY_LEFTSHIFT",
              54: "KEY_RIGHTSHIFT", 29: "KEY_LEFTCTRL", 56: "KEY_LEFTALT"})
SHIFTS = {42, 54}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", required=True)
    parser.add_argument("--hidraw")
    parser.add_argument("--seconds", type=float, default=10)
    args = parser.parse_args()
    event_fd = os.open(args.event, os.O_RDONLY | os.O_NONBLOCK)
    raw_fd = os.open(args.hidraw, os.O_RDONLY | os.O_NONBLOCK) if args.hidraw else None
    print("capturing", flush=True)
    deadline = time.monotonic() + args.seconds
    keys, raw = [], []
    pending = b""
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            break
        fds = [event_fd] + ([raw_fd] if raw_fd is not None else [])
        ready, _, _ = select.select(fds, [], [], left)
        if raw_fd is not None and raw_fd in ready:
            report = os.read(raw_fd, 4096)
            raw.append(report)
        if event_fd in ready:
            pending += os.read(event_fd, EVENT.size * 64)
            while len(pending) >= EVENT.size:
                _, _, etype, code, value = EVENT.unpack(pending[: EVENT.size])
                pending = pending[EVENT.size :]
                if etype == EV_KEY and value in (0, 1):
                    keys.append((code, value))
                    if code == 28 and value == 0:
                        deadline = min(deadline, time.monotonic() + 1.0)
    for report in raw:
        print(f"hidraw: {len(report)} bytes: {report.hex(' ')}")
    print("keys=" + " ".join(("+" if value else "-") + NAMES.get(code, f"KEY_{code}") for code, value in keys))
    shift, typed = False, ""
    for code, value in keys:
        if code in SHIFTS:
            shift = value == 1
        elif value == 1 and code in KEYS:
            typed += KEYS[code][1 if shift else 0]
        elif value == 1:
            typed += f"<{code}>"
    print(f"typed={typed!r}")


if __name__ == "__main__":
    main()
