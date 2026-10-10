#!/usr/bin/env python3
"""Touch the localkey sensor whenever the device waits for a touch.

usage: lk_tap.py CONTROL-SOCKET [--count N] [--long] [--delay SECONDS] [--timeout SECONDS]

Sends `watch` to localkeyd's control socket. Each time the presence indicator turns to
"waiting" (a request waits for user presence), it sends `tap` (`tap long` with --long) on a
second connection, after --delay seconds (default 0.2), up to N times (default 1), then
exits 0. Exits 1 if the N taps did not happen within --timeout seconds (default 60) or the
watch ended. Prints one line per tap. Run it in the background before the client that needs
the touch.
"""

import argparse
import socket
import sys
import time


def request(path, line):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(10)
        sock.connect(path)
        sock.sendall(line.encode() + b"\n")
        reply = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                return reply.decode(errors="replace").strip()
            reply += chunk


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("socket")
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--long", action="store_true")
    parser.add_argument("--delay", type=float, default=0.2)
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()
    deadline = time.monotonic() + args.timeout
    command = "tap long" if args.long else "tap"
    taps = 0
    with socket.socket(socket.AF_UNIX) as watch:
        watch.connect(args.socket)
        watch.sendall(b"watch\n")
        pending = b""
        while taps < args.count:
            left = deadline - time.monotonic()
            if left <= 0:
                print(f"lk_tap: timed out after {taps} tap(s)", flush=True)
                return 1
            watch.settimeout(left)
            try:
                chunk = watch.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                print(f"lk_tap: the watch ended after {taps} tap(s)", flush=True)
                return 1
            pending += chunk
            while b"\n" in pending and taps < args.count:
                line, pending = pending.split(b"\n", 1)
                if line == b"presence waiting":
                    time.sleep(args.delay)
                    reply = request(args.socket, command)
                    taps += 1
                    print(f"lk_tap: presence waiting -> {command}: {reply}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
