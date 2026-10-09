#!/usr/bin/env python3
"""Launch isolated normal-presence fido/card/device services and verify cleanup."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from emucard.client import CcidSocketConnection
from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice
from fido2.hid.base import HidDescriptor
from verify_ctap import SocketConnection
from yubikit.management import ManagementSession
from yubikit.piv import PivSession


def run(root, directory, report):
    tests = []
    completed = False
    try:
        for mode in ("fido", "card", "device"):
            connections, sockets = [], []
            with (directory / f"{mode}.log").open("w") as log:
                process = subprocess.Popen(
                    [
                        sys.executable,
                        str(root / "emulator.py"),
                        mode,
                        "--state-dir",
                        str(directory / mode),
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=log,
                    text=True,
                )
                try:
                    if mode == "device":
                        assert process.stdout.readline().startswith("device state: ")
                        prefixes = [
                            "shared CCID/OTP socket: ",
                            "shared-profile FIDO socket: ",
                        ]
                    else:
                        prefixes = [f"{mode} socket: "]
                    for prefix in prefixes:
                        line = process.stdout.readline().strip()
                        if not line.startswith(prefix):
                            raise RuntimeError(
                                f"launcher failed to describe socket: {line}"
                            )
                        sockets.append(Path(line[len(prefix) :]))
                    for _ in range(100):
                        if process.poll() is not None:
                            raise RuntimeError("launcher exited prematurely")
                        if all(path.is_socket() for path in sockets):
                            break
                        time.sleep(0.05)
                    else:
                        raise TimeoutError("launcher sockets not created")
                    card, fido = None, None
                    if mode in ("card", "device"):
                        card = CcidSocketConnection(sockets[0])
                        connections.append(card)
                        assert PivSession(card).version == (5, 7, 4)
                    if mode in ("fido", "device"):
                        path = sockets[-1]
                        fido = CtapHidDevice(
                            HidDescriptor(
                                str(path), 0x1209, 0xF1D0, 64, 64, "software", None
                            ),
                            SocketConnection(path),
                        )
                        connections.append(fido)
                        assert Ctap2(fido).get_info().max_msg_size == 1536
                    if mode == "device":
                        assert (
                            ManagementSession(card).read_device_info().serial
                            == ManagementSession(fido).read_device_info().serial
                        )
                finally:
                    for connection in reversed(connections):
                        connection.close()
                    process.terminate()
                    process.wait(8)
                    process.stdout.close()
                    for path in sockets:
                        assert not path.exists(), "launcher left socket after exit"
                    if sockets:
                        sockets[0].parent.rmdir()
                tests.append(
                    {
                        "name": f"{mode} starts with normal presence, answers wire metadata, shares identity when applicable and cleans up",
                        "passed": True,
                        "testing_auto_allow": False,
                    }
                )
                print("PASS", tests[-1]["name"], flush=True)
        completed = True
    finally:
        report.write_text(
            json.dumps(
                {"passed": completed, "tests": tests, "physical_device_access": False},
                indent=2,
            )
            + "\n"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=Path("/tmp"))
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="ske-launch-", dir=args.work_dir
    ) as directory:
        run(Path(__file__).resolve().parents[1], Path(directory), args.report)


if __name__ == "__main__":
    main()
