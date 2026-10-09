#!/usr/bin/env python3
"""Exercise GET CHALLENGE and CALCULATE touch policy through private CCID."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from yubikit.core.smartcard import ApduError
from yubikit.hsmauth import HsmAuthSession


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--variant", choices=("baseline", "fixed"), required=True)
    parser.add_argument("--platform", choices=("mac", "linux"), required=True)
    parser.add_argument("--ifd-driver", type=Path)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent / args.variant
    sys.path.insert(0, str(root))
    from emucard.client import CcidSocketConnection
    from emucard.ifd import IfdNativeConnection

    results = []
    for allow_touch in (False, True):
        with tempfile.TemporaryDirectory(prefix="hsm64-", dir="/tmp") as tmp:
            directory = Path(tmp)
            socket = directory / "s.sock"
            with (directory / "service.log").open("wb") as log:
                command = [
                    sys.executable, "-m", "emucard.service", "--state",
                    str(directory / "state.bin"), "--socket", str(socket),
                ]
                if allow_touch:
                    command.append("--testing")
                process = subprocess.Popen(
                    command, cwd=root, stdin=subprocess.DEVNULL,
                    stdout=log, stderr=log,
                )
                connection = None
                try:
                    for _ in range(100):
                        if process.poll() is not None:
                            raise RuntimeError((directory / "service.log").read_text())
                        if socket.exists():
                            try:
                                connection = (
                                    IfdNativeConnection(args.ifd_driver, socket)
                                    if args.ifd_driver else CcidSocketConnection(socket)
                                )
                            except (ConnectionRefusedError, FileNotFoundError):
                                pass
                            else:
                                break
                        time.sleep(0.03)
                    else:
                        raise TimeoutError("private card service startup")
                    session = HsmAuthSession(connection)
                    management_key = bytes(16)
                    password = b"0123456789abcdef"
                    key_enc = bytes(range(16))
                    key_mac = bytes(range(16, 32))
                    for label, touch in (("plain", False), ("touch", True)):
                        session.put_credential_symmetric(
                            management_key, label, key_enc, key_mac,
                            password, touch_required=touch,
                        )
                    plain_challenge = session.get_challenge("plain")
                    assert len(plain_challenge) == 8
                    plain_keys = session.calculate_session_keys_symmetric(
                        "plain", plain_challenge + bytes(8), password,
                    )
                    assert all(len(key) == 16 for key in plain_keys)
                    try:
                        touched_challenge = session.get_challenge("touch")
                    except ApduError as error:
                        challenge_sw = error.sw
                        touched_challenge = b""
                    else:
                        challenge_sw = 0x9000
                    if allow_touch or args.variant == "fixed":
                        assert challenge_sw == 0x9000 and len(touched_challenge) == 8
                    else:
                        assert challenge_sw == 0x6985 and not touched_challenge
                    context = (
                        touched_challenge if touched_challenge else bytes(8)
                    ) + bytes(8)
                    try:
                        touched_keys = session.calculate_session_keys_symmetric(
                            "touch", context, password,
                        )
                    except ApduError as error:
                        calculate_sw = error.sw
                        touched_keys = None
                    else:
                        calculate_sw = 0x9000
                    if allow_touch:
                        assert calculate_sw == 0x9000
                        assert touched_keys is not None
                        assert all(len(key) == 16 for key in touched_keys)
                    else:
                        assert calculate_sw == 0x6985 and touched_keys is None
                    credentials = session.list_credentials()
                    assert len(credentials) == 2
                    results.append({
                        "touch_approval_available": allow_touch,
                        "untouched_challenge_bytes": len(plain_challenge),
                        "untouched_keys_derived": True,
                        "touch_required_challenge_sw": f"{challenge_sw:04x}",
                        "touch_required_challenge_bytes": len(touched_challenge),
                        "touch_required_calculate_sw": f"{calculate_sw:04x}",
                        "credentials_remaining": len(credentials),
                    })
                finally:
                    if connection is not None:
                        connection.close()
                    process.terminate()
                    process.wait(5)

    output = {
        "passed": True,
        "variant": args.variant,
        "platform": args.platform,
        "route": "ifd" if args.ifd_driver else "socket",
        "unmodified_yubikit": True,
        "physical_or_host_device_access": False,
        "network_devices": False,
        "core_sha256": sha256(root / "emucard/core.py"),
        "results": results,
    }
    args.result.parent.mkdir(parents=True, exist_ok=True)
    args.result.write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
