#!/usr/bin/env python3
"""Probe CTAP 2.1 large-blob write ordering over a private HID socket."""

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin
from fido2.ctap2.pin import PinProtocolV2

tools = os.environ.get("SKE_TOOLS_DIR")
if tools is None:
    tools = str(Path(__file__).resolve().parents[2] / "outputs/security-key-emulator/tools")
sys.path.insert(0, tools)
from verify_ctap import Fixture  # noqa: E402


def status(call):
    try:
        call()
    except CtapError as exc:
        return int(exc.code)
    return 0


def run(binary):
    with tempfile.TemporaryDirectory(prefix="v62-largeblob-") as path:
        fixture = Fixture(binary.resolve(), Path(path))
        try:
            ct = fixture.start()
            pin = PinProtocolV2()
            ClientPin(ct, pin).set_pin("12345678")
            token = ClientPin(ct, pin).get_pin_token(
                "12345678", ClientPin.PERMISSION.LARGE_BLOB_WRITE
            )
            data = b"\x80" + hashlib.sha256(b"\x80").digest()[:16]

            def write(offset, chunk, length=None, authenticated=True):
                param = None
                protocol = None
                if authenticated:
                    message = (
                        b"\xff" * 32
                        + b"\x0c\x00"
                        + offset.to_bytes(4, "little")
                        + hashlib.sha256(chunk).digest()
                    )
                    param = pin.authenticate(token, message)
                    protocol = 2
                return ct.large_blobs(
                    offset,
                    set=chunk,
                    length=length,
                    pin_uv_param=param,
                    pin_uv_protocol=protocol,
                )

            result = {}
            result["begin"] = status(lambda: write(0, data[:8], 17))
            result["bad_offset_without_auth"] = status(
                lambda: write(9, b"x", authenticated=False)
            )
            result["finish_after_bad_offset"] = status(lambda: write(8, data[8:]))
            result["stored_after_finish"] = ct.large_blobs(0, get=17)[1].hex()
            result["begin_again"] = status(lambda: write(0, data[:8], 17))
            result["unauthenticated_restart"] = status(
                lambda: write(0, b"z", 17, authenticated=False)
            )
            result["resume_after_unauthenticated_restart"] = status(
                lambda: write(8, data[8:])
            )
            result["stored_at_end"] = ct.large_blobs(0, get=17)[1].hex()
            return result
        finally:
            fixture.stop()


if __name__ == "__main__":
    print(json.dumps(run(Path(sys.argv[1])), indent=2))
