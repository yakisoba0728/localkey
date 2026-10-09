#!/usr/bin/env python3
"""Private CCID/direct-IFD OATH SEND REMAINING CLA A/B, with stock YubiKit."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from yubikit.core import Tlv
from yubikit.oath import OathSession


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def state_digest(path: Path) -> str:
    raw = path.read_bytes()
    key = path.with_suffix(path.suffix + ".key").read_bytes()
    plain = AESGCM(key).decrypt(raw[4:16], raw[16:], b"EmulatedCard-v1")
    return hashlib.sha256(plain).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--variant", choices=("baseline", "fixed"), required=True)
    parser.add_argument("--platform", choices=("mac", "linux"), required=True)
    parser.add_argument("--ifd-driver", type=Path)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    candidate = Path(__file__).resolve().parent
    root = candidate / args.variant
    sys.path.insert(0, str(root))
    sys.path.insert(0, str(root / "tools"))
    from verify_smartcard import Fixture

    route = "ifd" if args.ifd_driver else "socket"
    with tempfile.TemporaryDirectory(prefix="v61-oath-remaining-") as tmp:
        directory = Path(tmp)
        fixture = Fixture(root, directory, args.ifd_driver)
        try:
            conn = fixture.start()
            oath = OathSession(conn)
            assert oath.version == (5, 7, 4)
            secret = b"12345678901234567890"
            for i in range(24):
                name = f"v61-{i:02d}@example.com".encode()
                oath.protocol.send_apdu(
                    0, 0x01, 0, 0,
                    Tlv(0x71, name) + Tlv(0x73, b"\x21\x06" + secret),
                )
            credentials = oath.list_credentials()
            assert len(credentials) == 24
            expected = oath.protocol.send_apdu(0, 0xA1, 0, 0)
            assert len(expected) > 257
            saved_state = state_digest(directory / "state.bin")

            first, first_sw = conn.send_and_receive(bytes.fromhex("00A1000001"))
            assert len(first) == 1 and first_sw & 0xFF00 == 0x6100
            malformed, malformed_sw = conn.send_and_receive(bytes.fromhex("80A50000"))
            assert state_digest(directory / "state.bin") == saved_state
            remaining = bytearray()
            continuation_statuses = []
            while True:
                part, sw = conn.send_and_receive(bytes.fromhex("00A50000"))
                remaining.extend(part)
                continuation_statuses.append(f"{sw:04x}")
                if sw == 0x9000:
                    break
                assert sw & 0xFF00 == 0x6100
                assert len(continuation_statuses) < 8

            full_after_malformed = first + remaining
            if args.variant == "baseline":
                assert malformed_sw & 0xFF00 == 0x6100
                assert len(malformed) == 256
                assert full_after_malformed != expected
                assert first + malformed + remaining == expected
            else:
                assert malformed_sw == 0x6E00 and not malformed
                assert full_after_malformed == expected
            assert state_digest(directory / "state.bin") == saved_state
            # A stock SDK read still works after the malformed probe and
            # provides a normal-path regression through its APDU continuation.
            assert len(oath.list_credentials()) == 24
            result = {
                "passed": True,
                "variant": args.variant,
                "platform": args.platform,
                "route": route,
                "unmodified_yubikit": True,
                "private_ccid_or_direct_ifd": True,
                "physical_or_host_device_access": False,
                "network_devices": False,
                "core_sha256": digest(root / "emucard/core.py"),
                "credential_count": len(credentials),
                "expected_list_length": len(expected),
                "first_sw": f"{first_sw:04x}",
                "malformed_cla_sw": f"{malformed_sw:04x}",
                "malformed_cla_consumed_bytes": len(malformed),
                "valid_remainder_matches_expected": full_after_malformed == expected,
                "continuation_statuses": continuation_statuses,
                "state_sha256": saved_state,
            }
        finally:
            fixture.stop()
    args.result.parent.mkdir(parents=True, exist_ok=True)
    args.result.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
