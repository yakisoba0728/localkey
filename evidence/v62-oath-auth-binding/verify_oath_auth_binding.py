#!/usr/bin/env python3
"""Two private OATH clients test authorization after access-code changes."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from yubikit.core import Tlv
from yubikit.core.smartcard import ApduError
from yubikit.oath import OathSession


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def state_digest(path: Path) -> str:
    raw = path.read_bytes()
    key = path.with_suffix(path.suffix + ".key").read_bytes()
    return hashlib.sha256(AESGCM(key).decrypt(
        raw[4:16], raw[16:], b"EmulatedCard-v1")).hexdigest()


def put(session: OathSession, name: bytes) -> None:
    session.protocol.send_apdu(
        0, 0x01, 0, 0,
        Tlv(0x71, name) + Tlv(0x73, b"\x21\x06" + b"12345678901234567890"),
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--variant", choices=("baseline", "fixed"), required=True)
    parser.add_argument("--platform", choices=("mac", "linux"), required=True)
    parser.add_argument("--ifd-driver", type=Path)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent / args.variant
    sys.path.insert(0, str(root))
    sys.path.insert(0, str(root / "tools"))
    from emucard.client import CcidSocketConnection
    from emucard.ifd import IfdNativeConnection
    from verify_smartcard import Fixture

    with tempfile.TemporaryDirectory(prefix="v62-oath-auth-") as tmp:
        directory = Path(tmp)
        fixture = Fixture(root, directory, args.ifd_driver)
        peer = None
        try:
            a_conn = fixture.start()
            socket_path = directory / "s.sock"
            peer = (
                IfdNativeConnection(args.ifd_driver, socket_path)
                if args.ifd_driver else CcidSocketConnection(socket_path)
            )
            a = OathSession(a_conn)
            b = OathSession(peer)
            assert not a.has_key and not b.has_key
            key1 = bytes(range(16))
            key2 = bytes(range(16, 32))
            phases = []

            def unauthorized_probe(label: str, name: bytes) -> None:
                before = state_digest(directory / "state.bin")
                try:
                    put(a, name)
                except ApduError as error:
                    sw = error.sw
                else:
                    sw = 0x9000
                after = state_digest(directory / "state.bin")
                names = {credential.id for credential in b.list_credentials()}
                if args.variant == "baseline":
                    assert sw == 0x9000 and name in names and before != after
                else:
                    assert sw == 0x6982 and name not in names and before == after
                phases.append({
                    "name": label,
                    "stale_client_sw": f"{sw:04x}",
                    "stale_client_inserted": name in names,
                    "encrypted_state_changed": before != after,
                })

            b.set_key(key1)
            put(b, b"owner-after-set")
            unauthorized_probe("code_enabled_after_another_client_selected_unlocked", b"stale-after-set")

            a = OathSession(a_conn)
            assert a.has_key
            a.validate(key1)
            put(a, b"validated-key1")
            b.set_key(key2)
            put(b, b"owner-after-rotation")
            unauthorized_probe("code_rotated_after_old_validation", b"stale-after-rotation")

            a = OathSession(a_conn)
            a.validate(key2)
            put(a, b"validated-key2")
            b.set_key(key1)
            b.set_key(key2)
            put(b, b"owner-after-roundtrip")
            unauthorized_probe("code_rotated_away_and_back", b"stale-after-roundtrip")

            a = OathSession(a_conn)
            a.validate(key2)
            put(a, b"validated-after-roundtrip")
            b.reset()
            assert not b.has_key
            b.set_key(key2)
            put(b, b"owner-after-reset")
            unauthorized_probe("app_reset_then_same_code_reinstalled", b"stale-after-reset")

            a = OathSession(a_conn)
            a.validate(key2)
            put(a, b"validated-after-reset")
            assert len(a.list_credentials()) >= 2

            continuations = []
            for label, command, next_key in (
                ("send_remaining_after_code_rotation", bytes.fromhex("00a50000"), key1),
                ("get_response_after_code_rotation", bytes.fromhex("00c00000"), key2),
            ):
                first, first_sw = a_conn.send_and_receive(bytes.fromhex("00a1000001"))
                assert len(first) == 1 and first_sw & 0xFF00 == 0x6100
                b.set_key(next_key)
                before = state_digest(directory / "state.bin")
                data, sw = a_conn.send_and_receive(command)
                after = state_digest(directory / "state.bin")
                if args.variant == "baseline":
                    assert data and (sw == 0x9000 or sw & 0xFF00 == 0x6100)
                else:
                    assert not data and sw == 0x6982
                assert before == after
                continuations.append({
                    "name": label,
                    "status": f"{sw:04x}",
                    "leaked_previous_response": bool(data),
                    "state_changed": before != after,
                })
                a = OathSession(a_conn)
                a.validate(next_key)
                assert len(a.list_credentials()) >= 2
            result = {
                "passed": True,
                "variant": args.variant,
                "platform": args.platform,
                "route": "ifd" if args.ifd_driver else "socket",
                "unmodified_yubikit": True,
                "two_private_clients": True,
                "physical_or_host_device_access": False,
                "network_devices": False,
                "core_sha256": digest(root / "emucard/core.py"),
                "phases": phases,
                "continuations": continuations,
                "normal_sdk_reauthorization": True,
            }
        finally:
            if peer:
                peer.close()
            fixture.stop()
    args.result.parent.mkdir(parents=True, exist_ok=True)
    args.result.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
