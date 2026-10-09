#!/usr/bin/env python3
"""A/B PIV GENERATE P1 rejection with stock YubiKit and private card routes."""

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

from yubikit.piv import DEFAULT_MANAGEMENT_KEY, KEY_TYPE, SLOT, PivSession


def run(root: Path, ifd: Path | None, fixed: bool):
    sys.path.insert(0, str(root))
    sys.path.insert(0, str(root / "tools"))
    from emucard.core import Apdu, EncryptedState
    from verify_smartcard import Fixture

    rows = []
    for p1 in (0x01, 0xFF):
        with tempfile.TemporaryDirectory(prefix="ske62-piv-generate-", dir="/tmp") as temporary:
            directory = Path(temporary)
            fixture = Fixture(root, directory, ifd)
            try:
                conn = fixture.start()
                piv = PivSession(conn)
                piv.authenticate(DEFAULT_MANAGEMENT_KEY)
                piv.generate_key(SLOT.AUTHENTICATION, KEY_TYPE.ECCP256)
                before_key = piv.get_slot_metadata(SLOT.AUTHENTICATION).public_key_encoded
                before_state = EncryptedState(directory / "state.bin").data["piv"]["keys"]
                before_file = (directory / "state.bin").read_bytes()

                malformed = bytes((0, 0x47, p1, 0x9A, 5, 0xAC, 3, 0x80, 1, 0x11))
                response, sw = conn.send_and_receive(malformed)
                assert sw == (0x6A86 if fixed else 0x9000), (p1, hex(sw))
                assert bool(response) != fixed
                after_file = (directory / "state.bin").read_bytes()
                after_key = piv.get_slot_metadata(SLOT.AUTHENTICATION).public_key_encoded
                after_state = EncryptedState(directory / "state.bin").data["piv"]["keys"]
                assert (after_key == before_key) == fixed
                assert (after_state == before_state) == fixed
                assert (after_file == before_file) == fixed

                # Both rejection and replacement must survive a private card
                # restart. The normal SDK command must still generate a key.
                conn = fixture.restart()
                piv = PivSession(conn)
                assert (piv.get_slot_metadata(SLOT.AUTHENTICATION).public_key_encoded == before_key) == fixed
                piv.authenticate(DEFAULT_MANAGEMENT_KEY)
                emitted = []
                original_send = conn.send_and_receive

                def capture(packet):
                    emitted.append(bytes(packet))
                    return original_send(packet)

                conn.send_and_receive = capture
                piv.generate_key(SLOT.AUTHENTICATION, KEY_TYPE.ECCP256)
                sdk_wire = next(packet for packet in reversed(emitted) if packet[1] == 0x47)
                sdk_apdu = Apdu.decode(sdk_wire)
                assert (sdk_apdu.cla, sdk_apdu.ins, sdk_apdu.p1, sdk_apdu.p2) == (0, 0x47, 0, 0x9A)
                assert sdk_apdu.le is None
                normal_key = piv.get_slot_metadata(SLOT.AUTHENTICATION).public_key_encoded
                assert normal_key not in (before_key, after_key)
                piv = PivSession(fixture.restart())
                assert piv.get_slot_metadata(SLOT.AUTHENTICATION).public_key_encoded == normal_key

                rows.append({"name": f"wrong_p1_{p1:02x}",
                             "malformed_apdu": malformed.hex(), "malformed_sw": f"{sw:04x}",
                             "old_public_key_preserved": after_key == before_key,
                             "decrypted_key_state_unchanged": after_state == before_state,
                             "encrypted_state_bytes_unchanged": after_file == before_file,
                             "valid_sdk_apdu": sdk_wire.hex(),
                             "normal_sdk_key_persists_after_restart": True,
                             "passed": True})
            finally:
                fixture.stop()
    return {"passed": True, "fixed": fixed,
            "route": "direct IFD" if ifd else "private CCID socket",
            "rows": rows,
            "core_sha256": hashlib.sha256((root / "emucard/core.py").read_bytes()).hexdigest(),
            "physical_or_host_device_access": False,
            "firmware_5_7_4_differential": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--ifd", type=Path)
    parser.add_argument("--fixed", action="store_true")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.root.resolve(), args.ifd.resolve() if args.ifd else None, args.fixed)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "cases": len(report["rows"]),
                      "route": report["route"], "fixed": args.fixed}))


if __name__ == "__main__":
    main()
