#!/usr/bin/env python3
"""A/B OpenPGP SET PIN RETRIES APDU header, private CCID or direct IFD only."""

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

from yubikit.openpgp import OpenPgpSession


CASES = (
    ("wrong_p1", "00f2010003040506", 0x6A86),
    ("wrong_p2", "00f2000103040506", 0x6A86),
    ("short_le_1", "00f200000304050601", 0x6700),
    ("extended_le_256", "00f200000000030405060100", 0x6700),
)


def counts(status):
    return [status.attempts_user, status.attempts_reset, status.attempts_admin]


def run(root: Path, ifd: Path | None, fixed: bool):
    sys.path.insert(0, str(root))
    sys.path.insert(0, str(root / "tools"))
    from emucard.core import Apdu, EncryptedState
    from verify_smartcard import Fixture

    rows = []
    for name, apdu_hex, fixed_sw in CASES:
        with tempfile.TemporaryDirectory(prefix="ske61-pgp-f2-", dir="/tmp") as temp:
            directory = Path(temp)
            fixture = Fixture(root, directory, ifd)
            try:
                conn = fixture.start()
                pgp = OpenPgpSession(conn)
                pgp.verify_admin("12345678")
                pgp.set_reset_code("87654321")
                assert counts(pgp.get_pin_status()) == [3, 3, 3]
                before = EncryptedState(directory / "state.bin").data["openpgp"]
                before_wire = (directory / "state.bin").read_bytes()

                raw = bytes.fromhex(apdu_hex)
                decoded = Apdu.decode(raw)
                response, sw = conn.send_and_receive(raw)
                assert response == b""
                assert sw == (fixed_sw if fixed else 0x9000), (name, hex(sw))
                after = EncryptedState(directory / "state.bin").data["openpgp"]
                after_wire = (directory / "state.bin").read_bytes()
                assert (after == before) == fixed
                assert (after_wire == before_wire) == fixed
                assert counts(pgp.get_pin_status()) == ([3, 3, 3] if fixed else [4, 5, 6])

                # Confirm the result survives service restart. Then use the
                # unmodified SDK to issue the valid command on that card.
                conn = fixture.restart()
                pgp = OpenPgpSession(conn)
                assert counts(pgp.get_pin_status()) == ([3, 3, 3] if fixed else [4, 5, 6])
                pgp.verify_admin("12345678")
                emitted = []
                original_send = conn.send_and_receive

                def capture(packet):
                    emitted.append(bytes(packet))
                    return original_send(packet)

                conn.send_and_receive = capture
                pgp.set_pin_attempts(7, 8, 9)
                sdk_wire = next(packet for packet in reversed(emitted) if packet[1] == 0xF2)
                sdk_apdu = Apdu.decode(sdk_wire)
                assert (sdk_apdu.cla, sdk_apdu.ins, sdk_apdu.p1, sdk_apdu.p2) == (0, 0xF2, 0, 0)
                assert sdk_apdu.data == b"\x07\x08\x09" and sdk_apdu.le is None
                assert counts(pgp.get_pin_status()) == [7, 8, 9]
                pgp = OpenPgpSession(fixture.restart())
                assert counts(pgp.get_pin_status()) == [7, 8, 9]

                rows.append({"name": name, "malformed_apdu": apdu_hex,
                             "decoded_p1": decoded.p1, "decoded_p2": decoded.p2,
                             "decoded_le": decoded.le,
                             "malformed_sw": f"{sw:04x}",
                             "malformed_state_unchanged": after == before,
                             "malformed_encrypted_bytes_unchanged": after_wire == before_wire,
                             "unmodified_sdk_wire": sdk_wire.hex(),
                             "valid_sdk_persisted_after_restart": True,
                             "passed": True})
            finally:
                fixture.stop()
    return {"passed": True, "fixed": fixed,
            "transport": "direct IFD" if ifd else "private CCID socket",
            "rows": rows,
            "core_sha256": hashlib.sha256((root / "emucard/core.py").read_bytes()).hexdigest(),
            "physical_or_host_device_access": False,
            "firmware_5_7_4_differential": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--ifd", type=Path)
    parser.add_argument("--fixed", action="store_true")
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    report = run(args.root.resolve(), args.ifd.resolve() if args.ifd else None, args.fixed)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "count": len(report["rows"]),
                      "transport": report["transport"], "fixed": args.fixed}))


if __name__ == "__main__":
    main()
