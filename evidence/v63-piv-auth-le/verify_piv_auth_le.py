#!/usr/bin/env python3
"""A/B malformed Le on PIV GENERAL AUTHENTICATE with PIN policy ALWAYS."""

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from yubikit.core import Tlv
from yubikit.core.smartcard import ApduError
from yubikit.piv import (
    DEFAULT_MANAGEMENT_KEY,
    KEY_TYPE,
    PIN_POLICY,
    SLOT,
    TOUCH_POLICY,
    PivSession,
)


MESSAGE = b"v63 PIV AUTHENTICATE Le authorization boundary"


def run(root: Path, ifd: Path | None, fixed: bool):
    sys.path.insert(0, str(root))
    sys.path.insert(0, str(root / "tools"))
    from emucard.core import Apdu, EncryptedState
    from verify_smartcard import Fixture

    with tempfile.TemporaryDirectory(prefix="ske63-piv-auth-le-", dir="/tmp") as temporary:
        directory = Path(temporary)
        fixture = Fixture(root, directory, ifd)
        try:
            conn = fixture.start()
            piv = PivSession(conn)
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
            public_key = piv.generate_key(
                SLOT.SIGNATURE, KEY_TYPE.ECCP256,
                PIN_POLICY.ALWAYS, TOUCH_POLICY.NEVER,
            )
            piv.verify_pin("123456")
            digest = hashes.Hash(hashes.SHA256())
            digest.update(MESSAGE)
            challenge = digest.finalize()
            data = bytes(Tlv(0x7C, Tlv(0x82, b"") + Tlv(0x81, challenge)))
            assert len(data) == 38
            malformed = bytes((0, 0x87, 0x11, 0x9C, len(data))) + data + b"\x01"
            assert Apdu.decode(malformed).le == 1
            before = EncryptedState(directory / "state.bin").data["piv"]
            before_file = (directory / "state.bin").read_bytes()
            first, sw = conn.send_and_receive(malformed)
            after_file = (directory / "state.bin").read_bytes()
            after = EncryptedState(directory / "state.bin").data["piv"]
            assert before == after
            if fixed:
                assert before_file == after_file

            if fixed:
                assert not first and sw == 0x6700, hex(sw)
            else:
                assert len(first) == 1 and sw & 0xFF00 == 0x6100, hex(sw)
                remaining = bytearray(first)
                while sw != 0x9000:
                    part, sw = conn.send_and_receive(bytes.fromhex("00c0000000"))
                    remaining.extend(part)
                signature = Tlv.unpack(0x82, Tlv.unpack(0x7C, bytes(remaining)))
                public_key.verify(signature, MESSAGE, ec.ECDSA(hashes.SHA256()))

            # A PIN_ALWAYS key grants exactly one valid signature. The malformed
            # command must not spend that authorization before a valid SDK call.
            emitted = []
            original_send = conn.send_and_receive

            def capture(packet):
                emitted.append(bytes(packet))
                return original_send(packet)

            conn.send_and_receive = capture
            try:
                sdk_signature = piv.sign(
                    SLOT.SIGNATURE, KEY_TYPE.ECCP256, MESSAGE, hashes.SHA256()
                )
            except ApduError as error:
                assert not fixed and error.sw == 0x6982, hex(error.sw)
                normal_after_malformed = "6982"
            else:
                assert fixed
                public_key.verify(sdk_signature, MESSAGE, ec.ECDSA(hashes.SHA256()))
                normal_after_malformed = "9000"

            piv.verify_pin("123456")
            sdk_signature = piv.sign(
                SLOT.SIGNATURE, KEY_TYPE.ECCP256, MESSAGE, hashes.SHA256()
            )
            public_key.verify(sdk_signature, MESSAGE, ec.ECDSA(hashes.SHA256()))
            sdk_wire = next(packet for packet in reversed(emitted) if packet[1] == 0x87)
            sdk_apdu = Apdu.decode(sdk_wire)
            assert (sdk_apdu.cla, sdk_apdu.ins, sdk_apdu.p1, sdk_apdu.p2) == (0, 0x87, 0x11, 0x9C)
            assert sdk_apdu.le is None
            try:
                piv.sign(SLOT.SIGNATURE, KEY_TYPE.ECCP256, MESSAGE, hashes.SHA256())
            except ApduError as error:
                assert error.sw == 0x6982
            else:
                raise AssertionError("valid PIN_ALWAYS signature did not spend authorization")

            piv = PivSession(fixture.restart())
            assert piv.get_slot_metadata(SLOT.SIGNATURE).pin_policy == PIN_POLICY.ALWAYS
            piv.verify_pin("123456")
            sdk_signature = piv.sign(
                SLOT.SIGNATURE, KEY_TYPE.ECCP256, MESSAGE, hashes.SHA256()
            )
            public_key.verify(sdk_signature, MESSAGE, ec.ECDSA(hashes.SHA256()))
            return {"passed": True, "fixed": fixed,
                    "route": "direct IFD" if ifd else "private CCID socket",
                    "malformed_apdu": malformed.hex(), "malformed_sw": f"{sw:04x}" if fixed else "61xx_then_9000",
                    "baseline_malformed_signature_verified": not fixed,
                    "malformed_persistent_state_unchanged": before == after,
                    "malformed_encrypted_state_bytes_unchanged": before_file == after_file,
                    "normal_sdk_after_malformed": normal_after_malformed,
                    "normal_sdk_wire": sdk_wire.hex(),
                    "normal_sdk_signature_verified_after_reverify": True,
                    "normal_sdk_key_persists_after_restart": True,
                    "core_sha256": hashlib.sha256((root / "emucard/core.py").read_bytes()).hexdigest(),
                    "physical_or_host_device_access": False,
                    "firmware_5_7_4_differential": False}
        finally:
            fixture.stop()


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
    print(json.dumps({"passed": report["passed"], "route": report["route"],
                      "fixed": args.fixed, "normal_sdk_after_malformed": report["normal_sdk_after_malformed"]}))


if __name__ == "__main__":
    main()
