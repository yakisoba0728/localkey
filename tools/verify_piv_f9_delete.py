#!/usr/bin/env python3
"""Yubico PIV 5.7 permits deleting F9 but forbids moving it."""

import argparse
import json
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from verify_smartcard import Fixture
from emucard.core import EncryptedState
from yubikit.core.smartcard import ApduError
from yubikit.piv import DEFAULT_MANAGEMENT_KEY, KEY_TYPE, PIN_POLICY, SLOT, PivSession


def denied(sw, callback):
    try:
        callback()
    except ApduError as error:
        assert error.sw == sw, hex(error.sw)
    else:
        raise AssertionError(f"expected APDU error {sw:04x}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--ifd", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--expect-fixed", action="store_true")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="piv-f9-delete-") as td:
        directory = Path(td)
        fixture = Fixture(args.root.resolve(), directory, args.ifd.resolve() if args.ifd else None)
        try:
            piv = PivSession(fixture.start())
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
            assert piv.get_slot_metadata(SLOT.ATTESTATION).key_type == KEY_TYPE.ECCP256
            pub = piv.generate_key(SLOT.AUTHENTICATION, KEY_TYPE.ECCP256)
            leaf = piv.attest_key(SLOT.AUTHENTICATION)
            issuer = piv.get_certificate(SLOT.ATTESTATION)
            issuer.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm))
            assert leaf.public_key().public_numbers() == pub.public_numbers()

            before_move = (directory / "state.bin").read_bytes()
            denied(0x6A86, lambda: piv.move_key(SLOT.ATTESTATION, SLOT.RETIRED2))
            assert (directory / "state.bin").read_bytes() == before_move

            before_delete = (directory / "state.bin").read_bytes()
            if args.expect_fixed:
                piv.delete_key(SLOT.ATTESTATION)
            else:
                denied(0x6A86, lambda: piv.delete_key(SLOT.ATTESTATION))
            after_delete = (directory / "state.bin").read_bytes()
            assert (after_delete != before_delete) == args.expect_fixed
            keys = EncryptedState(directory / "state.bin").data["piv"]["keys"]
            assert (str(int(SLOT.ATTESTATION)) in keys) != args.expect_fixed
            if args.expect_fixed:
                denied(0x6A88, lambda: piv.get_slot_metadata(SLOT.ATTESTATION))
                denied(0x6A88, lambda: piv.attest_key(SLOT.AUTHENTICATION))
            else:
                assert piv.get_slot_metadata(SLOT.ATTESTATION).key_type == KEY_TYPE.ECCP256

            piv = PivSession(fixture.restart())
            if args.expect_fixed:
                denied(0x6A88, lambda: piv.get_slot_metadata(SLOT.ATTESTATION))
            else:
                assert piv.get_slot_metadata(SLOT.ATTESTATION).key_type == KEY_TYPE.ECCP256
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
            piv.move_key(SLOT.AUTHENTICATION, SLOT.RETIRED1)
            assert piv.get_slot_metadata(SLOT.RETIRED1).key_type == KEY_TYPE.ECCP256
            piv.delete_key(SLOT.RETIRED1)
            denied(0x6A88, lambda: piv.get_slot_metadata(SLOT.RETIRED1))

            piv.reset()
            piv = PivSession(fixture.restart())
            if args.expect_fixed:
                denied(0x6A88, lambda: piv.get_slot_metadata(SLOT.ATTESTATION))
            else:
                assert piv.get_slot_metadata(SLOT.ATTESTATION).key_type == KEY_TYPE.ECCP256

            if args.expect_fixed:
                piv.authenticate(DEFAULT_MANAGEMENT_KEY)
                piv.put_key(SLOT.ATTESTATION, ec.generate_private_key(ec.SECP256R1()), PIN_POLICY.NEVER)
                assert piv.get_slot_metadata(SLOT.ATTESTATION).key_type == KEY_TYPE.ECCP256
                piv.reset()
                piv = PivSession(fixture.restart())
                assert piv.get_slot_metadata(SLOT.ATTESTATION).key_type == KEY_TYPE.ECCP256
            result = {
                "passed": True,
                "transport": "direct IFD" if args.ifd else "private CCID socket",
                "expect_fixed": args.expect_fixed,
                "f9_delete_succeeded": args.expect_fixed,
                "f9_move_rejected": True,
                "f9_deletion_persisted_across_restart": args.expect_fixed,
                "f9_deletion_persisted_across_piv_reset": args.expect_fixed,
                "normal_sdk_move_delete_and_attestation": True,
                "replacement_f9_survives_reset_after_deletion": args.expect_fixed,
                "physical_key_accessed": False,
            }
            result["tests"] = [
                "f9_delete_succeeded", "f9_move_rejected",
                "f9_deletion_persisted_across_restart",
                "f9_deletion_persisted_across_piv_reset",
                "normal_sdk_move_delete_and_attestation",
                "replacement_f9_survives_reset_after_deletion",
            ]
        finally:
            fixture.stop()

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
