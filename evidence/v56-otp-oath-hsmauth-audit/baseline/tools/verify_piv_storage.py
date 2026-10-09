#!/usr/bin/env python3
"""Check PIV data buffer, storage budgeting and protected reads on fresh state.

The published 3072/51200 byte ceilings are modeled; exact firmware APDU header
and NVM allocation overhead are unmeasured. No physical reader is opened.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from emucard.core import Card, EmulatorConnection, EncryptedState
from verify_smartcard import Fixture
from yubikit.core import Tlv
from yubikit.core.smartcard import ApduError, SmartCardProtocol
from yubikit.piv import DEFAULT_MANAGEMENT_KEY, KEY_TYPE, SLOT, PivSession


def run(root, directory, report):
    tests = []
    completed = False

    def check(value, name):
        if not value:
            raise AssertionError(name)
        tests.append({"name": name, "passed": True})
        print("PASS", name, flush=True)

    def denied(sw, fn, name):
        try:
            fn()
        except ApduError as error:
            check(error.sw == sw, name)
        else:
            raise AssertionError("accepted forbidden operation: " + name)

    fixture = Fixture(root, directory)
    try:
        connection = fixture.start()
        piv = PivSession(connection)
        piv.authenticate(DEFAULT_MANAGEMENT_KEY)
        piv.protocol = SmartCardProtocol(connection)
        piv.protocol.configure(piv.version, force_short=True)
        oid = 0x5FFF05
        piv.put_object(oid, bytes(range(256)) * 11 + bytes(range(247)))
        check(
            len(piv.get_object(oid)) == 3063,
            "modeled plaintext buffer accounts for object selector and outer TLV",
        )
        old_file = (directory / "state.bin").read_bytes()
        denied(
            0x6700,
            lambda: piv.put_object(oid, b"x" * 3064),
            "one byte above modeled APDU data buffer is rejected",
        )
        check(
            (directory / "state.bin").read_bytes() == old_file,
            "oversized short-APDU chain does not rewrite encrypted state",
        )
        denied(
            0x6700,
            lambda: piv.put_object(oid, b"x" * 14336),
            "SDK command chaining cannot bypass PIV data buffer limit",
        )
        check(
            len(piv.get_object(oid)) == 3063,
            "failed chained replacement preserves previous object",
        )
        piv.put_object(oid, b"")
        key = piv.generate_key(SLOT.AUTHENTICATION, KEY_TYPE.ECCP256)
        leaf = piv.attest_key(SLOT.AUTHENTICATION)
        check(
            leaf.public_key().public_numbers() == key.public_numbers(),
            "own software attestation is established before storage capacity test",
        )
        snapshot = EncryptedState(directory / "state.bin").data
        root_size = sum(
            len(value) // 2 for value in snapshot["piv"]["objects"].values()
        )
        check(
            0 < root_size < 1024,
            "own attestation certificate occupies the shared data-object budget",
        )
        objects = [0x5F0100 + index for index in range(16)]
        for tag in objects:
            piv.put_object(tag, b"a" * 3063)
        remaining = 51200 - root_size - len(objects) * 3063
        piv.put_object(oid, b"b" * remaining)
        snapshot = EncryptedState(directory / "state.bin").data
        check(
            sum(len(value) // 2 for value in snapshot["piv"]["objects"].values())
            == 51200,
            "multiple independent objects fill the modeled shared 51200-byte budget",
        )
        old_file = (directory / "state.bin").read_bytes()
        denied(
            0x6A84,
            lambda: piv.put_object(0x5F0200, b"c"),
            "new object cannot allocate one byte beyond shared storage budget",
        )
        check(
            (directory / "state.bin").read_bytes() == old_file,
            "capacity rejection is atomic on encrypted persistent state",
        )
        denied(
            0x6A84,
            lambda: piv.put_object(oid, b"d" * (remaining + 1)),
            "replacement cannot increase allocation beyond shared budget",
        )
        check(
            piv.get_object(oid) == b"b" * remaining,
            "out-of-space replacement preserves old object bytes",
        )
        piv.put_object(oid, b"d" * remaining)
        check(
            piv.get_object(oid) == b"d" * remaining,
            "same-size replacement releases its old allocation before budgeting",
        )
        piv.generate_key(SLOT.SIGNATURE, KEY_TYPE.ECCP256)
        check(
            piv.get_slot_metadata(SLOT.SIGNATURE).generated,
            "private-key generation remains available while data storage is full",
        )
        check(
            piv.attest_key(SLOT.SIGNATURE).issuer == leaf.issuer,
            "existing software CA can attest another generated key at full budget",
        )
        piv.put_object(oid, b"d" * (remaining - 1))
        piv.put_object(0x5F0200, b"c")
        check(
            piv.get_object(0x5F0200) == b"c",
            "shrinking a replacement releases space for another object",
        )
        piv.put_object(objects[0], b"")
        piv.put_object(0x5F0201, b"e" * 3063)
        check(
            piv.get_object(0x5F0201) == b"e" * 3063,
            "deleting an object releases its complete allocation",
        )
        connection = fixture.restart()
        piv = PivSession(connection)
        piv.authenticate(DEFAULT_MANAGEMENT_KEY)
        piv.protocol = SmartCardProtocol(connection)
        piv.protocol.configure(piv.version, force_short=True)
        denied(
            0x6A84,
            lambda: piv.put_object(0x5F0202, b"f"),
            "shared capacity accounting survives encrypted-state reload",
        )
        denied(
            0x6A82,
            lambda: piv.get_object(objects[0]),
            "deleted object remains absent after service restart",
        )
        piv.put_object(0x5F0201, b"")
        for tag in (0x5FC103, 0x5FC108, 0x5FC109, 0x5FC121):
            piv.put_object(tag, b"private")
            denied(
                0x6982,
                lambda tag=tag: piv.get_object(tag),
                f"protected PIV object {tag:06x} requires PIN after reconnect",
            )
        piv.verify_pin("123456")
        check(
            all(
                piv.get_object(tag) == b"private"
                for tag in (0x5FC103, 0x5FC108, 0x5FC109, 0x5FC121)
            ),
            "verified PIN authorizes all four documented protected PIV data objects",
        )
        denied(
            0x6A80,
            lambda: piv.put_object(0x600000, b"invalid"),
            "data tags outside documented PIV range are rejected",
        )
        denied(
            0x6A86,
            lambda: piv.protocol.send_apdu(
                0, 0xDB, 0, 0, Tlv(0x5C, oid.to_bytes(3, "big")) + Tlv(0x53, b"bad")
            ),
            "PUT DATA rejects incorrect P1/P2 before writing an object",
        )
        denied(
            0x6A86,
            lambda: piv.protocol.send_apdu(
                0, 0xCB, 0, 0, Tlv(0x5C, oid.to_bytes(3, "big"))
            ),
            "GET DATA rejects incorrect P1/P2",
        )

        legacy = EncryptedState(directory / "legacy.bin")
        legacy.data["piv"]["objects"] = {
            str(0x5F0100): (b"a" * 50000).hex(),
            str(0x5F0101): (b"b" * 4000).hex(),
        }
        legacy.flush()
        legacy_piv = PivSession(EmulatorConnection(Card(legacy, lambda _: True)))
        legacy_piv.authenticate(DEFAULT_MANAGEMENT_KEY)
        legacy_piv.put_object(0x5F0101, b"c" * 2000)
        check(
            len(legacy_piv.get_object(0x5F0101)) == 2000,
            "legacy over-capacity state permits a shrinking replacement",
        )
        legacy_piv.put_object(0x5F0101, b"")
        check(
            str(0x5F0101) not in legacy.data["piv"]["objects"],
            "legacy over-capacity state permits deleting objects to recover space",
        )

        fresh = EncryptedState(directory / "attestation.bin")
        card = Card(fresh, lambda _: True)
        fresh_piv = PivSession(EmulatorConnection(card))
        fresh_piv.authenticate(DEFAULT_MANAGEMENT_KEY)
        fresh_piv.generate_key(SLOT.AUTHENTICATION, KEY_TYPE.ECCP256)
        certificate_value = fresh.data["piv"]["objects"][str(0x5FFF01)]
        certificate_size = len(certificate_value) // 2
        fresh.data["piv"]["objects"] = {
            str(0x5FFF01): certificate_value,
            str(0x5F0100): (b"a" * (51200 - certificate_size)).hex(),
        }
        fresh.flush()
        old_state = copy.deepcopy(fresh.data)
        leaf = fresh_piv.attest_key(SLOT.AUTHENTICATION)
        check(
            leaf is not None,
            "preinitialized software issuer signs successfully when object storage is full",
        )
        check(
            fresh.data == old_state,
            "attestation consumes no new allocation or key fields at full storage capacity",
        )
        completed = True
    finally:
        fixture.stop()
        report.write_text(
            json.dumps(
                {
                    "passed": completed,
                    "tests": tests,
                    "scope": "fresh software model and independent SDK; no physical reader",
                    "buffer_model": "assembled plaintext APDU data <= 3072; outer TLV counted",
                    "storage_model": "sum of stored object values <= 51200; private keys excluded",
                    "hardware_allocation_boundaries_verified": False,
                    "known_unverified": [
                        "exact firmware APDU header and NVM record overhead",
                        "documented 3052-byte certificate boundary versus modeled APDU payload ceiling",
                        "firmware error status at allocation boundaries",
                        "own initial attestation object occupies a modeled value budget; exact firmware reservation overhead unmeasured",
                    ],
                    "sources": [
                        "https://docs.yubico.com/yesdk/users-manual/application-piv/cert-size.html",
                        "https://docs.yubico.com/yesdk/users-manual/application-piv/piv-objects.html",
                    ],
                },
                indent=2,
            )
            + "\n"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(
        prefix="ske-piv-", dir=args.work_dir or "/tmp"
    ) as directory:
        run(Path(__file__).resolve().parents[1], Path(directory), args.report.resolve())


if __name__ == "__main__":
    main()
