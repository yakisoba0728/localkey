#!/usr/bin/env python3
"""Verify v0.2 store migration using fresh legacy state, never user credentials."""

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from fido2.attestation import PackedAttestation
from verify_ctap import Fixture


def run(legacy, binary, directory):
    old = Fixture(legacy, directory)
    new = Fixture(binary, directory)
    checks = []

    def check(value, name):
        if not value:
            raise AssertionError(name)
        checks.append({"name": name, "passed": True})
        print("PASS", name, flush=True)

    rp = {"id": "localhost", "name": "Migration fixture"}
    challenge = hashlib.sha256(b"fresh migration fixture").digest()
    try:
        ct = old.start()
        att = ct.make_credential(
            challenge,
            rp,
            {"id": b"migration", "name": "fixture"},
            [{"type": "public-key", "alg": -7}],
            options={"rk": True},
        )
        cred = att.auth_data.credential_data
        PackedAttestation().verify(att.att_stmt, att.auth_data, challenge)
        old.stop()
        check(
            (directory / "state.bin").read_bytes()[4:6] == b"\x01\0",
            "legacy daemon writes store v1",
        )
        ct = new.start()
        assertion = ct.get_assertions(
            "localhost", challenge, [{"type": "public-key", "id": cred.credential_id}]
        )[0]
        cred.public_key.verify(
            bytes(assertion.auth_data) + challenge, assertion.signature
        )
        check(
            True,
            "new daemon loads legacy private key and independently verified signature",
        )
        new.stop()
        check(
            (directory / "state.bin").read_bytes()[4:6] == b"\x03\0",
            "first mutation atomically migrates to store v3",
        )
        ct = new.start()
        assertion2 = ct.get_assertions(
            "localhost", challenge, [{"type": "public-key", "id": cred.credential_id}]
        )[0]
        cred.public_key.verify(
            bytes(assertion2.auth_data) + challenge, assertion2.signature
        )
        check(
            assertion2.auth_data.counter > assertion.auth_data.counter,
            "counter remains monotonic after migration and restart",
        )
        new.stop()
        try:
            old.start()
        except RuntimeError as e:
            check(
                "store_version_unsupported" in str(e),
                "legacy daemon refuses v3 instead of ignoring credential policy",
            )
        else:
            raise AssertionError("legacy daemon accepted new policy store")
        return {"passed": True, "tests": checks, "physical_device_access": False}
    finally:
        old.stop()
        new.stop()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--legacy-binary", required=True, type=Path)
    p.add_argument("--binary", required=True, type=Path)
    p.add_argument("--work-dir", required=True, type=Path)
    p.add_argument("--report", required=True, type=Path)
    a = p.parse_args()
    with tempfile.TemporaryDirectory(prefix="m", dir=a.work_dir.resolve()) as directory:
        result = run(a.legacy_binary.resolve(), a.binary.resolve(), Path(directory))
    a.report.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
