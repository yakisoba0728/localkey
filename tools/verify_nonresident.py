#!/usr/bin/env python3
"""Verify stateless software FIDO/U2F with independent SDK/crypto and fresh state.

Reads only test-generated encrypted files. Never opens a physical HID device.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fido2 import cbor
from fido2.attestation import PackedAttestation
from fido2.cose import ES256
from fido2.ctap import CtapError
from fido2.ctap1 import ApduError, Ctap1
from fido2.ctap2 import ClientPin, CredentialManagement
from fido2.ctap2.pin import PinProtocolV1, PinProtocolV2
from verify_ctap import Fixture

RP = {"id": "localhost", "name": "Stateless fixture"}
CHALLENGE = hashlib.sha256(b"independent local stateless tests").digest()


def read_store(directory):
    raw = (directory / "state.bin").read_bytes()
    assert raw[:4] == b"SWPK"
    assert len(raw) == 40 + struct.unpack("<I", raw[36:40])[0] + 16
    key = (directory / "state.bin.dek").read_bytes()
    return cbor.decode(AESGCM(key).decrypt(raw[24:36], raw[40:], raw[:24]))


def hmac_result(ctap, credential, protocol, token=None):
    agreement = ctap.client_pin(protocol.VERSION, ClientPin.CMD.GET_KEY_AGREEMENT)[1]
    platform, shared = protocol.encapsulate(agreement)
    salts = hashlib.sha256(b"salt one").digest() + hashlib.sha256(b"salt two").digest()
    encrypted = protocol.encrypt(shared, salts)
    extension = {1: platform, 2: encrypted, 3: protocol.authenticate(shared, encrypted)}
    if protocol.VERSION == 2:
        extension[4] = 2
    assertion = ctap.get_assertion(
        RP["id"],
        CHALLENGE,
        allow_list=[{"type": "public-key", "id": credential.credential_id}],
        extensions={"hmac-secret": extension},
        pin_uv_param=protocol.authenticate(token, CHALLENGE) if token else None,
        pin_uv_protocol=protocol.VERSION if token else None,
    )
    credential.public_key.verify(
        bytes(assertion.auth_data) + CHALLENGE, assertion.signature
    )
    return protocol.decrypt(shared, assertion.auth_data.extensions["hmac-secret"])


def run(binary, directory, report):
    results = []
    fixture = Fixture(binary, directory)
    completed = False

    def check(value, name):
        if not value:
            raise AssertionError(name)
        results.append({"name": name, "passed": True})
        print("PASS", name, flush=True)

    def rejects(code, operation, name):
        try:
            operation()
        except CtapError as error:
            check(int(error.code) == code, name)
        else:
            raise AssertionError("accepted invalid operation: " + name)

    def make(ctap, alg=-7, protection=1):
        attestation = ctap.make_credential(
            CHALLENGE,
            RP,
            {"id": os.urandom(16), "name": "Independent fixture user"},
            [{"type": "public-key", "alg": alg}],
            options={"rk": False},
            extensions={
                "credBlob": bytes(range(32)),
                "credProtect": protection,
                "hmac-secret": True,
            },
        )
        PackedAttestation().verify(
            attestation.att_stmt, attestation.auth_data, CHALLENGE
        )
        assert attestation.auth_data.extensions["credBlob"] is False, (
            f"algorithm {alg} published discoverable-only credBlob profile"
        )
        return attestation.auth_data.credential_data

    try:
        ct = fixture.start()
        credentials = {}
        for alg in (-7, -8, -35):
            credential = credentials[alg] = make(ct, alg)
            check(
                len(credential.credential_id) == ct.info.max_cred_id_length == 128,
                f"algorithm {alg} packed self-attestation carries bounded independent wrapped ID",
            )
            assertion = ct.get_assertion(
                RP["id"],
                CHALLENGE,
                allow_list=[{"type": "public-key", "id": credential.credential_id}],
                extensions={"getCredBlob": True},
            )
            credential.public_key.verify(
                bytes(assertion.auth_data) + CHALLENGE, assertion.signature
            )
            check(
                assertion.user is None
                and assertion.auth_data.extensions["credBlob"] == b"",
                f"algorithm {alg} verifies independently with empty credBlob and no stored user identity",
            )
        snapshot = read_store(directory)
        check(
            snapshot["creds"] == [] and len(snapshot["nonresident_key"]) == 32,
            "actual encrypted store contains one root and no nonresident credential rows",
        )
        before = (directory / "state.bin").read_bytes()
        more = [make(ct) for _ in range(120)]
        check(
            len({c.credential_id for c in more}) == len(more),
            "repeated account registrations have unique randomized opaque IDs",
        )
        check(
            (directory / "state.bin").read_bytes() == before
            and ct.get_info().remaining_disc_creds == 100,
            "nonresident registration does not rewrite initialized store or consume discoverable capacity",
        )
        rejects(
            0x2E,
            lambda: ct.get_assertion(RP["id"], CHALLENGE),
            "nonresident credentials cannot be discovered by RP alone",
        )
        descriptor = {"type": "public-key", "id": credentials[-7].credential_id}
        rejects(
            0x19,
            lambda: ct.make_credential(
                CHALLENGE,
                RP,
                {"id": b"new"},
                [{"type": "public-key", "alg": -7}],
                exclude_list=[descriptor],
            ),
            "excludeList recognizes stateless credential after registration",
        )
        ct.make_credential(
            CHALLENGE,
            {"id": "other.example"},
            {"id": b"new"},
            [{"type": "public-key", "alg": -7}],
            exclude_list=[descriptor],
        )
        check(True, "credential from another RP does not incorrectly trigger exclusion")
        rejects(
            0x2E,
            lambda: ct.get_assertion(
                "other.example", CHALLENGE, allow_list=[descriptor]
            ),
            "wrapped key is cryptographically bound to the RP hash",
        )
        for offset in (0, 3, 4, 16, 52, 127):
            bad = bytearray(descriptor["id"])
            bad[offset] ^= 1
            rejects(
                0x2E,
                lambda bad=bad: ct.get_assertion(
                    RP["id"],
                    CHALLENGE,
                    allow_list=[{"type": "public-key", "id": bytes(bad)}],
                ),
                f"wrapped ID tampering at byte {offset} is rejected",
            )
        for candidate in (descriptor["id"][:-1], descriptor["id"] + b"x"):
            rejects(
                0x2E,
                lambda candidate=candidate: ct.get_assertion(
                    RP["id"],
                    CHALLENGE,
                    allow_list=[{"type": "public-key", "id": candidate}],
                ),
                "wrong-sized stateless ID cannot resolve a key",
            )
        first_hmac = hmac_result(ct, credentials[-8], PinProtocolV1())
        check(
            len(first_hmac) == 64 and first_hmac[:32] != first_hmac[32:],
            "stateless hmac-secret produces distinct results for two salts",
        )
        check(
            first_hmac == hmac_result(ct, credentials[-8], PinProtocolV2()),
            "PIN protocols 1 and 2 produce identical no-UV stateless hmac-secret",
        )
        counter = read_store(directory)["nonresident_counter"]
        ct = fixture.restart()
        for alg, credential in credentials.items():
            assertion = ct.get_assertion(
                RP["id"],
                CHALLENGE,
                allow_list=[{"type": "public-key", "id": credential.credential_id}],
            )
            credential.public_key.verify(
                bytes(assertion.auth_data) + CHALLENGE, assertion.signature
            )
            check(
                assertion.auth_data.counter > counter,
                f"algorithm {alg} resumes from ID with durable shared counter after process restart",
            )
            counter = assertion.auth_data.counter
        check(
            first_hmac == hmac_result(ct, credentials[-8], PinProtocolV2()),
            "stateless hmac-secret remains stable after encrypted-store restart",
        )

        protocol = PinProtocolV2()
        client_pin = ClientPin(ct, protocol)
        client_pin.set_pin("123456")
        token = client_pin.get_pin_token(
            "123456",
            ClientPin.PERMISSION.GET_ASSERTION | ClientPin.PERMISSION.MAKE_CREDENTIAL,
            RP["id"],
        )
        uv_hmac = hmac_result(ct, credentials[-8], protocol, token)
        check(
            uv_hmac != first_hmac
            and uv_hmac == hmac_result(ct, credentials[-8], protocol, token),
            "stateless hmac-secret preserves independent stable UV and no-UV secrets",
        )
        protected = make(ct, protection=3)
        protected_descriptor = {"type": "public-key", "id": protected.credential_id}
        rejects(
            0x2E,
            lambda: ct.get_assertion(
                RP["id"], CHALLENGE, allow_list=[protected_descriptor]
            ),
            "authenticated wrapped credProtect 3 blocks assertions without PIN",
        )
        assertion = ct.get_assertion(
            RP["id"],
            CHALLENGE,
            allow_list=[protected_descriptor],
            pin_uv_param=protocol.authenticate(token, CHALLENGE),
            pin_uv_protocol=2,
        )
        protected.public_key.verify(
            bytes(assertion.auth_data) + CHALLENGE, assertion.signature
        )
        check(
            assertion.auth_data.is_user_verified(),
            "PIN-authorized wrapped protected key signs successfully",
        )
        u2f = Ctap1(fixture.device)
        application = hashlib.sha256(RP["id"].encode()).digest()
        try:
            u2f.authenticate(CHALLENGE, application, protected.credential_id)
        except ApduError as error:
            check(
                error.code == 0x6A80,
                "U2F authentication cannot bypass wrapped credProtect 3",
            )
        else:
            raise AssertionError("U2F bypassed credential protection")
        for alg in (-8, -35):
            try:
                u2f.authenticate(CHALLENGE, application, credentials[alg].credential_id)
            except ApduError as error:
                check(error.code == 0x6A80, f"U2F rejects wrapped algorithm {alg}")
            else:
                raise AssertionError("U2F accepted non-ES256 key")
        u2f.authenticate(CHALLENGE, application, credentials[-7].credential_id).verify(
            application,
            CHALLENGE,
            b"\x04" + credentials[-7].public_key[-2] + credentials[-7].public_key[-3],
        )
        check(
            True,
            "wrapped ES256 CTAP2 credential is usable through U2F with its RP application hash",
        )
        registration = u2f.register(CHALLENGE, application)
        registration.verify(application, CHALLENGE)
        u2f.authenticate(CHALLENGE, application, registration.key_handle).verify(
            application, CHALLENGE, registration.public_key
        )
        check(
            len(registration.key_handle) == 128
            and read_store(directory)["creds"] == [],
            "U2F wrapped registration and signature require no credential row",
        )
        assertion = ct.get_assertion(
            RP["id"],
            CHALLENGE,
            allow_list=[{"type": "public-key", "id": registration.key_handle}],
        )
        ES256.from_ctap1(registration.public_key).verify(
            bytes(assertion.auth_data) + CHALLENGE, assertion.signature
        )
        check(
            assertion.user is None,
            "U2F wrapped handle resolves through CTAP2 without a user entity",
        )
        cm_token = client_pin.get_pin_token(
            "123456", ClientPin.PERMISSION.CREDENTIAL_MGMT
        )
        management = CredentialManagement(ct, protocol, cm_token)
        check(
            management.get_metadata()[1] == 0 and management.get_metadata()[2] == 100,
            "credential management counts exclude all stateless CTAP2 and U2F registrations",
        )
        token = client_pin.get_pin_token(
            "123456",
            ClientPin.PERMISSION.MAKE_CREDENTIAL,
            RP["id"],
        )
        for index in range(100):
            ct.make_credential(
                CHALLENGE,
                RP,
                {"id": index.to_bytes(2, "big")},
                [{"type": "public-key", "alg": -7}],
                options={"rk": True},
                pin_uv_param=protocol.authenticate(token, CHALLENGE),
                pin_uv_protocol=2,
            )
        check(
            ct.get_info().remaining_disc_creds == 0,
            "discoverable credential capacity remains exactly 100",
        )
        make(ct)
        full_registration = u2f.register(CHALLENGE, application)
        full_registration.verify(application, CHALLENGE)
        check(
            len(read_store(directory)["creds"]) == 100,
            "CTAP2 and U2F stateless registration both work when discoverable storage is full",
        )
        fixture.stop()
        ct = fixture.start()
        ct.reset()
        rejects(
            0x2E,
            lambda: ct.get_assertion(RP["id"], CHALLENGE, allow_list=[descriptor]),
            "factory reset invalidates old wrapped ID even though it had no store row",
        )
        fresh = make(ct)
        check(
            fresh.credential_id != descriptor["id"]
            and ct.get_info().remaining_disc_creds == 100,
            "post-reset registrations use a fresh root and restored discoverable capacity",
        )
        fixture.stop()

        legacy_dir = directory / "v2"
        legacy_dir.mkdir()
        legacy = Fixture(binary, legacy_dir)
        try:
            old_ct = legacy.start()
            attestation = old_ct.make_credential(
                CHALLENGE,
                RP,
                {"id": b"legacy"},
                [{"type": "public-key", "alg": -7}],
                options={"rk": True},
            )
            legacy_credential = attestation.auth_data.credential_data
            legacy.stop()
            saved = read_store(legacy_dir)
            saved["creds"][0]["rk"] = False
            raw = (legacy_dir / "state.bin").read_bytes()
            header = raw[:4] + b"\x02\0" + raw[6:24]
            nonce = os.urandom(12)
            plaintext = cbor.encode(saved)
            encrypted = AESGCM((legacy_dir / "state.bin.dek").read_bytes()).encrypt(
                nonce, plaintext, header
            )
            (legacy_dir / "state.bin").write_bytes(
                header + nonce + struct.pack("<I", len(plaintext)) + encrypted
            )
            old_ct = legacy.start()
            assertion = old_ct.get_assertion(
                RP["id"],
                CHALLENGE,
                allow_list=[
                    {"type": "public-key", "id": legacy_credential.credential_id}
                ],
            )
            legacy_credential.public_key.verify(
                bytes(assertion.auth_data) + CHALLENGE, assertion.signature
            )
            check(
                (legacy_dir / "state.bin").read_bytes()[4:6] == b"\x03\0",
                "previous v2 nonresident row retains its original key and migrates durably to v3",
            )
            make(old_ct)
            check(
                len(read_store(legacy_dir)["creds"]) == 1,
                "new wrapped registrations coexist with retained legacy nonresident row",
            )
        finally:
            legacy.stop()
        completed = True
    finally:
        fixture.stop()
        report.write_text(
            json.dumps(
                {
                    "passed": completed,
                    "tests": results,
                    "scope": "fresh software backend, independent fido2 SDK and crypto; actual encrypted test store inspection",
                    "physical_device_access": False,
                    "manufacturer_wrapping_format_reproduced": False,
                    "remaining": [
                        "exact reference counter timing/rollover and opaque credential ID format",
                        "published discoverable-only credBlob profile has not been differentially measured",
                        "hardware primary backends retain stored-handle behavior",
                        "legacy nonresident rows remain stored for compatibility",
                    ],
                },
                indent=2,
            )
            + "\n"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(
        prefix="ske-nr-", dir=args.work_dir or "/tmp"
    ) as directory:
        run(args.binary.resolve(), Path(directory), args.report.resolve())


if __name__ == "__main__":
    main()
