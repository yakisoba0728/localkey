#!/usr/bin/env python3
"""Compare public GetInfo with the saved reference; test limits on fresh software state.

This verifier never enumerates or sends commands to physical security keys.
The reference observation is metadata, not a full firmware conformance oracle.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import tempfile
from pathlib import Path

from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Config, Info
from fido2.ctap2.pin import PinProtocolV2
from fido2.hid import CTAPHID
from observe_reference import safe_value
from verify_ctap import Fixture


def run(binary, directory, observation, report):
    fixture = Fixture(binary, directory)
    tests = []

    def check(value, name):
        if not value:
            raise AssertionError(name)
        tests.append({"name": name, "passed": True})
        print("PASS", name, flush=True)

    def rejects(code, operation, name):
        try:
            operation()
        except CtapError as error:
            check(int(error.code) == code, name)
        else:
            raise AssertionError("invalid request accepted: " + name)

    try:
        ctap = fixture.start()
        raw = ctap.send_cbor(4)
        info = Info.from_dict(raw)
        reference = observation["reference"]["get_info_fields"]
        fields = {
            field.name: safe_value(getattr(info, field.name))
            for index, field in enumerate(dataclasses.fields(info), 1)
            if index in raw
        }
        identity_state = {"aaguid", "firmware_version", "remaining_disc_creds"}
        check(
            sorted(raw) == observation["reference"]["present_cbor_keys"],
            "GetInfo presence of every public CBOR key matches reference",
        )
        for name, value in reference.items():
            if name in identity_state:
                continue
            actual = fields[name]
            if name == "options":
                value = {k: v for k, v in value.items() if k != "clientPin"}
                actual = {k: v for k, v in actual.items() if k != "clientPin"}
            check(actual == value, f"reference GetInfo {name}")
        check(
            fields["aaguid"] != reference["aaguid"]
            and fields["firmware_version"] == 3
            and not fields["options"]["clientPin"]
            and fields["remaining_disc_creds"] == 100,
            "fresh software identity and state remain explicit",
        )
        challenge = hashlib.sha256(b"fresh reference-profile fixture").digest()
        rp = {"id": "localhost", "name": "Fresh local fixture"}
        unknown = {"type": "public-key", "id": b"x" * 128}
        rejects(
            0x2E,
            lambda: ctap.get_assertion("localhost", challenge, allow_list=[unknown]),
            "128-byte unknown credential ID is parsed and returns no credentials",
        )
        attestation = ctap.make_credential(
            challenge,
            rp,
            {"id": b"fixture"},
            [{"type": "public-key", "alg": -7}],
            exclude_list=[unknown],
        )
        credential = attestation.auth_data.credential_data
        assertion = ctap.get_assertion(
            "localhost",
            challenge,
            allow_list=[
                unknown,
                {"type": "public-key", "id": credential.credential_id},
            ],
        )
        credential.public_key.verify(
            assertion.auth_data + challenge, assertion.signature
        )
        check(
            True,
            "unknown 128-byte descriptor does not hide a valid allow-list credential",
        )

        # Direct HID calls deliberately cross maxMsgSize; the SDK normally guards it.
        for target, expected in ((1536, 0x2E), (1537, 0x39)):
            request = None
            for size in range(1300, target):
                candidate = b"\x02" + cbor.encode(
                    {
                        1: "unknown.localhost",
                        2: challenge,
                        5: {"up": False},
                        255: b"x" * size,
                    }
                )
                if len(candidate) == target:
                    request = candidate
                    break
            assert request is not None
            response = fixture.device.call(CTAPHID.CBOR, request)
            check(
                response == bytes([expected]),
                f"whole CTAP message boundary {target} bytes gives status 0x{expected:02x}",
            )
        check(
            ctap.get_info().max_msg_size == 1536,
            "oversized request preserves channel usability",
        )

        fragment_limit = info.max_msg_size - 64
        empty = b"\x80" + hashlib.sha256(b"\x80").digest()[:16]
        check(
            ctap.large_blobs(0, get=fragment_limit)[1] == empty,
            "large-blob read accepts measured maxMsgSize minus 64 fragment limit",
        )
        rejects(
            0x03,
            lambda: ctap.large_blobs(0, get=fragment_limit + 1),
            "oversized large-blob read returns INVALID_LENGTH",
        )
        rejects(
            0x03,
            lambda: ctap.large_blobs(0, set=b"x" * (fragment_limit + 1), length=3000),
            "oversized large-blob write returns INVALID_LENGTH before changing state",
        )
        data = cbor.encode([b"fresh large-blob content" * 120])
        data += hashlib.sha256(data).digest()[:16]
        for offset in range(0, len(data), fragment_limit):
            ctap.large_blobs(
                offset,
                set=data[offset : offset + fragment_limit],
                length=len(data) if offset == 0 else None,
            )
        restored = b"".join(
            ctap.large_blobs(offset, get=fragment_limit)[1]
            for offset in range(0, len(data), fragment_limit)
        )
        check(
            restored == data,
            "1472-byte fragments commit and read back complete integrity-checked array",
        )
        check(
            ctap.large_blobs(len(data), get=1)[1] == b"",
            "large-blob exact end returns empty bytes",
        )
        rejects(
            0x02,
            lambda: ctap.large_blobs(len(data) + 1, get=1),
            "large-blob offset past end returns INVALID_PARAMETER",
        )

        protocol = PinProtocolV2()
        ClientPin(ctap, protocol).set_pin("12345678")
        token = ClientPin(ctap, protocol).get_pin_token(
            "12345678", ClientPin.PERMISSION.AUTHENTICATOR_CFG
        )
        config = Config(ctap, protocol, token)
        rejects(
            0x15,
            lambda: config.set_min_pin_length(6, ["localhost", "other.localhost"]),
            "two minimum-PIN RPs exceed measured one-RP limit",
        )
        check(
            ctap.get_info().min_pin_length == 4,
            "rejected configuration leaves PIN policy unchanged",
        )
        config.set_min_pin_length(6, ["localhost"])
        check(
            ctap.get_info().min_pin_length == 6,
            "failed configuration preserves valid token for subsequent one-RP configuration",
        )
        fixture.restart()
        check(
            fixture.ctap.get_info().min_pin_length == 6,
            "measured-limit configuration survives restart",
        )
        report.update(
            passed=True,
            tests=tests,
            compared_reference_utc=observation["observed_utc"],
            get_info=fields,
            intentional_differences={
                name: {"software": fields[name], "reference": reference[name]}
                for name in sorted(identity_state)
            }
            | {
                "clientPin": {
                    "software": fields["options"]["clientPin"],
                    "reference": reference["options"]["clientPin"],
                }
            },
        )
    except Exception as error:
        report.update(
            passed=False, tests=tests, error=f"{type(error).__name__}: {error}"
        )
        raise
    finally:
        fixture.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument(
        "--reference",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "reference-observation.json",
    )
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    args.work_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "subject": "modified software authenticator versus saved public reference GetInfo",
        "physical_device_access": False,
        "complete_firmware_equivalence": False,
        "system_hid_registration_verified": False,
    }
    try:
        with tempfile.TemporaryDirectory(
            prefix="rp", dir=args.work_dir.resolve()
        ) as directory:
            run(
                args.binary.resolve(),
                Path(directory),
                json.loads(args.reference.read_text()),
                report,
            )
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
