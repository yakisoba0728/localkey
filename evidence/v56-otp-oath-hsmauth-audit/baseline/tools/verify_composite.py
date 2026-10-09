#!/usr/bin/env python3
"""Verify FIDO vendor management with the shared CCID/OTP profile over sockets."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fido2.attestation import PackedAttestation
from fido2.ctap import CtapError
from verify_ctap import Fixture as FidoFixture
from verify_smartcard import Fixture as CardFixture
from yubikit.core import TRANSPORT, ApplicationNotAvailableError
from yubikit.management import CAPABILITY, DeviceConfig, ManagementSession
from yubikit.oath import OathSession


def run(binary, root, directory, report):
    card_dir, fido_dir = directory / "card", directory / "fido"
    card_dir.mkdir()
    fido_dir.mkdir()
    card = CardFixture(root, card_dir)
    fido = FidoFixture(binary, fido_dir, card_dir / "s.sock")
    checks = []
    completed = False

    def check(value, name):
        if not value:
            raise AssertionError(name)
        checks.append({"name": name, "passed": True})
        print("PASS", name, flush=True)

    def denied(code, fn, name):
        try:
            fn()
        except CtapError as e:
            check(int(e.code) == code, name)
        else:
            raise AssertionError("accepted: " + name)

    try:
        conn = card.start()
        ctap = fido.start()
        mgmt = ManagementSession(fido.device)
        info = mgmt.read_device_info()
        check(
            mgmt.version == (5, 7, 4)
            and info.serial == ManagementSession(conn).read_device_info().serial,
            "FIDO INIT and CCID management share version and serial",
        )
        check(
            info.config.enabled_capabilities[TRANSPORT.USB] == CAPABILITY(0x33B),
            "FIDO vendor device information matches supported profile",
        )
        challenge = hashlib.sha256(b"combined local authenticator test").digest()
        attestation = ctap.make_credential(
            challenge,
            {"id": "localhost"},
            {"id": b"composite"},
            [{"type": "public-key", "alg": -7}],
            options={"rk": True},
        )
        PackedAttestation().verify(
            attestation.att_stmt, attestation.auth_data, challenge
        )
        check(True, "shared-profile FIDO registration signature independently verified")
        lock = os.urandom(16)
        mgmt.write_device_config(
            DeviceConfig(challenge_response_timeout=10), new_lock_code=lock
        )
        check(
            ManagementSession(conn).read_device_info().is_locked,
            "FIDO configuration lock visible over CCID",
        )
        denied(
            0x7F,
            lambda: mgmt.write_device_config(
                DeviceConfig(challenge_response_timeout=1)
            ),
            "FIDO vendor write rejects missing configuration lock code",
        )
        mgmt.write_device_config(
            DeviceConfig(challenge_response_timeout=11),
            cur_lock_code=lock,
            new_lock_code=bytes(16),
        )
        check(
            ManagementSession(conn).read_device_info().config.challenge_response_timeout
            == 11,
            "FIDO vendor unlock and configuration persist in shared state",
        )
        mgmt.write_device_config(
            DeviceConfig({TRANSPORT.USB: CAPABILITY(0x33B) & ~CAPABILITY.OATH})
        )
        try:
            OathSession(conn)
        except ApplicationNotAvailableError:
            check(True, "FIDO vendor app disable applies to CCID OATH selection")
        else:
            raise AssertionError("disabled OATH accepted")
        # Management remains accessible when the FIDO applications are disabled.
        mgmt.write_device_config(
            DeviceConfig(
                {TRANSPORT.USB: CAPABILITY(0x33B) & ~CAPABILITY.FIDO2 & ~CAPABILITY.U2F}
            )
        )
        denied(0x30, ctap.get_info, "shared configuration disables FIDO2 commands")
        check(
            fido.device.call(3, bytes.fromhex("0003000000")) == b"\x69\x85",
            "shared configuration disables U2F commands",
        )
        mgmt.write_device_config(DeviceConfig({TRANSPORT.USB: CAPABILITY(0x33B)}))
        check(
            ctap.get_info().versions and OathSession(conn).version == (5, 7, 4),
            "shared configuration re-enables FIDO and OATH",
        )
        credential = attestation.auth_data.credential_data
        assertion = ctap.get_assertion(
            "localhost",
            challenge,
            [{"type": "public-key", "id": credential.credential_id}],
        )
        credential.public_key.verify(
            bytes(assertion.auth_data) + challenge, assertion.signature
        )
        check(True, "FIDO credential survives application disable and re-enable")
        card.stop()
        denied(
            0x7F,
            ctap.get_info,
            "FIDO fails closed when shared configuration service is unavailable",
        )
        conn = card.start()
        check(
            mgmt.read_device_info().serial == info.serial and ctap.get_info().versions,
            "card service restart preserves shared identity and reconnects FIDO",
        )
        completed = True
    finally:
        fido.stop()
        card.stop()
        report.write_text(
            json.dumps(
                {
                    "passed": completed,
                    "tests": checks,
                    "physical_key_accessed": False,
                    "transport": "real CTAPHID and CCID socket frames",
                    "physical_usb_composite_verified": False,
                },
                indent=2,
            )
            + "\n"
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, default=Path(tempfile.gettempdir()))
    args = parser.parse_args()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="ske-composite-", dir=args.work_dir
    ) as directory:
        run(
            args.binary.resolve(),
            Path(__file__).resolve().parents[1],
            Path(directory),
            args.report,
        )


if __name__ == "__main__":
    main()
