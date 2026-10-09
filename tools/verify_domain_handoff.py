#!/usr/bin/env python3
"""Verify SCP11 handoff and sole c context with fresh owned software identities.

Use unmodified SDK PSO/MUT, receipts/KDF and response encryption/MAC. Private
connections model independent contexts, not proven hardware logical channels.
The c lifecycle model makes the latest committed successful c session replace
the previous one. Physical selection/status policy and final GP1.4 are unmeasured.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives import serialization
from emucard.client import CcidSocketConnection
from emucard.core import EncryptedState
from emucard.ifd import IfdNativeConnection
from verify_domain_cache import GP_SOURCE, host
from verify_smartcard import Fixture
from yubikit.core import Tlv
from yubikit.core.smartcard import AID, ApduError, ScpProcessor, SmartCardProtocol
from yubikit.core.smartcard.scp import KeyRef, Scp03KeyParams, Scp11KeyParams, ScpState
from yubikit.securitydomain import SecurityDomainSession


def run(root, directory, report, ifd_driver=None):
    fixture = Fixture(root, directory, ifd_driver)
    peers, tests = [], []
    passed = False

    def check(value, label):
        if not value:
            raise AssertionError(label)
        tests.append({"name": label, "passed": True})
        print("PASS", label, flush=True)

    def saved():
        return EncryptedState(directory / "state.bin").data

    def peer():
        conn = (
            IfdNativeConnection(ifd_driver, directory / "s.sock")
            if ifd_driver
            else CcidSocketConnection(directory / "s.sock")
        )
        peers.append(conn)
        return conn

    def params(kid):
        if kid is None:
            return Scp03KeyParams()
        return (
            Scp11KeyParams(KeyRef(kid, 1), public[kid])
            if kid == 0x13
            else Scp11KeyParams(KeyRef(kid, 1), public[kid], anchor, own_key, chain)
        )

    def authenticate(conn, kid=None):
        sd = SecurityDomainSession(conn)
        sd.authenticate(params(kid))
        return sd

    def denied(operation, label):
        path = directory / "state.bin"
        raw = path.read_bytes()
        try:
            operation()
        except ApduError as error:
            check(error.sw == 0x6982 and path.read_bytes() == raw, label)
        else:
            raise AssertionError("accepted terminated own context: " + label)

    def handoff(conn, old, kid):
        state = ScpState.scp11_init(old.protocol.send_apdu, params(kid))
        new = SmartCardProtocol(conn)
        base, formatter = new._build_base_processor()
        new._processor = ScpProcessor(base, formatter, state)
        return new

    try:
        conn = fixture.start()
        initial = authenticate(conn)
        public = {
            kid: initial.generate_ec_key(
                KeyRef(kid, 1), replace_kvn=1 if kid == 0x13 else 0
            )
            for kid in (0x11, 0x13, 0x15)
        }
        anchor = KeyRef(0x10, 1)
        ca, own_key, chain, _ = host("own handoff fixtures", anchor)
        initial.put_key(anchor, ca.public_key())
        cplc = initial.get_data(0x9F7F)
        original_keys = saved()["domain"]["keys"]
        original_apps = {k: v for k, v in saved().items() if k != "domain"}

        for outer in (None, 0x11, 0x13, 0x15):
            for kid in (0x11, 0x13, 0x15):
                label = f"outer {outer or 1:02x} to SCP11 {kid:02x}"
                old = authenticate(conn, outer)
                new = handoff(conn, old, kid)
                check(True, label + " SDK verifies protected PSO/MUT receipt and KDF")
                check(
                    new.send_apdu(0, 0xCA, 0x9F, 0x7F) == cplc,
                    label + " new context SDK decrypts response and verifies R-MAC",
                )
                info = new.send_apdu(0, 0xCA, 0, 0xE0)
                check(
                    len(Tlv.parse_list(info)) == len(original_keys) + 2,
                    label + " new context advances encryption/MAC counters",
                )
                denied(
                    lambda old=old: old.get_data(0x9F7F),
                    label + " terminated old wrapper denied; encrypted state unchanged",
                )

        first, second = peer(), peer()
        for transport in ("plain", "protected"):
            old = authenticate(first, 0x15)
            if transport == "plain":
                new = authenticate(second, 0x15).protocol
            else:
                outer = authenticate(second)
                new = handoff(second, outer, 0x15)
            check(
                new.send_apdu(0, 0xCA, 0x9F, 0x7F) == cplc,
                transport + " new c context is SDK-verified after peer supersession",
            )
            denied(
                lambda old=old: old.get_data(0x9F7F),
                transport + " prior peer c context is no longer active",
            )
            check(
                new.send_apdu(0, 0xCA, 0x9F, 0x7F) == cplc,
                transport + " old-peer denial does not close the current c owner",
            )

        # A failed committed handoff must not revoke another connection. Check
        # this for both plain/protected MUT; stored token and key retries roll back.
        for transport in ("plain", "protected"):
            old = authenticate(first, 0x15)
            outer = (
                authenticate(second)
                if transport == "protected"
                else SecurityDomainSession(second)
            )
            key_params = params(0x15)
            # Explicitly upload own certificates before sabotaging state commit.
            for index, cert in enumerate(chain):
                outer.protocol.send_apdu(
                    0x80,
                    0x2A,
                    anchor.kvn,
                    anchor.kid | (0x80 if index == 0 else 0),
                    cert.public_bytes(serialization.Encoding.DER),
                )
            skipped = []
            send = outer.protocol.send_apdu

            def phase(cla, ins, p1, p2, data, skipped=skipped, send=send):
                if ins == 0x2A:
                    assert cla == 0x80 and p1 == anchor.kvn
                    assert p2 == anchor.kid | (0x80 if not skipped else 0)
                    assert data == chain[len(skipped)].public_bytes(
                        serialization.Encoding.DER
                    )
                    skipped.append(data)
                    return b""
                assert ins == 0x82 and len(skipped) == len(chain)
                return send(cla, ins, p1, p2, data)

            path, backup = directory / "state.bin", directory / "own-backup.bin"
            before, raw = saved(), path.read_bytes()
            path.rename(backup)
            path.mkdir()
            try:
                try:
                    ScpState.scp11_init(phase, key_params)
                except ApduError as error:
                    check(
                        error.sw == 0x6581, transport + " failed c handoff returns 6581"
                    )
                else:
                    raise AssertionError("accepted controlled own commit failure")
            finally:
                path.rmdir()
                backup.rename(path)
            check(
                saved() == before and path.read_bytes() == raw,
                transport + " failed c handoff rolls back keys/token/ciphertext",
            )
            check(
                old.get_data(0x9F7F) == cplc,
                transport + " failed c handoff preserves other peer's SDK channel",
            )

        # A malformed MUT consumes the modeled retry but never supersedes the
        # other connection's successful c context.
        old = authenticate(first, 0x15)
        rejected = authenticate(second)
        before = saved()
        try:
            rejected.protocol.send_apdu(0x80, 0x82, 1, 0x15, b"\0")
        except ApduError as error:
            before["domain"]["keys"]["1501"]["retries"] -= 1
            check(
                error.sw == 0x6A80 and saved() == before,
                "malformed c request changes only durable retry, never session token",
            )
        else:
            raise AssertionError("accepted malformed own c request")
        check(old.get_data(0x9F7F) == cplc, "malformed peer MUT preserves c owner")

        # Active a/b/03 contexts survive another peer's c establishment.
        for kid in (None, 0x11, 0x13):
            other = authenticate(first, kid)
            current = authenticate(second, 0x15)
            check(
                other.get_data(0x9F7F) == current.get_data(0x9F7F) == cplc,
                f"new c context preserves independent peer {kid or 1:02x} channel",
            )

        # A SELECT or disconnect clears its own volatile wrapper. A later c
        # session remains usable; no stale owner reference blocks new sessions.
        current = authenticate(second, 0x15)
        plain = SmartCardProtocol(second)
        plain.select(AID.SECURE_DOMAIN)
        denied(lambda: current.get_data(0x9F7F), "SELECT closes prior c wrapper")
        active = authenticate(first, 0x15)
        second.close()
        peers.remove(second)
        replacement = peer()
        next_session = authenticate(replacement, 0x15)
        check(
            next_session.get_data(0x9F7F) == cplc,
            "new c session works after peer disconnect",
        )
        denied(
            lambda: active.get_data(0x9F7F),
            "new c after disconnect supersedes active prior peer",
        )
        replacement.close()
        peers.remove(replacement)
        after_owner_disconnect = authenticate(first, 0x15)
        check(
            after_owner_disconnect.get_data(0x9F7F) == cplc,
            "new SDK c session works after active c owner disconnects",
        )
        check(
            original_apps == {k: v for k, v in saved().items() if k != "domain"},
            "handoff/session management preserves all independent application state",
        )
        key_rows = saved()["domain"]["keys"]
        check(
            all(
                {k: v for k, v in key_rows[ref].items() if k != "retries"}
                == {k: v for k, v in row.items() if k != "retries"}
                for ref, row in original_keys.items()
            ),
            "handoff/supersession never replaces own key/certificate material",
        )
        passed = True
    finally:
        for conn in peers:
            conn.close()
        fixture.stop()
        report.write_text(
            json.dumps(
                {
                    "passed": passed,
                    "tests": tests,
                    "transport": "separate direct IFD handles"
                    if ifd_driver
                    else "private CCID sockets",
                    "physical_device_access": False,
                    "manufacturer_trust_reproduced": False,
                    "system_pcsc_reader_registered": False,
                    "c_session_model": "latest committed successful c context supersedes earlier c contexts in shared SD",
                    "source": {
                        "url": GP_SOURCE,
                        "version": "1.3.0.13 public review",
                        "sections": ["4.6", "7.5.2", "7.6.1", "7.7.1"],
                    },
                    "unverified": [
                        "physical logical-channel replacement/status policy and final GP1.4",
                        "failed MUT old-context lifetime",
                        "SD content transaction/replay rollback",
                        "OS reader/browser interoperability",
                    ],
                },
                indent=2,
            )
            + "\n"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=Path(tempfile.gettempdir()))
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--ifd-driver", type=Path)
    args = parser.parse_args()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="ske-handoff-", dir=args.work_dir
    ) as directory:
        run(
            Path(__file__).resolve().parents[1],
            Path(directory),
            args.report,
            args.ifd_driver,
        )


if __name__ == "__main__":
    main()
