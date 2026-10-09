#!/usr/bin/env python3
"""Verify shared Domain revocation/rollback with fresh independent software peers.

Both clients use private sockets or separate direct IFD handles. The unchanged
SDK verifies receipts, derived keys and encrypted response MACs. No system
reader discovery, real credentials, factory trust or physical-key commands.
Global lifecycle/status expectations remain explicit GP public-review models.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from emucard.client import CcidSocketConnection
from emucard.core import EncryptedState
from emucard.ifd import IfdNativeConnection
from verify_domain_cache import GP_SOURCE, host
from verify_smartcard import Fixture
from yubikit.core import Tlv
from yubikit.core.smartcard import ApduError, ScpProcessor, SmartCardProtocol
from yubikit.core.smartcard.scp import KeyRef, Scp03KeyParams, Scp11KeyParams, ScpState
from yubikit.securitydomain import SecurityDomainSession


def run(root, directory, report, ifd_driver=None):
    fixture = Fixture(root, directory, ifd_driver)
    peers = []
    tests = []
    passed = False

    def check(value, label):
        if not value:
            raise AssertionError(label)
        tests.append({"name": label, "passed": True})
        print("PASS", label, flush=True)

    def saved():
        return EncryptedState(directory / "state.bin").data

    def new_peer():
        peer = (
            IfdNativeConnection(ifd_driver, directory / "s.sock")
            if ifd_driver
            else CcidSocketConnection(directory / "s.sock")
        )
        peers.append(peer)
        return peer

    current_protocols = {}

    def authenticate(conn, kid=None, *, plain=False):
        sd = SecurityDomainSession(conn)
        if not plain:
            sd.authenticate(
                Scp11KeyParams(
                    KeyRef(kid, 1), private[kid].public_key(), anchor, own_key, chain
                )
                if kid
                else Scp03KeyParams()
            )
        current_protocols[conn] = sd.protocol
        return sd

    def upload(sd, *, partial=False):
        for index, cert in enumerate(chain[:1] if partial else chain):
            sd.protocol.send_apdu(
                0x80,
                0x2A,
                anchor.kvn,
                anchor.kid | (0x80 if index == 0 else 0),
                cert.public_bytes(serialization.Encoding.DER),
            )

    def cached(conn, kid):
        protocol = SmartCardProtocol(conn)
        protocol._processor, formatter = protocol._build_base_processor()
        skipped = []

        def phase(cla, ins, p1, p2, data):
            if ins == 0x2A:
                index = len(skipped)
                assert data == chain[index].public_bytes(serialization.Encoding.DER)
                assert cla == 0x80 and p1 == anchor.kvn
                assert p2 == anchor.kid | (0x80 if index == 0 else 0)
                skipped.append(data)
                return b""
            assert cla == 0x80 and ins == 0x82 and len(skipped) == len(chain)
            return current_protocols[conn].send_apdu(cla, ins, p1, p2, data)

        state = ScpState.scp11_init(
            phase,
            Scp11KeyParams(
                KeyRef(kid, 1), private[kid].public_key(), anchor, own_key, chain
            ),
        )
        protocol._processor = ScpProcessor(protocol._processor, formatter, state)
        current_protocols[conn] = protocol
        return protocol

    def stale(conn, kid, label):
        before = saved()
        try:
            cached(conn, kid)
        except ApduError as error:
            expected = before
            expected["domain"]["keys"][KeyRef(kid, 1).hex()]["retries"] -= 1
            check(
                error.sw == 0x6985 and saved() == expected,
                label + "; modeled 6985 and only durable retry changed",
            )
        else:
            raise AssertionError("accepted revoked own cross-client cache: " + label)

    def denied(sw, operation, label):
        raw = (directory / "state.bin").read_bytes()
        try:
            operation()
        except ApduError as error:
            check(
                error.sw == sw and raw == (directory / "state.bin").read_bytes(),
                label + "; encrypted state unchanged",
            )
        else:
            raise AssertionError("accepted prohibited own operation: " + label)

    def list_payload(ref, counter):
        values = b""
        for serial in serials:
            value = serial.to_bytes((serial.bit_length() + 7) // 8, "big")
            values += Tlv(0x93, b"\0" + value if value[0] & 0x80 else value)
        return (
            Tlv(0xA6, Tlv(0x83, ref))
            + Tlv(0x92, counter.to_bytes(2, "big"))
            + Tlv(0x70, values)
        )

    try:
        first = fixture.start()
        second = new_peer()
        sd = authenticate(second)
        anchor, other = KeyRef(0x10, 1), KeyRef(0x20, 1)
        private = {kid: ec.generate_private_key(ec.SECP256R1()) for kid in (0x11, 0x15)}
        for kid, key in private.items():
            sd.put_key(KeyRef(kid, 1), key)
        ca, own_key, chain, _ = host("shared-domain independent", anchor)
        for ref in (anchor, other):
            sd.put_key(ref, ca.public_key())
        serials = [cert.serial_number for cert in chain]
        cplc = sd.get_data(0x9F7F)
        original_peers = {k: v for k, v in saved().items() if k != "domain"}

        # Old code fails here: a peer STORE leaves the other Card's OCE cached.
        for kid in (0x11, 0x15):
            kind = "SCP11" + ("a" if kid == 0x11 else "c")
            for action in ("exclude", "identical", "clear", "other CA", "counter"):
                b = authenticate(second)
                b.store_allowlist(anchor, serials)
                a = authenticate(first)
                upload(a)
                before = saved()
                if action == "counter":
                    b = authenticate(second, 0x15)
                    count = (
                        saved()["domain"]["keys"][anchor.hex()].get(
                            "allowlist_counter", 0
                        )
                        + 1
                    )
                    b.store_data(list_payload(anchor, count))
                else:
                    b.store_allowlist(
                        other if action == "other CA" else anchor,
                        []
                        if action == "clear"
                        else serials[:-1] + [serials[-1] + 1]
                        if action == "exclude"
                        else serials,
                    )
                check(
                    a.get_data(0x9F7F) == cplc,
                    kind
                    + " "
                    + action
                    + " update preserves previously active peer SCP03",
                )
                stale(
                    first,
                    kid,
                    kind + " peer " + action + " policy commit invalidates old cache",
                )
                after = saved()
                check(
                    before["domain"]["keys"][KeyRef(kid, 1).hex()]["private"]
                    == after["domain"]["keys"][KeyRef(kid, 1).hex()]["private"],
                    kind
                    + " "
                    + action
                    + " revocation never replaces independent SD key",
                )

            b = authenticate(second)
            b.store_allowlist(anchor, serials)
            a = authenticate(first)
            upload(a)
            denied(
                0x6A80,
                lambda b=b: b.store_data(
                    Tlv(0xA6, Tlv(0x83, anchor)) + Tlv(0x70, Tlv(0x94, b"\1"))
                ),
                kind + " rejected peer policy does not change shared state",
            )
            accepted = cached(first, kid)
            check(
                accepted.send_apdu(0, 0xCA, 0x9F, 0x7F) == cplc,
                kind
                + " prior peer cache survives rejected mutation and dictionary rollback",
            )

            a = authenticate(first)
            upload(a)
            b = authenticate(second)
            old = saved()
            path, backup = directory / "state.bin", directory / "own-backup.bin"
            raw = path.read_bytes()
            path.rename(backup)
            path.mkdir()
            try:
                try:
                    b.store_allowlist(anchor, [serials[-1] + 1])
                except ApduError as error:
                    check(
                        error.sw == 0x6581,
                        kind + " peer failed commit returns SDK-verified 6581",
                    )
                else:
                    raise AssertionError("accepted controlled own storage failure")
            finally:
                path.rmdir()
                backup.rename(path)
            check(
                saved() == old and path.read_bytes() == raw,
                kind
                + " peer failed commit restores policy, generation and ciphertext together",
            )
            accepted = cached(first, kid)
            check(
                accepted.send_apdu(0, 0xCA, 0x9F, 0x7F) == cplc,
                kind + " failed peer commit leaves prior OCE cache valid",
            )

            b = authenticate(second)
            b.store_allowlist(anchor, serials)
            a = authenticate(first)
            upload(a, partial=True)
            b.store_allowlist(anchor, [])
            denied(
                0x6985,
                lambda a=a: a.protocol.send_apdu(
                    0x80,
                    0x2A,
                    anchor.kvn,
                    anchor.kid,
                    chain[-1].public_bytes(serialization.Encoding.DER),
                ),
                kind + " peer policy commit invalidates a partially uploaded chain",
            )

            # Updating a CA public key alone intentionally retains validated OCE
            # per GP7.5 note; later full PSO must validate against the new CA.
            b = authenticate(second)
            b.store_allowlist(anchor, serials)
            a = authenticate(first)
            upload(a)
            changed = ec.generate_private_key(ec.SECP256R1())
            b.put_key(anchor, changed.public_key(), replace_kvn=1)
            accepted = cached(first, kid)
            check(
                accepted.send_apdu(0, 0xCA, 0x9F, 0x7F) == cplc,
                kind + " peer CA-key replacement retains previously validated own OCE",
            )
            before = saved()
            try:
                authenticate(first, kid)
            except ApduError as error:
                # SELECT and the first successful PSO re-encrypt the same state
                # with fresh nonces, so compare plaintext state for this flow.
                check(
                    error.sw == 0x6982 and saved() == before,
                    kind + " fresh PSO rejects replaced CA without state mutation",
                )
            else:
                raise AssertionError("accepted fresh chain signed by replaced own CA")
            b.put_key(anchor, ca.public_key(), replace_kvn=1)

            a = authenticate(first, kid)
            b = authenticate(second)
            b.store_allowlist(anchor, [serials[-1] + 1])
            check(
                a.get_data(0x9F7F) == cplc,
                kind
                + " successful peer revocation retains already established SDK channel",
            )

        # Reset the shared Domain on B, then reuse exactly the fixture-owned SD
        # private keys. Even matching old crypto keys must not restore old caches
        # or established channels from the previous Domain identity.
        b = authenticate(second)
        b.store_allowlist(anchor, serials)
        a = authenticate(first, plain=True)
        upload(a)
        third = new_peer()
        c = authenticate(third, plain=True)
        upload(c)
        active03 = authenticate(new_peer())
        active_c_peer = new_peer()
        active_c = authenticate(active_c_peer, 0x15)
        path, backup = directory / "state.bin", directory / "own-backup.bin"
        old, raw = saved(), path.read_bytes()
        path.rename(backup)
        path.mkdir()
        try:
            try:
                b.protocol.send_apdu(0x80, 0xE4, 0, 1, Tlv(0xD0, b"\0"))
            except ApduError as error:
                check(
                    error.sw == 0x6581, "failed shared reset returns SDK-verified 6581"
                )
            else:
                raise AssertionError("accepted controlled own reset commit failure")
        finally:
            path.rmdir()
            backup.rename(path)
        check(
            saved() == old and path.read_bytes() == raw,
            "failed shared reset restores all keys/policy/identity/ciphertext together",
        )
        check(
            active03.get_data(0x9F7F) == cplc,
            "failed shared reset preserves another peer's SCP03 channel",
        )
        check(
            active_c.get_data(0x9F7F) == cplc,
            "failed shared reset preserves another peer's SCP11c channel",
        )
        check(
            cached(first, 0x11).send_apdu(0, 0xCA, 0x9F, 0x7F) == cplc,
            "failed shared reset preserves cached own a authorization",
        )
        check(
            cached(third, 0x15).send_apdu(0, 0xCA, 0x9F, 0x7F) == cplc,
            "failed shared reset preserves cached own c authorization",
        )
        b = authenticate(second)
        # These cache-only peers intentionally have no established transport,
        # so the reset test reaches cache validation rather than an old-channel
        # or plaintext transport guard. Live channel peers are tested separately.
        upload(authenticate(first, plain=True))
        upload(authenticate(third, plain=True))
        # The successful cached c handshake superseded active_c. Reestablish
        # it so the following reset checks a live, SDK-verified peer context.
        active_c = authenticate(active_c_peer, 0x15)
        check(
            active_c.get_data(0x9F7F) == cplc,
            "peer c channel is live immediately before shared reset",
        )
        b.delete_key(kid=1, kvn=0xFF)
        b.delete_key(kid=0x11)
        b.delete_key(kid=0x15, delete_last=True)
        denied(
            0x6982,
            lambda: active03.get_data(0x9F7F),
            "shared Domain reset terminates old peer SCP03 channel",
        )
        denied(
            0x6982,
            lambda: active_c.get_data(0x9F7F),
            "shared Domain reset terminates an old peer SCP11c channel",
        )
        b = authenticate(second)
        check(b.get_data(0x9F7F) != cplc, "shared Domain reset rotates own identity")
        for kid, key in private.items():
            b.put_key(KeyRef(kid, 1), key)
        # Use separate peers for channel closure and cache revocation: touching
        # an invalid old channel clears its cache, masking a stale-cache bug.
        # These two peers have sent nothing since PSO before the reset.
        stale(first, 0x11, "old own a cache cannot cross reset/reprovision boundary")
        stale(third, 0x15, "old own c cache cannot cross reset/reprovision boundary")
        check(
            original_peers == {k: v for k, v in saved().items() if k != "domain"},
            "shared policy/cache/reset changes retain every independent peer application",
        )

        # Legacy migration adds internal bookkeeping only; keys/certs/retries
        # and existing published CPLC remain byte-for-byte unchanged.
        for peer in peers:
            peer.close()
        peers.clear()
        fixture.stop()
        state = EncryptedState(directory / "state.bin")
        prior = state.data["domain"]
        prior.pop("oce_policy_generation", None)
        state.flush()
        snapshot = json.loads(json.dumps(prior))
        first = fixture.start()
        public_session = SecurityDomainSession(first)
        public_session.get_key_information()
        migrated = saved()["domain"]
        check(
            {k: v for k, v in migrated.items() if k != "oce_policy_generation"}
            == snapshot,
            "legacy policy-generation migration preserves keys/certificates/retries/CPLC",
        )
        check(
            len(bytes.fromhex(migrated["oce_policy_generation"])) == 16,
            "legacy Domain gains independent internal generation bookkeeping",
        )
        passed = True
    finally:
        for peer in peers:
            peer.close()
        fixture.stop()
        report.write_text(
            json.dumps(
                {
                    "passed": passed,
                    "tests": tests,
                    "transport": "separate direct IFD handles"
                    if ifd_driver
                    else "separate private CCID sockets",
                    "physical_device_access": False,
                    "manufacturer_trust_reproduced": False,
                    "system_pcsc_reader_registered": False,
                    "sdk_phase_control": "skip only already explicitly uploaded own PSO; unchanged SDK MUT/receipt/KDF/secure messaging",
                    "source": {
                        "url": GP_SOURCE,
                        "version": "1.3.0.13 public review",
                        "sections": ["7.5", "7.6.1", "7.9"],
                    },
                    "unverified": [
                        "actual firmware cross-channel lifecycle/status and finalGP1.4",
                        "transient OCE logical-channel scope and physical c replacement policy",
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
        prefix="ske-domain-shared-", dir=args.work_dir
    ) as directory:
        run(
            Path(__file__).resolve().parents[1],
            Path(directory),
            args.report,
            args.ifd_driver,
        )


if __name__ == "__main__":
    main()
