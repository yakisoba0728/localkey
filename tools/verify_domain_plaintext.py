#!/usr/bin/env python3
"""Verify vendor plaintext termination on fresh owned software identities.

Unmodified SDK establishes SCP03/a/b/c and verifies receipts and response MACs.
Only private software CCID sockets or direct IFD handles are opened. No real
YubiKey, manufacturer identity, system reader or existing credential is used.
Yubico documents termination/revocation; exact firmware status and possible
handshake exceptions remain unmeasured. Status6982 is the software model.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from functools import partial
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from emucard.client import CcidSocketConnection
from emucard.core import EncryptedState
from emucard.ifd import IfdNativeConnection
from verify_domain_cache import host
from verify_smartcard import Fixture
from yubikit.core import Tlv
from yubikit.core.smartcard import ApduError, SmartCardProtocol
from yubikit.core.smartcard.scp import KeyRef, Scp03KeyParams, Scp11KeyParams, ScpState
from yubikit.oath import OathSession
from yubikit.piv import (
    DEFAULT_MANAGEMENT_KEY,
    KEY_TYPE,
    PIN_POLICY,
    SLOT,
    TOUCH_POLICY,
    PivSession,
)
from yubikit.securitydomain import SecurityDomainSession

VENDOR_SOURCE = (
    "https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-scp.html"
)


def run(root, directory, report, ifd_driver=None):
    fixture, tests = Fixture(root, directory, ifd_driver), []
    peers, passed = [], False

    def check(value, label):
        if not value:
            raise AssertionError(label)
        tests.append({"name": label, "passed": True})
        print("PASS", label, flush=True)

    def saved():
        return EncryptedState(directory / "state.bin").data

    def params(kid):
        if kid is None:
            return Scp03KeyParams()
        if kid == 0x13:
            return Scp11KeyParams(KeyRef(kid, 1), public[kid])
        return Scp11KeyParams(KeyRef(kid, 1), public[kid], anchor, own_key, chain)

    def authenticate(connection, kid=None):
        sd = SecurityDomainSession(connection)
        sd.authenticate(params(kid))
        return sd

    def denied(operation, label, *, sw=0x6982):
        before, raw = saved(), (directory / "state.bin").read_bytes()
        try:
            operation()
        except ApduError as error:
            check(
                error.sw == sw
                and saved() == before
                and (directory / "state.bin").read_bytes() == raw,
                label + f"; modeled{sw:04x} and keys/retries/ciphertext unchanged",
            )
        else:
            raise AssertionError(
                "accepted own plaintext during secure session: " + label
            )

    def upload(protocol):
        for index, cert in enumerate(chain):
            protocol.send_apdu(
                0x80,
                0x2A,
                anchor.kvn,
                anchor.kid | (0x80 if index < len(chain) - 1 else 0),
                cert.public_bytes(serialization.Encoding.DER),
            )

    def absent_oce(plain, label):
        before, skipped = saved(), []

        def phase(cla, ins, p1, p2, data):
            if ins == 0x2A:
                index = len(skipped)
                assert data == chain[index].public_bytes(serialization.Encoding.DER)
                assert p1 == anchor.kvn and p2 == anchor.kid | (
                    0x80 if index < len(chain) - 1 else 0
                )
                skipped.append(data)
                return b""
            assert cla == 0x80 and ins == 0x82 and len(skipped) == len(chain)
            return plain.send_apdu(cla, ins, p1, p2, data)

        try:
            ScpState.scp11_init(phase, params(0x11))
        except ApduError as error:
            before["domain"]["keys"]["1101"]["retries"] -= 1
            check(
                error.sw == 0x6985 and saved() == before,
                label + "; cached OCE revoked; only modeled absent-MUT retry changes",
            )
        else:
            raise AssertionError("plaintext termination retained own OCE authorization")

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
        ca, own_key, chain, _ = host("own plaintext lifecycle", anchor)
        initial.put_key(anchor, ca.public_key())
        cplc = initial.get_data(0x9F7F)
        original_apps = {k: v for k, v in saved().items() if k != "domain"}
        original_keys = saved()["domain"]["keys"]
        peer = (
            IfdNativeConnection(ifd_driver, directory / "s.sock")
            if ifd_driver
            else CcidSocketConnection(directory / "s.sock")
        )
        peers.append(peer)
        independent = authenticate(peer)

        def request(kid):
            ephemeral = ec.generate_private_key(ec.SECP256R1()).public_key()
            point = ephemeral.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
            return Tlv(
                0xA6,
                Tlv(0x90, bytes([0x11, {0x11: 1, 0x13: 0, 0x15: 3}[kid]]))
                + Tlv(0x95, b"\x3c")
                + Tlv(0x80, b"\x88")
                + Tlv(0x81, b"\x10"),
            ) + Tlv(0x5F49, point)

        root_der, leaf_der = [
            cert.public_bytes(serialization.Encoding.DER) for cert in chain
        ]
        packets = (
            ("PSO prefix", 0x80, 0x2A, 1, 0x90, root_der),
            ("PSO final", 0x80, 0x2A, 1, 0x10, leaf_der),
            ("PSO ISO chained CLA90", 0x90, 0x2A, 1, 0x90, root_der[:30]),
            ("INIT UPDATE", 0x80, 0x50, 0xFF, 0, b"ownhost0"),
            ("INIT UPDATE CLA90", 0x90, 0x50, 0xFF, 0, b"ownhost0"),
            ("valid MUT a", 0x80, 0x82, 1, 0x11, request(0x11)),
            ("valid MUT c", 0x80, 0x82, 1, 0x15, request(0x15)),
            ("valid INTERNAL b", 0x80, 0x88, 1, 0x13, request(0x13)),
            ("MUT ISO chained CLA90", 0x90, 0x82, 1, 0x11, b"own"),
            ("GET DATA", 0, 0xCA, 0x9F, 0x7F, b""),
            ("GET RESPONSE", 0, 0xC0, 0, 0, b""),
            ("unsupported CLA", 0x40, 0xCA, 0x9F, 0x7F, b""),
            ("SELECT invalid CLA", 0x80, 0xA4, 4, 0, b"own invalid CLA"),
            ("SELECT short AID", 0, 0xA4, 4, 0, b"\x01"),
        )
        for outer in (None, 0x11, 0x13, 0x15):
            for description, cla, ins, p1, p2, data in packets:
                label = f"SCP{outer or 3:02x} plain {description}"
                old = authenticate(conn, outer)
                upload(old.protocol)
                plain = SmartCardProtocol(conn)
                denied(
                    partial(plain.send_apdu, cla, ins, p1, p2, data),
                    label + " rejected before dispatch",
                    sw={"SELECT invalid CLA": 0x6E00, "SELECT short AID": 0x6A86}.get(
                        description, 0x6982
                    ),
                )
                # Probe OCE before touching the stale wrapper: its rejection
                # resets volatile state and could hide a missing SELECT reset.
                absent_oce(plain, label)
                denied(partial(old.get_data, 0x9F7F), label + " old wrapper closed")
                check(
                    plain.send_apdu(0, 0xCA, 0x9F, 0x7F) == cplc,
                    label + " now-plain selected application remains usable",
                )
                check(
                    independent.get_data(0x9F7F) == cplc,
                    label + " other peer SCP03 remains SDK-verified",
                )
                check(
                    authenticate(conn, outer).get_data(0x9F7F) == cplc,
                    label + " fresh SDK session recovers with receipt/KDF/R-MAC",
                )

        check(
            original_apps == {k: v for k, v in saved().items() if k != "domain"},
            "transport rejection preserves all independent stored application data",
        )
        check(
            all(
                {
                    k: v
                    for k, v in saved()["domain"]["keys"][ref].items()
                    if k != "retries"
                }
                == {k: v for k, v in row.items() if k != "retries"}
                for ref, row in original_keys.items()
            ),
            "plaintext boundary never replaces CA/SD key or certificate material",
        )

        piv_boundaries = (
            ("plaintext PSO", 0x80, 0x2A, 1, 0x90, root_der, 0x6982),
            ("malformed plaintext SELECT", 0, 0xA4, 4, 0, b"\x01", 0x6A86),
        )
        for outer, boundary in (
            (outer, boundary)
            for outer in (None, 0x11, 0x13, 0x15)
            for boundary in piv_boundaries
        ):
            description, cla, ins, p1, p2, data, sw = boundary
            label = f"PIV {outer or 3:02x} {description}"
            piv = PivSession(conn, params(outer))
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
            piv_public = piv.generate_key(
                SLOT.AUTHENTICATION,
                KEY_TYPE.ECCP256,
                PIN_POLICY.ONCE,
                TOUCH_POLICY.NEVER,
            )
            piv.verify_pin("123456")
            message = b"own plaintext termination PIN proof"
            signature = piv.sign(
                SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, message, hashes.SHA256()
            )
            piv_public.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            check(True, label + " prior PIN/admin and signature verified")
            plain = SmartCardProtocol(conn)
            denied(
                partial(plain.send_apdu, cla, ins, p1, p2, data),
                label + " closes transport",
                sw=sw,
            )
            piv.protocol = plain
            denied(
                partial(
                    piv.sign,
                    SLOT.AUTHENTICATION,
                    KEY_TYPE.ECCP256,
                    message,
                    hashes.SHA256(),
                ),
                label + " formerly verified PIN revoked",
            )
            denied(
                partial(piv.generate_key, SLOT.SIGNATURE, KEY_TYPE.ECCP256),
                label + " formerly verified management key revoked",
            )
            piv.verify_pin("123456")
            signature = piv.sign(
                SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, message, hashes.SHA256()
            )
            piv_public.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            check(True, label + " explicit PIN verification restores signing")

        oath = OathSession(conn)
        own_access_key = oath.derive_key("own software access lifecycle")
        oath.set_key(own_access_key)
        for outer in (None, 0x11, 0x13, 0x15):
            oath = OathSession(conn, params(outer))
            oath.validate(own_access_key)
            check(not oath.list_credentials(), f"OATH {outer or 3:02x} access verified")
            plain = SmartCardProtocol(conn)
            denied(
                partial(plain.send_apdu, 0x80, 0x50, 0xFF, 0, b"ownhost0"),
                f"OATH {outer or 3:02x} plain handshake closes transport",
            )
            oath.protocol = plain
            denied(
                oath.list_credentials,
                f"OATH {outer or 3:02x} access authorization revoked",
            )
            oath = OathSession(conn, params(outer))
            oath.validate(own_access_key)
            check(
                not oath.list_credentials(),
                f"OATH {outer or 3:02x} new challenge/access recovers",
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
                    "transport": "direct IFD" if ifd_driver else "private CCID socket",
                    "physical_device_access": False,
                    "manufacturer_trust_reproduced": False,
                    "system_pcsc_reader_registered": False,
                    "source": VENDOR_SOURCE,
                    "scp_variants": ["03", "11a", "11b", "11c"],
                    "plaintext_packet_cases_per_variant": 14,
                    "existing_error_status_model": "6982; malformed SELECT retains validation6e00/6a86; physical error statuses unmeasured",
                    "physical_handshake_exceptions_measured": False,
                    "sdk_phase_control": "PSO skipped only to probe cleared cache; SDK MUT receipt/KDF/secure messaging unchanged",
                    "unverified": [
                        "physical firmware error/status and possible handshake exceptions",
                        "native system PCSC/browser and entitled macOS transports",
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
        prefix="ske-plain-", dir=args.work_dir
    ) as directory:
        run(
            Path(__file__).resolve().parents[1],
            Path(directory),
            args.report,
            args.ifd_driver,
        )


if __name__ == "__main__":
    main()
