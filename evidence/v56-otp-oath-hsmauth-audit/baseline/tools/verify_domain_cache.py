#!/usr/bin/env python3
"""Exercise own SCP11 PSO caches and allowlist/anchor lifecycle over private RPC.

The phase-control callback skips PSO only after the fixture explicitly sent its
own certificates. The unchanged SDK still creates MUTUAL AUTHENTICATE, verifies
the receipt, derives keys and checks encrypted/MAC-protected responses. These
are GP public-review models, not observed firmware-5.7.4 error/lifecycle behavior.
No hardware discovery, credentials, manufacturer keys or certificates are used.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from emucard.core import EncryptedState
from verify_domain_profile import OCE, ROOT, name, own_cert
from verify_smartcard import Fixture
from yubikit.core import Tlv
from yubikit.core.smartcard import ApduError, ScpProcessor, SmartCardProtocol
from yubikit.core.smartcard.scp import KeyRef, Scp03KeyParams, Scp11KeyParams, ScpState
from yubikit.securitydomain import SecurityDomainSession

GP_SOURCE = (
    "https://globalplatform.org/wp-content/uploads/2023/08/"
    "GPC_2.3_F_SCP11_v1.3.0.13_PublicRvw.pdf"
)


def host(label, anchor, leaf_key=None):
    ca = ec.generate_private_key(ec.SECP256R1())
    leaf_key = leaf_key or ec.generate_private_key(ec.SECP256R1())
    root_name, leaf_name = name(label + " CA"), name(label + " OCE")
    root = own_cert(
        ca.public_key(), ca, root_name, root_name, ROOT, ca=True, path_length=0
    )
    leaf = own_cert(leaf_key.public_key(), ca, leaf_name, root_name, OCE)
    return ca, leaf_key, (root, leaf), anchor


def run(root, directory, report, ifd_driver=None):
    fixture = Fixture(root, directory, ifd_driver)
    tests = []
    passed = False

    def check(value, label):
        if not value:
            raise AssertionError(label)
        tests.append({"name": label, "passed": True})
        print("PASS", label, flush=True)

    def saved():
        return EncryptedState(directory / "state.bin").data

    def authenticate(params=None):
        sd = SecurityDomainSession(conn)
        sd.authenticate(params or Scp03KeyParams())
        return sd

    def params(kid, identity):
        _, private, chain, ref = identity
        return Scp11KeyParams(KeyRef(kid, 1), public[kid], ref, private, chain)

    def upload(sd, identity):
        _, _, chain, ref = identity
        for index, cert in enumerate(chain):
            sd.protocol.send_apdu(
                0x80,
                0x2A,
                ref.kvn,
                ref.kid | (0x80 if index < len(chain) - 1 else 0),
                cert.public_bytes(serialization.Encoding.DER),
            )

    def finish(sd, key_params):
        # Keep the card selection and previously uploaded PSO authorization;
        # a normal SDK authenticate would resend PSO and hide stale-cache bugs.
        protocol = SmartCardProtocol(conn)
        protocol._processor, formatter = protocol._build_base_processor()
        skipped = []

        def phase(cla, ins, p1, p2, data):
            if ins == 0x2A:
                index = len(skipped)
                expected = key_params.certificates[index].public_bytes(
                    serialization.Encoding.DER
                )
                ref = key_params.oce_ref
                assert cla == 0x80 and p1 == ref.kvn
                assert p2 == ref.kid | (
                    0x80 if index < len(key_params.certificates) - 1 else 0
                )
                assert data == expected
                skipped.append(data)
                return b""
            assert cla == 0x80 and ins == 0x82
            assert len(skipped) == len(key_params.certificates)
            return sd.protocol.send_apdu(cla, ins, p1, p2, data)

        scp = ScpState.scp11_init(phase, key_params)
        protocol._processor = ScpProcessor(protocol._processor, formatter, scp)
        sd.protocol = protocol
        return sd

    def absent(sd, key_params, label):
        before = saved()
        try:
            finish(sd, key_params)
        except ApduError as error:
            after = saved()
            expected = before
            expected["domain"]["keys"][key_params.ref.hex()]["retries"] -= 1
            check(
                error.sw == 0x6985 and after == expected,
                label + "; GP modeled 6985 and only modeled retry consumed",
            )
        else:
            raise AssertionError("accepted missing/stale OCE cache: " + label)

    def denied(sd, payload, label):
        before = saved()
        try:
            sd.store_data(payload)
        except ApduError as error:
            check(
                error.sw == 0x6A80 and saved() == before,
                label + "; persistent state unchanged",
            )
        else:
            raise AssertionError("accepted malformed allowlist: " + label)

    def secure_read(sd, label):
        check(sd.get_data(0x9F7F) == cplc, label)

    try:
        conn = fixture.start()
        sd = authenticate()
        cplc = sd.get_data(0x9F7F)
        public = {kid: sd.generate_ec_key(KeyRef(kid, 1)) for kid in (0x11, 0x15)}
        anchor, other = KeyRef(0x10, 1), KeyRef(0x20, 1)
        first = host("first independent", anchor)
        second = host("second independent", other)
        for identity in (first, second):
            ca, _, chain, ref = identity
            sd.put_key(ref, ca.public_key())
            sd.store_ca_issuer(
                ref,
                chain[0]
                .extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
                .value.digest,
            )
        peers = {key: value for key, value in saved().items() if key != "domain"}

        for kid in (0x11, 0x15):
            label = "SCP11" + ("a" if kid == 0x11 else "c")
            key_params = params(kid, first)
            allowed = [cert.serial_number for cert in first[2]]

            # Reproduce invalidation first so an old implementation fails on
            # successful stale authorization, rather than just on status 6982.
            sd = authenticate()
            sd.store_allowlist(anchor, allowed)
            upload(sd, first)
            secure_read(sd, label + " PSO retains current SDK SCP03 protected read")
            sd.store_allowlist(anchor, allowed[:-1] + [first[2][-1].serial_number + 1])
            secure_read(
                sd, label + " deny-list update preserves existing SCP03 channel"
            )
            absent(sd, key_params, label + " disallowing update invalidates cached OCE")
            before = saved()
            try:
                authenticate(key_params)
            except ApduError as error:
                check(
                    error.sw == 0x6982 and saved() == before,
                    label + " fresh SDK PSO also denies the now unlisted own leaf",
                )
            else:
                raise AssertionError("unlisted own leaf accepted")

            sd = authenticate()
            sd.store_allowlist(anchor, allowed)
            upload(sd, first)
            sd = finish(sd, key_params)
            secure_read(
                sd, label + " cached PSO independently passes SDK receipt/KDF/MAC"
            )

            sd = authenticate()
            absent(sd, key_params, label + " MUTUAL AUTHENTICATE requires PSO first")

            for action in ("identical", "clear", "other anchor"):
                sd = authenticate()
                sd.store_allowlist(anchor, allowed)
                upload(sd, first)
                sd.store_allowlist(
                    other if action == "other anchor" else anchor,
                    [cert.serial_number for cert in second[2]]
                    if action == "other anchor"
                    else allowed
                    if action == "identical"
                    else [],
                )
                secure_read(sd, label + " " + action + " update keeps current channel")
                absent(
                    sd, key_params, label + " " + action + " update drops cached OCE"
                )
                sd = authenticate()
                sd.store_allowlist(anchor, allowed)
                sd = authenticate(key_params)
                secure_read(
                    sd, label + " " + action + " update recovers with fresh SDK PSO"
                )

            sd = authenticate()
            sd.store_allowlist(anchor, allowed)
            upload(sd, first)
            for payload, reason in (
                (Tlv(0x70, Tlv(0x94, b"\1")), "wrong serial tag"),
                (Tlv(0x70, Tlv(0x93, b"")), "empty serial"),
                (Tlv(0x70, Tlv(0x93, b"\1" * 22)), "oversized serial"),
                (Tlv(0x70, b"\x93\x02\x01"), "truncated serial"),
            ):
                denied(sd, Tlv(0xA6, Tlv(0x83, anchor)) + payload, label + " " + reason)
            sd = finish(sd, key_params)
            secure_read(
                sd, label + " rejected updates retain independently validated OCE"
            )

            # A completed certificate chain must not remain the prefix for the
            # next PSO. Replace OCE with another independently signed own leaf.
            new_leaf_key = ec.generate_private_key(ec.SECP256R1())
            new_leaf = own_cert(
                new_leaf_key.public_key(),
                first[0],
                name(label + " replacement OCE"),
                first[2][0].subject,
                OCE,
            )
            replacement = (first[0], new_leaf_key, (first[2][0], new_leaf), anchor)
            sd = authenticate()
            sd.store_allowlist(anchor, allowed + [new_leaf.serial_number])
            upload(sd, first)
            upload(sd, replacement)
            sd = finish(sd, params(kid, replacement))
            secure_read(
                sd, label + " second complete PSO replaces first host before MUT"
            )

            sd = authenticate()
            upload(sd, first)
            sd.protocol.send_apdu(
                0x80,
                0x2A,
                other.kvn,
                other.kid | 0x80,
                second[2][0].public_bytes(serialization.Encoding.DER),
            )
            absent(
                sd,
                key_params,
                label + " new partial PSO cannot reuse prior complete OCE",
            )

            sd = authenticate()
            upload(sd, first)
            sd.protocol.select(bytes.fromhex("a000000151000000"))
            absent(sd, key_params, label + " SELECT drops volatile OCE")

            sd = authenticate()
            upload(sd, first)
            conn = fixture.restart()
            sd = SecurityDomainSession(conn)
            absent(sd, key_params, label + " restart never persists host cache")

        # GP distinguishes CA-key replacement from allowlist updates: retain the
        # list and cached OCE, but discard the old CA Identifier (SKI).
        sd = authenticate()
        allowed = [cert.serial_number for cert in first[2]]
        sd.store_allowlist(anchor, allowed)
        upload(sd, first)
        changed = host("replacement anchor", anchor)
        sd.put_key(anchor, changed[0].public_key(), replace_kvn=1)
        row = saved()["domain"]["keys"][anchor.hex()]
        check(
            row["allowlist"] == allowed and "ski" not in row,
            "same-version CA replacement retains linked allowlist and drops old SKI",
        )
        sd = finish(sd, params(0x11, first))
        secure_read(
            sd, "CA replacement preserves previously validated OCE per GP model"
        )

        sd = authenticate()
        moved = KeyRef(anchor.kid, 2)
        sd.put_key(moved, changed[0].public_key(), replace_kvn=1)
        row = saved()["domain"]["keys"][moved.hex()]
        check(
            row["allowlist"] == allowed
            and anchor.hex() not in saved()["domain"]["keys"],
            "new-version CA replacement moves linked allowlist to replacement row",
        )
        conn = fixture.restart()
        sd = authenticate()
        check(
            saved()["domain"]["keys"][moved.hex()] == row,
            "restart preserves replacement CA key and its linked allowlist",
        )
        moved_identity = (changed[0], changed[1], changed[2], moved)
        before = saved()
        try:
            authenticate(params(0x11, moved_identity))
        except ApduError as error:
            check(
                error.sw == 0x6982 and saved() == before,
                "retained allowlist rejects the new unlisted chain signed by the replacement CA",
            )
        else:
            raise AssertionError("replacement CA lost its allowlist enforcement")
        sd = authenticate()
        before = saved()
        try:
            sd.put_key(KeyRef(anchor.kid, 0), first[0].public_key(), replace_kvn=2)
        except ApduError as error:
            check(
                error.sw == 0x6A80 and saved() == before,
                "invalid replacement leaves CA key and linked allowlist unchanged",
            )
        else:
            raise AssertionError("accepted zero-version CA replacement")
        sd.delete_key(moved.kid, moved.kvn)
        sd.put_key(moved, changed[0].public_key())
        check(
            "allowlist" not in saved()["domain"]["keys"][moved.hex()],
            "CA deletion removes linked allowlist; later key creation has no inherited list",
        )
        sd = authenticate(params(0x11, moved_identity))
        secure_read(
            sd, "new CA and own certificate chain work after linked-list deletion"
        )
        sd.store_allowlist(moved, [cert.serial_number for cert in changed[2]])
        secure_read(
            sd,
            "successful allowlist STORE retains the current SCP11a protected channel",
        )
        sd.store_ca_issuer(
            moved,
            changed[2][0]
            .extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
            .value.digest,
        )
        secure_read(
            sd,
            "current SCP11a still authorizes later management after cache invalidation",
        )
        conn = fixture.restart()
        check(
            peers == {key: value for key, value in saved().items() if key != "domain"},
            "cache/allowlist/anchor tests and restart preserve every peer application",
        )
        passed = True
    finally:
        fixture.stop()
        report.write_text(
            json.dumps(
                {
                    "passed": passed,
                    "tests": tests,
                    "transport": "direct IFD ABI"
                    if ifd_driver
                    else "private CCID socket",
                    "physical_device_access": False,
                    "manufacturer_trust_reproduced": False,
                    "system_pcsc_reader_registered": False,
                    "source": {
                        "url": GP_SOURCE,
                        "version": "1.3.0.13 public review",
                        "sections": ["7.5", "7.6.1", "7.9", "7.10"],
                    },
                    "sdk_phase_control": "only skip the already explicitly presented own PSO certificates; unchanged SDK MUT request, receipt/KDF/secure messaging",
                    "unverified": [
                        "physical cache/lifecycle/error status and finalized GP1.4 differences",
                        "allowlist scope across every chain certificate",
                        "firmware SCP11c counter semantics and critical SD subject ID",
                        "intermediate PSO per-certificate validation and firmware constraints",
                        "actual OS reader/browser interoperability",
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
        prefix="ske-domain-cache-", dir=args.work_dir
    ) as directory:
        run(
            Path(__file__).resolve().parents[1],
            Path(directory),
            args.report,
            args.ifd_driver,
        )


if __name__ == "__main__":
    main()
