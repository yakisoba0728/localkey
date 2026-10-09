#!/usr/bin/env python3
"""Verify incremental PSO, cache and channel lifecycle on fresh own software keys.

Unchanged SDK validates MUT receipts/KDF and encrypted/MAC-protected responses.
Explicit phase control omits PSO only to probe previously uploaded or absent OCE.
No physical key, manufacturer identity, system reader or real credential access.
Status6982 and existing date/role/budget policy remain software profile models.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from emucard.core import EncryptedState
from verify_domain_cache import GP_SOURCE
from verify_domain_profile import KA, OCE, ROOT, name, own_cert
from verify_smartcard import Fixture
from yubikit.core.smartcard import ApduError, ScpProcessor, SmartCardProtocol
from yubikit.core.smartcard.scp import KeyRef, Scp03KeyParams, Scp11KeyParams, ScpState
from yubikit.piv import (
    DEFAULT_MANAGEMENT_KEY,
    KEY_TYPE,
    PIN_POLICY,
    SLOT,
    TOUCH_POLICY,
    PivSession,
)
from yubikit.securitydomain import SecurityDomainSession


def replace_extension(cert, signer, value):
    builder = (
        x509.CertificateBuilder()
        .subject_name(cert.subject)
        .issuer_name(cert.issuer)
        .public_key(cert.public_key())
        .serial_number(cert.serial_number)
        .not_valid_before(cert.not_valid_before_utc)
        .not_valid_after(cert.not_valid_after_utc)
    )
    for extension in cert.extensions:
        builder = builder.add_extension(
            value if extension.oid == value.oid else extension.value,
            extension.critical,
        )
    return builder.sign(signer, hashes.SHA256())


def run(root, directory, report, ifd_driver=None):
    fixture, tests, passed = Fixture(root, directory, ifd_driver), [], False

    def check(value, label):
        if not value:
            raise AssertionError(label)
        tests.append({"name": label, "passed": True})
        print("PASS", label, flush=True)

    def saved():
        return EncryptedState(directory / "state.bin").data

    def authenticate():
        sd = SecurityDomainSession(conn)
        sd.authenticate(Scp03KeyParams())
        return sd

    def send(protocol, cert, *, final=False, ref=None):
        ref = ref or anchor
        data = (
            cert
            if isinstance(cert, bytes)
            else cert.public_bytes(serialization.Encoding.DER)
        )
        return protocol.send_apdu(
            0x80, 0x2A, ref.kvn, ref.kid | (0 if final else 0x80), data
        )

    def denied(protocol, cert, label, *, final=False, ref=None, sw=0x6982):
        raw = (directory / "state.bin").read_bytes()
        try:
            send(protocol, cert, final=final, ref=ref)
        except ApduError as error:
            check(
                error.sw == sw and (directory / "state.bin").read_bytes() == raw,
                label + "; exact encrypted state unchanged",
            )
        else:
            raise AssertionError("accepted invalid own PSO: " + label)

    def finish(through, kid, certificates, ref=None):
        key_params = Scp11KeyParams(
            KeyRef(kid, 1), public[kid], ref or anchor, leaf_key, certificates
        )
        protocol = SmartCardProtocol(conn)
        base, formatter = protocol._build_base_processor()
        protocol._processor = base
        skipped = []

        def phase(cla, ins, p1, p2, data):
            if ins == 0x2A:
                index = len(skipped)
                assert data == certificates[index].public_bytes(
                    serialization.Encoding.DER
                )
                assert cla == 0x80 and p1 == key_params.oce_ref.kvn
                assert p2 == key_params.oce_ref.kid | (
                    0x80 if index < len(certificates) - 1 else 0
                )
                skipped.append(data)
                return b""
            assert ins == 0x82 and len(skipped) == len(certificates)
            return through.send_apdu(cla, ins, p1, p2, data)

        state = ScpState.scp11_init(phase, key_params)
        protocol._processor = ScpProcessor(base, formatter, state)
        return protocol

    def missing(through, kid, label):
        before = saved()
        try:
            finish(through, kid, chain)
        except ApduError as error:
            before["domain"]["keys"][KeyRef(kid, 1).hex()]["retries"] -= 1
            check(
                error.sw == 0x6985 and saved() == before,
                label + "; absent OCE denies MUT and only durable retry changes",
            )
        else:
            raise AssertionError("intermediate/failed PSO granted OCE: " + label)

    try:
        conn = fixture.start()
        sd = authenticate()
        public = {kid: sd.generate_ec_key(KeyRef(kid, 1)) for kid in (0x11, 0x15)}
        anchor, alternative, wrong = KeyRef(0x10, 1), KeyRef(0x20, 1), KeyRef(0x21, 1)
        ca, mid, leaf_key = [ec.generate_private_key(ec.SECP256R1()) for _ in range(3)]
        root_name, mid_name, leaf_name = [
            name("incremental own " + s) for s in ("CA", "KA", "OCE")
        ]
        root_cert = own_cert(
            ca.public_key(), ca, root_name, root_name, ROOT, ca=True, path_length=1
        )
        mid_cert = own_cert(
            mid.public_key(), ca, mid_name, root_name, KA, ca=True, path_length=0
        )
        leaf = own_cert(leaf_key.public_key(), mid, leaf_name, mid_name, OCE)
        direct = own_cert(leaf_key.public_key(), ca, leaf_name, root_name, OCE)
        chain = (root_cert, mid_cert, leaf)
        for ref in (anchor, alternative):
            sd.put_key(ref, ca.public_key())
            sd.store_ca_issuer(
                ref, x509.SubjectKeyIdentifier.from_public_key(ca.public_key()).digest
            )
        sd.put_key(wrong, ec.generate_private_key(ec.SECP256R1()).public_key())
        cplc = sd.get_data(0x9F7F)
        original_keys = saved()["domain"]["keys"]
        original_apps = {k: v for k, v in saved().items() if k != "domain"}
        proper = root_cert.public_bytes(serialization.Encoding.DER)
        broken = proper[:-1] + bytes([proper[-1] ^ 1])
        x509.load_der_x509_certificate(broken)
        weak_usage = x509.KeyUsage(
            False, False, False, False, True, False, False, False, False
        )
        invalid = {
            "wrong signature in intact DER": broken,
            "non-CA as intermediate": own_cert(
                ca.public_key(), ca, root_name, root_name, ROOT
            ),
            "intermediate lacking keyCertSign": replace_extension(
                root_cert, ca, weak_usage
            ),
            "wrong critical prefix role": own_cert(
                ca.public_key(), ca, root_name, root_name, OCE, ca=True
            ),
            "expired prefix date model": own_cert(
                ca.public_key(), ca, root_name, root_name, ROOT, ca=True, expired=True
            ),
            "unsupported role qualifier": own_cert(
                ca.public_key(),
                ca,
                root_name,
                root_name,
                ROOT,
                ca=True,
                qualifiers=["https://example.invalid/own"],
            ),
            "wrong issuer identifier": own_cert(
                ca.public_key(), ca, root_name, root_name, ROOT, ca=True, akid=bytes(20)
            ),
            "unknown critical constraint": own_cert(
                ca.public_key(),
                ca,
                root_name,
                root_name,
                ROOT,
                ca=True,
                extra=(
                    x509.UnrecognizedExtension(
                        x509.ObjectIdentifier("1.3.6.1.4.1.55555.1"), b"own"
                    ),
                    True,
                ),
            ),
            "unsupported P384 prefix curve": own_cert(
                ec.generate_private_key(ec.SECP384R1()).public_key(),
                ca,
                mid_name,
                root_name,
                KA,
                ca=True,
            ),
            "unsupported RSA prefix key": own_cert(
                rsa.generate_private_key(65537, 2048).public_key(),
                ca,
                mid_name,
                root_name,
                KA,
                ca=True,
            ),
        }
        for label, certificate in invalid.items():
            sd = authenticate()
            denied(sd.protocol, certificate, "first prefix " + label)
            check(
                sd.get_data(0x9F7F) == cplc,
                "failed prefix preserves active SCP03: " + label,
            )

        for continuation in (False, True):
            sd = authenticate()
            if continuation:
                send(sd.protocol, root_cert)
            before = saved()
            try:
                send(sd.protocol, bytes(8), ref=wrong if continuation else anchor)
            except ApduError as error:
                before["domain"]["keys"][anchor.hex()]["retries"] -= 1
                check(
                    error.sw == 0x6A80 and saved() == before,
                    f"malformed PSO continuation={continuation} consumes only initial CA retry",
                )
            else:
                raise AssertionError("accepted malformed own prefix DER")
            check(
                sd.get_data(0x9F7F) == cplc,
                f"malformed PSO continuation={continuation} preserves active channel",
            )
            missing(
                sd.protocol,
                0x11,
                f"malformed PSO continuation={continuation} clears OCE",
            )

        # Incorrect next certificates must not wait for the final leaf either.
        for label, bad in (
            (
                "second-prefix wrong signature",
                mid_cert.public_bytes(serialization.Encoding.DER)[:-1]
                + bytes([mid_cert.public_bytes(serialization.Encoding.DER)[-1] ^ 1]),
            ),
            (
                "second-prefix wrong issuer AKI",
                own_cert(
                    mid.public_key(),
                    ca,
                    mid_name,
                    root_name,
                    KA,
                    ca=True,
                    akid=bytes(20),
                ),
            ),
            (
                "second-prefix non-CA",
                own_cert(mid.public_key(), ca, mid_name, root_name, KA),
            ),
        ):
            sd = authenticate()
            send(sd.protocol, root_cert)
            denied(sd.protocol, bad, label)
            check(
                sd.get_data(0x9F7F) == cplc, label + " preserves active outer wrapper"
            )
            missing(sd.protocol, 0x11, label + " clears rejected chain")

        sd = authenticate()
        send(
            sd.protocol,
            own_cert(
                ca.public_key(), ca, root_name, root_name, ROOT, ca=True, path_length=0
            ),
        )
        denied(
            sd.protocol, mid_cert, "path-length limit enforced when excess CA arrives"
        )
        missing(sd.protocol, 0x15, "path-length error does not authorize c")

        # A valid intermediate alone must never be treated as an OCE credential.
        for kid in (0x11, 0x15):
            sd = authenticate()
            send(sd.protocol, root_cert)
            check(
                sd.get_data(0x9F7F) == cplc,
                f"{kid:02x} valid prefix preserves current wrapper",
            )
            missing(
                sd.protocol,
                kid,
                f"{kid:02x} partial chain cannot grant ECKA authorization",
            )

        for certificates in (chain, (mid_cert, leaf), (direct,)):
            for kid in (0x11, 0x15):
                sd = authenticate()
                for index, cert in enumerate(certificates):
                    send(sd.protocol, cert, final=index == len(certificates) - 1)
                new = finish(sd.protocol, kid, certificates)
                check(
                    new.send_apdu(0, 0xCA, 0x9F, 0x7F) == cplc,
                    f"{kid:02x} chain{len(certificates)} SDK validates receipt/KDF/encrypted MAC response",
                )

        # Only the initial reference controls the chain; later arbitrary P1/P2
        # cannot redirect it to the wrong owned CA or force an unrelated lookup.
        for kid in (0x11, 0x15):
            sd = authenticate()
            send(sd.protocol, root_cert)
            send(sd.protocol, mid_cert, ref=wrong)
            send(sd.protocol, leaf, final=True, ref=KeyRef(0x7F, 127))
            check(
                finish(sd.protocol, kid, chain).send_apdu(0, 0xCA, 0x9F, 0x7F) == cplc,
                f"{kid:02x} continuation ignores changed CA references while first anchor remains binding",
            )
        sd = authenticate()
        denied(
            sd.protocol, root_cert, "wrong initial anchor cannot fall back", ref=wrong
        )

        # Preserve wildcard candidates: a prefix's first signature match is not
        # enough to choose a CA before every prefix/leaf serial is checked.
        sd = authenticate()
        sd.store_allowlist(
            anchor,
            [root_cert.serial_number, mid_cert.serial_number, leaf.serial_number + 1],
        )
        sd.store_allowlist(
            alternative,
            [root_cert.serial_number, mid_cert.serial_number, leaf.serial_number],
        )
        for kid in (0x11, 0x15):
            sd = authenticate()
            for index, cert in enumerate(chain):
                send(sd.protocol, cert, final=index == len(chain) - 1, ref=KeyRef(0, 0))
            check(
                finish(sd.protocol, kid, chain, KeyRef(0, 0)).send_apdu(
                    0, 0xCA, 0x9F, 0x7F
                )
                == cplc,
                f"{kid:02x} wildcard keeps alternative CA eligible through final allowlist check",
            )
        sd = authenticate()
        send(sd.protocol, root_cert)
        send(sd.protocol, mid_cert)
        denied(
            sd.protocol,
            leaf,
            "explicit CA cannot switch to alternative allowlist",
            final=True,
        )
        sd.store_allowlist(anchor, [])
        sd.store_allowlist(alternative, [])

        # Yubico's established transport rejects plaintext PSO. That boundary
        # is covered by verify_domain_plaintext; this suite uses protected PSO.
        sd = authenticate()
        free_root = own_cert(ca.public_key(), ca, root_name, root_name, None, ca=True)
        free_leaf = own_cert(leaf_key.public_key(), ca, leaf_name, root_name, None)
        send(sd.protocol, free_root)
        send(sd.protocol, free_leaf, final=True)
        check(
            finish(sd.protocol, 0x11, (free_root, free_leaf)).send_apdu(
                0, 0xCA, 0x9F, 0x7F
            )
            == cplc,
            "existing policy-free certificate profile remains supported incrementally",
        )
        check(
            original_apps == {k: v for k, v in saved().items() if k != "domain"},
            "PSO validation/cache/ref changes preserve every independent application",
        )
        check(
            all(
                {
                    k: v
                    for k, v in saved()["domain"]["keys"][ref].items()
                    if k not in ("retries", "allowlist")
                }
                == {k: v for k, v in row.items() if k not in ("retries", "allowlist")}
                for ref, row in original_keys.items()
            ),
            "PSO validation never replaces CA or own SD key/certificate material",
        )

        piv = PivSession(conn, Scp03KeyParams())
        piv.authenticate(DEFAULT_MANAGEMENT_KEY)
        piv_public = piv.generate_key(
            SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, PIN_POLICY.ONCE, TOUCH_POLICY.NEVER
        )
        piv.verify_pin("123456")
        send(piv.protocol, root_cert)
        message = b"own protected PSO preserves existing application PIN scope"
        signature = piv.sign(
            SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, message, hashes.SHA256()
        )
        piv_public.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        check(
            True,
            "protected valid PSO preserves PIV verified PIN and independently verified signature",
        )
        denied(
            piv.protocol,
            broken,
            "protected invalid continuation denied before final leaf",
        )
        signature = piv.sign(
            SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, message, hashes.SHA256()
        )
        piv_public.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        check(
            True,
            "failed protected PSO preserves PIV verified PIN and old secure messaging",
        )
        for index, cert in enumerate(chain):
            send(piv.protocol, cert, final=index == len(chain) - 1)
        signature = piv.sign(
            SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, message, hashes.SHA256()
        )
        piv_public.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        check(True, "protected complete PSO also preserves PIV application PIN scope")
        piv.protocol = finish(piv.protocol, 0x11, chain)
        before = (directory / "state.bin").read_bytes()
        try:
            piv.sign(SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, message, hashes.SHA256())
        except ApduError as error:
            check(
                error.sw == 0x6982 and (directory / "state.bin").read_bytes() == before,
                "actual MUT handoff clears prior PIV PIN scope without changing state",
            )
        else:
            raise AssertionError("new own SCP context inherited PIV PIN")
        passed = True
    finally:
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
                    "source": {
                        "url": GP_SOURCE,
                        "version": "1.3.0.13 public review",
                        "sections": ["7.5.1", "7.5.2", "7.6.1"],
                    },
                    "existing_error_status_model": "6982; firmware rejection status and GP table6600 not reconciled",
                    "allowlist_model": "vendor each presented certificate; physical scope/status pending",
                    "sdk_phase_control": "explicit PSO omitted to probe uploaded or absent OCE; MUT uses current protected transport; unchanged SDK receipt/KDF/secure messaging",
                    "unverified": [
                        "physical incremental verification/status and final GP1.4",
                        "physical every-certificate allowlist scope and rejection timing/status",
                        "SD SubjectID and exact dates/qualifiers/budgets",
                        "Yubico applicability of GP new-content transactions and OS interoperability",
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
    with tempfile.TemporaryDirectory(prefix="ske-pso-", dir=args.work_dir) as directory:
        run(
            Path(__file__).resolve().parents[1],
            Path(directory),
            args.report,
            args.ifd_driver,
        )


if __name__ == "__main__":
    main()
