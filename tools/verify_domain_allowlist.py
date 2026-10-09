#!/usr/bin/env python3
"""Verify Yubico each-certificate allowlist scope on fresh own software keys.

Unmodified SDK validates MUT receipt/KDF and encrypted response MACs. Controlled
PSO phases expose incremental membership/cache behavior without resending PSO.
No physical key, manufacturer trust, system reader or existing credential used.
Vendor prose describes every certificate; immediate-prefix rejection timing
and numeric6982/6985 statuses are software models, not firmware measurements.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from functools import partial
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from emucard.client import CcidSocketConnection
from emucard.core import EncryptedState
from emucard.ifd import IfdNativeConnection
from verify_domain_profile import KA, OCE, ROOT, name, own_cert
from verify_smartcard import Fixture
from yubikit.core.smartcard import ApduError, ScpProcessor, SmartCardProtocol
from yubikit.core.smartcard.scp import KeyRef, Scp03KeyParams, Scp11KeyParams, ScpState
from yubikit.securitydomain import SecurityDomainSession

VENDOR_SOURCE = "https://docs.yubico.com/software/yubikey/tools/ykman/Security_Domain_SD_Commands.html"


def with_serial(cert, signer, serial):
    builder = (
        x509.CertificateBuilder()
        .subject_name(cert.subject)
        .issuer_name(cert.issuer)
        .public_key(cert.public_key())
        .serial_number(serial)
        .not_valid_before(cert.not_valid_before_utc)
        .not_valid_after(cert.not_valid_after_utc)
    )
    for extension in cert.extensions:
        builder = builder.add_extension(extension.value, extension.critical)
    return builder.sign(signer, hashes.SHA256())


def run(root, directory, report, ifd_driver=None):
    fixture, tests, peers = Fixture(root, directory, ifd_driver), [], []
    passed = False

    def check(value, label):
        if not value:
            raise AssertionError(label)
        tests.append({"name": label, "passed": True})
        print("PASS", label, flush=True)

    def saved():
        return EncryptedState(directory / "state.bin").data

    def params(kid, certificates=(), ref=None):
        return (
            Scp03KeyParams()
            if kid is None
            else Scp11KeyParams(
                KeyRef(kid, 1),
                public[kid],
                ref or anchor,
                own_key,
                certificates or chain,
            )
        )

    def authenticate(connection=None, kid=None, certificates=(), ref=None):
        sd = SecurityDomainSession(connection or conn)
        sd.authenticate(params(kid, certificates, ref))
        return sd

    def peer():
        connection = (
            IfdNativeConnection(ifd_driver, directory / "s.sock")
            if ifd_driver
            else CcidSocketConnection(directory / "s.sock")
        )
        peers.append(connection)
        return connection

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

    def upload(protocol, certificates=(), ref=None):
        certificates = certificates or chain
        for index, cert in enumerate(certificates):
            send(protocol, cert, final=index == len(certificates) - 1, ref=ref)

    def denied(operation, label, *, sw=0x6982, ciphertext=True):
        before, raw = saved(), (directory / "state.bin").read_bytes()
        try:
            operation()
        except ApduError as error:
            check(
                error.sw == sw
                and saved() == before
                and (not ciphertext or (directory / "state.bin").read_bytes() == raw),
                label + f"; modeled{sw:04x} and persistent state unchanged",
            )
        else:
            raise AssertionError("accepted unlisted own certificate: " + label)

    def finish(through, kid, certificates=(), ref=None):
        certificates = certificates or chain
        key_params = params(kid, certificates, ref)
        protocol = SmartCardProtocol(conn)
        base, formatter = protocol._build_base_processor()
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
            finish(through, kid)
        except ApduError as error:
            before["domain"]["keys"][KeyRef(kid, 1).hex()]["retries"] -= 1
            check(
                error.sw == 0x6985 and saved() == before,
                label + "; revoked OCE denies MUT; only modeled durable retry changes",
            )
        else:
            raise AssertionError("unlisted/partial chain retained OCE: " + label)

    try:
        conn = fixture.start()
        sd = authenticate()
        anchor, alternative = KeyRef(0x10, 1), KeyRef(0x20, 1)
        public = {kid: sd.generate_ec_key(KeyRef(kid, 1)) for kid in (0x11, 0x15)}
        ca, mid, own_key = [ec.generate_private_key(ec.SECP256R1()) for _ in range(3)]
        ca_name, mid_name, host_name = [
            name("own serial " + label) for label in ("CA", "KA", "OCE")
        ]
        root_cert = own_cert(
            ca.public_key(), ca, ca_name, ca_name, ROOT, ca=True, path_length=1
        )
        middle = own_cert(
            mid.public_key(), ca, mid_name, ca_name, KA, ca=True, path_length=0
        )
        leaf = own_cert(own_key.public_key(), mid, host_name, mid_name, OCE)
        direct = own_cert(own_key.public_key(), ca, host_name, ca_name, OCE)
        chain = (root_cert, middle, leaf)
        serials = [cert.serial_number for cert in chain]
        for ref in (anchor, alternative):
            sd.put_key(ref, ca.public_key())
            sd.store_ca_issuer(
                ref, x509.SubjectKeyIdentifier.from_public_key(ca.public_key()).digest
            )
        cplc = sd.get_data(0x9F7F)
        original_keys = saved()["domain"]["keys"]
        original_apps = {k: v for k, v in saved().items() if k != "domain"}
        independent = authenticate(peer())

        for kid in (0x11, 0x15):
            for omitted, description in enumerate(("root", "intermediate", "leaf")):
                label = f"{kid:02x} omits {description}"
                sd = authenticate()
                sd.store_allowlist(anchor, serials[:omitted] + serials[omitted + 1 :])
                for cert in chain[:omitted]:
                    send(sd.protocol, cert)
                denied(
                    partial(send, sd.protocol, chain[omitted], final=omitted == 2),
                    label + " immediate rejection",
                )
                check(
                    sd.get_data(0x9F7F) == cplc,
                    label + " protected outer channel preserved",
                )
                check(
                    independent.get_data(0x9F7F) == cplc,
                    label + " independent peer channel preserved",
                )
                missing(sd.protocol, kid, label + " incomplete/rejected cache cleared")
                denied(
                    partial(authenticate, kid=kid),
                    label + " fresh full SDK chain rejected",
                    ciphertext=False,
                )

        for certificates, description in (
            (chain, "root+intermediate+leaf"),
            ((middle, leaf), "optional root not presented"),
            ((direct,), "direct leaf; stored CA has no presented root serial"),
        ):
            sd = authenticate()
            allowed = [cert.serial_number for cert in certificates]
            sd.store_allowlist(anchor, allowed)
            check(
                saved()["domain"]["keys"][anchor.hex()]["allowlist"] == allowed,
                description + " exact list stored",
            )
            for kid in (0x11, 0x15):
                check(
                    authenticate(kid=kid, certificates=certificates).get_data(0x9F7F)
                    == cplc,
                    f"{kid:02x} {description} SDK receipt/KDF/encrypted R-MAC validated",
                )

        # Listed serials do not replace certificate signature checks.
        sd = authenticate()
        sd.store_allowlist(anchor, serials)
        raw = root_cert.public_bytes(serialization.Encoding.DER)
        broken = raw[:-1] + bytes([raw[-1] ^ 1])
        denied(
            partial(send, sd.protocol, broken),
            "listed root with broken signature rejected",
        )

        # Prefix and leaf must be accepted under the same eligible CA policy;
        # two matching public keys do not allow a union of different allowlists.
        for kid in (0x11, 0x15):
            sd = authenticate()
            sd.store_allowlist(anchor, [serials[0], serials[1], serials[2] + 1])
            sd.store_allowlist(alternative, serials)
            check(
                authenticate(kid=kid, ref=KeyRef(0, 0)).get_data(0x9F7F) == cplc,
                f"{kid:02x} wildcard preserves alternative through leaf membership",
            )
            denied(
                partial(authenticate, kid=kid),
                f"{kid:02x} explicit reference cannot switch to alternative list",
                ciphertext=False,
            )
            sd = authenticate()
            sd.store_allowlist(anchor, [serials[0]])
            sd.store_allowlist(alternative, serials[1:])
            send(sd.protocol, root_cert, ref=KeyRef(0, 0))
            denied(
                partial(send, sd.protocol, middle, ref=KeyRef(0, 0)),
                f"{kid:02x} wildcard cannot union prefix serials from different anchors",
            )
            missing(
                sd.protocol, kid, f"{kid:02x} split-anchor rejection cannot grant OCE"
            )
            sd = authenticate()
            sd.store_allowlist(anchor, [serials[0], serials[2]])
            sd.store_allowlist(alternative, serials)
            send(sd.protocol, root_cert)
            denied(
                partial(send, sd.protocol, middle, ref=alternative),
                f"{kid:02x} continuation reference ignored; initial list remains binding",
            )
            missing(
                sd.protocol,
                kid,
                f"{kid:02x} redirected continuation does not restore OCE",
            )
            sd = authenticate()
            upload(sd.protocol, ref=KeyRef(0, 0))
            check(
                finish(sd.protocol, kid, ref=KeyRef(0, 0)).send_apdu(
                    0, 0xCA, 0x9F, 0x7F
                )
                == cplc,
                f"{kid:02x} wildcard switches candidate when later CA serial is omitted",
            )

        # Positive ASN.1 sign-padding in the wire list must compare as serial
        # integers, and must include every certificate rather than only the leaf.
        padded = tuple(
            with_serial(cert, signer, serial)
            for cert, signer, serial in zip(
                chain, (ca, ca, mid), (128, 129, 255), strict=True
            )
        )
        sd = authenticate()
        sd.store_allowlist(anchor, [128, 129, 255])
        check(
            saved()["domain"]["keys"][anchor.hex()]["allowlist"] == [128, 129, 255],
            "ASN.1 positive sign padding decodes to all three exact serial integers",
        )
        for kid in (0x11, 0x15):
            check(
                authenticate(kid=kid, certificates=padded).get_data(0x9F7F) == cplc,
                f"{kid:02x} positive sign-padded serial chain SDK interoperability",
            )

        # A new rejected root must replace, not leave reusable, a previously
        # complete OCE cache. All crypto/roles are valid; only its serial differs.
        changed_root = with_serial(root_cert, ca, root_cert.serial_number + 1)
        for kid in (0x11, 0x15):
            sd = authenticate()
            sd.store_allowlist(anchor, serials)
            upload(sd.protocol)
            denied(
                partial(send, sd.protocol, changed_root),
                f"{kid:02x} unlisted replacement prefix rejects despite prior complete OCE",
            )
            missing(
                sd.protocol,
                kid,
                f"{kid:02x} prior complete OCE not reused after rejected prefix",
            )

        # A failed peer policy commit must preserve the all-cert list and cached
        # authorization. A successful peer subset update invalidates it.
        for kid in (0x11, 0x15):
            sd = authenticate()
            sd.store_allowlist(anchor, serials)
            sd.store_allowlist(alternative, [])
            upload(sd.protocol)
            updater = authenticate(peers[0])
            before, raw = saved(), (directory / "state.bin").read_bytes()
            path, backup = directory / "state.bin", directory / "own-backup.bin"
            path.rename(backup)
            path.mkdir()
            try:
                try:
                    updater.store_allowlist(anchor, serials[1:])
                except ApduError as error:
                    check(
                        error.sw == 0x6581,
                        f"{kid:02x} subset policy failed commit returns modeled6581",
                    )
                else:
                    raise AssertionError(
                        "accepted controlled own policy commit failure"
                    )
            finally:
                path.rmdir()
                backup.rename(path)
            check(
                saved() == before and path.read_bytes() == raw,
                f"{kid:02x} failed subset commit rolls back list/generation/ciphertext",
            )
            check(
                finish(sd.protocol, kid).send_apdu(0, 0xCA, 0x9F, 0x7F) == cplc,
                f"{kid:02x} peer failed subset update retains SDK-verified cached OCE",
            )
            sd = authenticate()
            upload(sd.protocol)
            updater = authenticate(peers[0])
            updater.store_allowlist(anchor, serials[1:])
            check(
                sd.get_data(0x9F7F) == cplc,
                f"{kid:02x} peer committed subset preserves existing secure transport",
            )
            missing(
                sd.protocol,
                kid,
                f"{kid:02x} peer committed subset revokes previously complete OCE",
            )
            denied(
                partial(authenticate, kid=kid),
                f"{kid:02x} fresh SDK obeys peer subset list",
                ciphertext=False,
            )

        sd = authenticate()
        sd.store_allowlist(anchor, [])
        check(
            "allowlist" not in saved()["domain"]["keys"][anchor.hex()],
            "empty list clears policy; does not deny every certificate",
        )
        for kid in (0x11, 0x15):
            check(
                authenticate(kid=kid).get_data(0x9F7F) == cplc,
                f"{kid:02x} clearlist permits any otherwise valid complete chain",
            )
        sd = authenticate()
        sd.store_allowlist(anchor, serials[1:])
        before = saved()
        for connection in peers:
            connection.close()
        peers.clear()
        conn = fixture.restart()
        check(
            saved() == before,
            "restart preserves subset policy, own key material and CPLC",
        )
        denied(
            partial(authenticate, kid=0x11),
            "restart still rejects unlisted presented root",
            ciphertext=False,
        )
        sd = authenticate()
        sd.store_allowlist(anchor, serials)
        check(
            authenticate(kid=0x15).get_data(0x9F7F) == cplc,
            "restart and policy repair restore full SDK c interoperability",
        )
        check(
            original_apps == {k: v for k, v in saved().items() if k != "domain"},
            "serial-policy checks preserve every independent application",
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
            "serial-policy changes never replace CA/SD keys, SKI or certificate material",
        )
        passed = True
    finally:
        for connection in peers:
            connection.close()
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
                    "allowlist_model": "each presented certificate under one eligible CA policy",
                    "prefix_rejection_timing_is_software_model": True,
                    "physical_certificate_serial_scope_or_status_measured": False,
                    "sdk_phase_control": "PSO skipped only for previously uploaded/absent cache; current protected MUT; unchanged SDK receipt/KDF/R-MAC",
                    "unverified": [
                        "physical every-certificate serial scope and rejection timing/status",
                        "native OS transports and final GP1.4 differences",
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
        prefix="ske-allow-", dir=args.work_dir
    ) as directory:
        run(
            Path(__file__).resolve().parents[1],
            Path(directory),
            args.report,
            args.ifd_driver,
        )


if __name__ == "__main__":
    main()
