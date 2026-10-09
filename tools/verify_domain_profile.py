#!/usr/bin/env python3
"""Verify own SCP identities, role policies, budgets and retry boundary semantics.

Only fresh software-card sockets or direct IFD ABI are opened. No physical
reader, factory certificate, manufacturer key or existing credential is used.
Numeric retry/EC/certificate/allowlist ceilings remain unmeasured software models.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from emucard.core import EncryptedState
from verify_smartcard import Fixture
from yubikit.core import Version
from yubikit.core.smartcard import ApduError, ExtendedApduFormatter, SmartCardProtocol
from yubikit.core.smartcard.scp import (
    KeyRef,
    Scp03KeyParams,
    Scp11KeyParams,
    StaticKeys,
)
from yubikit.oath import HASH_ALGORITHM, OATH_TYPE, CredentialData, OathSession
from yubikit.piv import KEY_TYPE, SLOT, PivSession
from yubikit.securitydomain import SecurityDomainSession

# Independent expected wire constants from GP SCP11 Annex D, not imported from
# the implementation's role parser.
ROLE = "2.840.114283.100.0.1.2.1."
OCE, SD, ROOT, KA = (x509.ObjectIdentifier(ROLE + str(n)) for n in (0, 10, 20, 40))


def point(key):
    return key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def own_cert(
    pub,
    signer,
    subject,
    issuer,
    role,
    *,
    ca=False,
    path_length=None,
    akid=None,
    extra=None,
    qualifiers=None,
    key_agreement=None,
    expired=False,
):
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=2))
        .not_valid_after(now + datetime.timedelta(days=-1 if expired else 2))
        .add_extension(x509.BasicConstraints(ca, path_length if ca else None), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), False)
        .add_extension(
            x509.AuthorityKeyIdentifier(akid, None, None)
            if akid is not None
            else x509.AuthorityKeyIdentifier.from_issuer_public_key(
                signer.public_key()
            ),
            False,
        )
        .add_extension(
            x509.KeyUsage(
                False,
                False,
                False,
                False,
                not ca if key_agreement is None else key_agreement,
                ca,
                ca,
                False,
                False,
            ),
            True,
        )
    )
    if role is not None:
        builder = builder.add_extension(
            x509.CertificatePolicies([x509.PolicyInformation(role, qualifiers)]), True
        )
    if extra is not None:
        builder = builder.add_extension(*extra)
    return builder.sign(signer, hashes.SHA256())


def name(label):
    return x509.Name(
        [x509.NameAttribute(x509.NameOID.COMMON_NAME, "Local software " + label)]
    )


def run(root, directory, report, ifd_driver=None):
    fixture = Fixture(root, directory, ifd_driver)
    checks = []
    passed = False
    conn = None

    def check(condition, label):
        if not condition:
            raise AssertionError(label)
        checks.append({"name": label, "passed": True})
        print("PASS", label, flush=True)

    def saved():
        return EncryptedState(directory / "state.bin").data

    def denied(sw, operation, label, immutable=True):
        before = (directory / "state.bin").read_bytes()
        before_state = saved() if immutable == "state" else None
        try:
            operation()
        except ApduError as error:
            check(
                error.sw == sw
                and (
                    saved() == before_state
                    if immutable == "state"
                    else not immutable
                    or before == (directory / "state.bin").read_bytes()
                ),
                label
                + (
                    "; persistent state unchanged across SDK selection/certificate APDUs"
                    if immutable == "state"
                    else "; ciphertext unchanged"
                    if immutable
                    else "; durable failure"
                ),
            )
        else:
            raise AssertionError("accepted: " + label)

    def authenticate(params, wide_model_envelope=False):
        session = SecurityDomainSession(conn)
        if wide_model_envelope:
            # An isolated software-envelope fixture, not a change to yubikit or
            # an assertion that a real 5.7.4 card accepts these larger bundles.
            # The SDK's normal MAC formatter caps messages at 3062 bytes even
            # when short transport chaining is enabled. Keep its crypto/chain
            # implementation, using an explicit per-instance test formatter.
            session.protocol = SmartCardProtocol(conn)
            session.protocol.configure(Version(5, 7, 4), force_short=True)
        session.authenticate(params)
        if wide_model_envelope:
            session.protocol._processor.extended_formatter = ExtendedApduFormatter(
                65544
            )
        return session

    def set_retries(ref, value):
        nonlocal conn
        fixture.stop()
        state = EncryptedState(directory / "state.bin")
        state.data["domain"]["keys"][ref.hex()]["retries"] = value
        state.flush()
        conn = fixture.start()

    try:
        conn = fixture.start()
        sd = SecurityDomainSession(conn)
        b_ref = KeyRef(0x13, 1)
        own = sd.get_certificate_bundle(b_ref)[-1]
        own.public_key().verify(
            own.signature,
            own.tbs_certificate_bytes,
            ec.ECDSA(own.signature_hash_algorithm),
        )
        check(
            "Local software" in own.subject.rfc4514_string()
            and own.issuer == own.subject,
            "fresh own SCP11b certificate independently self-verifies with software identity",
        )
        policy = own.extensions.get_extension_for_class(x509.CertificatePolicies)
        usage = own.extensions.get_extension_for_class(x509.KeyUsage)
        check(
            policy.critical
            and len(policy.value) == 1
            and policy.value[0].policy_identifier == SD,
            "own SCP11b certificate carries critical GP SD role policy",
        )
        check(
            usage.critical
            and usage.value.key_agreement
            and not usage.value.key_cert_sign,
            "own SCP11b certificate key usage is ECKA without CA signing privilege",
        )
        check(
            not own.extensions.get_extension_for_class(x509.BasicConstraints).value.ca,
            "own SCP11b certificate has no CA or manufacturer trust",
        )
        b_params = Scp11KeyParams(b_ref, own.public_key())
        check(
            authenticate(b_params).get_key_information(),
            "independent SDK accepts role-bearing own SCP11b identity",
        )

        # An unrelated OATH key/counter and independent PIV issuer survive Domain reset.
        oath = OathSession(conn)
        peer = oath.put_credential(
            CredentialData(
                "domain peer",
                OATH_TYPE.HOTP,
                HASH_ALGORITHM.SHA1,
                b"12345678901234567890",
            )
        )
        first_code = oath.calculate(peer.id, b"")
        piv_issuer = PivSession(conn).get_certificate(SLOT.ATTESTATION).public_key()

        sd = authenticate(Scp03KeyParams())
        a_ref, c_ref, ca_ref = KeyRef(0x11, 1), KeyRef(0x15, 1), KeyRef(0x20, 1)
        a_pub, c_pub = sd.generate_ec_key(a_ref), sd.generate_ec_key(c_ref)
        ca, mid, host = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
        ca_name, mid_name, host_name = name("root"), name("intermediate"), name("OCE")
        root_cert = own_cert(
            ca.public_key(), ca, ca_name, ca_name, ROOT, ca=True, path_length=1
        )
        mid_cert = own_cert(
            mid.public_key(), ca, mid_name, ca_name, KA, ca=True, path_length=0
        )
        leaf = own_cert(host.public_key(), mid, host_name, mid_name, OCE)
        direct_leaf = own_cert(host.public_key(), ca, host_name, ca_name, OCE)
        sd.put_key(ca_ref, ca.public_key())
        sd.store_ca_issuer(
            ca_ref, x509.SubjectKeyIdentifier.from_public_key(ca.public_key()).digest
        )

        def host_params(certificates, *, ref=a_ref, pub=a_pub, anchor=ca_ref):
            return Scp11KeyParams(ref, pub, anchor, host, certificates)

        def certificate_chain(count, leaf_pub, leaf_role, root_role, mid_role):
            chain = [
                own_cert(
                    ca.public_key(),
                    ca,
                    ca_name,
                    ca_name,
                    root_role,
                    ca=True,
                    path_length=count - 2,
                )
            ]
            parent_key, parent_name = ca, ca_name
            for index in range(count - 2):
                key = ec.generate_private_key(ec.SECP256R1())
                subject = name(f"bounded chain {count} intermediate {index}")
                chain.append(
                    own_cert(
                        key.public_key(),
                        parent_key,
                        subject,
                        parent_name,
                        mid_role,
                        ca=True,
                        path_length=count - index - 3,
                    )
                )
                parent_key, parent_name = key, subject
            chain.append(
                own_cert(leaf_pub, parent_key, host_name, parent_name, leaf_role)
            )
            return chain

        for ref, pub in ((a_ref, a_pub), (c_ref, c_pub)):
            for chain in ([root_cert, mid_cert, leaf], [mid_cert, leaf], [direct_leaf]):
                session = authenticate(host_params(chain, ref=ref, pub=pub))
                check(
                    a_ref in session.get_key_information(),
                    f"SCP11 {ref.kid:02x} critical OCE/CA/KA role policies accepted for chain length {len(chain)}",
                )

        host_eight = certificate_chain(8, host.public_key(), OCE, ROOT, KA)
        for ref, pub in ((a_ref, a_pub), (c_ref, c_pub)):
            check(
                authenticate(
                    host_params(host_eight, ref=ref, pub=pub)
                ).get_key_information(),
                f"SCP11 {ref.kid:02x} accepts eight-certificate software chain budget",
            )
        host_nine = certificate_chain(9, host.public_key(), OCE, ROOT, KA)
        denied(
            0x6985,
            lambda: authenticate(host_params(host_nine)),
            "ninth host certificate exceeds software chain budget",
            immutable="state",
        )
        sd = authenticate(Scp03KeyParams(), wide_model_envelope=True)
        stored_eight = certificate_chain(
            8,
            a_pub,
            SD,
            x509.ObjectIdentifier(ROLE + "30"),
            x509.ObjectIdentifier(ROLE + "50"),
        )
        sd.store_certificate_bundle(a_ref, stored_eight)
        fetched = sd.get_certificate_bundle(a_ref)
        for index in range(1, len(fetched)):
            fetched[index].verify_directly_issued_by(fetched[index - 1])
        check(
            len(fetched) == 8 and point(fetched[-1].public_key()) == point(a_pub),
            "eight-certificate SD software store round-trips with explicit test MAC envelope, short chaining and independent signatures",
        )
        stored_nine = certificate_chain(
            9,
            a_pub,
            SD,
            x509.ObjectIdentifier(ROLE + "30"),
            x509.ObjectIdentifier(ROLE + "50"),
        )
        denied(
            0x6A80,
            lambda: sd.store_certificate_bundle(a_ref, stored_nine),
            "ninth stored certificate rejected without overwriting prior bundle",
        )

        variants = [
            (
                "OCE claims SD role",
                own_cert(host.public_key(), mid, host_name, mid_name, SD),
            ),
            (
                "OCE claims root role",
                own_cert(host.public_key(), mid, host_name, mid_name, ROOT),
            ),
            (
                "unknown critical role policy",
                own_cert(
                    host.public_key(),
                    mid,
                    host_name,
                    mid_name,
                    x509.ObjectIdentifier("1.2.3.4"),
                ),
            ),
            (
                "unsupported role qualifier",
                own_cert(
                    host.public_key(),
                    mid,
                    host_name,
                    mid_name,
                    OCE,
                    qualifiers=["https://example.invalid/software-policy"],
                ),
            ),
            (
                "wrong leaf issuer AKI",
                own_cert(
                    host.public_key(), mid, host_name, mid_name, OCE, akid=b"\xff" * 20
                ),
            ),
            (
                "expired OCE",
                own_cert(
                    host.public_key(), mid, host_name, mid_name, OCE, expired=True
                ),
            ),
            (
                "OCE without key agreement",
                own_cert(
                    host.public_key(),
                    mid,
                    host_name,
                    mid_name,
                    OCE,
                    key_agreement=False,
                ),
            ),
            (
                "OCE carrying CA signing privilege",
                own_cert(
                    host.public_key(),
                    mid,
                    host_name,
                    mid_name,
                    OCE,
                    ca=True,
                    path_length=0,
                    key_agreement=True,
                ),
            ),
            (
                "unknown critical extension",
                own_cert(
                    host.public_key(),
                    mid,
                    host_name,
                    mid_name,
                    OCE,
                    extra=(
                        x509.UnrecognizedExtension(
                            x509.ObjectIdentifier("1.2.3.5"), b"\x04\0"
                        ),
                        True,
                    ),
                ),
            ),
        ]
        for label, bad in variants:
            denied(
                0x6982,
                lambda bad=bad: authenticate(host_params([root_cert, mid_cert, bad])),
                "certificate constraint rejects " + label,
                immutable="state",
            )
        wrong_root = own_cert(
            ca.public_key(), ca, ca_name, ca_name, KA, ca=True, path_length=1
        )
        wrong_mid = own_cert(
            mid.public_key(), ca, mid_name, ca_name, ROOT, ca=True, path_length=0
        )
        denied(
            0x6982,
            lambda: authenticate(host_params([wrong_root, mid_cert, leaf])),
            "root certificate cannot substitute intermediate role",
            immutable="state",
        )
        denied(
            0x6982,
            lambda: authenticate(host_params([root_cert, wrong_mid, leaf])),
            "intermediate cannot substitute root role",
            immutable="state",
        )
        wrong_mid_aki = own_cert(
            mid.public_key(),
            ca,
            mid_name,
            ca_name,
            KA,
            ca=True,
            path_length=0,
            akid=b"\xaa" * 20,
        )
        denied(
            0x6982,
            lambda: authenticate(host_params([root_cert, wrong_mid_aki, leaf])),
            "intermediate issuer AKI must match preceding SKI",
            immutable="state",
        )
        unknown_noncritical = own_cert(
            host.public_key(),
            mid,
            host_name,
            mid_name,
            OCE,
            extra=(
                x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.5"), b"\x04\0"),
                False,
            ),
        )
        check(
            authenticate(
                host_params([root_cert, mid_cert, unknown_noncritical])
            ).get_key_information(),
            "unknown noncritical metadata does not replace critical role checks",
        )
        legacy_root = own_cert(
            ca.public_key(), ca, ca_name, ca_name, None, ca=True, path_length=0
        )
        legacy_leaf = own_cert(host.public_key(), ca, host_name, ca_name, None)
        check(
            authenticate(host_params([legacy_root, legacy_leaf])).get_key_information(),
            "existing independent policy-free certificate profile remains supported",
        )
        denied(
            0x6982,
            lambda: PivSession(
                conn, host_params([root_cert, mid_cert, leaf])
            ).generate_key(SLOT.AUTHENTICATION, KEY_TYPE.ECCP256),
            "SCP11 host authentication does not grant PIV management-key authorization",
            immutable="state",
        )

        # Two owned anchors can legitimately share a public key but carry different
        # allowlists. Wildcard selection must try a usable alternative.
        sd = authenticate(Scp03KeyParams())
        ca_two = KeyRef(0x21, 1)
        sd.put_key(ca_two, ca.public_key())
        sd.store_ca_issuer(
            ca_two, x509.SubjectKeyIdentifier.from_public_key(ca.public_key()).digest
        )
        sd.store_allowlist(
            ca_ref,
            [root_cert.serial_number, mid_cert.serial_number, leaf.serial_number + 1],
        )
        sd.store_allowlist(
            ca_two,
            [root_cert.serial_number, mid_cert.serial_number, leaf.serial_number],
        )
        denied(
            0x6982,
            lambda: authenticate(host_params([root_cert, mid_cert, leaf])),
            "explicit disallowed anchor cannot use another anchor allowlist",
            immutable="state",
        )
        check(
            authenticate(
                host_params([root_cert, mid_cert, leaf], anchor=KeyRef(0, 0))
            ).get_key_information(),
            "wildcard host anchor selection continues past a disallowed matching anchor",
        )
        sd = authenticate(Scp03KeyParams())
        sd.store_allowlist(ca_ref, [])
        serials = list(range(1, 65))
        sd.store_allowlist(ca_two, serials)
        check(
            saved()["domain"]["keys"][ca_two.hex()]["allowlist"] == serials,
            "64-entry software allowlist model is stored exactly",
        )
        denied(
            0x6A80,
            lambda: sd.store_allowlist(ca_two, list(range(1, 66))),
            "65-entry allowlist exceeds software model atomically",
        )
        sd.store_allowlist(ca_two, [])
        check(
            "allowlist" not in saved()["domain"]["keys"][ca_two.hex()],
            "empty allowlist clears restriction without deleting owned anchor",
        )

        # Exercise the documented three-set SCP03 capacity and replacement at full.
        custom = {
            n: StaticKeys(os.urandom(16), os.urandom(16), os.urandom(16))
            for n in (1, 2, 4, 127)
        }
        for version in (1, 2, 127):
            sd.put_key(KeyRef(1, version), custom[version])
            check(
                KeyRef(1, version) in sd.get_key_information(),
                f"documented SCP03 set capacity admits independent KVN {version}",
            )
        check(
            KeyRef(1, 255) not in sd.get_key_information(),
            "custom SCP03 sets replace development default",
        )
        denied(
            0x6A84,
            lambda: sd.put_key(KeyRef(1, 4), custom[4]),
            "fourth SCP03 set rejected at documented capacity",
        )
        sd.put_key(KeyRef(1, 4), custom[4], replace_kvn=1)
        check(
            KeyRef(1, 1) not in sd.get_key_information()
            and KeyRef(1, 4) in sd.get_key_information(),
            "replacement at full SCP03 capacity releases previous version atomically",
        )
        denied(
            0x6985,
            lambda: sd.put_key(KeyRef(1, 4), custom[4], replace_kvn=2),
            "SCP03 replacement cannot collide with another existing version",
        )
        denied(
            0x6A88,
            lambda: sd.put_key(KeyRef(1, 5), custom[4], replace_kvn=99),
            "SCP03 replacement of missing version leaves keys intact",
        )
        sd = authenticate(Scp03KeyParams(KeyRef(1, 127), custom[127]))
        check(
            sd.get_key_information(),
            "independent SDK authenticates highest custom SCP03 version",
        )

        # Retain the established EC budget model; do not claim hardware measurement.
        for version in range(2, 13):
            sd.generate_ec_key(KeyRef(0x11, version))
        check(
            sum(ref.kid not in (1, 2, 3) for ref in sd.get_key_information()) == 16,
            "16-row software EC budget includes private and public anchors",
        )
        denied(
            0x6A84,
            lambda: sd.generate_ec_key(KeyRef(0x11, 13)),
            "17th EC row exceeds software budget",
        )
        denied(
            0x6A84,
            lambda: sd.put_key(KeyRef(0x22, 1), ca.public_key()),
            "public anchor shares software EC budget",
        )
        denied(
            0x6A84,
            lambda: sd.put_key(
                KeyRef(0x13, 2), ec.generate_private_key(ec.SECP256R1())
            ),
            "encrypted private import shares software EC budget",
        )
        replaced = sd.generate_ec_key(KeyRef(0x11, 20), replace_kvn=2)
        check(
            KeyRef(0x11, 2) not in sd.get_key_information()
            and len(point(replaced)) == 65,
            "EC replacement at full capacity is atomic and returns independent key",
        )
        sd.delete_key(kid=0x11, kvn=20)
        sd.generate_ec_key(KeyRef(0x13, 2))
        check(
            KeyRef(0x13, 2) in sd.get_key_information(),
            "EC deletion makes room for a fresh private key",
        )
        conn = fixture.restart()
        sd = authenticate(Scp03KeyParams(KeyRef(1, 127), custom[127]))
        check(
            len(sd.get_key_information()) == 25
            and ca_ref in sd.get_supported_ca_identifiers(),
            "full SCP03/EC key table and anchor metadata survive restart",
        )

        # SDK reset uses KVN=0 repeatedly. Blocked newest versions must not hide
        # another usable version. The old implementation stopped at the newest.
        for ref, pub in ((a_ref, a_pub), (c_ref, c_pub)):
            set_retries(ref, 1)
            authenticate(host_params([root_cert, mid_cert, leaf], ref=ref, pub=pub))
            check(
                saved()["domain"]["keys"][ref.hex()]["retries"] == 64,
                f"last modeled SCP11 {ref.kid:02x} retry authenticates role-bearing host and restores tries",
            )
        sd = authenticate(Scp03KeyParams(KeyRef(1, 127), custom[127]))
        sd.reset()
        denied(
            0x6982,
            sd.get_key_information,
            "full-table failure-driven reset terminates the prior authenticated channel",
            immutable="state",
        )
        sd = SecurityDomainSession(conn)
        expected = {KeyRef(1, 255), KeyRef(2, 255), KeyRef(3, 255), b_ref}
        check(
            set(sd.get_key_information()) == expected,
            "SDK reset reaches all three SCP03 versions and all sixteen EC rows",
        )
        new_own = sd.get_certificate_bundle(b_ref)[-1]
        check(
            point(new_own.public_key()) != point(own.public_key()),
            "Domain reset creates fresh independent SCP11b identity",
        )
        check(
            point(PivSession(conn).get_certificate(SLOT.ATTESTATION).public_key())
            == point(piv_issuer),
            "Domain reset retains independent PIV issuer",
        )
        oath = OathSession(conn)
        check(
            len(oath.list_credentials()) == 1
            and oath.calculate(peer.id, b"") != first_code,
            "Domain reset retains OATH secret and durable HOTP progression",
        )

        set_retries(KeyRef(1, 255), 1)
        sd = authenticate(Scp03KeyParams())
        check(
            saved()["domain"]["keys"]["01ff"]["retries"] == 64,
            "last modeled SCP03 retry can complete authentication and restore all tries",
        )
        set_retries(b_ref, 1)
        sd = SecurityDomainSession(conn)
        fresh_b = sd.get_certificate_bundle(b_ref)[-1]
        authenticate(Scp11KeyParams(b_ref, fresh_b.public_key()))
        check(
            saved()["domain"]["keys"]["1301"]["retries"] == 64,
            "last modeled SCP11b retry completes independent SDK receipt and restores tries",
        )
        set_retries(b_ref, 1)
        sd = SecurityDomainSession(conn)
        denied(
            0x6A80,
            lambda: sd.protocol.send_apdu(0x80, 0x88, 1, 0x13, bytes(8)),
            "invalid final SCP11b request consumes final try",
            immutable=False,
        )
        check(
            saved()["domain"]["keys"]["1301"]["retries"] == 0,
            "failed final SCP11b retry persists as zero",
        )
        conn = fixture.restart()
        sd = SecurityDomainSession(conn)
        denied(
            0x6983,
            lambda: sd.authenticate(Scp11KeyParams(b_ref, fresh_b.public_key())),
            "zero-retry SCP11b stays blocked across restart",
            immutable="state",
        )

        sd = authenticate(Scp03KeyParams())
        sd.put_key(ca_ref, ca.public_key())
        set_retries(ca_ref, 1)
        sd = SecurityDomainSession(conn)
        denied(
            0x6A80,
            lambda: sd.protocol.send_apdu(0x80, 0x2A, 1, 0x20, bytes(8)),
            "invalid final OCE certificate consumes final anchor try",
            immutable=False,
        )
        check(
            saved()["domain"]["keys"][ca_ref.hex()]["retries"] == 0,
            "failed final anchor retry persists as zero",
        )
        sd = SecurityDomainSession(conn)
        denied(
            0x6983,
            lambda: sd.protocol.send_apdu(0x80, 0x2A, 1, 0x20, bytes(8)),
            "blocked public anchor stays unavailable",
            immutable="state",
        )

        set_retries(KeyRef(1, 255), 1)
        sd = SecurityDomainSession(conn)
        sd.protocol.send_apdu(0x80, 0x50, 0, 0, b"12345678")
        check(
            saved()["domain"]["keys"]["01ff"]["retries"] == 0,
            "final SCP03 INIT reserves final attempt durably before external authentication",
        )
        sd = SecurityDomainSession(conn)
        denied(
            0x6983,
            lambda: sd.authenticate(Scp03KeyParams()),
            "next zero-retry attempt restores default Domain when all rows are blocked",
            immutable=False,
        )
        check(
            set(sd.get_key_information()) == expected
            and saved()["domain"]["keys"]["01ff"]["retries"] == 64,
            "blocked-domain recovery replenishes development defaults and independent identity",
        )
        authenticate(Scp03KeyParams())
        check(True, "independent SDK can authenticate after blocking reset recovery")
        passed = True
    finally:
        fixture.stop()
        report.write_text(
            json.dumps(
                {
                    "passed": passed,
                    "tests": checks,
                    "scope": "fresh software cards; direct IFD ABI"
                    if ifd_driver
                    else "fresh software cards; private CCID socket",
                    "physical_device_access": False,
                    "manufacturer_trust_reproduced": False,
                    "role_policy_source": "GP SCP11 X509 certificate tables and Annex D; public review v1.3.0.13",
                    "policy_free_legacy_profile_preserved": True,
                    "retry_and_ec_allowlist_limits": "software model; physical values/rejection/lifecycle unmeasured",
                    "scp03_three_set_limit_source": "published Yubico SCP03 manual; no physical boundary writes",
                    "large_certificate_store_fixture": "fresh short SDK protocol and per-instance extended MAC formatter 65544; pinned normal SDK envelope limit 3062 unchanged; physical acceptance unverified",
                    "unverified": [
                        "critical SD subject-ID handling and physical certificate rejection/status; reference advertises no BF20, software returns GP-model 6A81",
                        "physical SCP03 version boundaries/status, SCP11 version reservations, retry/delete timing, EC/allowlist/certificate ceilings",
                        "actual OS resource-manager/USB discovery and physical certificate rejection behavior",
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
        prefix="ske-domain-profile-", dir=args.work_dir
    ) as directory:
        run(
            Path(__file__).resolve().parents[1],
            Path(directory),
            args.report,
            args.ifd_driver,
        )


if __name__ == "__main__":
    main()
