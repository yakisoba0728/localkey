#!/usr/bin/env python3
"""Compare saved public metadata and test independent software Domain lifecycle.

Uses fresh socket or direct IFD fixtures only; never discovers physical readers.
Public reference reads do not prove physical reset or certificate error behavior.
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
from verify_domain_profile import OCE, ROOT, name, own_cert
from verify_smartcard import Fixture
from yubikit.core import Tlv
from yubikit.core.smartcard import ApduError, SmartCardProtocol
from yubikit.core.smartcard.scp import KeyRef, Scp03KeyParams, Scp11KeyParams
from yubikit.oath import HASH_ALGORITHM, OATH_TYPE, CredentialData, OathSession
from yubikit.securitydomain import SecurityDomainSession

from emucard.core import EncryptedState


def run(root, directory, report, ifd_driver=None):
    reference = json.loads(
        (root / "security-domain-reference-observation.json").read_text()
    )
    expected_select = bytes.fromhex(reference["select_public_template"])
    expected_recognition = bytes.fromhex(reference["card_recognition_data"])
    fixture = Fixture(root, directory, ifd_driver)
    checks = []
    passed = False

    def check(value, label):
        if not value:
            raise AssertionError(label)
        checks.append({"name": label, "passed": True})
        print("PASS", label, flush=True)

    def saved():
        return EncryptedState(directory / "state.bin").data

    def denied(sw, operation, label):
        before = saved()
        try:
            operation()
        except ApduError as error:
            check(
                error.sw == sw and saved() == before,
                label + "; persistent state unchanged",
            )
        else:
            raise AssertionError("accepted: " + label)

    def authenticate(params):
        session = SecurityDomainSession(conn)
        session.authenticate(params)
        return session

    try:
        conn = fixture.start()
        protocol = SmartCardProtocol(conn)
        select = protocol.select(bytes.fromhex("a000000151000000"))
        check(
            select == expected_select,
            "SELECT public template exactly matches saved firmware-5.7.4 response",
        )
        check(
            protocol.select(bytes.fromhex("a000000151")) == expected_select,
            "partial public Domain AID returns the complete public SELECT template",
        )
        first, sw = conn.send_and_receive(bytes.fromhex("00a4040008a00000015100000003"))
        remainder, last_sw = conn.send_and_receive(bytes.fromhex("00c0000000"))
        check(
            len(first) == 3
            and sw == 0x6116
            and last_sw == 0x9000
            and first + remainder == expected_select,
            "short SELECT Le uses GET RESPONSE and reconstructs measured public bytes",
        )

        sd = SecurityDomainSession(conn)
        check(
            sd.get_data(0x66) == expected_recognition,
            "GET DATA 0066 exactly matches all 63 captured public bytes",
        )
        recognition = Tlv.parse_list(sd.get_card_recognition_data())
        check(
            [item.tag for item in recognition] == [6, 0x60, 0x63, 0x64, 0x64],
            "SDK recognition has GP/version/identification and separate SCP03/SCP11 templates",
        )
        check(
            Tlv.unpack(6, recognition[1].value)
            == bytes.fromhex("2a864886fc6b02020301"),
            "public recognition declares GP card specification 2.3.1",
        )
        scp03, scp11 = (Tlv.unpack(6, item.value) for item in recognition[3:])
        check(
            scp03 == bytes.fromhex("2a864886fc6b040360"),
            "captured SCP03 implementation option 60 is preserved",
        )
        check(
            scp11 == bytes.fromhex("2a864886fc6b04119b06"),
            "captured two-byte SCP11 implementation option 9b06 is preserved",
        )
        options = scp11[-2:]
        check(
            options[0] & 0x1B == 0x1B and not options[0] & 0x04,
            "GP option bits advertise a/b/c and certificate chains with transient OCE keys",
        )
        check(
            not options[0] & 0x40 and options[1] & 0x06 == 0x06,
            "GP option bits advertise S8 and X509 while excluding legacy certificate format",
        )
        check(
            not options[0] & 0x20 and not options[1] & 0x01,
            "reference advertises no BF20 authorization for either SCP11a or SCP11c",
        )
        first, sw = conn.send_and_receive(bytes.fromhex("00ca006607"))
        remainder, last_sw = conn.send_and_receive(bytes.fromhex("00c0000000"))
        check(
            len(first) == 7
            and sw == 0x6138
            and last_sw == 0x9000
            and first + remainder == expected_recognition,
            "short recognition Le uses GET RESPONSE without losing either option template",
        )
        rows = []
        for entry in Tlv.parse_list(sd.get_data(0xE0)):
            data = Tlv.unpack(0xC0, entry)
            rows.append(
                {
                    "tag": "c0",
                    "value_length": len(data),
                    "type_lengths": [
                        {"type": f"{kind:02x}", "length": length}
                        for kind, length in zip(data[2::2], data[3::2])
                    ],
                }
            )
        check(
            rows == reference["key_information_schema"]["entries"],
            "fresh own key-table type/length schema matches captured public schema",
        )
        own_id = sd.get_data(0x9F7F)
        check(
            len(own_id) == reference["cplc_schema"]["response_length"] == 42,
            "CPLC raw response has measured 42-byte format",
        )
        check(
            own_id[:2] == b"\0\0"
            and own_id[:2].hex() != reference["cplc_schema"]["platform_prefix"],
            "CPLC uses explicit software platform marker instead of claiming Infineon silicon",
        )
        check(
            len(set(own_id[2:])) > 1,
            "CPLC identifier is independently generated software data",
        )
        check(
            SecurityDomainSession(conn).get_data(0x9F7F) == own_id,
            "CPLC is stable across repeated public SELECT and read",
        )
        sd = authenticate(Scp03KeyParams())
        check(
            sd.get_data(0x9F7F) == own_id and sd.get_data(0x66) == expected_recognition,
            "SCP03 SDK encryption and response MAC preserve CPLC and public recognition",
        )
        own_b = sd.get_certificate_bundle(KeyRef(0x13, 1))[-1]
        b_params = Scp11KeyParams(KeyRef(0x13, 1), own_b.public_key())
        sd = authenticate(b_params)
        check(
            sd.get_data(0x9F7F) == own_id and sd.get_data(0x66) == expected_recognition,
            "SCP11b SDK encryption and response MAC preserve public metadata",
        )
        denied(
            0x6982,
            lambda: sd.delete_key(kvn=255, delete_last=True),
            "SCP11b public read privilege cannot reset the Domain",
        )
        sd = authenticate(Scp03KeyParams())
        check(
            sd.protocol.send_apdu(0, 0xA4, 4, 0, bytes.fromhex("a000000151000000"))
            == expected_select,
            "encrypted SELECT returns the public template with a valid SDK response MAC",
        )
        denied(
            0x6982,
            sd.get_key_information,
            "encrypted SELECT terminates the previous app-scoped channel",
        )
        check(
            SecurityDomainSession(conn).get_data(0x9F7F) == own_id,
            "public metadata remains available after encrypted SELECT channel closure",
        )
        conn = fixture.restart()
        check(
            SecurityDomainSession(conn).get_data(0x9F7F) == own_id,
            "CPLC survives software-card restart",
        )

        # A separate fresh card has a separate identifier even in the same process.
        fixture.stop()
        second_directory = directory / "other"
        second_directory.mkdir()
        second = Fixture(root, second_directory, ifd_driver)
        try:
            other = SecurityDomainSession(second.start()).get_data(0x9F7F)
            check(
                len(other) == 42 and other != own_id,
                "separate fresh software cards receive distinct CPLC identifiers",
            )
        finally:
            second.stop()
        conn = fixture.start()

        # Migrate only absent own metadata without replacing a legacy key or cert.
        before = saved()
        fixture.stop()
        legacy = EncryptedState(directory / "state.bin")
        legacy.data["domain"].pop("cplc")
        legacy.flush()
        conn = fixture.start()
        migrated_id = SecurityDomainSession(conn).get_data(0x9F7F)
        migrated = saved()
        check(
            len(migrated_id) == 42 and migrated_id != own_id,
            "legacy state without CPLC gains one fresh own identifier",
        )
        check(
            migrated["domain"]["keys"] == before["domain"]["keys"],
            "CPLC migration preserves every existing own key, certificate and retry count",
        )
        check(
            {k: v for k, v in migrated.items() if k != "domain"}
            == {k: v for k, v in before.items() if k != "domain"},
            "CPLC migration preserves all other application state",
        )
        conn = fixture.restart()
        sd = SecurityDomainSession(conn)
        check(
            sd.get_data(0x9F7F) == migrated_id,
            "migrated own CPLC is persisted rather than regenerated on restart",
        )
        denied(
            0x6A88,
            lambda: sd.get_data(0x1234),
            "unsupported public metadata tag remains unavailable",
        )

        # Critical or noncritical BF20 constraints cannot become an unrestricted
        # authenticated host. The no-support flags are measured; 6A81 is a GP
        # public-review error model, not a measured firmware rejection status.
        sd = authenticate(Scp03KeyParams())
        a_ref, c_ref, anchor_ref = KeyRef(0x11, 1), KeyRef(0x15, 1), KeyRef(0x20, 1)
        a_pub, c_pub = sd.generate_ec_key(a_ref), sd.generate_ec_key(c_ref)
        ca, host = (ec.generate_private_key(ec.SECP256R1()) for _ in range(2))
        ca_name, host_name = name("metadata CA"), name("metadata OCE")
        root_cert = own_cert(
            ca.public_key(), ca, ca_name, ca_name, ROOT, ca=True, path_length=0
        )
        leaf = own_cert(host.public_key(), ca, host_name, ca_name, OCE)
        sd.put_key(anchor_ref, ca.public_key())
        rule_oid = x509.ObjectIdentifier("2.840.114283.100.0.1.2.0.1")
        rules = Tlv(4, Tlv(0xE3, Tlv(0xEF, Tlv(0x8C, b""))))
        for ref, pub in ((a_ref, a_pub), (c_ref, c_pub)):
            for critical in (True, False):
                constrained = own_cert(
                    host.public_key(),
                    ca,
                    host_name,
                    ca_name,
                    OCE,
                    extra=(x509.UnrecognizedExtension(rule_oid, rules), critical),
                )
                params = Scp11KeyParams(
                    ref, pub, anchor_ref, host, [root_cert, constrained]
                )
                denied(
                    0x6A81,
                    lambda params=params: authenticate(params),
                    f"software GP unsupported-BF20 response for SCP11 {ref.kid:02x} critical={critical}",
                )
            valid_params = Scp11KeyParams(ref, pub, anchor_ref, host, [root_cert, leaf])
            check(
                authenticate(valid_params).get_data(0x9F7F) == migrated_id,
                f"SCP11 {ref.kid:02x} valid own chain recovers after BF20 denial",
            )
        constrained_root = own_cert(
            ca.public_key(),
            ca,
            ca_name,
            ca_name,
            ROOT,
            ca=True,
            path_length=0,
            extra=(x509.UnrecognizedExtension(rule_oid, rules), True),
        )
        sd = SecurityDomainSession(conn)
        denied(
            0x6A81,
            lambda: sd.protocol.send_apdu(
                0x80,
                0x2A,
                anchor_ref.kvn,
                anchor_ref.kid | 0x80,
                constrained_root.public_bytes(serialization.Encoding.DER),
            ),
            "BF20 is rejected in an intermediate PSO before a final leaf can reuse its chain",
        )
        denied(
            0x6982,
            lambda: sd.generate_ec_key(KeyRef(0x11, 2)),
            "failed BF20 PSO never leaves a management-authorized channel",
        )

        # Deleting the last management key with the explicit delete_last flag
        # follows the documented automatic reset. Independent app state remains.
        sd = authenticate(Scp03KeyParams())
        for ref in (a_ref, c_ref, anchor_ref):
            sd.delete_key(kid=ref.kid, kvn=ref.kvn)
        check(
            sd.get_data(0x9F7F) == migrated_id,
            "ordinary key deletion retains the own Domain CPLC",
        )
        denied(
            0x6985,
            lambda: sd.delete_key(kvn=255),
            "last management-key deletion requires explicit delete_last",
        )
        oath = OathSession(conn)
        credential = oath.put_credential(
            CredentialData(
                "CPLC peer",
                OATH_TYPE.HOTP,
                HASH_ALGORITHM.SHA1,
                b"12345678901234567890",
            )
        )
        oath.calculate(credential.id, b"")
        before_reset = saved()
        sd = authenticate(Scp03KeyParams())
        sd.delete_key(kvn=255, delete_last=True)
        check(
            True,
            "last-key DELETE response is authenticated by the old SDK channel before it closes",
        )
        reset = saved()
        check(
            set(reset["domain"]["keys"]) == {"01ff", "1301"},
            "explicit last-key deletion restores the documented fresh default key table",
        )
        check(
            reset["domain"]["cplc"] != migrated_id.hex(),
            "documented Domain reset rotates the independent CPLC identifier",
        )
        check(
            reset["domain"]["keys"]["1301"]["private"]
            != before_reset["domain"]["keys"]["1301"]["private"],
            "Domain reset generates a fresh independent SCP11b identity",
        )
        check(
            {k: v for k, v in reset.items() if k != "domain"}
            == {k: v for k, v in before_reset.items() if k != "domain"},
            "Domain reset retains peer application keys and durable HOTP progression",
        )
        denied(
            0x6982,
            sd.get_key_information,
            "pre-reset SDK channel cannot authorize a follow-up encrypted command",
        )
        sd = authenticate(Scp03KeyParams())
        reset_id = sd.get_data(0x9F7F)
        check(
            len(reset_id) == 42 and reset_id.hex() == reset["domain"]["cplc"],
            "fresh default SCP03 channel authenticates after explicit last-key reset",
        )
        conn = fixture.restart()
        check(
            SecurityDomainSession(conn).get_data(0x9F7F) == reset_id,
            "reset CPLC identifier remains stable after restart",
        )

        # SDK reset exercises failure-driven software recovery separately.
        sd = authenticate(Scp03KeyParams())
        sd.reset()
        denied(
            0x6982,
            sd.get_key_information,
            "failure-driven SDK reset also terminates the old authenticated channel",
        )
        sd = SecurityDomainSession(conn)
        final_id = sd.get_data(0x9F7F)
        check(
            len(final_id) == 42 and final_id != reset_id,
            "failure-driven SDK software reset also rotates own CPLC",
        )
        check(
            sd.get_data(0x66) == expected_recognition,
            "public recognition remains invariant through both software reset paths",
        )
        passed = True
    finally:
        fixture.stop()
        report.write_text(
            json.dumps(
                {
                    "passed": passed,
                    "tests": checks,
                    "scope": "fresh software fixtures; saved public reference comparison",
                    "transport": "direct IFD ABI"
                    if ifd_driver
                    else "private CCID socket",
                    "physical_device_access": False,
                    "system_pcsc_reader_registered": False,
                    "manufacturer_trust_reproduced": False,
                    "public_select_and_recognition_byte_comparison": True,
                    "reference_scp03_option": "60",
                    "reference_scp11_option": "9b06",
                    "reference_advertises_bf20": False,
                    "unsupported_bf20_status_model": "6a81; GP SCP11 public review Table 7-13; physical rejection unmeasured",
                    "cplc_format": "42 raw bytes; 0000 software platform plus own random 40-byte identifier",
                    "reference_cplc_identifier_retained": False,
                    "cplc_reset_source": "published Yubico SCP technical manual; physical lifecycle unmeasured",
                    "unverified": [
                        "physical certificate rejection/status and exact retry/delete lifecycle",
                        "critical SD subject-ID handling",
                        "native OS reader enumeration and browser flow",
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
        prefix="ske-domain-meta-", dir=args.work_dir
    ) as directory:
        run(
            Path(__file__).resolve().parents[1],
            Path(directory),
            args.report,
            args.ifd_driver,
        )


if __name__ == "__main__":
    main()
