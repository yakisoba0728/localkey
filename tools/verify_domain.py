#!/usr/bin/env python3
"""Exercise SCP and device management through serialized CCID/OTP wire frames.

All state is created in a private temporary directory. No physical readers or
hardware keys are opened. Yubico's unmodified SDK validates secure messaging.
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
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from emucard.client import OtpSocketConnection
from verify_smartcard import Fixture
from yubikit.core import TRANSPORT, ApplicationNotAvailableError
from yubikit.core.smartcard import ApduError
from yubikit.core.smartcard.scp import (
    KeyRef,
    Scp03KeyParams,
    Scp11KeyParams,
    StaticKeys,
)
from yubikit.management import CAPABILITY, FORM_FACTOR, DeviceConfig, ManagementSession
from yubikit.oath import HASH_ALGORITHM, OATH_TYPE, CredentialData, OathSession
from yubikit.piv import DEFAULT_MANAGEMENT_KEY, KEY_TYPE, SLOT, PivSession
from yubikit.securitydomain import SecurityDomainSession


def point(pub):
    return pub.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def cert(pub, signer, issuer, subject, ca=False, serial=None):
    now = datetime.datetime.now(datetime.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pub)
        .serial_number(serial or x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.BasicConstraints(ca=ca, path_length=1 if ca else None), True
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()),
            False,
        )
        .add_extension(
            x509.KeyUsage(False, False, False, False, not ca, ca, ca, False, False),
            True,
        )
        .sign(signer, hashes.SHA256())
    )


def run(root, directory, report, ifd_driver=None):
    fixture = Fixture(root, directory, ifd_driver)
    checks = []
    completed = False

    def check(value, name):
        if not value:
            raise AssertionError(name)
        checks.append({"name": name, "passed": True})
        print("PASS", name, flush=True)

    def denied(sw, fn, name):
        try:
            fn()
        except ApplicationNotAvailableError:
            check(sw == 0x6A82, name)
        except ApduError as e:
            check(e.sw == sw, name)
        else:
            raise AssertionError("accepted: " + name)

    try:
        conn = fixture.start()
        mgmt = ManagementSession(conn)
        info = mgmt.read_device_info()
        check(
            info.version == (5, 7, 4) and info.form_factor == FORM_FACTOR.USB_C_NANO,
            "management USB-C Nano compatibility profile",
        )
        check(
            info.serial
            and info.supported_capabilities == {TRANSPORT.USB: CAPABILITY(0x33B)}
            and not info.is_fips,
            "management own serial, USB capabilities and no FIPS claim",
        )
        serial = info.serial
        lock = os.urandom(16)
        mgmt.write_device_config(
            DeviceConfig(challenge_response_timeout=7), new_lock_code=lock
        )
        check(mgmt.read_device_info().is_locked, "management configuration lock")
        denied(
            0x6982,
            lambda: mgmt.write_device_config(
                DeviceConfig(challenge_response_timeout=8)
            ),
            "management write requires current lock code",
        )
        mgmt.write_device_config(
            DeviceConfig(challenge_response_timeout=8),
            cur_lock_code=lock,
            new_lock_code=bytes(16),
        )
        check(
            not mgmt.read_device_info().is_locked
            and mgmt.read_device_info().config.challenge_response_timeout == 8,
            "management unlock and timeout persistence",
        )
        mgmt.write_device_config(
            DeviceConfig({TRANSPORT.USB: CAPABILITY(0x33B) & ~CAPABILITY.OATH}),
            reboot=True,
        )
        denied(0x6A82, lambda: OathSession(conn), "disabled OATH AID unavailable")
        mgmt = ManagementSession(conn)
        mgmt.write_device_config(
            DeviceConfig({TRANSPORT.USB: CAPABILITY(0x33B)}), reboot=True
        )
        OathSession(conn)
        check(True, "management re-enables OATH")
        with OtpSocketConnection(directory / "s.sock") as otp_conn:
            otp_mgmt = ManagementSession(otp_conn)
            check(
                otp_mgmt.read_device_info().serial == serial,
                "OTP HID management matches CCID identity",
            )
            otp_mgmt.write_device_config(DeviceConfig(challenge_response_timeout=9))
            check(
                otp_mgmt.read_device_info().config.challenge_response_timeout == 9,
                "OTP HID management write and response CRC",
            )
        sd = SecurityDomainSession(conn)
        keys = sd.get_key_information()
        check(
            set(keys)
            == {KeyRef(1, 255), KeyRef(2, 255), KeyRef(3, 255), KeyRef(0x13, 1)},
            "Security Domain default key information",
        )
        bundle = sd.get_certificate_bundle(KeyRef(0x13, 1))
        check(
            len(bundle) == 1 and "Local software" in bundle[0].subject.rfc4514_string(),
            "SCP11 development certificate bundle",
        )
        bparams = Scp11KeyParams(KeyRef(0x13, 1), bundle[-1].public_key())
        sd.authenticate(bparams)
        check(
            sd.get_key_information() == keys,
            "SCP11b SDK receipt, encrypted read and response MAC",
        )
        denied(
            0x6982,
            lambda: sd.generate_ec_key(KeyRef(0x11, 2)),
            "SCP11b cannot provision Security Domain keys",
        )
        piv = PivSession(conn, bparams)
        piv.authenticate(DEFAULT_MANAGEMENT_KEY)
        pub = piv.generate_key(SLOT.AUTHENTICATION, KEY_TYPE.ECCP256)
        piv.verify_pin("123456")
        message = b"SCP11 independent signature verification"
        pub.verify(
            piv.sign(SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, message, hashes.SHA256()),
            message,
            ec.ECDSA(hashes.SHA256()),
        )
        check(True, "SCP11b encrypted PIV signature independently verified")
        oath = OathSession(conn, bparams)
        credential = oath.put_credential(
            CredentialData(
                "scp11", OATH_TYPE.TOTP, HASH_ALGORITHM.SHA1, b"12345678901234567890"
            )
        )
        check(
            len(oath.calculate(credential.id, b"\0" * 8)) > 0,
            "SCP11b encrypted OATH credential",
        )
        mgmt = ManagementSession(conn, bparams)
        check(mgmt.read_device_info().serial == serial, "SCP11b management reads")
        sd = SecurityDomainSession(conn)
        sd.authenticate(Scp03KeyParams())
        check(sd.get_card_recognition_data(), "Security Domain GP recognition data")
        a_ref, c_ref, anchor_ref = KeyRef(0x11, 2), KeyRef(0x15, 3), KeyRef(0x20, 1)
        a_pub = sd.generate_ec_key(a_ref)
        c_pub = sd.generate_ec_key(c_ref)
        check(
            len(point(a_pub)) == len(point(c_pub)) == 65,
            "SCP03 authenticated SCP11a/c generation",
        )
        ca = ec.generate_private_key(ec.SECP256R1())
        host = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name(
            [x509.NameAttribute(x509.NameOID.COMMON_NAME, "Local fixture root")]
        )
        host_name = x509.Name(
            [x509.NameAttribute(x509.NameOID.COMMON_NAME, "Local fixture OCE")]
        )
        root_cert = cert(ca.public_key(), ca, ca_name, ca_name, True)
        leaf_cert = cert(host.public_key(), ca, ca_name, host_name)
        sd.put_key(anchor_ref, ca.public_key())
        ski = x509.SubjectKeyIdentifier.from_public_key(ca.public_key()).digest
        sd.store_ca_issuer(anchor_ref, ski)
        sd.store_allowlist(
            anchor_ref, [root_cert.serial_number, leaf_cert.serial_number]
        )
        check(
            sd.get_supported_ca_identifiers() == {anchor_ref: ski},
            "OCE anchor SKI provisioning and enumeration",
        )
        sd.store_certificate_bundle(
            a_ref, [root_cert, cert(a_pub, ca, ca_name, host_name)]
        )
        check(
            len(sd.get_certificate_bundle(a_ref)) == 2,
            "Security Domain stores leaf-last certificate bundle",
        )
        for ref, key in ((a_ref, a_pub), (c_ref, c_pub)):
            params = Scp11KeyParams(ref, key, anchor_ref, host, [root_cert, leaf_cert])
            sd = SecurityDomainSession(conn)
            sd.authenticate(params)
            check(
                a_ref in sd.get_key_information(),
                f"SCP11 {ref.kid:02x} mutual certificate authentication",
            )
            imported = ec.generate_private_key(ec.SECP256R1())
            target = KeyRef(0x13, 4)
            if ref.kid == 0x15:
                denied(
                    0x6985,
                    lambda sd=sd, ref=ref: sd.delete_key(kid=ref.kid, kvn=ref.kvn),
                    "SCP11c denies current-key DELETE as in published SDK tests",
                )
                denied(
                    0x6985,
                    lambda sd=sd, imported=imported: sd.put_key(
                        KeyRef(0x13, 5), imported
                    ),
                    "SCP11c denies private PUT KEY in replayable session",
                )
                continue
            if target in sd.get_key_information():
                sd.delete_key(kid=target.kid, kvn=target.kvn)
            sd.put_key(target, imported)
            check(
                target in sd.get_key_information(),
                f"SCP11 {ref.kid:02x} encrypted private-key import using session DEK",
            )
            imported_params = Scp11KeyParams(target, imported.public_key())
            other = SecurityDomainSession(conn)
            other.authenticate(imported_params)
            check(
                target in other.get_key_information(),
                "imported SCP11 private key establishes verified channel",
            )
        sd = SecurityDomainSession(conn)
        sd.authenticate(Scp03KeyParams())
        sd.store_allowlist(
            anchor_ref, [root_cert.serial_number, leaf_cert.serial_number + 1]
        )
        denied(
            0x6982,
            lambda: SecurityDomainSession(conn).authenticate(
                Scp11KeyParams(a_ref, a_pub, anchor_ref, host, [root_cert, leaf_cert])
            ),
            "SCP11 OCE certificate serial allowlist rejection",
        )
        sd = SecurityDomainSession(conn)
        sd.authenticate(Scp03KeyParams())
        sd.store_allowlist(anchor_ref, [])
        bad_root = cert(
            ca.public_key(),
            ec.generate_private_key(ec.SECP256R1()),
            ca_name,
            ca_name,
            True,
        )
        denied(
            0x6982,
            lambda: SecurityDomainSession(conn).authenticate(
                Scp11KeyParams(a_ref, a_pub, anchor_ref, host, [bad_root, leaf_cert])
            ),
            "SCP11 rejects invalid certificate signature",
        )
        wrong_pub = ec.generate_private_key(ec.SECP256R1()).public_key()
        try:
            SecurityDomainSession(conn).authenticate(
                Scp11KeyParams(KeyRef(0x13, 1), wrong_pub)
            )
        except InvalidSignature:
            check(True, "SCP11 wrong card key rejected by SDK receipt verification")
        else:
            raise AssertionError("wrong card key accepted")
        sd = SecurityDomainSession(conn)
        sd.authenticate(Scp03KeyParams())
        new_keys = StaticKeys(os.urandom(16), os.urandom(16), os.urandom(16))
        sd.put_key(KeyRef(1, 1), new_keys)
        check(
            KeyRef(1, 255) not in sd.get_key_information()
            and KeyRef(1, 1) in sd.get_key_information(),
            "first custom SCP03 key removes public default set",
        )
        params = Scp03KeyParams(KeyRef(1, 1), new_keys)
        sd = SecurityDomainSession(conn)
        sd.authenticate(params)
        check(
            sd.get_key_information(), "custom SCP03 keys handshake and secure messaging"
        )
        denied(
            0x6A80,
            lambda: sd.put_key(KeyRef(1, 255), new_keys),
            "Security Domain rejects factory-reserved SCP03 version 255",
        )
        check(
            KeyRef(1, 255) not in sd.get_key_information(),
            "rejected provision leaves key table unchanged",
        )
        sd.delete_key(kid=0x13, kvn=4)
        check(
            KeyRef(0x13, 4) not in sd.get_key_information(),
            "Security Domain authenticated key deletion",
        )
        conn = fixture.restart()
        sd = SecurityDomainSession(conn)
        sd.authenticate(params)
        check(
            a_ref in sd.get_key_information()
            and sd.get_supported_ca_identifiers()[anchor_ref] == ski,
            "SCP03/SCP11 keys and metadata persist across restart",
        )
        sd = SecurityDomainSession(conn)
        sd.reset()
        check(
            set(sd.get_key_information()) == set(keys),
            "Security Domain reset blocks all keys and restores defaults",
        )
        new_bundle = sd.get_certificate_bundle(KeyRef(0x13, 1))
        check(
            point(new_bundle[-1].public_key()) != point(bundle[-1].public_key()),
            "Security Domain reset generates a fresh software SCP11b key",
        )
        check(
            ManagementSession(conn).read_device_info().serial == serial,
            "Security Domain reset preserves device serial and management configuration",
        )
        completed = True
    finally:
        fixture.stop()
        report.write_text(
            json.dumps(
                {
                    "passed": completed,
                    "tests": checks,
                    "physical_key_accessed": False,
                    "transport": "direct native IFD ABI for CCID; private socket for OTP HID"
                    if ifd_driver
                    else "private CCID and OTP HID sockets",
                    "system_pcsc_reader_registered": False,
                },
                indent=2,
            )
            + "\n"
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", type=Path, default=Path(tempfile.gettempdir()))
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--ifd-driver", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="ske-domain-", dir=args.work_dir
    ) as directory:
        run(root, Path(directory), args.report, args.ifd_driver)


if __name__ == "__main__":
    main()
