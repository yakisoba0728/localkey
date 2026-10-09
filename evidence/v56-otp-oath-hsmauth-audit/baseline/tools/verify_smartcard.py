#!/usr/bin/env python3
"""Verify serialized CCID/APDU behavior with Yubico SDK and independent crypto.
This creates a new local test card; it never opens PC/SC or a physical reader.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import hmac
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography import x509
from cryptography.hazmat.primitives import cmac, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers import algorithms
from emucard.client import CcidSocketConnection, OtpSocketConnection
from yubihsm.core import _derive
from yubikit.core import InvalidPinError
from yubikit.core.smartcard import ApduError
from yubikit.core.smartcard.scp import Scp03KeyParams, StaticKeys
from yubikit.hsmauth import HsmAuthSession
from yubikit.oath import HASH_ALGORITHM, OATH_TYPE, CredentialData, OathSession
from yubikit.openpgp import KEY_REF, OID, OpenPgpSession
from yubikit.piv import (
    DEFAULT_MANAGEMENT_KEY,
    KEY_TYPE,
    PIN_POLICY,
    SLOT,
    TOUCH_POLICY,
    PivSession,
)
from yubikit.yubiotp import (
    SLOT as OTP_SLOT,
)
from yubikit.yubiotp import (
    HmacSha1SlotConfiguration,
    UpdateConfiguration,
    YubiOtpSession,
)


class Fixture:
    def __init__(self, root, directory, ifd_driver=None, *, startup_timeout=None):
        self.root = root
        self.directory = directory
        self.process = self.connection = None
        self.ifd_driver = ifd_driver
        self.startup_timeout = startup_timeout

    def start(self):
        self.log = (self.directory / "log.txt").open("ab")
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "emucard.service",
                "--testing",
                "--state",
                str(self.directory / "state.bin"),
                "--socket",
                str(self.directory / "s.sock"),
            ],
            cwd=self.root,
            stdout=self.log,
            stderr=self.log,
        )
        started = time.monotonic()
        # The default retains the existing portable fixture wait. QEMU TCG
        # callers may explicitly budget slower runtime/key initialization.
        deadline = started + (3 if self.startup_timeout is None else self.startup_timeout)
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError((self.directory / "log.txt").read_text())
            if (self.directory / "s.sock").exists():
                # bind() creates the path before listen()/startup completes.
                # Wait for a real CCID power response, including in IFD tests.
                try:
                    ready = CcidSocketConnection(self.directory / "s.sock")
                except ConnectionRefusedError:
                    pass
                else:
                    ready.close()
                    break
            time.sleep(0.03)
        else:
            diagnostic = (self.directory / "log.txt").read_text()
            raise RuntimeError(f"card service did not become ready after {time.monotonic() - started:.2f}s: {diagnostic}")
        if self.ifd_driver:
            from emucard.ifd import IfdNativeConnection

            self.connection = IfdNativeConnection(
                self.ifd_driver, self.directory / "s.sock"
            )
        else:
            self.connection = CcidSocketConnection(self.directory / "s.sock")
        return self.connection

    def stop(self):
        if self.connection:
            self.connection.close()
            self.connection = None
        if self.process:
            self.process.terminate()
            self.process.wait(5)
            self.process = None
        if hasattr(self, "log"):
            self.log.close()
        if (self.directory / "s.sock").exists():
            raise AssertionError("service left its socket after shutdown")

    def restart(self):
        self.stop()
        return self.start()


def certificate(key):
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name(
        [x509.NameAttribute(x509.NameOID.COMMON_NAME, "Local emulator fixture")]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )


def run(root, directory, report, ifd_driver=None):
    f = Fixture(root, directory, ifd_driver)
    tests = []

    def check(value, name):
        if not value:
            raise AssertionError(name)
        tests.append({"name": name, "passed": True})
        print("PASS", name, flush=True)

    def denied(sw, fn, name):
        try:
            fn()
        except ApduError as e:
            check(e.sw == sw, name)
        else:
            raise AssertionError("accepted forbidden operation: " + name)

    msg = b"Local fixture signing challenge"
    try:
        conn = f.start()
        p = PivSession(conn)
        check(p.version == (5, 7, 4), "PIV protocol version profile")
        denied(
            0x6982,
            lambda: p.generate_key(SLOT.AUTHENTICATION, KEY_TYPE.ECCP256),
            "PIV generate requires management key",
        )
        p.authenticate(DEFAULT_MANAGEMENT_KEY)
        for alg in KEY_TYPE:
            pub = p.generate_key(
                SLOT.AUTHENTICATION, alg, PIN_POLICY.ONCE, TOUCH_POLICY.NEVER
            )
            p.verify_pin("123456")
            if alg == KEY_TYPE.X25519:
                peer = x25519.X25519PrivateKey.generate()
                expected = peer.exchange(pub)
                actual = p.calculate_secret(SLOT.AUTHENTICATION, peer.public_key())
                check(actual == expected, "PIV X25519 shared secret")
            else:
                hash_alg = (
                    hashes.SHA384() if alg == KEY_TYPE.ECCP384 else hashes.SHA256()
                )
                sig = p.sign(
                    SLOT.AUTHENTICATION,
                    alg,
                    msg,
                    None if alg == KEY_TYPE.ED25519 else hash_alg,
                    padding.PKCS1v15() if alg.name.startswith("RSA") else None,
                )
                if alg == KEY_TYPE.ED25519:
                    pub.verify(sig, msg)
                elif alg.name.startswith("RSA"):
                    pub.verify(sig, msg, padding.PKCS1v15(), hash_alg)
                else:
                    pub.verify(sig, msg, ec.ECDSA(hash_alg))
                check(True, "PIV independent signature " + alg.name)
            metadata = p.get_slot_metadata(SLOT.AUTHENTICATION)
            check(
                metadata.key_type == alg and metadata.generated,
                "PIV slot metadata " + alg.name,
            )
        p.generate_key(SLOT.SIGNATURE, KEY_TYPE.ECCP256, PIN_POLICY.ALWAYS)
        leaf = p.attest_key(SLOT.SIGNATURE)
        root_certificate = p.get_certificate(SLOT.ATTESTATION)
        root_certificate.public_key().verify(
            leaf.signature,
            leaf.tbs_certificate_bytes,
            ec.ECDSA(leaf.signature_hash_algorithm),
        )
        check(
            "software emulator" in leaf.subject.rfc4514_string()
            and leaf.public_key().public_numbers()
            == p.get_slot_metadata(SLOT.SIGNATURE).public_key.public_numbers(),
            "PIV local software attestation certificate chain",
        )
        p.verify_pin("123456")
        p.sign(SLOT.SIGNATURE, KEY_TYPE.ECCP256, msg, hashes.SHA256())
        denied(
            0x6982,
            lambda: p.sign(SLOT.SIGNATURE, KEY_TYPE.ECCP256, msg, hashes.SHA256()),
            "PIV ALWAYS consumes PIN verification",
        )
        rsa_pub = p.generate_key(SLOT.KEY_MANAGEMENT, KEY_TYPE.RSA2048, PIN_POLICY.ONCE)
        p.verify_pin("123456")
        enc = rsa_pub.encrypt(
            b"local plaintext",
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None
            ),
        )
        check(
            p.decrypt(
                SLOT.KEY_MANAGEMENT,
                enc,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            == b"local plaintext",
            "PIV RSA OAEP decryption",
        )
        for alg, curve in [
            (KEY_TYPE.ECCP256, ec.SECP256R1()),
            (KEY_TYPE.ECCP384, ec.SECP384R1()),
        ]:
            pub = p.generate_key(SLOT.KEY_MANAGEMENT, alg, PIN_POLICY.ONCE)
            peer = ec.generate_private_key(curve)
            p.verify_pin("123456")
            check(
                p.calculate_secret(SLOT.KEY_MANAGEMENT, peer.public_key())
                == peer.exchange(ec.ECDH(), pub),
                "PIV ECDH " + alg.name,
            )
        imported = ec.generate_private_key(ec.SECP256R1())
        p.put_key(SLOT.AUTHENTICATION, imported, PIN_POLICY.ONCE)
        denied(
            0x6A80,
            lambda: p.attest_key(SLOT.AUTHENTICATION),
            "PIV imported key cannot claim generated provenance",
        )
        p.verify_pin("123456")
        sig = p.sign(SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, msg, hashes.SHA256())
        imported.public_key().verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        check(
            not p.get_slot_metadata(SLOT.AUTHENTICATION).generated,
            "PIV imported key provenance and signature",
        )
        cert = certificate(imported)
        p.put_certificate(SLOT.AUTHENTICATION, cert, compress=True)
        check(
            p.get_certificate(SLOT.AUTHENTICATION).public_bytes(
                serialization.Encoding.DER
            )
            == cert.public_bytes(serialization.Encoding.DER),
            "PIV compressed X.509 certificate round trip",
        )
        p.move_key(SLOT.AUTHENTICATION, SLOT.RETIRED1)
        check(
            p.get_slot_metadata(SLOT.RETIRED1).key_type == KEY_TYPE.ECCP256,
            "PIV move key",
        )
        p.delete_key(SLOT.RETIRED1)
        denied(0x6A88, lambda: p.get_slot_metadata(SLOT.RETIRED1), "PIV delete key")
        p.change_pin("123456", "654321")
        p.verify_pin("654321")
        try:
            p.verify_pin("wrong")
        except InvalidPinError as e:
            check(e.attempts_remaining == 2, "PIV wrong PIN decreases durable retries")
        else:
            raise AssertionError("PIV wrong PIN accepted")
        p.verify_pin("654321")
        check(
            p.get_pin_metadata().attempts_remaining == 3,
            "PIV correct PIN restores retries",
        )
        # PGP operates through the same CCID reader, with separate PIN/keys.
        g = OpenPgpSession(conn)
        check(g.get_pin_status().attempts_user == 3, "OpenPGP initial PIN status")
        denied(
            0x6982,
            lambda: g.generate_ec_key(KEY_REF.SIG, OID.Ed25519),
            "OpenPGP key generation requires admin PIN",
        )
        g.verify_admin("12345678")
        for oid in [OID.SECP256R1, OID.SECP384R1, OID.Ed25519]:
            pub = g.generate_ec_key(KEY_REF.SIG, oid)
            g.verify_pin("123456")
            sig = g.sign(
                msg, hashes.SHA384() if oid == OID.SECP384R1 else hashes.SHA256()
            )
            if oid == OID.Ed25519:
                pub.verify(sig, msg)
            else:
                pub.verify(
                    sig,
                    msg,
                    ec.ECDSA(
                        hashes.SHA384() if oid == OID.SECP384R1 else hashes.SHA256()
                    ),
                )
            check(True, "OpenPGP independent signature " + oid.name)
            denied(
                0x6982,
                lambda: g.sign(msg, hashes.SHA256()),
                "OpenPGP SIG requires PIN again " + oid.name,
            )
        pub = g.generate_rsa_key(KEY_REF.SIG, 2048)
        g.verify_pin("123456")
        sig = g.sign(msg, hashes.SHA256())
        pub.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
        check(True, "OpenPGP RSA signature")
        pub = g.generate_ec_key(KEY_REF.AUT, OID.Ed25519)
        denied(
            0x6982,
            lambda: g.authenticate(msg, hashes.SHA256()),
            "OpenPGP SIG verification cannot authorize AUT",
        )
        g.verify_pin("123456", extended=True)
        pub.verify(g.authenticate(msg, hashes.SHA256()), msg)
        check(True, "OpenPGP Ed25519 authentication")
        for oid, peer in [
            (OID.SECP256R1, ec.generate_private_key(ec.SECP256R1())),
            (OID.X25519, x25519.X25519PrivateKey.generate()),
        ]:
            pub = g.generate_ec_key(KEY_REF.DEC, oid)
            g.verify_pin("123456", extended=True)
            expected = (
                peer.exchange(pub)
                if oid == OID.X25519
                else peer.exchange(ec.ECDH(), pub)
            )
            check(
                g.decrypt(peer.public_key()) == expected,
                "OpenPGP shared secret " + oid.name,
            )
        pub = g.generate_rsa_key(KEY_REF.DEC, 2048)
        g.verify_pin("123456", extended=True)
        check(
            g.decrypt(pub.encrypt(b"pgp message", padding.PKCS1v15()))
            == b"pgp message",
            "OpenPGP RSA decryption",
        )
        for key in [
            ed25519.Ed25519PrivateKey.generate(),
            ec.generate_private_key(ec.SECP384R1()),
            rsa.generate_private_key(65537, 2048),
        ]:
            g.put_key(KEY_REF.SIG, key)
            g.verify_pin("123456")
            sig = g.sign(
                msg,
                hashes.SHA384()
                if isinstance(key, ec.EllipticCurvePrivateKey)
                else hashes.SHA256(),
            )
            pub = key.public_key()
            if isinstance(key, ed25519.Ed25519PrivateKey):
                pub.verify(sig, msg)
            elif isinstance(key, rsa.RSAPrivateKey):
                pub.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
            else:
                pub.verify(sig, msg, ec.ECDSA(hashes.SHA384()))
            check(True, "OpenPGP import and signature " + type(key).__name__)
        cert1 = certificate(ec.generate_private_key(ec.SECP256R1()))
        cert2 = certificate(ec.generate_private_key(ec.SECP384R1()))
        g.put_certificate(KEY_REF.SIG, cert1)
        g.put_certificate(KEY_REF.DEC, cert2)
        check(
            g.get_certificate(KEY_REF.SIG).serial_number == cert1.serial_number
            and g.get_certificate(KEY_REF.DEC).serial_number == cert2.serial_number,
            "OpenPGP separate certificate slots",
        )
        g.change_pin("123456", "654321")
        g.verify_pin("654321")
        check(True, "OpenPGP PIN change")
        h = HsmAuthSession(conn)
        h.put_credential_symmetric(bytes(16), "local", b"a" * 16, b"b" * 16, "password")
        check(len(h.list_credentials()) == 1, "YubiHSM Auth credential list")
        context = bytes(range(16))
        keys = h.calculate_session_keys_symmetric("local", context, "password")
        check(
            keys.key_senc == _derive(b"a" * 16, 4, context)
            and keys.key_smac == _derive(b"b" * 16, 6, context)
            and keys.key_srmac == _derive(b"b" * 16, 7, context),
            "YubiHSM Auth derivation matches independent python-yubihsm",
        )
        try:
            h.calculate_session_keys_symmetric("local", context, "wrong")
        except InvalidPinError as e:
            check(e.attempts_remaining == 7, "YubiHSM Auth wrong password retries")
        else:
            raise AssertionError("wrong HSM password accepted")
        denied(
            0x6982,
            lambda: h.calculate_session_keys_symmetric(
                "local", context, "password", bytes(8)
            ),
            "YubiHSM Auth rejects bad card cryptogram",
        )
        keys = h.calculate_session_keys_symmetric(
            "local", context, "password", _derive(b"b" * 16, 0, context, 64)
        )
        check(len(keys.key_senc) == 16, "YubiHSM Auth accepts valid card cryptogram")
        h.put_management_key(bytes(16), b"c" * 16)
        check(h.get_management_key_retries() == 8, "YubiHSM Auth management key change")
        h.delete_credential(b"c" * 16, "local")
        check(not h.list_credentials(), "YubiHSM Auth credential deletion")
        static = ec.generate_private_key(ec.SECP256R1())
        h.put_credential_asymmetric(b"c" * 16, "asym", static, "password")
        check(
            h.get_public_key("asym").public_numbers()
            == static.public_key().public_numbers(),
            "YubiHSM Auth imported asymmetric public key",
        )
        peer_static = ec.generate_private_key(ec.SECP256R1())
        peer_ephemeral = ec.generate_private_key(ec.SECP256R1())
        epk = h.get_challenge("asym", "password")
        epk_peer = peer_ephemeral.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        shared = peer_ephemeral.exchange(
            ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), epk)
        ) + peer_static.exchange(ec.ECDH(), static.public_key())
        material = b"".join(
            hashlib.sha256(shared + i.to_bytes(4, "big") + b"\x3c\x88\x10").digest()
            for i in (1, 2)
        )
        m = cmac.CMAC(algorithms.AES(material[:16]))
        m.update(epk_peer + epk)
        receipt = m.finalize()
        keys = h.calculate_session_keys_asymmetric(
            "asym", epk + epk_peer, peer_static.public_key(), "password", receipt
        )
        check(
            keys.key_senc + keys.key_smac + keys.key_srmac == material[16:],
            "YubiHSM Auth asymmetric derivation agrees with independent peer",
        )
        denied(
            0x6985,
            lambda: h.calculate_session_keys_asymmetric(
                "asym", epk + epk_peer, peer_static.public_key(), "password", receipt
            ),
            "YubiHSM Auth ephemeral challenge is single use",
        )
        epk = h.get_challenge("asym", "password")
        denied(
            0x6982,
            lambda: h.calculate_session_keys_asymmetric(
                "asym", epk + epk_peer, peer_static.public_key(), "password", bytes(16)
            ),
            "YubiHSM Auth rejects asymmetric receipt mismatch",
        )
        h.generate_credential_asymmetric(b"c" * 16, "generated", "password")
        check(
            h.get_public_key("generated").curve.name == "secp256r1",
            "YubiHSM Auth generates asymmetric key",
        )
        h.delete_credential(b"c" * 16, "asym")
        h.delete_credential(b"c" * 16, "generated")
        h.put_credential_symmetric(
            b"c" * 16, "persistent", b"a" * 16, b"b" * 16, "password"
        )
        # Optional OATH profile; reference physical device currently has this disabled.
        o = OathSession(conn)
        hotp = o.put_credential(
            CredentialData(
                "rfc4226",
                OATH_TYPE.HOTP,
                HASH_ALGORITHM.SHA1,
                b"12345678901234567890",
                counter=0,
            )
        )
        check(
            [o.calculate_code(hotp).value for _ in range(3)]
            == ["755224", "287082", "359152"],
            "OATH HOTP RFC4226 published vectors",
        )
        totp = o.put_credential(
            CredentialData(
                "rfc6238",
                OATH_TYPE.TOTP,
                HASH_ALGORITHM.SHA1,
                b"12345678901234567890",
                digits=8,
            )
        )
        check(
            o.calculate_code(totp, 59).value == "94287082",
            "OATH TOTP RFC6238 published vector",
        )
        all_codes = o.calculate_all(59)
        check(
            any(
                c.id == totp.id and value is not None and value.value == "94287082"
                for c, value in all_codes.items()
            ),
            "OATH calculate-all uses application A4 command",
        )
        new_id = o.rename_credential(totp.id, "renamed")
        check(
            any(c.id == new_id for c in o.list_credentials())
            and all(c.id != totp.id for c in o.list_credentials()),
            "OATH rename retains credential",
        )
        o.set_key(b"k" * 16)
        o = OathSession(conn)
        denied(0x6982, o.list_credentials, "OATH locked list denied")
        o.validate(b"k" * 16)
        check(len(o.list_credentials()) == 2, "OATH access key challenge-response")
        otp = YubiOtpSession(conn)
        secret = bytes(range(20))
        access = bytes(range(6))
        check(
            not otp.get_config_state().is_configured(OTP_SLOT.ONE),
            "OTP empty slot status",
        )
        otp.put_configuration(
            OTP_SLOT.ONE, HmacSha1SlotConfiguration(secret), acc_code=access
        )
        for challenge in (b"test", b"ends in zero\0", bytes(range(63))):
            check(
                otp.calculate_hmac_sha1(OTP_SLOT.ONE, challenge)
                == hmac.digest(secret, challenge, "sha1"),
                "OTP HMAC independent verification " + str(len(challenge)),
            )
        denied(
            0x6982,
            lambda: otp.delete_slot(OTP_SLOT.ONE, b"x" * 6),
            "OTP access code protects deletion",
        )
        denied(0x6982, otp.swap_slots, "OTP protected slot cannot be swapped")
        otp.update_configuration(
            OTP_SLOT.ONE,
            UpdateConfiguration().append_cr(True).pacing(True, False),
            acc_code=access,
            cur_acc_code=access,
        )
        check(
            otp.calculate_hmac_sha1(OTP_SLOT.ONE, b"test")
            == hmac.digest(secret, b"test", "sha1"),
            "OTP settings update retains secret",
        )
        otp.put_configuration(
            OTP_SLOT.TWO, HmacSha1SlotConfiguration(secret).lt64(False)
        )
        check(
            otp.calculate_hmac_sha1(OTP_SLOT.TWO, bytes(64))
            == hmac.digest(secret, bytes(64), "sha1"),
            "OTP full length HMAC challenge",
        )
        otp.update_configuration(
            OTP_SLOT.ONE, UpdateConfiguration().pacing(True, False), cur_acc_code=access
        )
        otp.swap_slots()
        check(
            otp.calculate_hmac_sha1(OTP_SLOT.TWO, b"test")
            == hmac.digest(secret, b"test", "sha1"),
            "OTP slot swap preserves configuration",
        )
        otp.delete_slot(OTP_SLOT.ONE)
        check(
            not otp.get_config_state().is_configured(OTP_SLOT.ONE),
            "OTP slot deletion status",
        )
        with OtpSocketConnection(directory / "s.sock") as hid:
            otp_hid = YubiOtpSession(hid)
            check(
                otp_hid.get_config_state().is_configured(OTP_SLOT.TWO),
                "OTP HID feature report status matches CCID",
            )
            check(
                otp_hid.calculate_hmac_sha1(OTP_SLOT.TWO, b"new report challenge")
                == hmac.digest(secret, b"new report challenge", "sha1"),
                "OTP HID frame CRC and independent HMAC signature",
            )
            otp_hid.put_configuration(OTP_SLOT.ONE, HmacSha1SlotConfiguration(secret))
            check(
                otp_hid.get_config_state().is_configured(OTP_SLOT.ONE),
                "OTP HID configuration frame with skipped zero packets",
            )
            otp_hid.delete_slot(OTP_SLOT.ONE)
            check(
                not otp_hid.get_config_state().is_configured(OTP_SLOT.ONE),
                "OTP HID deletion updates programming sequence",
            )
        # The SDK encrypts APDUs and independently validates response MACs.
        secure = PivSession(conn, Scp03KeyParams())
        secure.authenticate(DEFAULT_MANAGEMENT_KEY)
        secure_pub = secure.generate_key(
            SLOT.RETIRED2, KEY_TYPE.ECCP256, PIN_POLICY.ONCE
        )
        secure.verify_pin("654321")
        sig = secure.sign(SLOT.RETIRED2, KEY_TYPE.ECCP256, msg, hashes.SHA256())
        secure_pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        check(True, "SCP03 SDK verifies encrypted PIV signature and response MAC")
        blob = bytes(range(256)) * 8
        secure.put_object(0x5FFF05, blob)
        check(
            secure.get_object(0x5FFF05) == blob, "SCP03 long encrypted APDU round trip"
        )
        _, sw = conn.send_and_receive(b"\0\xfd\0\0\0")
        check(sw == 0x6982, "SCP03 session rejects plaintext downgrade")
        try:
            PivSession(
                conn, Scp03KeyParams(keys=StaticKeys(b"x" * 16, b"y" * 16, b"z" * 16))
            )
        except ValueError:
            check(True, "SCP03 incorrect static keys rejected by SDK")
        else:
            raise AssertionError("wrong secure-channel keys accepted")
        secure = PivSession(conn, Scp03KeyParams())
        original = conn.send_and_receive

        def corrupted(packet):
            value = bytearray(packet)
            value[-1] ^= 1
            return original(bytes(value))

        conn.send_and_receive = corrupted
        try:
            denied(0x6982, secure.get_serial, "SCP03 altered command MAC rejected")
        finally:
            conn.send_and_receive = original
        conn = f.restart()
        p = PivSession(conn)
        p.verify_pin("654321")
        check(True, "PIV PIN survives encrypted state restart")
        g = OpenPgpSession(conn)
        g.verify_pin("654321")
        sig = g.sign(msg, hashes.SHA256())
        key.public_key().verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
        check(True, "OpenPGP private key and PIN survive restart")
        h = HsmAuthSession(conn)
        check(
            h.list_credentials()[0].label == "persistent",
            "YubiHSM Auth credential survives restart",
        )
        o = OathSession(conn)
        o.validate(b"k" * 16)
        check(
            len(o.list_credentials()) == 2,
            "OATH access key and credentials survive restart",
        )
        otp = YubiOtpSession(conn)
        check(
            otp.calculate_hmac_sha1(OTP_SLOT.TWO, b"test")
            == hmac.digest(secret, b"test", "sha1"),
            "OTP secret survives encrypted state restart",
        )
        raw = (directory / "state.bin").read_bytes()
        check(
            b"654321" not in raw
            and b"password" not in raw
            and b"12345678901234567890" not in raw,
            "state file does not contain plaintext secrets",
        )
        check(
            (directory / "state.bin.key").stat().st_mode & 0o077 == 0,
            "state wrapping key mode 0600",
        )
        o = OathSession(conn)
        o.reset()
        check(not o.list_credentials() and not o.has_key, "OATH app reset")
        h = HsmAuthSession(conn)
        h.reset()
        check(not h.list_credentials(), "YubiHSM Auth app reset")
        g = OpenPgpSession(conn)
        g.reset()
        g = OpenPgpSession(conn)
        g.verify_pin("123456")
        check(
            g.get_pin_status().attempts_user == 3,
            "OpenPGP app reset with blocked-PIN precondition",
        )
        p = PivSession(conn)
        p.reset()
        p.verify_pin("123456")
        check(
            p.get_pin_metadata().default_value, "PIV app reset with blocked PIN and PUK"
        )
        report.update(passed=True, tests=tests)
    except Exception as e:
        report.update(passed=False, tests=tests, error=f"{type(e).__name__}: {e}")
        raise
    finally:
        f.stop()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--work-dir", required=True, type=Path)
    p.add_argument("--report", required=True, type=Path)
    p.add_argument(
        "--ifd-driver", type=Path, help="optional compiled macOS IFD reader driver"
    )
    a = p.parse_args()
    report = {
        "subject": "new CCID/APDU emulator",
        "physical_device_access": False,
        "transport": "native macOS IFD Handler ABI -> serialized CCID"
        if a.ifd_driver
        else "private Unix socket with CCID frames",
        "system_pcsc_reader_registered": False,
    }
    try:
        with tempfile.TemporaryDirectory(
            prefix="c", dir=a.work_dir.resolve()
        ) as directory:
            run(
                Path(__file__).resolve().parents[1],
                Path(directory),
                report,
                a.ifd_driver,
            )
    finally:
        a.report.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
