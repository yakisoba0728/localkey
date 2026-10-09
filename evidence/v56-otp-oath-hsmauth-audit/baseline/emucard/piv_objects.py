"""PIV initial objects and an independent software attestation slot.

Certificates identify a local software issuer. No factory trust is reproduced.
"""

from __future__ import annotations

import datetime
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from yubikit.core import Tlv

from .core import dump_key, load_key, require

ATTESTATION_SLOT = str(0xF9)
ATTESTATION_OBJECT = str(0x5FFF01)
SELECT_RESPONSE = bytes.fromhex("61114f0600001000010079074f05a000000308")
APPLICATION_AID = bytes.fromhex("a000000308000010000100")
DISCOVERY = bytes.fromhex("7e124f0ba0000003080000100001005f2f024000")
READ_ONLY_OBJECTS = (0x7E, 0x7F61)
MAX_CERTIFICATE_BYTES = 3052
CERTIFICATE_OBJECT_IDS = frozenset(
    (0x5FC101, 0x5FC105, 0x5FC10A, 0x5FC10B, 0x5FFF01)
    + tuple(range(0x5FC10D, 0x5FC121))
)


def initialize(d):
    """Initialize once or preserve the issuer of a previous lazy-CA store.

    Legacy stores may already exceed the modeled quota. Migration preserves their
    data; the existing shrinking/deletion recovery rules remain applicable.
    A deliberately replaced key or deleted certificate is never regenerated.
    """
    if ATTESTATION_SLOT in d["keys"]:
        return False
    key = (
        load_key(d["development_ca"])
        if "development_ca" in d
        else ec.generate_private_key(ec.SECP256R1())
    )
    if "development_ca_certificate" in d:
        encoded = bytes.fromhex(d["development_ca_certificate"])
    else:
        now = datetime.datetime.now(datetime.timezone.utc)
        name = x509.Name(
            [
                x509.NameAttribute(
                    x509.NameOID.COMMON_NAME, "Local software emulator development CA"
                )
            ]
        )
        encoded = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256())
            .public_bytes(serialization.Encoding.DER)
        )
    d["keys"][ATTESTATION_SLOT] = {
        "key": dump_key(key),
        "alg": 17,
        "pin_policy": 1,
        "touch_policy": 1,
        "generated": True,
    }
    d["objects"].setdefault(ATTESTATION_OBJECT, Tlv(0x70, encoded).hex())
    d.pop("development_ca", None)
    d.pop("development_ca_certificate", None)
    return True


def attest(card, slot, row):
    d = card.state.data["piv"]
    require(ATTESTATION_SLOT in d["keys"], 0x6A88)
    require(ATTESTATION_OBJECT in d["objects"], 0x6A82)
    encoded = Tlv.parse_dict(bytes.fromhex(d["objects"][ATTESTATION_OBJECT]))
    issuer = x509.load_der_x509_certificate(encoded[0x70])
    key = load_key(d["keys"][ATTESTATION_SLOT]["key"])
    require(isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)), 0x6A80)
    subject = x509.Name(
        [
            x509.NameAttribute(
                x509.NameOID.COMMON_NAME, f"Local software emulator PIV slot {slot:02x}"
            )
        ]
    )
    serial = bytes.fromhex(card.state.data["serial"]).lstrip(b"\0") or b"\0"
    if serial[0] & 0x80:
        serial = b"\0" + serial
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject)
        .public_key(load_key(row["key"]).public_key())
        .serial_number(secrets.randbits(128) or 1)
        .not_valid_before(issuer.not_valid_before_utc)
        .not_valid_after(issuer.not_valid_after_utc)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    # Public profile metadata for this software device, never factory claims.
    for oid, value in (
        ("1.3.6.1.4.1.41482.3.3", b"\x05\x07\x04"),
        ("1.3.6.1.4.1.41482.3.7", Tlv(2, serial)),
        ("1.3.6.1.4.1.41482.3.8", bytes([row["pin_policy"], row["touch_policy"]])),
        ("1.3.6.1.4.1.41482.3.9", b"\x04"),
    ):
        certificate = certificate.add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), bytes(value)),
            critical=False,
        )
    return certificate.sign(key, hashes.SHA256()).public_bytes(
        serialization.Encoding.DER
    )
