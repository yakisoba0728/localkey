"""OpenPGP KDF PIN storage and software attestation using own fresh identities."""

import copy
import datetime
import hashlib
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, x25519
from yubikit.core import Tlv

from .core import dump_key, load_key, require, tlvs
from .profile import OPENPGP_CERTIFICATE_LENGTH, OPENPGP_DEFAULT_RSA_ATTRIBUTES


def pin_bytes(d, name):
    if name + "_value" in d:
        return bytes.fromhex(d[name + "_value"])
    return d[name].encode()


def pin_length(d, name, value):
    length = d.get("kdf_hash_length")
    require(
        len(value) == length
        if length
        else (8 if name != "pin" else 6) <= len(value) <= 127,
        0x6A80,
    )


def store_pin(d, name, value):
    d[name + "_value"] = value.hex()
    d[name] = ""  # Never retain a plaintext PIN alongside its derived value.


def default_hash(fields, name):
    salt = fields.get(0x86 if name == "admin" else 0x84, fields[0x84])
    unit = salt + (b"12345678" if name == "admin" else b"123456")
    count = int.from_bytes(fields[0x83], "big")
    # RFC 4880 §3.7.1.3 requires one complete salt+passphrase block even
    # when the encoded octet count is smaller than that block.
    count = max(count, len(unit))
    digest = hashlib.sha256() if fields[0x82] == b"\x08" else hashlib.sha512()
    # The RFC4880 S2K count measures bytes, not rounds. Hash in bounded chunks.
    chunk = unit * max(1, 65536 // len(unit))
    while count >= len(chunk):
        digest.update(chunk)
        count -= len(chunk)
    digest.update((unit * ((count + len(unit) - 1) // len(unit)))[:count])
    return digest.digest()


def set_kdf(d, data):
    require(not any(str(slot) in d["keys"] for slot in (1, 2, 3)), 0x6985)
    fields = tlvs(data)
    require(fields.get(0x81) in (b"\0", b"\3"), 0x6A80)
    if fields[0x81] == b"\0":
        require(set(fields) == {0x81}, 0x6A80)
        d.pop("kdf_hash_length", None)
        user, admin = b"123456", b"12345678"
    else:
        require(
            {0x81, 0x82, 0x83, 0x84} <= set(fields) <= set(range(0x81, 0x89)), 0x6A80
        )
        require(fields[0x82] in (b"\x08", b"\x0a") and len(fields[0x83]) == 4, 0x6A80)
        # The device only consumes hashes; this bound applies to local default
        # derivation when the optional initial hash fields are omitted.
        require(1 <= int.from_bytes(fields[0x83], "big") <= 0x4000000, 0x6A80)
        require(
            all(len(fields[t]) == 8 for t in (0x84, 0x85, 0x86) if t in fields), 0x6A80
        )
        length = 32 if fields[0x82] == b"\x08" else 64
        require(
            all(len(fields[t]) == length for t in (0x87, 0x88) if t in fields), 0x6A80
        )
        user = fields[0x87] if 0x87 in fields else default_hash(fields, "pin")
        admin = fields[0x88] if 0x88 in fields else default_hash(fields, "admin")
        d["kdf_hash_length"] = length
    d["objects"][str(0xF9)] = data.hex()
    store_pin(d, "pin", user)
    store_pin(d, "admin", admin)
    store_pin(d, "reset", b"")
    d["pin_retries"], d["admin_retries"], d["reset_retries"] = (
        d["pin_max"],
        d["admin_max"],
        0,
    )


def template(data):
    crt, remaining = Tlv.parse_from(data)
    require(crt.tag in (0xB6, 0xB8, 0xA4), 0x6A80)
    slot = {0xB6: 1, 0xB8: 2, 0xA4: 3}[crt.tag]
    if crt.value:
        if crt.tag == 0xB6 and crt.value == Tlv(0x84, b"\x81"):
            slot = 0x81
        else:
            require(crt.value == Tlv(0x84, bytes([slot])), 0x6A80)
    return slot, remaining


def attributes_tag(slot):
    return 0xDA if slot == 0x81 else 0xC0 + slot


def ensure_attestation(d):
    if "129" in d["keys"] or d.get("attestation_removed"):
        return
    key = rsa.generate_private_key(65537, 2048)
    d["keys"]["129"] = {"key": dump_key(key), "generated": True}
    d["objects"][str(0xDA)] = OPENPGP_DEFAULT_RSA_ATTRIBUTES.hex()
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name(
        [
            x509.NameAttribute(
                x509.NameOID.COMMON_NAME,
                "Local software emulator OpenPGP attestation template",
            )
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .sign(key, hashes.SHA256())
    )
    d["objects"][str(0xFC)] = cert.public_bytes(serialization.Encoding.DER).hex()


def reset_state(d):
    from .core import defaults

    fresh = defaults(piv_attestation=False)["openpgp"]
    # ATT is an independent issuer installed once. Application reset must not
    # replace it, resurrect a deleted certificate/key, or restore old trust.
    if "129" in d["keys"]:
        fresh["keys"]["129"] = copy.deepcopy(d["keys"]["129"])
    if "attestation_removed" in d:
        fresh["attestation_removed"] = d["attestation_removed"]
    for oid in (0xDA, 0xDB, 0xDC, 0xDD, 0xD9, 0xFC):
        if str(oid) in d["objects"]:
            fresh["objects"][str(oid)] = d["objects"][str(oid)]
    return fresh


def der_integer(number):
    require(number >= 0, 0x6A80)
    data = number.to_bytes(max(1, (number.bit_length() + 7) // 8), "big")
    if data[0] & 0x80:
        data = b"\0" + data
    return Tlv(2, data)


def attestation(card, slot):
    d = card.state.data["openpgp"]
    ensure_attestation(d)
    require(slot in (1, 2, 3) and str(slot) in d["keys"], 0x6A88)
    row = d["keys"][str(slot)]
    require(row["generated"] and "129" in d["keys"], 0x6A80)
    key = load_key(d["keys"]["129"]["key"])
    require(
        not isinstance(key, (ed25519.Ed25519PrivateKey, x25519.X25519PrivateKey)),
        0x6A80,
    )
    raw = bytes.fromhex(d["objects"].get(str(0xFC), ""))
    require(raw, 0x6A88)
    template_cert = x509.load_der_x509_certificate(raw)
    require(
        template_cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        == key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        0x6A80,
    )
    uif = bytes.fromhex(d["objects"].get(str(0xD9), "0020"))[0]
    card.touch_key("OpenPGP attestation", 3 if uif in (3, 4) else 2 if uif else 1)
    slot_name = {1: "SIG", 2: "DEC", 3: "AUT"}[slot]
    name = x509.Name(
        [
            x509.NameAttribute(
                x509.NameOID.COMMON_NAME,
                f"Local software emulator OpenPGP key {slot_name}",
            )
        ]
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(template_cert.subject)
        .public_key(load_key(row["key"]).public_key())
        .serial_number(int.from_bytes(secrets.token_bytes(16), "big") or 1)
        .not_valid_before(template_cert.not_valid_before_utc)
        .not_valid_after(template_cert.not_valid_after_utc)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
    )
    objects = d["objects"]
    fingerprint = bytes.fromhex(objects.get(str(0xC6 + slot), "00" * 20))
    generation_time = bytes.fromhex(objects.get(str(0xCD + slot), "00" * 4))
    user_uif = bytes.fromhex(objects.get(str(0xD5 + slot), "0020"))
    require(
        len(fingerprint) == 20 and len(generation_time) == 4 and len(user_uif) == 2,
        0x6A80,
    )
    # Public metadata of this software instance. Version/form factor describe
    # the compatibility profile; own names/serial/issuer carry no factory trust.
    fields = {
        1: Tlv(
            0x0C,
            bytes.fromhex(objects.get(str(0x5B), "")).decode("latin-1").encode("utf-8"),
        ),
        2: der_integer(1),
        3: Tlv(4, b"\x05\x07\x04"),
        4: Tlv(4, fingerprint),
        5: Tlv(4, generation_time),
        7: der_integer(int(card.state.data["serial"], 16)),
        8: Tlv(4, user_uif[:1]),
        9: Tlv(4, b"\x04"),
        10: Tlv(4, b"\0"),
        11: Tlv(4, b"\0"),
    }
    if slot == 1:
        fields[6] = der_integer(d["sig_counter"])
    for suffix, value in sorted(fields.items()):
        leaf = leaf.add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier(f"1.3.6.1.4.1.41482.5.{suffix}"), bytes(value)
            ),
            critical=False,
        )
    encoded = leaf.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
    require(len(encoded) <= OPENPGP_CERTIFICATE_LENGTH, 0x6A84)
    d["objects"]["certificate" + str(slot)] = encoded.hex()
