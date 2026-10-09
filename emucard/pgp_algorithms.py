"""Observed OpenPGP algorithm inventory and standard private-key templates.

The FA response is measured read-only; acceptance/rejection at physical write
boundaries is unmeasured. New keys use the advertised canonical attributes and
standard import layout. Existing legacy keys are never rewritten here.
"""

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519
from yubikit.core import Tlv

from .core import require

# Order is part of the captured public 5.7.4 FA response.
CURVES = {
    bytes.fromhex(oid): curve
    for oid, curve in (
        ("2a8648ce3d030107", ec.SECP256R1),
        ("2b81040022", ec.SECP384R1),
        ("2b81040023", ec.SECP521R1),
        ("2b8104000a", ec.SECP256K1),
        ("2b2403030208010107", ec.BrainpoolP256R1),
        ("2b240303020801010b", ec.BrainpoolP384R1),
        ("2b240303020801010d", ec.BrainpoolP512R1),
    )
}
ED25519_OID = bytes.fromhex("2b06010401da470f01")
X25519_OID = bytes.fromhex("2b060104019755010501")
ATTRIBUTE_TAGS = {1: 0xC1, 2: 0xC2, 3: 0xC3, 0x81: 0xDA}
SUPPORTED_ATTRIBUTES = {
    slot: tuple(
        [b"\x01" + bits.to_bytes(2, "big") + b"\0\x11\0" for bits in (2048, 3072, 4096)]
        + [bytes([0x12 if slot == 2 else 0x13]) + oid for oid in CURVES]
        + ([b"\x12" + X25519_OID] if slot == 2 else [])
        + ([b"\x16" + ED25519_OID] if slot in (1, 3) else [])
    )
    for slot in ATTRIBUTE_TAGS
}


def algorithm_information():
    return Tlv(
        0xFA,
        b"".join(
            Tlv(ATTRIBUTE_TAGS[slot], attrs)
            for slot, variants in SUPPORTED_ATTRIBUTES.items()
            for attrs in variants
        ),
    )


def validate_attributes(slot, attrs):
    require(
        slot in SUPPORTED_ATTRIBUTES and attrs in SUPPORTED_ATTRIBUTES[slot], 0x6A80
    )


def generate_key(slot, attrs):
    validate_attributes(slot, attrs)
    if attrs[0] == 1:
        return rsa.generate_private_key(65537, int.from_bytes(attrs[1:3], "big"))
    if attrs[0] == 0x16:
        return ed25519.Ed25519PrivateKey.generate()
    if attrs[1:] == X25519_OID:
        return x25519.X25519PrivateKey.generate()
    return ec.generate_private_key(CURVES[attrs[1:]]())


def import_fields(rest):
    parts = Tlv.parse_list(rest)
    require([part.tag for part in parts] == [0x7F48, 0x5F48], 0x6A80)
    headers, values = (part.value for part in parts)
    fields = {}
    index = position = 0
    while index < len(headers):
        require(index + 2 <= len(headers), 0x6A80)
        tag, length = headers[index : index + 2]
        index += 2
        if length & 0x80:
            width = length & 0x7F
            require(1 <= width <= 2 and index + width <= len(headers), 0x6A80)
            length = int.from_bytes(headers[index : index + width], "big")
            index += width
        require(
            tag not in fields and length > 0 and position + length <= len(values),
            0x6A80,
        )
        fields[tag] = values[position : position + length]
        position += length
    require(position == len(values), 0x6A80)
    return fields


def import_key(slot, attrs, rest):
    validate_attributes(slot, attrs)
    fields = import_fields(rest)
    if attrs[0] == 1:
        bits = int.from_bytes(attrs[1:3], "big")
        require(tuple(fields) == (0x91, 0x92, 0x93), 0x6A80)
        require(fields[0x91] == b"\x01\0\x01", 0x6A80)
        require(len(fields[0x92]) == len(fields[0x93]) == bits // 16, 0x6A80)
        p, q = (int.from_bytes(fields[tag], "big") for tag in (0x92, 0x93))
        require((p * q).bit_length() == bits, 0x6A80)
        private = pow(65537, -1, (p - 1) * (q - 1))
        return rsa.RSAPrivateNumbers(
            p,
            q,
            private,
            private % (p - 1),
            private % (q - 1),
            pow(q, -1, p),
            rsa.RSAPublicNumbers(65537, p * q),
        ).private_key()
    require(tuple(fields) == (0x92,), 0x6A80)
    secret = fields[0x92]
    if attrs[0] == 0x16:
        require(len(secret) == 32, 0x6A80)
        return ed25519.Ed25519PrivateKey.from_private_bytes(secret)
    if attrs[1:] == X25519_OID:
        require(len(secret) == 32, 0x6A80)
        return x25519.X25519PrivateKey.from_private_bytes(secret[::-1])
    curve = CURVES[attrs[1:]]()
    require(len(secret) == (curve.key_size + 7) // 8, 0x6A80)
    value = int.from_bytes(secret, "big")
    require(0 < value and value.bit_length() <= curve.key_size, 0x6A80)
    return ec.derive_private_key(value, curve)
