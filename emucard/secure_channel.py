"""SCP03 and SCP11 card-side secure messaging for this development card.

The keys are a public development profile. They are unrelated to factory keys.
"""

import hashlib
import hmac
import os
import struct
import time

from cryptography.hazmat.primitives import cmac, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from yubikit.core import Tlv

DEVELOPMENT_KEY = bytes(range(0x40, 0x50))
SCP03_IMPLEMENTATION_OPTION = 0x60  # Measured public profile: random S8, R-MAC/R-ENC.


class ChannelError(Exception):
    def __init__(self, sw):
        self.sw = sw


def require(value, sw=0x6982):
    if not value:
        raise ChannelError(sw)


def mac(key, value):
    ctx = cmac.CMAC(algorithms.AES(key))
    ctx.update(value)
    return ctx.finalize()


def derive(key, constant, context, bits=128):
    return mac(
        key,
        bytes(11) + bytes([constant, 0]) + struct.pack(">H", bits) + b"\x01" + context,
    )[: bits // 8]


class SecureChannel:
    def __init__(self, host, kvn, enc, auth, dek=None):
        require(len(host) == 8 and 0 <= kvn <= 255, 0x6A88)
        self.kvn = kvn
        self.scp_kid = 0x01
        self.dek = dek or enc
        self.oce_authenticated = False
        self.challenge = os.urandom(8)
        context = host + self.challenge
        self.enc = derive(enc, 4, context)
        self.auth = derive(auth, 6, context)
        self.response_auth = derive(auth, 7, context)
        self.card_cryptogram = derive(self.auth, 0, context, 64)
        self.host_cryptogram = derive(self.auth, 1, context, 64)
        self.chain = bytes(16)
        self.counter = 1
        self.established = False
        self.created = time.monotonic()
        self.chunks = b""
        self.chunk_header = None

    def initialization(self, serial):
        diversification = hashlib.sha256(b"local-development-card" + serial).digest()[
            :10
        ]
        return (
            diversification
            + bytes([self.kvn, 3, SCP03_IMPLEMENTATION_OPTION])
            + self.challenge
            + self.card_cryptogram
        )

    @classmethod
    def scp11(cls, data, kid, private_key, host_static=None):
        parts = Tlv.parse_list(data)
        require(
            len(parts) == 2 and parts[0].tag == 0xA6 and parts[1].tag == 0x5F49, 0x6A80
        )
        fields = Tlv.parse_list(parts[0].value)
        expected = [
            (0x90, bytes([0x11, {0x11: 1, 0x13: 0, 0x15: 3}[kid]])),
            (0x95, b"\x3c"),
            (0x80, b"\x88"),
            (0x81, b"\x10"),
        ]
        require([(f.tag, f.value) for f in fields] == expected, 0x6A80)
        host_ephemeral = ec.EllipticCurvePublicKey.from_encoded_point(
            private_key.curve, parts[1].value
        )
        require(kid == 0x13 or host_static is not None, 0x6982)
        host_static = host_static or host_ephemeral
        # SCP11c is scriptable: its SD contribution is the provisioned static
        # key for both ECDH terms. Only a/b generate a card ephemeral key.
        card_key = (
            private_key if kid == 0x15 else ec.generate_private_key(private_key.curve)
        )
        public = Tlv(
            0x5F49,
            card_key.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            ),
        )
        shared = card_key.exchange(ec.ECDH(), host_ephemeral) + private_key.exchange(
            ec.ECDH(), host_static
        )
        material = X963KDF(hashes.SHA256(), 80, b"\x3c\x88\x10").derive(shared)
        receipt = mac(material[:16], data + public)
        channel = cls.__new__(cls)
        channel.scp_kid = kid
        channel.enc, channel.auth, channel.response_auth, channel.dek = [
            material[i : i + 16] for i in range(16, 80, 16)
        ]
        channel.chain = receipt
        channel.counter = 1
        channel.established = True
        channel.oce_authenticated = kid != 0x13
        channel.created = time.monotonic()
        channel.chunks = b""
        channel.chunk_header = None
        return channel, public + Tlv(0x86, receipt)

    def cipher(self, counter, response=False):
        ctx = Cipher(algorithms.AES(self.enc), modes.ECB()).encryptor()
        seed = bytes([0x80 if response else 0]) + counter.to_bytes(15, "big")
        iv = ctx.update(seed) + ctx.finalize()
        return Cipher(algorithms.AES(self.enc), modes.CBC(iv))

    def unwrap(self, apdu, raw):
        require(
            time.monotonic() - self.created < 3600
            and apdu.cla in (4, 0x14, 0x84, 0x94),
            0x6985,
        )
        header = (apdu.cla & ~0x10, apdu.ins, apdu.p1, apdu.p2)
        if self.chunk_header is not None:
            require(header == self.chunk_header, 0x6883)
        if apdu.cla & 0x10:
            require(len(self.chunks) + len(apdu.data) <= 32768, 0x6700)
            self.chunk_header = header
            self.chunks += apdu.data
            return None
        if self.chunks:
            payload = self.chunks + apdu.data
            require(len(payload) <= 32768, 0x6700)
            prefix = bytes(header) + b"\0" + struct.pack(">H", len(payload))
            self.chunks = b""
            self.chunk_header = None
        else:
            payload = apdu.data
            prefix = raw[:7] if len(raw) > 5 and raw[4] == 0 else raw[:5]
        require(len(payload) >= 8, 0x6982)
        data, tag = payload[:-8], payload[-8:]
        chain = mac(self.auth, self.chain + prefix + data)
        require(hmac.compare_digest(chain[:8], tag), 0x6982)
        self.chain = chain
        if not self.established:
            require(
                time.monotonic() - self.created < 30
                and apdu.ins == 0x82
                and apdu.p1 == 0x33
                and apdu.p2 == 0,
                0x6985,
            )
            require(hmac.compare_digest(data, self.host_cryptogram), 0x6982)
            self.established = True
            self.oce_authenticated = True
            return b"", True
        require(apdu.cla in (4, 0x84) and len(data) > 0 and len(data) % 16 == 0, 0x6982)
        ctx = self.cipher(self.counter).decryptor()
        plain = ctx.update(data) + ctx.finalize()
        plain = plain.rstrip(b"\0")
        require(plain[-1:] == b"\x80", 0x6982)
        self.counter += 1
        return plain[:-1], False

    def wrap(self, data, sw):
        if data:
            data = data + b"\x80" + bytes(15 - len(data) % 16)
            ctx = self.cipher(self.counter - 1, True).encryptor()
            data = ctx.update(data) + ctx.finalize()
        tag = mac(self.response_auth, self.chain + data + struct.pack(">H", sw))[:8]
        return data + tag, sw
