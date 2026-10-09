"""Local smart-card emulator core. Fresh keys; no manufacturer identity.
ISO 7816 APDUs and CCID messages are real wire formats, not SDK method mocks.
"""

from __future__ import annotations

import copy
import hmac
import json
import os
import struct
import tempfile
import threading
import time
from collections.abc import Callable
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import cmac, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed25519,
    padding,
    rsa,
    utils,
    x25519,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from yubikit.core import TRANSPORT, Tlv
from yubikit.core.smartcard import AID, SmartCardConnection

from .profile import (
    CCID_CLOCK_KHZ,
    CCID_DATA_RATE,
    CCID_PAYLOAD_LENGTH,
    MAX_COMMAND_APDU_LENGTH,
    OPENPGP_CHALLENGE_LENGTH,
    OPENPGP_EXTENDED_CAPABILITIES,
    OPENPGP_EXTENDED_LENGTH_INFO,
    OPENPGP_GENERAL_FEATURE_MANAGEMENT,
    OPENPGP_HISTORICAL_BYTES,
    PIV_APDU_DATA_LENGTH,
    PIV_OBJECT_STORAGE_LENGTH,
)
from .secure_channel import ChannelError

VERSION = b"\x05\x07\x04"  # protocol compatibility profile, not a hardware attestation
# Independent software ATR: direct convention, explicit FI/DI 1/1, no VPP
# or extra guard time, T=1/LRC and a valid TCK. The interface-byte presence
# pattern also lets the stock Yubico PC/SC SDK identify this USB connection.
# Contains no manufacturer historical bytes, serial, key or attestation data.
ATR = bytes.fromhex("3bf011000001e0")


class CardError(Exception):
    def __init__(self, sw, durable=False):
        self.sw = sw
        self.durable = durable


def fail(sw):
    raise CardError(sw)


def require(test, sw=0x6982):
    if not test:
        fail(sw)


def tlvs(data):
    result = {}
    for value in Tlv.parse_list(data):
        require(value.tag not in result, 0x6A80)
        result[value.tag] = value.value
    return result


def public_data(key):
    pub = key.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        n = pub.public_numbers()
        return Tlv(0x81, n.n.to_bytes(key.key_size // 8, "big")) + Tlv(
            0x82, n.e.to_bytes(3, "big")
        )
    if isinstance(pub, ec.EllipticCurvePublicKey):
        value = pub.public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
    else:
        value = pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    return Tlv(0x86, value)


def load_key(value):
    return serialization.load_der_private_key(bytes.fromhex(value), None)


def dump_key(key):
    return key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).hex()


def raw_rsa(key, value):
    nums = key.private_numbers()
    n = nums.public_numbers.n
    require(
        len(value) == key.key_size // 8 and int.from_bytes(value, "big") < n, 0x6A80
    )
    return pow(int.from_bytes(value, "big"), nums.d, n).to_bytes(
        key.key_size // 8, "big"
    )


def ec_digest_signature(key, value, raw=False):
    alg = {
        20: hashes.SHA1,
        28: hashes.SHA224,
        32: hashes.SHA256,
        48: hashes.SHA384,
        64: hashes.SHA512,
    }.get(len(value))
    require(alg is not None, 0x6A80)
    sig = key.sign(value, ec.ECDSA(utils.Prehashed(alg())))
    if raw:
        r, s = utils.decode_dss_signature(sig)
        n = (key.key_size + 7) // 8
        return r.to_bytes(n, "big") + s.to_bytes(n, "big")
    return sig


def aes_cmac(key, value):
    c = cmac.CMAC(algorithms.AES(key))
    c.update(value)
    return c.finalize()


def scp03_kdf(key, constant, context, bits=128):
    require(bits in (64, 128), 0x6A80)
    # SCP03 derivation: 11 zero bytes || constant || separator || L || counter || context.
    data = (
        b"\0" * 11 + bytes([constant, 0]) + struct.pack(">H", bits) + b"\x01" + context
    )
    return aes_cmac(key, data)[: bits // 8]


def crc16(value):
    crc = 0xFFFF
    for byte in value:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x8408 if crc & 1 else 0)
    return crc


def defaults(*, piv_attestation=True):
    data = {
        "serial": os.urandom(4).hex(),
        "piv": {
            "pin": "123456",
            "puk": "12345678",
            "pin_retries": 3,
            "puk_retries": 3,
            "pin_max": 3,
            "puk_max": 3,
            "mgmt": bytes.fromhex("0102030405060708" * 3).hex(),
            "mgmt_type": 10,
            "mgmt_touch": False,
            "keys": {},
            "objects": {},
        },
        "openpgp": {
            "pin": "123456",
            "admin": "12345678",
            "reset": "",
            "pin_retries": 3,
            "admin_retries": 3,
            "reset_retries": 0,
            "pin_max": 3,
            "admin_max": 3,
            "reset_max": 3,
            "keys": {},
            "objects": {
                "193": "010800001100",
                "194": "010800001100",
                "195": "010800001100",
            },
            "sig_counter": 0,
            "terminated": False,
        },
        "hsmauth": {"mgmt": "00" * 16, "mgmt_retries": 8, "credentials": {}},
        "oath": {"credentials": {}, "access_key": "", "salt": os.urandom(8).hex()},
        "otp": {"slots": {}, "sequence": 0},
    }
    if piv_attestation:
        from .piv_objects import initialize

        initialize(data["piv"])
    return data


class EncryptedState:
    """Atomic AES-GCM state with a separate mode-0600 local key file.
    OS protected storage is a separate integration; file storage is software security.
    """

    def __init__(self, path: Path | None = None):
        # Volatile device-power state is shared by logical transport sessions.
        # A new EncryptedState on process restart starts a new OTP power session.
        self.otp_sessions = {}
        self.otp_touch_owner = None
        self.otp_touch_mode = None
        self.path = Path(path) if path else None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            require(not self.path.is_symlink(), 0x6581)
            key_path = self.path.with_suffix(self.path.suffix + ".key")
            if key_path.exists():
                require(
                    not key_path.is_symlink() and key_path.stat().st_mode & 0o077 == 0,
                    0x6581,
                )
                self.key = key_path.read_bytes()
            else:
                self.key = os.urandom(32)
                fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as f:
                    f.write(self.key)
                    f.flush()
                    os.fsync(f.fileno())
            require(len(self.key) == 32, 0x6581)
            if self.path.exists():
                raw = self.path.read_bytes()
                require(raw[:4] == b"EKC1", 0x6581)
                self.data = json.loads(
                    AESGCM(self.key).decrypt(raw[4:16], raw[16:], b"EmulatedCard-v1")
                )
                from .piv_objects import initialize

                if initialize(self.data["piv"]):
                    self.flush()
            else:
                self.data = defaults()
                self.flush()
        else:
            self.data = defaults()

    def flush(self):
        if not self.path:
            return
        nonce = os.urandom(12)
        raw = (
            b"EKC1"
            + nonce
            + AESGCM(self.key).encrypt(
                nonce,
                json.dumps(self.data, sort_keys=True).encode(),
                b"EmulatedCard-v1",
            )
        )
        fd, name = tempfile.mkstemp(prefix=".card-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(raw)
                f.flush()
                os.fsync(f.fileno())
            os.replace(name, self.path)
            dfd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        finally:
            if os.path.exists(name):
                os.unlink(name)


@dataclass(frozen=True)
class Apdu:
    cla: int
    ins: int
    p1: int
    p2: int
    data: bytes
    le: int | None
    # A five-byte command ending in 00 is indistinguishable on the wire from
    # explicit short Le=256; retain its encoding for app-level compatibility.
    short_zero_tail: bool = False

    @classmethod
    def decode(cls, value):
        require(4 <= len(value) <= MAX_COMMAND_APDU_LENGTH, 0x6700)
        cla, ins, p1, p2 = value[:4]
        data = b""
        le = None
        if len(value) == 5:
            le = value[4] or 256
        elif len(value) > 5:
            if value[4]:
                start = 5
                n = value[4]
                width = 1
            else:
                require(len(value) >= 7, 0x6700)
                start = 7
                n = int.from_bytes(value[5:7], "big")
                width = 2
                if len(value) == 7:
                    return cls(cla, ins, p1, p2, b"", n or 65536)
                require(n > 0, 0x6700)
            require(len(value) in (start + n, start + n + width), 0x6700)
            data = value[start : start + n]
            if len(value) > start + n:
                le = int.from_bytes(value[start + n :], "big") or (
                    256 if width == 1 else 65536
                )
        return cls(cla, ins, p1, p2, data, le, len(value) == 5 and value[4] == 0)


class Card:
    def __init__(
        self,
        state: EncryptedState | None = None,
        touch: Callable[[str], bool] | None = None,
    ):
        self.state = state or EncryptedState()
        self.cancelled = lambda: False
        self.commit_guard = nullcontext
        self.did_commit = lambda: None
        touch_callback = touch or (lambda _: False)
        self.touch = lambda label: (
            not self.cancelled() and touch_callback(label) and not self.cancelled()
        )
        self.selected = None
        self.verified = set()
        self.mgmt_verified = False
        self.witness = None
        self.chained = b""
        self.chain_header = None
        self.pending = b""
        self.cached_touch = {}
        self.oath_authenticated = False
        self.oath_challenge = None
        self.certificate_slot = 3
        self.hsm_ephemeral = {}
        self.otp_sessions = self.state.otp_sessions
        self.otp_update_pending = None
        self.reset_otp_power_after_commit = False
        self.secure_channel = None
        self.close_wrapping_channel = False
        self.reset_oce_cache()

    def reset_oce_cache(self):
        # Invalidate authorization for a future SCP11a/c handshake without
        # revoking the current secure-messaging transport or verified PINs.
        self.oce_chain = []
        self.oce_ref = None
        self.oce_public = None
        self.oce_trusted_ref = None
        self.oce_created = 0
        self.oce_policy_generation = None

    def reset_session(self, preserve_otp_touch=False):
        self.verified.clear()
        self.mgmt_verified = False
        self.witness = None
        self.chained = b""
        self.chain_header = None
        self.pending = b""
        self.cached_touch.clear()
        self.oath_authenticated = False
        self.oath_challenge = None
        self.certificate_slot = 3
        self.hsm_ephemeral.clear()
        self.otp_update_pending = None
        if not preserve_otp_touch and self.state.otp_touch_owner is self:
            self.state.otp_touch_owner = None
            self.state.otp_touch_mode = None
        self.reset_otp_power_after_commit = False
        self.secure_channel = None
        self.reset_oce_cache()

    def reset_power_session(self):
        """Reset volatile OTP counters on an explicit emulated power cycle."""
        self.reset_session()
        self.otp_sessions.clear()
        self.state.otp_touch_owner = None
        self.state.otp_touch_mode = None

    def transmit(self, value):
        self.close_wrapping_channel = False
        try:
            require(not self.cancelled(), 0x6400)
            apdu = Apdu.decode(value)
            if apdu.cla in (4, 0x14, 0x84, 0x94):
                require(self.secure_channel is not None, 0x6982)
                channel = self.secure_channel
                from .domain import state as domain_state

                # Domain factory reset closes every connection's old channel;
                # ordinary policy updates leave established transport intact.
                require(channel.domain_id == domain_state(self)["cplc"], 0x6982)
                if channel.scp_kid == 0x15:
                    require(
                        channel.session_generation
                        == domain_state(self).get("scp11c_session_generation"),
                        0x6982,
                    )
                decoded = channel.unwrap(apdu, value)
                if decoded is None:
                    return b"", 0x9000
                plain, handshake = decoded
                if handshake:
                    from .domain import AUTHENTICATION_TRIES

                    previous = copy.deepcopy(self.state.data)
                    row = domain_state(self)["keys"].get(channel.key_ref)
                    if row:
                        row["retries"] = AUTHENTICATION_TRIES
                    try:
                        self.commit()
                    except (OSError, CardError) as e:
                        self.state.data = previous
                        self.reset_session()
                        return b"", e.sw if isinstance(e, CardError) else 0x6581
                    return channel.wrap(b"", 0x9000)
                packet = bytes([apdu.cla & ~4, apdu.ins, apdu.p1, apdu.p2])
                if plain:
                    packet += b"\0" + struct.pack(">H", len(plain)) + plain
                if apdu.le is not None:
                    if not plain:
                        packet += b"\0"
                    packet += struct.pack(">H", apdu.le if apdu.le < 65536 else 0)
                response, sw = self._transmit_plain(packet)
                next_channel = self.secure_channel
                if self.close_wrapping_channel:
                    self.secure_channel = None
                elif (
                    sw == 0x9000
                    and apdu.ins in (0x82, 0x88)
                    and apdu.p2 in (0x11, 0x13, 0x15)
                    and next_channel is not None
                    and next_channel is not channel
                    and next_channel.established
                ):
                    # Protect this response using the old wrapper, then use
                    # the successfully established SCP11 context for new APDUs.
                    self.secure_channel = next_channel
                else:
                    # The SDK reset nests invalid authentication attempts and
                    # SCP03 INIT (not yet authenticated) in an outer channel.
                    self.secure_channel = channel
                return channel.wrap(response, sw)
            if apdu.ins == 0xA4 and apdu.p1 == 4:
                # Even a malformed plaintext SELECT ends authorization before
                # header/AID validation. Clearing only the wrapper would leave
                # PIN/admin/OCE state available to subsequent plain commands.
                self.reset_session()
            elif self.secure_channel is not None and self.secure_channel.established:
                # Yubico's transport requires protection for every command
                # after establishment, including PSO and new handshakes. The
                # outer error handler clears the channel and authorizations.
                fail(0x6982)
            return self._transmit_plain(value)
        except (CardError, ChannelError) as e:
            self.reset_session()
            return b"", e.sw
        except (ValueError, TypeError, IndexError):
            self.reset_session()
            return b"", 0x6A80

    def reset_for_channel(self):
        # OATH's SELECT challenge precedes the SCP handshake in the public SDK.
        # Keep that challenge while clearing verified PINs and old channel keys.
        challenge = self.oath_challenge
        self.reset_session()
        if self.selected == AID.OATH:
            self.oath_challenge = challenge

    def _transmit_plain(self, value):
        previous = copy.deepcopy(self.state.data)
        previous_otp_sessions = copy.deepcopy(self.otp_sessions)
        previous_otp_reset = self.reset_otp_power_after_commit
        apdu = None
        try:
            apdu = Apdu.decode(value)
            require(not self.cancelled(), 0x6400)
            require(apdu.cla in (0, 0x10, 0x80, 0x90), 0x6E00)
            if apdu.ins == 0xC0 or (self.selected == AID.OATH and apdu.ins == 0xA5):
                if self.selected == AID.OPENPGP and apdu.ins == 0xC0:
                    # An unfinished OpenPGP command chain requires the next
                    # fragment with the same INS/P1/P2, not GET RESPONSE.
                    require(self.chain_header is None, 0x6883)
                    # OpenPGP 3.4.1 section 7.2.9 requires plaintext CLA 00.
                    # Check it before consuming the buffered response. The
                    # public SDK emits a four-byte GET RESPONSE in extended
                    # APDU mode, so retain that compatibility behavior.
                    require(apdu.cla == 0, 0x6E00)
                require(apdu.p1 == 0 and apdu.p2 == 0 and not apdu.data, 0x6A86)
                n = apdu.le or 256
                out = self.pending[:n]
                self.pending = self.pending[n:]
                return out, 0x6100 | min(
                    len(self.pending), 255
                ) if self.pending else 0x9000
            self.pending = b""
            header = (apdu.cla & ~0x10, apdu.ins, apdu.p1, apdu.p2)
            if self.chain_header is not None:
                require(header == self.chain_header, 0x6883)
            if self.selected == AID.OPENPGP and apdu.ins == 0xCA:
                # OpenPGP GET DATA has only CLA 00/0C in section 7.2.6;
                # reject an invalid chained prefix before recording it.
                require(not (apdu.cla & 0x10), 0x6E00)
            if apdu.cla & 0x10:
                limit = PIV_APDU_DATA_LENGTH if self.selected == AID.PIV else 32768
                require(len(self.chained) + len(apdu.data) <= limit, 0x6700)
                self.chain_header = header
                self.chained += apdu.data
                return b"", 0x9000
            if self.chained:
                limit = PIV_APDU_DATA_LENGTH if self.selected == AID.PIV else 32768
                require(len(self.chained) + len(apdu.data) <= limit, 0x6700)
                apdu = Apdu(
                    apdu.cla,
                    apdu.ins,
                    apdu.p1,
                    apdu.p2,
                    self.chained + apdu.data,
                    apdu.le,
                    apdu.short_zero_tail,
                )
                self.chained = b""
                self.chain_header = None
            if apdu.cla == 0x80 and apdu.ins in (0x50, 0x2A, 0x82, 0x88):
                from .domain import handshake

                out = handshake(self, apdu)
            elif apdu.ins == 0xA4 and apdu.p1 == 4:
                require(apdu.cla == 0, 0x6E00)
                require(apdu.p1 == 4 and len(apdu.data) >= 5, 0x6A86)
                self.reset_session()
                self.close_wrapping_channel = True
                self.selected = None
                aid = next((a for a in AID if bytes(a).startswith(apdu.data)), None)
                if aid is None:
                    from .piv_objects import APPLICATION_AID

                    if APPLICATION_AID.startswith(apdu.data):
                        aid = AID.PIV
                require(
                    aid
                    in (
                        AID.PIV,
                        AID.OPENPGP,
                        AID.HSMAUTH,
                        AID.OATH,
                        AID.OTP,
                        AID.SECURE_DOMAIN,
                        AID.MANAGEMENT,
                    ),
                    0x6A82,
                )
                from .management import application_enabled

                require(application_enabled(self, aid), 0x6A82)
                self.selected = aid
                if aid == AID.MANAGEMENT:
                    out = b"5.7.4"
                elif aid == AID.SECURE_DOMAIN:
                    from .domain import SELECT_RESPONSE as domain_select_response
                    from .domain import state as domain_state

                    domain_state(self)
                    out = domain_select_response
                elif aid == AID.OTP:
                    out = self.otp_status()
                elif aid == AID.HSMAUTH:
                    out = Tlv(0x79, VERSION)
                elif aid == AID.OATH:
                    out = self.oath_select()
                elif aid == AID.OPENPGP:
                    require(not self.state.data["openpgp"]["terminated"], 0x6285)
                    out = b""
                elif aid == AID.PIV:
                    from .piv_objects import SELECT_RESPONSE

                    out = SELECT_RESPONSE
                else:
                    out = b""
            else:
                require(self.selected is not None, 0x6999)
                from .management import application_enabled

                require(application_enabled(self, self.selected), 0x6A82)
                require(
                    apdu.cla == 0
                    or (
                        self.selected == AID.SECURE_DOMAIN
                        and apdu.ins in (0xF0, 0xF1, 0xD8, 0xE4)
                    )
                    or (self.selected == AID.OPENPGP and apdu.ins == 0xFB),
                    0x6E00,
                )
                from .domain import dispatch as domain_dispatch
                from .management import dispatch as management_dispatch

                method = {
                    AID.PIV: self.piv,
                    AID.OPENPGP: self.openpgp,
                    AID.HSMAUTH: self.hsmauth,
                    AID.OATH: self.oath,
                    AID.OTP: self.otp,
                    AID.SECURE_DOMAIN: lambda a: domain_dispatch(self, a),
                    AID.MANAGEMENT: lambda a: management_dispatch(self, a),
                }[self.selected]
                out = bytes(method(apdu) or b"")
            self.commit()
            if apdu.le is not None and len(out) > apdu.le:
                self.pending = out[apdu.le :]
                out = out[: apdu.le]
                return out, 0x6100 | min(len(self.pending), 255)
            return out, 0x9000
        except (CardError, ChannelError) as e:
            # Wrong PIN retries are intentional durable mutations.
            if (
                getattr(e, "durable", False)
                or e.sw & 0xFFF0 == 0x63C0
                or e.sw == 0x6983
            ):
                try:
                    self.commit(durable=True)
                except (OSError, CardError) as cancelled:
                    self.state.data = previous
                    self.otp_sessions.clear()
                    self.otp_sessions.update(previous_otp_sessions)
                    self.reset_otp_power_after_commit = previous_otp_reset
                    self.reset_session()
                    return b"", cancelled.sw if isinstance(
                        cancelled, CardError
                    ) else 0x6581
            else:
                self.state.data = previous
                self.otp_sessions.clear()
                self.otp_sessions.update(previous_otp_sessions)
                self.reset_otp_power_after_commit = previous_otp_reset
            self.chained = b""
            self.chain_header = None
            if (
                apdu is not None
                and apdu.cla == 0x80
                and apdu.ins in (0x50, 0x2A, 0x82, 0x88)
            ):
                if apdu.ins == 0x2A and not self.close_wrapping_channel:
                    self.reset_oce_cache()
                else:
                    self.reset_session()
            return b"", e.sw
        except (ValueError, KeyError, IndexError, TypeError):
            self.state.data = previous
            self.otp_sessions.clear()
            self.otp_sessions.update(previous_otp_sessions)
            self.reset_otp_power_after_commit = previous_otp_reset
            self.chained = b""
            self.chain_header = None
            if apdu is not None and apdu.cla == 0x80 and apdu.ins == 0x2A:
                self.reset_oce_cache()
            return b"", 0x6A80
        except OSError:
            self.state.data = previous
            self.otp_sessions.clear()
            self.otp_sessions.update(previous_otp_sessions)
            self.reset_otp_power_after_commit = previous_otp_reset
            self.reset_session()
            self.close_wrapping_channel = True
            return b"", 0x6581

    def _flush_committed_state(self):
        self.state.flush()
        if self.reset_otp_power_after_commit:
            # A rejected/failed management write must not reset counters.
            self.otp_sessions.clear()
            self.state.otp_touch_owner = None
            self.state.otp_touch_mode = None
            self.reset_otp_power_after_commit = False

    def commit(self, durable=False):
        # ABORT and persistence share one completion boundary. An operation
        # committed before ABORT may finish; one cancelled first must roll back.
        with self.commit_guard():
            # A PIN/key comparison already performed still consumes its retry.
            # ABORT must not let clients erase failed authentication attempts.
            require(durable or not self.cancelled(), 0x6400)
            self._flush_committed_state()
            self.did_commit()

    def verify(self, area, name, value, min_length=0):
        d = self.state.data[area]
        count = name + "_retries"
        require(d[count] > 0, 0x6983)
        if area == "openpgp":
            from .pgp_extensions import pin_bytes

            expected = pin_bytes(d, name)
        else:
            expected = d[name].encode()
        if not hmac.compare_digest(value, expected):
            d[count] -= 1
            self.verified.discard((area, name))
            if area == "openpgp":
                for reference in (0x81, 0x82) if name == "pin" else (0x83,):
                    self.verified.discard(("openpgp", reference))
                raise CardError(0x6982, durable=True)
            fail(0x63C0 | min(d[count], 15))
        require(len(value) >= min_length, 0x6A80)
        d[count] = d.get(name + "_max", 3)
        self.verified.add((area, name))

    def touch_key(self, label, policy):
        if policy not in (2, 3):
            return
        if policy == 3 and time.monotonic() - self.cached_touch.get(label, -100) < 15:
            return
        require(self.touch(label), 0x6985)
        self.cached_touch[label] = time.monotonic()

    def piv_cipher(self, data, encrypt=True):
        d = self.state.data["piv"]
        key = bytes.fromhex(d["mgmt"])
        if d["mgmt_type"] == 3:
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES

            algo = TripleDES(key)
        else:
            algo = algorithms.AES(key)
        ctx = (
            Cipher(algo, modes.ECB()).encryptor()
            if encrypt
            else Cipher(algo, modes.ECB()).decryptor()
        )
        return ctx.update(data) + ctx.finalize()

    def piv(self, a):
        d = self.state.data["piv"]
        require(len(a.data) <= PIV_APDU_DATA_LENGTH, 0x6700)
        ins = a.ins
        if ins == 0xFD:
            return VERSION
        if ins == 0xF8:
            return bytes.fromhex(self.state.data["serial"])
        if ins == 0xF9:
            require(a.p2 == 0 and a.p1 != 0xF9 and str(a.p1) in d["keys"], 0x6A88)
            row = d["keys"][str(a.p1)]
            require(row["generated"], 0x6A80)
            return self.development_attestation(a.p1, row)
        if ins == 0xF7:
            if a.p2 in (0x80, 0x81):
                name = "pin" if a.p2 == 0x80 else "puk"
                default = "123456" if name == "pin" else "12345678"
                return Tlv(5, bytes([d[name] == default])) + Tlv(
                    6, bytes([d[name + "_max"], d[name + "_retries"]])
                )
            if a.p2 == 0x9B:
                return (
                    Tlv(1, bytes([d["mgmt_type"]]))
                    + Tlv(2, bytes([0, 2 if d["mgmt_touch"] else 1]))
                    + Tlv(5, bytes([d["mgmt"] == ("0102030405060708" * 3)]))
                )
            require(str(a.p2) in d["keys"], 0x6A88)
            row = d["keys"][str(a.p2)]
            key = load_key(row["key"])
            return (
                Tlv(1, bytes([row["alg"]]))
                + Tlv(2, bytes([row["pin_policy"], row["touch_policy"]]))
                + Tlv(3, bytes([1 if row["generated"] else 2]))
                + Tlv(4, public_data(key))
            )
        if ins == 0x20:
            require(a.p1 == 0 and a.p2 == 0x80, 0x6A86)
            require(a.le is None, 0x6700)
            if not a.data:
                require(
                    ("piv", "pin") in self.verified, 0x63C0 | min(d["pin_retries"], 15)
                )
                return
            require(len(a.data) == 8, 0x6700)
            self.verified.discard(("piv", "pin"))
            self.verify("piv", "pin", a.data.rstrip(b"\xff"))
            return
        if ins in (0x24, 0x2C):
            require(
                a.p1 == 0
                and (a.p2 == 0x80 if ins == 0x2C else a.p2 in (0x80, 0x81)),
                0x6A86,
            )
            require(a.le is None and len(a.data) == 16, 0x6700)
            name = "puk" if ins == 0x2C or a.p2 == 0x81 else "pin"
            self.verify("piv", name, a.data[:8].rstrip(b"\xff"))
            dest = "pin" if ins == 0x2C else name
            value = a.data[8:].rstrip(b"\xff").decode()
            require(6 <= len(value) <= 8, 0x6A80)
            d[dest] = value
            d[dest + "_retries"] = d[dest + "_max"]
            self.verified.discard(("piv", dest))
            return
        if ins == 0x87:
            values = tlvs(Tlv.unpack(0x7C, a.data))
            if a.p2 == 0x9B:
                require(a.p1 == d["mgmt_type"], 0x6A86)
                size = 8 if a.p1 == 3 else 16
                if values.get(0x80) == b"":
                    self.witness = os.urandom(size)
                    return Tlv(0x7C, Tlv(0x80, self.piv_cipher(self.witness)))
                if (
                    values.get(0x81) == b""
                    and 0x82 not in values
                    and 0x80 not in values
                ):
                    self.witness = os.urandom(size)
                    return Tlv(0x7C, Tlv(0x81, self.witness))
                if 0x80 in values:
                    require(
                        self.witness is not None
                        and hmac.compare_digest(values[0x80], self.witness),
                        0x6982,
                    )
                    require(len(values.get(0x81, b"")) == size, 0x6A80)
                    self.touch_key("PIV management key", 2 if d["mgmt_touch"] else 1)
                    self.witness = None
                    self.mgmt_verified = True
                    return Tlv(0x7C, Tlv(0x82, self.piv_cipher(values[0x81])))
                if 0x82 in values:
                    require(
                        self.witness is not None
                        and hmac.compare_digest(
                            values[0x82], self.piv_cipher(self.witness)
                        ),
                        0x6982,
                    )
                    self.touch_key("PIV management key", 2 if d["mgmt_touch"] else 1)
                    self.witness = None
                    self.mgmt_verified = True
                    return b""
                fail(0x6A80)
            require(a.p2 != 0xF9, 0x6A86)
            require(str(a.p2) in d["keys"], 0x6A88)
            row = d["keys"][str(a.p2)]
            require(a.p1 == row["alg"], 0x6A80)
            require(row["pin_policy"] == 1 or ("piv", "pin") in self.verified)
            self.touch_key(f"PIV slot {a.p2:02x}", row["touch_policy"])
            key = load_key(row["key"])
            if 0x85 in values:
                if isinstance(key, x25519.X25519PrivateKey):
                    out = key.exchange(
                        x25519.X25519PublicKey.from_public_bytes(values[0x85])
                    )
                else:
                    require(isinstance(key, ec.EllipticCurvePrivateKey), 0x6A80)
                    out = key.exchange(
                        ec.ECDH(),
                        ec.EllipticCurvePublicKey.from_encoded_point(
                            key.curve, values[0x85]
                        ),
                    )
            else:
                require(0x81 in values, 0x6A80)
                value = values[0x81]
                if isinstance(key, rsa.RSAPrivateKey):
                    out = raw_rsa(key, value)
                elif isinstance(key, ec.EllipticCurvePrivateKey):
                    out = ec_digest_signature(key, value)
                elif isinstance(key, ed25519.Ed25519PrivateKey):
                    out = key.sign(value)
                else:
                    fail(0x6A80)
            if row["pin_policy"] == 3:
                self.verified.discard(("piv", "pin"))
            return Tlv(0x7C, Tlv(0x82, out))
        if ins == 0x47:
            require(self.mgmt_verified)
            # The PIV GENERATE ASYMMETRIC KEY PAIR command has no Le. Reject an
            # explicit response limit before replacing the slot's private key.
            require(a.le is None, 0x6700)
            require(
                a.p2 in list(range(0x82, 0x96)) + [0x9A, 0x9C, 0x9D, 0x9E, 0xF9], 0x6A86
            )
            values = tlvs(Tlv.unpack(0xAC, a.data))
            alg = values[0x80][0]
            require(a.p2 != 0xF9 or alg in (7, 5, 22, 17, 20), 0x6A80)
            pin_policy = values.get(0xAA, b"\0")[0] or (
                1 if a.p2 in (0x9E, 0xF9) else 3 if a.p2 == 0x9C else 2
            )
            touch_policy = values.get(0xAB, b"\0")[0] or 1
            require(pin_policy in (1, 2, 3) and touch_policy in (1, 2, 3), 0x6A80)
            key = self.generate_piv_key(alg)
            d["keys"][str(a.p2)] = {
                "key": dump_key(key),
                "alg": alg,
                "pin_policy": pin_policy,
                "touch_policy": touch_policy,
                "generated": True,
            }
            return Tlv(0x7F49, public_data(key))
        if ins == 0xFE:
            require(self.mgmt_verified)
            require(a.le is None, 0x6700)
            require(
                a.p2 in (0x9A, 0x9C, 0x9D, 0x9E, 0xF9) or 0x82 <= a.p2 <= 0x95, 0x6A86
            )
            v = tlvs(a.data)
            alg = a.p1
            require(a.p2 != 0xF9 or alg in (7, 5, 22, 17, 20), 0x6A80)
            if alg in (6, 7, 5, 22):
                p = int.from_bytes(v[1], "big")
                q = int.from_bytes(v[2], "big")
                e = 65537
                n = p * q
                private = pow(e, -1, (p - 1) * (q - 1))
                key = rsa.RSAPrivateNumbers(
                    p,
                    q,
                    private,
                    private % (p - 1),
                    private % (q - 1),
                    pow(q, -1, p),
                    rsa.RSAPublicNumbers(e, n),
                ).private_key()
                require(
                    key.key_size == {6: 1024, 7: 2048, 5: 3072, 22: 4096}[alg], 0x6A80
                )
            elif alg in (17, 20):
                key = ec.derive_private_key(
                    int.from_bytes(v[6], "big"),
                    ec.SECP256R1() if alg == 17 else ec.SECP384R1(),
                )
            elif alg == 224:
                key = ed25519.Ed25519PrivateKey.from_private_bytes(v[6])
            elif alg == 225:
                key = x25519.X25519PrivateKey.from_private_bytes(v[6])
            else:
                fail(0x6A80)
            pin_policy = v.get(0xAA, b"\0")[0] or (
                1 if a.p2 in (0x9E, 0xF9) else 3 if a.p2 == 0x9C else 2
            )
            touch_policy = v.get(0xAB, b"\0")[0] or 1
            require(pin_policy in (1, 2, 3) and touch_policy in (1, 2, 3), 0x6A80)
            d["keys"][str(a.p2)] = {
                "key": dump_key(key),
                "alg": alg,
                "pin_policy": pin_policy,
                "touch_policy": touch_policy,
                "generated": False,
            }
            return
        if ins == 0xCB:
            require((a.p1, a.p2) == (0x3F, 0xFF), 0x6A86)
            values = tlvs(a.data)
            oid = int.from_bytes(values[0x5C], "big")
            require(oid in (0x7E, 0x7F61) or 0x5F0000 <= oid <= 0x5FFFFF, 0x6A80)
            if oid == 0x7E:
                from .piv_objects import DISCOVERY

                return DISCOVERY
            if oid == 0x7F61:
                fail(0x6A82)
            require(str(oid) in d["objects"], 0x6A82)
            if oid in (0x5FC103, 0x5FC108, 0x5FC109, 0x5FC121):
                require(("piv", "pin") in self.verified)
            return Tlv(0x53, bytes.fromhex(d["objects"][str(oid)]))
        if ins == 0xDB:
            require(self.mgmt_verified)
            require(a.le is None, 0x6700)
            require((a.p1, a.p2) == (0x3F, 0xFF), 0x6A86)
            v = tlvs(a.data)
            oid = int.from_bytes(v[0x5C], "big")
            require(oid in (0x7E, 0x7F61) or 0x5F0000 <= oid <= 0x5FFFFF, 0x6A80)
            require(oid not in (0x7E, 0x7F61), 0x6A80)
            value = v[0x53]
            self.put_piv_object(oid, value)
            return
        if ins == 0xF6:
            require(self.mgmt_verified)
            require(a.p2 != 0xF9, 0x6A86)
            require(str(a.p2) in d["keys"], 0x6A88)
            if a.p1 == 0xFF:
                del d["keys"][str(a.p2)]
            else:
                require(
                    a.p1 in list(range(0x82, 0x96)) + [0x9A, 0x9C, 0x9D, 0x9E], 0x6A86
                )
                require(str(a.p1) not in d["keys"], 0x6985)
                d["keys"][str(a.p1)] = d["keys"].pop(str(a.p2))
            return
        if ins == 0xFF:
            require(self.mgmt_verified)
            require(len(a.data) >= 3, 0x6700)
            alg = a.data[0]
            key = Tlv.unpack(0x9B, a.data[1:])
            require(len(key) == {3: 24, 8: 16, 10: 24, 12: 32}.get(alg), 0x6A80)
            d["mgmt"] = key.hex()
            d["mgmt_type"] = alg
            d["mgmt_touch"] = a.p2 == 0xFE
            self.mgmt_verified = False
            return
        if ins == 0xFA:
            require(self.mgmt_verified and ("piv", "pin") in self.verified)
            require(not a.data, 0x6700)
            require(1 <= a.p1 <= 255 and 1 <= a.p2 <= 255, 0x6A80)
            d.update(
                pin="123456",
                puk="12345678",
                pin_retries=a.p1,
                puk_retries=a.p2,
                pin_max=a.p1,
                puk_max=a.p2,
            )
            self.verified.clear()
            return
        if ins == 0xFB:
            require(d["pin_retries"] == 0 and d["puk_retries"] == 0, 0x6985)
            # F9 and its certificate survive PIV application reset, including
            # intentionally replaced keys and intentionally deleted certificates.
            from .piv_objects import ATTESTATION_OBJECT, ATTESTATION_SLOT

            restored = defaults(piv_attestation=False)["piv"]
            for name, tag in (
                ("keys", ATTESTATION_SLOT),
                ("objects", ATTESTATION_OBJECT),
            ):
                if tag in d[name]:
                    restored[name][tag] = d[name][tag]
            self.state.data["piv"] = restored
            self.reset_session()
            return
        # Unsupported instructions fail explicitly; never claim success.
        fail(0x6D00)

    def put_piv_object(self, oid, value):
        from .piv_objects import CERTIFICATE_OBJECT_IDS, MAX_CERTIFICATE_BYTES

        if oid in CERTIFICATE_OBJECT_IDS:
            # The YubiKey 5 certificate limit applies to the stored certificate
            # bytes (tag 70), not to the wrapping PIV object or APDU. Leave
            # malformed-object handling to the existing PUT DATA path until its
            # firmware-specific rejection order can be measured.
            try:
                certificates = [
                    item.value for item in Tlv.parse_list(value) if item.tag == 0x70
                ]
            except ValueError:
                certificates = []
            require(
                all(len(cert) <= MAX_CERTIFICATE_BYTES for cert in certificates),
                0x6A80,
            )
        objects = self.state.data["piv"]["objects"]
        # Replacement releases the old allocation; private keys use separate
        # storage. Exact firmware record overhead remains a differential case.
        size = sum(len(data) // 2 for tag, data in objects.items() if tag != str(oid))
        old_size = len(objects.get(str(oid), "")) // 2
        require(
            size + len(value) <= PIV_OBJECT_STORAGE_LENGTH or len(value) <= old_size,
            0x6A84,
        )
        if value:
            objects[str(oid)] = value.hex()
        else:
            objects.pop(str(oid), None)

    def development_attestation(self, slot, row):
        """Local software certificate, never a manufacturer/hardware identity."""
        from .piv_objects import attest

        return attest(self, slot, row)

    @staticmethod
    def generate_piv_key(alg):
        if alg in (6, 7, 5, 22):
            return rsa.generate_private_key(
                65537, {6: 1024, 7: 2048, 5: 3072, 22: 4096}[alg]
            )
        if alg in (17, 20):
            return ec.generate_private_key(
                ec.SECP256R1() if alg == 17 else ec.SECP384R1()
            )
        if alg == 224:
            return ed25519.Ed25519PrivateKey.generate()
        if alg == 225:
            return x25519.X25519PrivateKey.generate()
        fail(0x6A80)

    def openpgp(self, a):
        from .pgp_algorithms import generate_key, import_key, validate_attributes
        from .pgp_extensions import (
            attestation,
            attributes_tag,
            ensure_attestation,
            pin_bytes,
            pin_length,
            reset_state,
            set_kdf,
            store_pin,
            template,
        )

        d = self.state.data["openpgp"]
        ensure_attestation(d)
        ins = a.ins
        if ins == 0xF1:
            return VERSION
        if ins == 0x44:
            require(a.p1 == a.p2 == 0 and not a.data, 0x6A86)
            # A no-data five-byte trailing 00 is indistinguishable from short
            # Le=256. Preserve that ambiguous encoding, but reject explicit Le.
            require(a.le is None or a.short_zero_tail, 0x6700)
            require(d["terminated"], 0x6985)
            self.state.data["openpgp"] = reset_state(d)
            self.reset_session()
            return
        require(not d["terminated"], 0x6985)
        if ins == 0xE6:
            require(a.p1 == a.p2 == 0 and not a.data, 0x6A86)
            require(a.le is None or a.short_zero_tail, 0x6700)
            require(d["pin_retries"] == 0 and d["admin_retries"] == 0, 0x6985)
            d["terminated"] = True
            self.reset_session()
            return
        if ins == 0x84:
            require(a.p1 == 0 and a.p2 == 0 and not a.data, 0x6A86)
            require(a.le is not None and a.le <= OPENPGP_CHALLENGE_LENGTH, 0x6700)
            return os.urandom(a.le)
        if ins == 0x20:
            require(a.p1 in (0, 0xFF), 0x6A86)
            require(a.p2 in (0x81, 0x82, 0x83), 0x6A86)
            # ShortApduFormatter emits a fifth 00 byte for no-data/no-Le.
            # Its wire form is indistinguishable from short Le=256. Accept
            # only that ambiguous form, not explicit extended Le=256.
            require(a.le is None or (not a.data and a.short_zero_tail), 0x6700)
            name = "admin" if a.p2 == 0x83 else "pin"
            ref = ("openpgp", a.p2)
            if a.p1 == 0xFF:
                require(not a.data, 0x6700)
                self.verified.discard(ref)
                return
            if not a.data:
                require(ref in self.verified, 0x63C0 | d[name + "_retries"])
                return
            self.verified.discard(ref)
            self.verify("openpgp", name, a.data)
            self.verified.add(ref)
            return
        if ins == 0x24:
            require(a.p1 == 0, 0x6A86)
            require(a.p2 in (0x81, 0x83), 0x6A86)
            require(a.le is None, 0x6700)
            name = "admin" if a.p2 == 0x83 else "pin"
            old = pin_bytes(d, name)
            self.verify("openpgp", name, a.data[: len(old)])
            new = a.data[len(old) :]
            pin_length(d, name, new)
            store_pin(d, name, new)
            self.verified.clear()
            return
        if ins == 0x2C:
            require(a.p2 == 0x81, 0x6A86)
            require(a.le is None, 0x6700)
            if a.p1 == 2:
                require(("openpgp", 0x83) in self.verified)
                new = a.data
            elif a.p1 == 0:
                old = pin_bytes(d, "reset")
                self.verify("openpgp", "reset", a.data[: len(old)])
                new = a.data[len(old) :]
            else:
                fail(0x6A86)
            pin_length(d, "pin", new)
            store_pin(d, "pin", new)
            d["pin_retries"] = d["pin_max"]
            self.verified.clear()
            return
        if ins == 0xCA:
            oid = a.p1 * 256 + a.p2
            if oid in (0x103, 0x104):
                require(("openpgp", 0x82 if oid == 0x103 else 0x83) in self.verified)
            if oid == 0x7F21:
                return bytes.fromhex(
                    d["objects"].get(
                        str(0xFC)
                        if self.certificate_slot == 0x81
                        else "certificate" + str(self.certificate_slot),
                        "",
                    )
                )
            return self.openpgp_data(oid)
        if ins == 0xCC:
            require((a.p1, a.p2) == (0x7F, 0x21), 0x6A86)
            # GET NEXT DATA has no command data (OpenPGP 3.4.1 section 7.2.7).
            # Validate the APDU before advancing the current certificate.
            require(not a.data, 0x6700)
            next_slot = {3: 2, 2: 1, 1: 0x81}.get(self.certificate_slot)
            require(next_slot is not None, 0x6A88)
            self.certificate_slot = next_slot
            return bytes.fromhex(
                d["objects"].get(
                    str(0xFC)
                    if self.certificate_slot == 0x81
                    else "certificate" + str(self.certificate_slot),
                    "",
                )
            )
        if ins == 0xFB:
            require(a.cla == 0x80, 0x6E00)
            require(a.p2 == 0 and not a.data and a.p1 in (1, 2, 3), 0x6A86)
            # Yubico's GET ATTESTATION uses Le=00 and returns no data.
            # Reject an explicit different Le before replacing the certificate.
            require(a.le in (None, 256, 65536), 0x6700)
            require(
                ("openpgp", 0x81) in self.verified or ("openpgp", 0x82) in self.verified
            )
            attestation(self, a.p1)
            return
        if ins == 0xDA:
            from .pgp_objects import validate_write

            oid = a.p1 * 256 + a.p2
            require(
                ("openpgp", 0x82 if oid in (0x101, 0x103) else 0x83) in self.verified
            )
            require(a.le is None, 0x6700)
            validate_write(oid, a.data)
            if oid == 0x7F21:
                d["objects"][
                    str(0xFC)
                    if self.certificate_slot == 0x81
                    else "certificate" + str(self.certificate_slot)
                ] = a.data.hex()
            elif oid == 0xFC:
                d["objects"][str(oid)] = a.data.hex()
            elif oid == 0xD3:
                if a.data:
                    pin_length(d, "reset", a.data)
                store_pin(d, "reset", a.data)
                d["reset_retries"] = 3 if a.data else 0
            elif oid in (0xC1, 0xC2, 0xC3, 0xDA):
                slot = 0x81 if oid == 0xDA else oid - 0xC0
                validate_attributes(slot, a.data)
                if d["objects"].get(str(oid)) != a.data.hex():
                    d["keys"].pop(str(slot), None)
                    d["objects"][str(0xDB if slot == 0x81 else 0xC6 + slot)] = "00" * 20
                    d["objects"][str(0xDD if slot == 0x81 else 0xCD + slot)] = "00" * 4
                    if slot == 0x81:
                        d["attestation_removed"] = True
                d["objects"][str(oid)] = a.data.hex()
            elif oid == 0xC4:
                require(len(a.data) == 1 and a.data[0] in (0, 1), 0x6A80)
                d["objects"][str(oid)] = a.data.hex()
            elif oid in (0xD6, 0xD7, 0xD8, 0xD9):
                require(len(a.data) == 2 and a.data[0] in (0, 1, 2, 3, 4), 0x6A80)
                require(
                    bytes.fromhex(d["objects"].get(str(oid), "0000"))[0] not in (2, 4)
                    or a.data[0]
                    == bytes.fromhex(d["objects"].get(str(oid), "0000"))[0],
                    0x6985,
                )
                d["objects"][str(oid)] = a.data.hex()
            elif oid == 0xF9:
                set_kdf(d, a.data)
                self.verified.clear()
            else:
                d["objects"][str(oid)] = a.data.hex()
            return
        if ins == 0x47:
            require(a.p2 == 0, 0x6A86)
            if a.p1 == 0x80:
                require(a.le in (None, 256, 65536), 0x6700)
            slot, rest = template(a.data)
            require(not rest, 0x6A80)
            if a.p1 == 0x80:
                require(("openpgp", 0x83) in self.verified)
                key = generate_key(
                    slot, bytes.fromhex(d["objects"][str(attributes_tag(slot))])
                )
                d["keys"][str(slot)] = {"key": dump_key(key), "generated": True}
                if slot == 1:
                    d["sig_counter"] = 0
            else:
                require(a.p1 == 0x81, 0x6A86)
                require(str(slot) in d["keys"], 0x6A88)
                key = load_key(d["keys"][str(slot)]["key"])
            return Tlv(0x7F49, public_data(key))
        if ins in (0x2A, 0x88):
            if ins == 0x88:
                require(a.p1 == a.p2 == 0, 0x6A86)
            slot = (
                3
                if ins == 0x88
                else 1
                if (a.p1, a.p2) == (0x9E, 0x9A)
                else 2
                if (a.p1, a.p2) == (0x80, 0x86)
                else 0
            )
            require(slot != 0, 0x6A86)
            if slot in (1, 3):
                require(a.le in (None, 256, 65536), 0x6700)
            require(("openpgp", 0x81 if slot == 1 else 0x82) in self.verified)
            require(str(slot) in d["keys"], 0x6A88)
            uif = bytes.fromhex(d["objects"].get(str(0xD5 + slot), "0020"))[0]
            if uif:
                self.touch_key(f"OpenPGP key {slot}", 3 if uif in (3, 4) else 2)
            key = load_key(d["keys"][str(slot)]["key"])
            if slot == 2:
                if isinstance(key, rsa.RSAPrivateKey):
                    require(a.data[:1] == b"\0", 0x6A80)
                    out = key.decrypt(a.data[1:], padding.PKCS1v15())
                else:
                    value = Tlv.unpack(
                        0x86, Tlv.unpack(0x7F49, Tlv.unpack(0xA6, a.data))
                    )
                    if isinstance(key, x25519.X25519PrivateKey):
                        out = key.exchange(
                            x25519.X25519PublicKey.from_public_bytes(value)
                        )
                    else:
                        require(isinstance(key, ec.EllipticCurvePrivateKey), 0x6A80)
                        out = key.exchange(
                            ec.ECDH(),
                            ec.EllipticCurvePublicKey.from_encoded_point(
                                key.curve, value
                            ),
                        )
            elif isinstance(key, rsa.RSAPrivateKey):
                size = key.key_size // 8
                require(len(a.data) <= size - 11, 0x6A80)
                out = raw_rsa(
                    key, b"\0\x01" + b"\xff" * (size - len(a.data) - 3) + b"\0" + a.data
                )
            elif isinstance(key, ed25519.Ed25519PrivateKey):
                out = key.sign(a.data)
            elif isinstance(key, ec.EllipticCurvePrivateKey):
                out = ec_digest_signature(key, a.data, raw=True)
            else:
                fail(0x6A80)
            if slot == 1:
                d["sig_counter"] += 1
                if d["objects"].get(str(0xC4), "00") == "00":
                    self.verified.discard(("openpgp", 0x81))
            return out
        if ins == 0xDB:
            require(("openpgp", 0x83) in self.verified)
            require((a.p1, a.p2) == (0x3F, 0xFF), 0x6A86)
            require(a.le is None, 0x6700)
            template = Tlv.unpack(0x4D, a.data)
            from .pgp_extensions import template as parse_template

            slot, rest = parse_template(template)
            if not rest:
                d["keys"].pop(str(slot), None)
                if slot == 0x81:
                    d["attestation_removed"] = True
                return
            attrs = bytes.fromhex(d["objects"][str(attributes_tag(slot))])
            key = import_key(slot, attrs, rest)
            d["keys"][str(slot)] = {"key": dump_key(key), "generated": False}
            if slot == 1:
                d["sig_counter"] = 0
            return
        if ins == 0xF2:
            require(("openpgp", 0x83) in self.verified and len(a.data) == 3, 0x6982)
            require(not d.get("kdf_hash_length"), 0x6985)
            require(all(1 <= v <= 15 for v in a.data), 0x6A80)
            for name, count in zip(("pin", "reset", "admin"), a.data):
                d[name + "_max"] = d[name + "_retries"] = count
            if not pin_bytes(d, "reset"):
                d["reset_retries"] = 0
            self.verified.clear()
            return
        if ins == 0xA5:
            require(a.p1 in (0, 1, 2, 3) and a.p2 == 4, 0x6A86)
            require(Tlv.unpack(0x5C, Tlv.unpack(0x60, a.data)) == b"\x7f\x21", 0x6A80)
            self.certificate_slot = 0x81 if a.p1 == 3 else 3 - a.p1
            return
        fail(0x6D00)

    def openpgp_data(self, oid):
        from .pgp_objects import READABLE_STORED_OBJECTS

        d = self.state.data["openpgp"]
        objs = d["objects"]
        if oid == 0x4F:
            return (
                bytes.fromhex("d276000124010304ffff")
                + bytes.fromhex(self.state.data["serial"])
                + b"\0\0"
            )
        if oid == 0xC4:
            return bytes.fromhex(objs.get("196", "00")) + bytes(
                [
                    127,
                    127,
                    127,
                    d["pin_retries"],
                    d["reset_retries"],
                    d["admin_retries"],
                ]
            )
        if oid == 0xC0:
            # The reference exposes this only inside Application Related Data.
            fail(0x6B00)
        if oid == 0x5F52:
            return OPENPGP_HISTORICAL_BYTES
        if oid == 0x7F66:
            return OPENPGP_EXTENDED_LENGTH_INFO
        if oid == 0x7F74:
            return OPENPGP_GENERAL_FEATURE_MANAGEMENT
        if oid == 0x7A:
            return Tlv(0x7A, Tlv(0x93, d["sig_counter"].to_bytes(3, "big")))
        if oid == 0x65:
            return Tlv(
                0x65,
                b"".join(
                    Tlv(t, bytes.fromhex(objs.get(str(t), "30" if t == 0x5F35 else "")))
                    for t in (0x5B, 0x5F2D, 0x5F35)
                ),
            )
        if oid == 0x6E:
            discretionary = Tlv(0xC0, OPENPGP_EXTENDED_CAPABILITIES)
            discretionary += b"".join(
                Tlv(t, bytes.fromhex(objs.get(str(t), "132a8648ce3d030107")))
                for t in (0xC1, 0xC2, 0xC3, 0xDA)
            )
            discretionary += Tlv(0xC4, self.openpgp_data(0xC4))
            discretionary += Tlv(
                0xC5,
                b"".join(
                    bytes.fromhex(objs.get(str(t), "00" * 20))
                    for t in (0xC7, 0xC8, 0xC9, 0xDB)
                ),
            )
            discretionary += Tlv(
                0xC6,
                b"".join(
                    bytes.fromhex(objs.get(str(t), "00" * 20))
                    for t in (0xCA, 0xCB, 0xCC, 0xDC)
                ),
            )
            discretionary += Tlv(
                0xCD,
                b"".join(
                    bytes.fromhex(objs.get(str(t), "00" * 4))
                    for t in (0xCE, 0xCF, 0xD0, 0xDD)
                ),
            )
            discretionary += Tlv(
                0xDE,
                b"".join(
                    bytes(
                        [
                            slot,
                            0
                            if str(slot) not in d["keys"]
                            else 1
                            if d["keys"][str(slot)]["generated"]
                            else 2,
                        ]
                    )
                    for slot in (1, 2, 3, 0x81)
                ),
            )
            discretionary += Tlv(0x7F66, OPENPGP_EXTENDED_LENGTH_INFO)
            discretionary += b"".join(
                Tlv(t, bytes.fromhex(objs.get(str(t), "0020")))
                for t in (0xD6, 0xD7, 0xD8, 0xD9)
            )
            return Tlv(
                0x6E,
                Tlv(0x4F, self.openpgp_data(0x4F))
                + Tlv(0x5F52, OPENPGP_HISTORICAL_BYTES)
                + Tlv(0x7F74, OPENPGP_GENERAL_FEATURE_MANAGEMENT)
                + Tlv(0x73, discretionary),
            )
        if oid == 0xF9:
            return bytes.fromhex(objs.get(str(oid), "810100"))
        if oid == 0xFA:
            from .pgp_algorithms import algorithm_information

            return algorithm_information()
        if oid in READABLE_STORED_OBJECTS and str(oid) in objs:
            return bytes.fromhex(objs[str(oid)])
        if oid == 0x5F35:
            return b"0"
        if oid in (0xD6, 0xD7, 0xD8, 0xD9):
            return b"\0\x20"
        if oid in (0xC7, 0xC8, 0xC9, 0xDB, 0xCA, 0xCB, 0xCC, 0xDC):
            return bytes(20)
        if oid in (0xCE, 0xCF, 0xD0, 0xDD):
            return bytes(4)
        if oid in (
            0x5B,
            0x5E,
            0x5F2D,
            0x5F35,
            0x5F50,
            0x7F21,
            0x101,
            0x102,
            0x103,
            0x104,
        ):
            return b""
        fail(0x6B00)

    def hsmauth(self, a):
        d = self.state.data["hsmauth"]
        ins = a.ins
        if ins == 8:
            pairs = Tlv.parse_list(a.data)
            require(
                len(pairs) == 2
                and all(t.tag == 0x7B and len(t.value) == 16 for t in pairs),
                0x6A80,
            )
            new_key = pairs[1].value
            v = {0x7B: pairs[0].value, 0x75: new_key}
        else:
            v = tlvs(a.data)

        def mgmt():
            require(d["mgmt_retries"] > 0, 0x6983)
            if not hmac.compare_digest(v.get(0x7B, b""), bytes.fromhex(d["mgmt"])):
                d["mgmt_retries"] -= 1
                fail(0x63C0 | d["mgmt_retries"])
            d["mgmt_retries"] = 8

        if ins == 7:
            return VERSION
        if ins == 9:
            return bytes([d["mgmt_retries"]])
        if ins == 6:
            require((a.p1, a.p2) == (0xDE, 0xAD), 0x6A86)
            require(not a.data, 0x6700)
            # A short trailing 00 is ambiguous with a no-data formatter tail.
            require(a.le is None or a.short_zero_tail, 0x6700)
            self.state.data["hsmauth"] = defaults(piv_attestation=False)["hsmauth"]
            return
        if ins == 5:
            return b"".join(
                Tlv(
                    0x72,
                    bytes([row["alg"], row["touch"]])
                    + bytes.fromhex(label)
                    + bytes([row["retries"]]),
                )
                for label, row in d["credentials"].items()
            )
        if ins in (1, 2, 8):
            mgmt()
        if ins == 8:
            key = v.get(0x75, v.get(0x7B, b""))
            require(len(key) == 16, 0x6A80)
            d["mgmt"] = key.hex()
            return
        label = v.get(0x71, b"")
        require(1 <= len(label) <= 64, 0x6A80)
        if ins == 1:
            # The YubiHSM Auth label is an encoded UTF-8 string. Reject bad
            # bytes before persisting a credential that SDK listing cannot read.
            try:
                label.decode("utf-8")
            except UnicodeDecodeError:
                fail(0x6A80)
        labelkey = label.hex()
        if ins == 1:
            require(labelkey not in d["credentials"], 0x6983)
            require(len(d["credentials"]) < 32, 0x6A84)
            require(len(v[0x74]) == 1, 0x6A80)
            alg = v[0x74][0]
            password = v[0x73]
            require(len(password) == 16, 0x6A80)
            require(alg in (38, 39), 0x6A80)
            touch_policy = v.get(0x7A, b"\0")
            require(len(touch_policy) == 1 and touch_policy[0] in (0, 1), 0x6A80)
            if alg == 38:
                require(len(v[0x75]) == 16 and len(v[0x76]) == 16, 0x6A80)
                key = (v[0x75] + v[0x76]).hex()
            else:
                require(len(v[0x7D]) in (0, 32), 0x6A80)
                private = (
                    ec.derive_private_key(
                        int.from_bytes(v[0x7D], "big"), ec.SECP256R1()
                    )
                    if v[0x7D]
                    else ec.generate_private_key(ec.SECP256R1())
                )
                key = dump_key(private)
            d["credentials"][labelkey] = {
                "alg": alg,
                "key": key,
                "password": password.hex(),
                "retries": 8,
                "touch": bool(touch_policy[0]),
            }
            return
        require(labelkey in d["credentials"], 0x6A82)
        row = d["credentials"][labelkey]
        if ins == 2:
            self.hsm_ephemeral.pop(labelkey, None)
            del d["credentials"][labelkey]
            return
        if ins == 10:
            require(row["alg"] == 39, 0x6A81)
            return (
                load_key(row["key"])
                .public_key()
                .public_bytes(
                    serialization.Encoding.X962,
                    serialization.PublicFormat.UncompressedPoint,
                )
            )
        if ins in (3, 4, 11):
            if ins != 4 or 0x73 in v or row["alg"] == 39:
                require(row["retries"] > 0, 0x6983)
                if not hmac.compare_digest(
                    v.get(0x73, b""), bytes.fromhex(row["password"])
                ):
                    row["retries"] -= 1
                    remaining = row["retries"]
                    if remaining == 0:
                        self.hsm_ephemeral.pop(labelkey, None)
                        del d["credentials"][labelkey]
                    fail(0x63C0 | remaining)
                row["retries"] = 8
            if row["touch"]:
                require(self.touch("YubiHSM Auth " + label.decode()), 0x6985)
            if ins == 4:
                if row["alg"] == 38:
                    return os.urandom(8)
                private = ec.generate_private_key(ec.SECP256R1())
                public = private.public_key().public_bytes(
                    serialization.Encoding.X962,
                    serialization.PublicFormat.UncompressedPoint,
                )
                self.hsm_ephemeral[labelkey] = (private, public, time.monotonic())
                return public
            if ins == 11:
                fail(0x6A81)  # not advertised by this profile
            if row["alg"] == 39:
                pending = self.hsm_ephemeral.pop(labelkey, None)
                require(
                    pending is not None and time.monotonic() - pending[2] < 30, 0x6985
                )
                context = v[0x77]
                require(
                    len(context) == 130
                    and hmac.compare_digest(context[:65], pending[1]),
                    0x6A80,
                )
                peer_static = ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256R1(), v[0x7C]
                )
                peer_ephemeral = ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256R1(), context[65:]
                )
                shared = pending[0].exchange(ec.ECDH(), peer_ephemeral) + load_key(
                    row["key"]
                ).exchange(ec.ECDH(), peer_static)
                material = X963KDF(hashes.SHA256(), 64, b"\x3c\x88\x10").derive(shared)
                require(
                    hmac.compare_digest(
                        v.get(0x78, b""),
                        aes_cmac(material[:16], context[65:] + context[:65]),
                    ),
                    0x6982,
                )
                return material[16:]
            context = v[0x77]
            require(len(context) == 16, 0x6A80)
            key = bytes.fromhex(row["key"])
            enc, mac = key[:16], key[16:]
            if 0x78 in v:
                require(
                    hmac.compare_digest(v[0x78], scp03_kdf(mac, 0, context, 64)), 0x6982
                )
            return (
                scp03_kdf(enc, 4, context)
                + scp03_kdf(mac, 6, context)
                + scp03_kdf(mac, 7, context)
            )
        fail(0x6D00)

    def oath_select(self):
        d = self.state.data["oath"]
        out = Tlv(0x79, VERSION) + Tlv(0x71, bytes.fromhex(d["salt"]))
        if d["access_key"]:
            self.oath_challenge = os.urandom(8)
            out += Tlv(0x74, self.oath_challenge) + Tlv(0x7B, b"\x01")
        else:
            self.oath_authenticated = True
        return out

    def oath(self, a):
        d = self.state.data["oath"]
        ins = a.ins
        require(ins in (1, 2, 3, 4, 5, 0xA1, 0xA2, 0xA3, 0xA4), 0x6D00)
        if ins == 4:
            require((a.p1, a.p2) == (0xDE, 0xAD), 0x6A86)
        else:
            require(
                a.p1 == 0 and a.p2 in ((0, 1) if ins in (0xA2, 0xA4) else (0,)), 0x6A86
            )
        # OATH property is a tag/value pair rather than a normal TLV.
        data = a.data
        touch = False
        increasing = False
        if ins == 1:
            parsed = []
            pos = 0
            property_seen = False
            while pos < len(data):
                if data[pos] == 0x78:
                    require(not property_seen, 0x6A80)
                    property_seen = True
                    require(pos + 2 <= len(data), 0x6A80)
                    require(not data[pos + 1] & ~3, 0x6A80)
                    touch = bool(data[pos + 1] & 2)
                    increasing = bool(data[pos + 1] & 1)
                    pos += 2
                else:
                    start = pos
                    pos += 1
                    if data[start] & 0x1F == 0x1F:
                        while True:
                            require(pos < len(data), 0x6A80)
                            part = data[pos]
                            pos += 1
                            if not part & 0x80:
                                break
                    require(pos < len(data), 0x6A80)
                    length = data[pos]
                    pos += 1
                    if length & 0x80:
                        width = length & 0x7F
                        require(1 <= width <= 2 and pos + width <= len(data), 0x6A80)
                        length = int.from_bytes(data[pos : pos + width], "big")
                        pos += width
                    require(pos + length <= len(data), 0x6A80)
                    pos += length
                    parsed.append(data[start:pos])
            v = tlvs(b"".join(parsed))
        elif ins == 5:
            pairs = Tlv.parse_list(data)
            require(
                len(pairs) == 2
                and all(t.tag == 0x71 and 1 <= len(t.value) <= 64 for t in pairs),
                0x6A80,
            )
            v = {0x71: pairs[0].value, 0x72: pairs[1].value}
        else:
            v = tlvs(data)
        required, optional = {
            1: ({0x71, 0x73}, {0x7A}),
            2: ({0x71}, set()),
            3: ({0x73}, {0x74, 0x75}),
            4: (set(), set()),
            5: ({0x71, 0x72}, set()),
            0xA1: (set(), set()),
            0xA2: ({0x71, 0x74}, set()),
            0xA3: ({0x74, 0x75}, set()),
            0xA4: ({0x74}, set()),
        }[ins]
        require(required <= v.keys() <= required | optional, 0x6A80)
        if 0x71 in v:
            require(1 <= len(v[0x71]) <= 64, 0x6A80)
        if ins == 4:
            self.state.data["oath"] = defaults(piv_attestation=False)["oath"]
            self.oath_authenticated = True
            return
        if ins == 0xA3:
            require(d["access_key"], 0x6984)
            require(len(v[0x75]) == 20, 0x6A80)
            require(self.oath_challenge is not None, 0x6985)
            key = bytes.fromhex(d["access_key"])
            require(
                hmac.compare_digest(
                    v[0x75], hmac.digest(key, self.oath_challenge, "sha1")
                )
            )
            self.oath_authenticated = True
            self.oath_challenge = None
            return Tlv(0x75, hmac.digest(key, v[0x74], "sha1"))
        require(self.oath_authenticated or not d["access_key"])
        if ins == 3:
            key = v[0x73]
            if not key:
                require(len(v) == 1, 0x6A80)
                d["access_key"] = ""
                return
            require(key[0] == 0x21 and len(key) == 17, 0x6A80)
            require(
                0x74 in v and 0x75 in v and len(v[0x74]) == 8 and len(v[0x75]) == 20,
                0x6A80,
            )
            require(
                hmac.compare_digest(v[0x75], hmac.digest(key[1:], v[0x74], "sha1")),
                0x6984,
            )
            d["access_key"] = key[1:].hex()
            return
        if ins == 0xA1:
            return b"".join(
                Tlv(0x72, bytes([r["type"] | r["hash"]]) + bytes.fromhex(name))
                for name, r in d["credentials"].items()
            )
        if ins == 1:
            name = v[0x71]
            key = v[0x73]
            # Yubico's PUT wire format requires at least 14 secret bytes;
            # host SDKs zero-pad shorter source secrets before sending.
            require(1 <= len(name) <= 64 and len(key) >= 2 + 14, 0x6A80)
            require(
                key[0] & 0xF0 in (0x10, 0x20)
                and key[0] & 15 in (1, 2, 3)
                and 6 <= key[1] <= 8,
                0x6A80,
            )
            if 0x7A in v:
                require(key[0] & 0xF0 == 0x10 and len(v[0x7A]) == 4, 0x6A80)
            require(
                name.hex() in d["credentials"] or len(d["credentials"]) < 64, 0x6A84
            )
            d["credentials"][name.hex()] = {
                "secret": key[2:].hex(),
                "type": key[0] & 0xF0,
                "hash": key[0] & 15,
                "digits": key[1],
                "counter": int.from_bytes(v.get(0x7A, b"\0" * 4), "big"),
                "touch": touch,
                "increasing": increasing,
            }
            return
        if ins == 2:
            require(v[0x71].hex() in d["credentials"], 0x6984)
            del d["credentials"][v[0x71].hex()]
            return
        if ins == 5:
            old = v[0x71].hex()
            new = v[0x72].hex()
            require(old in d["credentials"], 0x6984)
            require(new == old or new not in d["credentials"], 0x6985)
            d["credentials"][new] = d["credentials"].pop(old)
            return
        if ins in (0xA2, 0xA4):
            out = b""
            if ins == 0xA2:
                require(v[0x71].hex() in d["credentials"], 0x6984)
            items = (
                d["credentials"].items()
                if ins == 0xA4
                else [(v[0x71].hex(), d["credentials"][v[0x71].hex()])]
            )
            for name, row in items:
                if ins == 0xA4:
                    out += Tlv(0x71, bytes.fromhex(name))
                    if row["type"] == 0x10:
                        out += Tlv(0x77, bytes([row["digits"]]))
                        continue
                    if row["touch"]:
                        out += Tlv(0x7C, bytes([row["digits"]]))
                        continue
                elif row["touch"]:
                    label = bytes.fromhex(name).decode("utf-8", "backslashreplace")
                    label = "".join(
                        char if char.isprintable() else ascii(char)[1:-1]
                        for char in label
                    )
                    require(
                        self.touch("OATH " + label),
                        0x6985,
                    )
                if row["type"] == 0x10:
                    # A persisted next-counter sentinel may exceed the 8-byte
                    # HOTP moving-factor range after the last valid code.
                    require(0 <= row["counter"] < 1 << 64, 0x6581)
                challenge = (
                    row["counter"].to_bytes(8, "big")
                    if row["type"] == 0x10
                    else v[0x74]
                )
                if row.get("increasing"):
                    require(len(challenge) == 8, 0x6A80)
                    count = int.from_bytes(challenge, "big")
                    require(count > row.get("last_challenge", -1), 0x6985)
                    row["last_challenge"] = count
                digest = hmac.digest(
                    bytes.fromhex(row["secret"]),
                    challenge,
                    {1: "sha1", 2: "sha256", 3: "sha512"}[row["hash"]],
                )
                if row["type"] == 0x10:
                    row["counter"] += 1
                if a.p2 == 1:
                    offset = digest[-1] & 15
                    truncated = (
                        int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
                    )
                    out += Tlv(
                        0x76, bytes([row["digits"]]) + truncated.to_bytes(4, "big")
                    )
                else:
                    out += Tlv(0x75, bytes([row["digits"]]) + digest)
            return out
        fail(0x6D00)

    def otp_status(self):
        d = self.state.data["otp"]
        flags = 0
        for slot, row in d["slots"].items():
            config = bytes.fromhex(row["config"])
            n = int(slot)
            flags |= 1 << (n - 1)
            # Keyboard OTP slots are touch-triggered. Preserve the existing
            # challenge-response button-trigger status behavior.
            challenge_response = bool(config[46] & 0x40 and config[47] & 0x20)
            if not challenge_response or config[47] & 8:
                flags |= 1 << (n + 1)
            if config[45] & 0x80:
                flags |= 0x10
        return VERSION + bytes([d.get("sequence", 0)]) + struct.pack("<H", flags)

    def otp_ticket(self, slot, uid):
        row = self.state.data["otp"]["slots"][str(slot)]
        config = bytes.fromhex(row["config"])
        if slot not in self.otp_sessions:
            row["use_counter"] = min(row.get("use_counter", 0) + 1, 0x7FFF)
            self.otp_sessions[slot] = [
                0,
                time.monotonic(),
                int.from_bytes(os.urandom(3), "little"),
            ]
        session = self.otp_sessions[slot]
        if session[0] > 255:
            row["use_counter"] = min(row["use_counter"] + 1, 0x7FFF)
            session[0] = 0
        ticks = (session[2] + int((time.monotonic() - session[1]) * 8)) & 0xFFFFFF
        plain = (
            uid
            + struct.pack("<H", row["use_counter"])
            + ticks.to_bytes(3, "little")
            + bytes([session[0]])
            + os.urandom(2)
        )
        session[0] += 1
        plain += struct.pack("<H", (~crc16(plain)) & 0xFFFF)
        cipher = Cipher(algorithms.AES(config[22:38]), modes.ECB()).encryptor()
        return cipher.update(plain) + cipher.finalize()

    def otp_keypress(self, slot):
        """Produce software button output; an OS keyboard transport is separate."""
        previous = copy.deepcopy(self.state.data)
        previous_otp_sessions = copy.deepcopy(self.otp_sessions)
        try:
            return self._otp_keypress(slot)
        except (CardError, OSError):
            self.state.data = previous
            self.otp_sessions.clear()
            self.otp_sessions.update(previous_otp_sessions)
            raise

    def _otp_keypress(self, slot, update=False):
        d = self.state.data["otp"]
        from .keyboard import modhex, strong_password
        from .management import application_enabled

        require(application_enabled(self, AID.OTP), 0x6985)
        require(str(slot) in d["slots"], 0x6A88)
        require(self.touch("OTP slot " + str(slot)), 0x6985)
        row = d["slots"][str(slot)]
        c = bytes.fromhex(row["config"])
        require(not c[45] & 0x40, 0x6985)  # dormant slot
        if update:
            require(c[47] & 0xA0 == 0xA0 and not c[46] & 0x40, 0x6985)
            c = bytearray(c)
            c[22:38] = os.urandom(16)
            c[50:] = struct.pack("<H", (~crc16(c[:50])) & 0xFFFF)
            c = bytes(c)
            row["config"] = c.hex()
        if c[46] & 0x40:
            require(not c[47] & 0x20, 0x6985)  # challenge-response slots do not type
            count = row.get("hotp_counter", int.from_bytes(c[20:22], "big") << 4)
            require(count < 0xFFFFFFFFFFFFFFFF, 0x6985)
            digest = hmac.digest(c[22:38] + c[16:20], count.to_bytes(8, "big"), "sha1")
            offset = digest[-1] & 15
            digits = 8 if c[47] & 2 else 6
            code = str(
                (int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF)
                % 10**digits
            ).zfill(digits)
            row["hotp_counter"] = count + 1
            fixed = c[: c[44]]
            prefix = ""
            for index, byte in enumerate(fixed):
                use_modhex = (
                    (c[47] & 0x50) == 0x50
                    or index == 0
                    and c[47] & 0x10
                    or index < 2
                    and c[47] & 0x40
                )
                prefix += modhex(bytes([byte])) if use_modhex else f"{byte:02x}"
            out = {"text": prefix + code, "fixed_chars": len(prefix)}
        elif c[47] & 2 and not c[47] & 0x20:
            out = {"scan_codes": list(c[:38].split(b"\0", 1)[0])}
        elif c[47] & 0x20:
            plain = c[16:22] + bytes(8)
            plain += struct.pack("<H", (~crc16(plain)) & 0xFFFF)
            ctx = Cipher(algorithms.AES(c[22:38]), modes.ECB()).encryptor()
            ticket = ctx.update(plain) + ctx.finalize()
            if c[47] & 2:
                ticket = ticket[:8]
            fixed = modhex(c[: c[44]])
            out = {
                "text": fixed + strong_password(modhex(ticket), c[47]),
                "fixed_chars": len(fixed),
            }
        else:
            ticket = c[: c[44]] + self.otp_ticket(slot, c[16:22])
            reference = "cbdefghijklnrtuv" if c[47] & 1 else ""
            out = {
                "text": reference + modhex(ticket),
                "fixed_chars": len(reference) + 2 * c[44],
            }
        out["append_cr"] = bool(c[46] & 0x20)
        self.state.flush()
        return out

    def otp_keyboard_events(self, slot):
        from .keyboard import events

        require(self.state.otp_touch_owner is None, 0x6985)
        previous = copy.deepcopy(self.state.data)
        previous_otp_sessions = copy.deepcopy(self.otp_sessions)
        try:
            output = self.otp_keypress(slot)
            return events(
                output,
                bytes.fromhex(self.state.data["otp"]["slots"][str(slot)]["config"]),
                self.state.data["otp"].get("scan_map"),
            )
        except (CardError, OSError):
            self.state.data = previous
            self.otp_sessions.clear()
            self.otp_sessions.update(previous_otp_sessions)
            self.state.flush()
            raise

    def otp_button_press_events(self):
        """Begin an explicit software touch and return any immediate OTP output.

        A lone active slot 1 fast-triggers on contact. All other configurations
        defer selection to the release duration; the legacy hold API is separate.
        """
        from .management import application_enabled

        require(self.state.otp_touch_owner is None, 0x6985)
        require(application_enabled(self, AID.OTP), 0x6985)
        slots = self.state.data["otp"]["slots"]
        row = slots.get("1") if len(slots) == 1 else None
        if row is not None and self.otp_update_pending is None:
            config = bytes.fromhex(row["config"])
            manual_update = config[47] & 0xA0 == 0xA0 and not config[46] & 0x40
            challenge_response = bool(config[46] & 0x40 and config[47] & 0x20)
            if challenge_response:
                self.state.otp_touch_owner = self
                self.state.otp_touch_mode = "silent"
                return []
            if not config[45] & 0x40 and not manual_update:
                events = self.otp_keyboard_events(1)
                self.state.otp_touch_owner = self
                self.state.otp_touch_mode = "fast"
                return events
        self.state.otp_touch_owner = self
        self.state.otp_touch_mode = "deferred"
        return []

    def otp_button_release_events(self, duration_ms):
        """End an explicit software touch without duplicating fast output."""
        require(type(duration_ms) is int and 0 <= duration_ms <= 60000, 0x6A80)
        require(self.state.otp_touch_owner is self, 0x6985)
        mode = self.state.otp_touch_mode
        self.state.otp_touch_owner = None
        self.state.otp_touch_mode = None
        return [] if mode in ("fast", "silent") else self.otp_button_events(duration_ms)

    def otp_button_events(self, duration_ms):
        """Model documented hold/release windows; no physical sensor or OS input.

        A long hold arms a static-ticket change. A later short press confirms it.
        When both slots request manual updates, firmware selection is unspecified;
        reject that ambiguous configuration rather than change the wrong password.
        """
        from .keyboard import events
        from .management import application_enabled

        require(type(duration_ms) is int and 0 <= duration_ms <= 60000, 0x6A80)
        require(self.state.otp_touch_owner is None, 0x6985)
        require(application_enabled(self, AID.OTP), 0x6985)
        d = self.state.data["otp"]
        slots = {
            int(n): bytes.fromhex(row["config"])
            for n, row in d["slots"].items()
            if not bytes.fromhex(row["config"])[45] & 0x40
        }
        previous = copy.deepcopy(self.state.data)
        previous_otp_sessions = copy.deepcopy(self.otp_sessions)
        try:
            if 8000 <= duration_ms <= 15000:
                self.otp_update_pending = None
                candidates = [
                    n
                    for n, c in slots.items()
                    if c[47] & 0xA0 == 0xA0 and not c[46] & 0x40
                ]
                require(len(candidates) == 1, 0x6985)
                require(self.touch("OTP arm static password update"), 0x6985)
                slot = candidates[0]
                self.otp_update_pending = (slot, slots[slot])
                return []
            if self.otp_update_pending:
                slot, config = self.otp_update_pending
                self.otp_update_pending = None
                require(
                    300 <= duration_ms <= 1500 and slots.get(slot) == config, 0x6985
                )
                output = self._otp_keypress(slot, update=True)
            else:
                # With both slots present, use the documented short and long
                # release windows. Firmware 3+ fast-triggers a lone slot 1 at
                # contact, so a later release in the gap/slot-2 window still
                # produces that slot-1 output within the modeled hold range.
                short_start = 300 if len(d["slots"]) == 1 else 1000
                slot = (
                    1
                    if (
                        1 in slots
                        and len(d["slots"]) == 1
                        and 300 <= duration_ms <= 5000
                    )
                    or short_start <= duration_ms <= 2500
                    else 2
                    if 3000 <= duration_ms <= 5000
                    else 0
                )
                require(slot in slots, 0x6985)
                output = self.otp_keypress(slot)
            return events(
                output,
                bytes.fromhex(d["slots"][str(slot)]["config"]),
                d.get("scan_map"),
            )
        except (CardError, OSError):
            self.state.data = previous
            self.otp_sessions.clear()
            self.otp_sessions.update(previous_otp_sessions)
            self.state.flush()
            raise

    def otp_slot2_writable(self):
        slots = self.state.data["otp"]["slots"]
        first = bytes.fromhex(slots["1"]["config"]) if "1" in slots else bytes(52)
        second = bytes.fromhex(slots["2"]["config"]) if "2" in slots else bytes(52)
        require(not first[46] & 0x80 or second[46] & 0x80, 0x6985)

    def otp(self, a):
        d = self.state.data["otp"]
        slots = d["slots"]
        if a.ins == 3:
            return self.otp_status()
        require(a.ins == 1, 0x6D00)
        require(a.p2 == 0, 0x6A86)
        if a.p1 == 0x10:
            require(
                any(bytes.fromhex(row["config"])[45] & 4 for row in slots.values()),
                0x6985,
            )
            return bytes.fromhex(self.state.data["serial"])
        if a.p1 == 0x13:
            from .management import read_config

            require(len(a.data) in (0, 1), 0x6A80)
            return read_config(self, a.data[0] if a.data else 0)
        if a.p1 == 0x15:
            from .management import write_config

            write_config(self, a.data)
            return
        if a.p1 in (0x30, 0x38, 0x20, 0x28):
            slot = 1 if a.p1 in (0x30, 0x20) else 2
            require(str(slot) in slots, 0x6985)
            c = bytes.fromhex(slots[str(slot)]["config"])
            require(c[46] & 0x40 and c[47] & 0x20, 0x6985)
            require(not c[45] & 0x40, 0x6985)
            if c[47] & 8:
                require(self.touch("OTP challenge slot " + str(slot)), 0x6985)
            if a.p1 in (0x30, 0x38):
                require(
                    c[47] & 2
                    and len(a.data) <= 64
                    and (c[47] & 4 or len(a.data) == 64),
                    0x6A80,
                )
                # A full-size LT64 frame uses its final byte as the pad marker.
                # Short APDUs carry their explicit length, so trailing data
                # bytes are preserved. An empty challenge is represented by 00.
                if c[47] & 4:
                    challenge = (
                        a.data.rstrip(a.data[-1:])
                        if len(a.data) == 64
                        else a.data
                    ) or b"\0"
                else:
                    challenge = a.data
                return hmac.digest(c[22:38] + c[16:20], challenge, "sha1")
            require(not c[47] & 2 and len(a.data) == 6, 0x6A80)
            return self.otp_ticket(
                slot, bytes(x ^ y for x, y in zip(a.data, c[16:22], strict=True))
            )
        if a.p1 == 6:
            self.otp_slot2_writable()
            require(
                all(
                    bytes.fromhex(r["config"])[38:44] == bytes(6)
                    for r in slots.values()
                ),
                0x6982,
            )
            slots_copy = copy.deepcopy(slots)
            slots.clear()
            for n, row in slots_copy.items():
                slots[str(3 - int(n))] = row
            self.otp_sessions.clear()
        elif a.p1 in (1, 3, 4, 5):
            require(len(a.data) == 58, 0x6700)
            slot = 1 if a.p1 in (1, 4) else 2
            if slot == 2:
                self.otp_slot2_writable()
            n = str(slot)
            config = a.data[:52]
            current = slots.get(n)
            if current:
                old = bytes.fromhex(current["config"])
                access = old[38:44]
                require(
                    access == bytes(6) or hmac.compare_digest(access, a.data[52:]),
                    0x6982,
                )
            if config == bytes(52):
                require(a.p1 in (1, 3), 0x6A80)
                slots.pop(n, None)
            else:
                require(
                    crc16(config) == 0xF0B8
                    and config[44] <= 16
                    and config[48:50] == bytes(2),
                    0x6A80,
                )
                if a.p1 in (4, 5):
                    require(current is not None and old[45] & 0x20, 0x6985)
                    require(not config[45] & 0x40 or old[45] & 0x40, 0x6985)
                    require(
                        config[:38] == bytes(38)
                        and not config[46] & ~0x3F
                        and not config[47] & ~0x0C,
                        0x6A80,
                    )
                    merged = bytearray(old)
                    merged[38:44] = config[38:44]
                    merged[45] = config[45]
                    merged[46] = (old[46] & ~0x3F) | config[46]
                    merged[47] = (old[47] & ~0x0C) | config[47]
                    merged[50:] = struct.pack("<H", (~crc16(merged[:50])) & 0xFFFF)
                    current["config"] = merged.hex()
                else:
                    slots[n] = {"config": config.hex(), "use_counter": 0}
            self.otp_sessions.pop(slot, None)
        elif a.p1 in (8, 9):
            require(len(a.data) == 62 and a.data[0] <= 54, 0x6700)
            n = "1" if a.p1 == 8 else "2"
            if n == "2":
                self.otp_slot2_writable()
            require(n in slots, 0x6985)
            access = bytes.fromhex(slots[n]["config"])[38:44]
            require(
                access == bytes(6) or hmac.compare_digest(access, a.data[56:]), 0x6982
            )
            slots[n]["ndef"] = a.data[:56].hex()
        elif a.p1 == 0x12:
            require(len(a.data) == 51, 0x6700)
            require(
                all(
                    bytes.fromhex(r["config"])[38:44] == bytes(6)
                    or hmac.compare_digest(
                        bytes.fromhex(r["config"])[38:44], a.data[45:]
                    )
                    for r in slots.values()
                ),
                0x6982,
            )
            require(all(code & 0x7F <= 101 for code in a.data[:45]), 0x6A80)
            d["scan_map"] = a.data[:45].hex()
        else:
            fail(0x6D00)
        d["sequence"] = (d.get("sequence", 0) + 1) & 255
        if not slots:
            d["sequence"] = 0
        return self.otp_status()


class EmulatorConnection(SmartCardConnection):
    """SDK adapter carrying serialized ISO 7816 commands to the same APDU core."""

    def __init__(self, card):
        self.card = card

    @property
    def transport(self):
        return TRANSPORT.USB

    def send_and_receive(self, apdu):
        return self.card.transmit(apdu)

    def close(self):
        self.card.reset_session()


class CcidDevice:
    """One-slot CCID bulk protocol engine, suitable for a separate device transport."""

    def __init__(self, card, cancel_event=None):
        self.card = card
        self.powered = False
        self.parameters = bytes.fromhex("1110004d002000")
        self.clock_status = 3
        self.abort_sequence = None
        self.cancel_event = threading.Event() if cancel_event is None else cancel_event
        self.command_parts = bytearray()
        self.response_parts = b""
        self.card.cancelled = self.cancel_event.is_set
        self.lock = threading.RLock()
        self.abort_condition = threading.Condition(self.lock)
        self.card.commit_guard = lambda: self.lock
        self.card.did_commit = self._committed
        self.committed = False
        self.busy = False

    def _committed(self):
        self.committed = True

    def reset_transfer(self):
        self.command_parts.clear()
        self.response_parts = b""

    @staticmethod
    def response_type(command):
        if command in (0x62, 0x6F, 0x69):
            return 0x80
        if command in (0x61, 0x6C, 0x6D):
            return 0x82
        if command == 0x6B:
            return 0x83
        if command == 0x73:
            return 0x84
        return 0x81

    def abort(self, slot, sequence):
        """Control-pipe phase. The sequence identifies the matching bulk ABORT."""
        if slot != 0 or not 0 <= sequence <= 255:
            return False
        with self.lock:
            self.abort_sequence = sequence
            if not self.busy or not self.committed:
                self.cancel_event.set()
            self.abort_condition.notify_all()
        return True

    def _reply(self, kind, slot, sequence, error=None, data=b"", tail=0):
        status = (2 if slot else 0 if self.powered else 1) | (
            0x40 if error is not None else 0
        )
        response = self.response_type(kind)
        if response == 0x81:
            tail = self.clock_status
        elif response == 0x82:
            tail = 1
            if not slot and self.powered and not data:
                data = self.parameters
        return (
            struct.pack(
                "<BIBBBBB",
                response,
                len(data),
                slot,
                sequence,
                status,
                0 if error is None else error,
                tail,
            )
            + data
        )

    @staticmethod
    def parameter_error(data):
        # The software T=1 ATR uses FI/DI 1/1 and direct convention/LRC.
        # Non-electrical timing/IFSC values are modeled within their CCID ranges.
        if data[0] != 0x11:
            return 10
        if data[1] not in (0x10, 0x12):
            return 11
        if data[3] > 0x9F:
            return 13
        if data[4] > 3:
            return 14
        if data[5] > 254:
            return 15
        if data[6] != 0:
            return 16
        return None

    def exchange(self, packet):
        require(len(packet) >= 10, 0x6700)
        kind, length, slot, seq, p1, p2, p3 = struct.unpack("<BIBBBBB", packet[:10])
        data = packet[10:]
        if slot:
            return self._reply(kind, slot, seq, 5)
        if length != len(data) or length > CCID_PAYLOAD_LENGTH:
            with self.lock:
                if not self.busy:
                    self.reset_transfer()
            return self._reply(kind, slot, seq, 1)
        with self.lock:
            if self.abort_sequence is not None and kind != 0x72:
                return self._reply(kind, slot, seq, 0xFF)
            if self.busy:
                return self._reply(kind, slot, seq, 0xE0)
            self.busy = True
            self.committed = False
        try:
            no_data = kind in (0x62, 0x63, 0x65, 0x6C, 0x6D, 0x6E, 0x6A, 0x71, 0x72)
            if no_data and length:
                return self._reply(kind, slot, seq, 1)
            # Validate command-specific header fields in offset order.
            if kind in (0x63, 0x65, 0x6C, 0x6D, 0x72, 0x73, 0x6B):
                for offset, value in ((7, p1), (8, p2), (9, p3)):
                    if value:
                        return self._reply(kind, slot, seq, offset)
            elif kind in (0x62, 0x61, 0x6E, 0x71):
                for offset, value in ((8, p2), (9, p3)):
                    if value:
                        return self._reply(kind, slot, seq, offset)
            elif kind == 0x6F and (p3 or p2 not in (0, 1, 2, 3, 0x10)):
                self.reset_transfer()
                return self._reply(kind, slot, seq, 8)
            if kind == 0x62:
                if p1 > 3:
                    return self._reply(kind, slot, seq, 7)
                self.card.reset_session()
                self.reset_transfer()
                self.parameters = bytes.fromhex("1110004d002000")
                self.clock_status, self.powered = 0, True
                return self._reply(kind, slot, seq, data=ATR)
            if kind == 0x63:
                self.card.reset_session()
                self.reset_transfer()
                self.clock_status, self.powered = 3, False
                return self._reply(kind, slot, seq)
            if kind == 0x65:
                return self._reply(kind, slot, seq)
            if kind == 0x72:
                with self.abort_condition:
                    # Control and bulk pipes can be delivered in either order.
                    # The private transport is bounded; an incomplete pair does
                    # not keep its worker alive indefinitely.
                    self.abort_condition.wait_for(
                        lambda: self.abort_sequence is not None, timeout=25
                    )
                    if self.abort_sequence != seq:
                        # CCID 1.1 names CMD_NOT_ABORTED without assigning its
                        # number. Preserve the pending barrier using CMD_ABORTED.
                        return self._reply(kind, slot, seq, 0xFF)
                    self.abort_sequence = None
                    self.cancel_event.clear()
                    self.reset_transfer()
                return self._reply(kind, slot, seq)
            if kind in (0x61, 0x6C, 0x6D):
                if not self.powered:
                    return self._reply(kind, slot, seq, 0xFE)
                if kind == 0x61:
                    if p1 != 1:
                        return self._reply(kind, slot, seq, 7)
                    if length != 7:
                        return self._reply(kind, slot, seq, 1)
                    error = self.parameter_error(data)
                    if error is not None:
                        return self._reply(kind, slot, seq, error)
                    data = bytes([data[0], data[1] & ~2]) + data[2:]
                    self.parameters = data
                elif kind == 0x6D:
                    self.parameters = bytes.fromhex("1110004d002000")
                return self._reply(kind, slot, seq, data=self.parameters, tail=1)
            if kind == 0x6E:
                if p1 > 1:
                    return self._reply(kind, slot, seq, 7)
                if not self.powered:
                    return self._reply(kind, slot, seq, 0xFE)
                if p1 and self.parameters[4] == 0:
                    return self._reply(kind, slot, seq, 7)
                self.clock_status = (
                    (1 if self.parameters[4] == 3 else self.parameters[4]) if p1 else 0
                )
                return self._reply(kind, slot, seq)
            if kind == 0x73:
                if length != 8:
                    return self._reply(kind, slot, seq, 1)
                if not self.powered:
                    return self._reply(kind, slot, seq, 0xFE)
                frequency, rate = struct.unpack("<II", data)
                if frequency != CCID_CLOCK_KHZ:
                    return self._reply(kind, slot, seq, 10)
                if rate != CCID_DATA_RATE:
                    return self._reply(kind, slot, seq, 14)
                return self._reply(
                    kind,
                    slot,
                    seq,
                    data=struct.pack("<II", CCID_CLOCK_KHZ, CCID_DATA_RATE),
                )
            if kind == 0x6F:
                if not self.powered or self.clock_status:
                    return self._reply(kind, slot, seq, 0xFE)
                if p2 == 0x10:
                    if data or self.command_parts or not self.response_parts:
                        self.reset_transfer()
                        return self._reply(kind, slot, seq, 8 if not data else 1)
                    out = self.response_parts[:CCID_PAYLOAD_LENGTH]
                    self.response_parts = self.response_parts[len(out) :]
                    return self._reply(
                        kind, slot, seq, data=out, tail=3 if self.response_parts else 2
                    )
                if self.response_parts:
                    self.reset_transfer()
                    return self._reply(kind, slot, seq, 8)
                if p2 in (1, 3):
                    if (
                        not data
                        or (p2 == 1 and self.command_parts)
                        or (p2 == 3 and not self.command_parts)
                    ):
                        self.reset_transfer()
                        return self._reply(kind, slot, seq, 8 if data else 1)
                    if len(self.command_parts) + length > MAX_COMMAND_APDU_LENGTH:
                        self.reset_transfer()
                        return self._reply(kind, slot, seq, 1)
                    self.command_parts.extend(data)
                    return self._reply(kind, slot, seq, tail=0x10)
                if p2 == 2:
                    if not self.command_parts:
                        return self._reply(kind, slot, seq, 8)
                    if len(self.command_parts) + length > MAX_COMMAND_APDU_LENGTH:
                        self.reset_transfer()
                        return self._reply(kind, slot, seq, 1)
                    data = bytes(self.command_parts) + data
                    self.command_parts.clear()
                elif self.command_parts:
                    self.reset_transfer()
                    return self._reply(kind, slot, seq, 8)
                payload, sw = self.card.transmit(data)
                if self.cancel_event.is_set():
                    self.card.reset_session()
                    self.reset_transfer()
                    return self._reply(kind, slot, seq, 0xFF)
                payload += struct.pack(">H", sw)
                out = payload[:CCID_PAYLOAD_LENGTH]
                self.response_parts = payload[len(out) :]
                return self._reply(
                    kind, slot, seq, data=out, tail=1 if self.response_parts else 0
                )
            # T=0, PIN-pad, mechanics and vendor Escape are not advertised.
            return self._reply(kind, slot, seq, 0)
        finally:
            with self.lock:
                self.busy = False
