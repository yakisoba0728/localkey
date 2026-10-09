"""GlobalPlatform Security Domain APDUs for fresh, software-owned SCP keys.

Wire formats follow GlobalPlatform SCP03/SCP11 and Yubico's public SDK.
The development certificate has no Yubico manufacturer trust.
"""

import datetime
import hmac
import os
import time

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from yubikit.core import Tlv

from .core import CardError, dump_key, fail, load_key, require, tlvs
from .secure_channel import DEVELOPMENT_KEY, ChannelError, SecureChannel

PRIVATE_KIDS = (0x11, 0x13, 0x15)
PUBLIC_KIDS = (0x10, *range(0x20, 0x30))
# The retry/budget ceilings are a software model, not physical measurements.
AUTHENTICATION_TRIES = 64
SCP11_ROLE_PREFIX = "2.840.114283.100.0.1.2.1"
ROLE_OCE = x509.ObjectIdentifier(SCP11_ROLE_PREFIX + ".0")
ROLE_SD = x509.ObjectIdentifier(SCP11_ROLE_PREFIX + ".10")
ROLE_KLOC_CA = x509.ObjectIdentifier(SCP11_ROLE_PREFIX + ".20")
ROLE_KLOC_KA = x509.ObjectIdentifier(SCP11_ROLE_PREFIX + ".40")
AUTHORIZATION_RULES_OID = x509.ObjectIdentifier("2.840.114283.100.0.1.2.0.1")

# Firmware-5.7.4 public SELECT/GET DATA bytes, observed with no authentication.
# SCP03 i=0x60; SCP11 i=0x9b06 advertises a/b/c, transient OCE keys, chains,
# S8, X.509 and no legacy certificates. Neither a nor c advertises BF20 rules.
SELECT_RESPONSE = bytes.fromhex("6f178408a000000151000000a50b730906072a864886fc6b01")
CARD_RECOGNITION_DATA = bytes.fromhex(
    "733d06072a864886fc6b01600c060a2a864886fc6b02020301"
    "630906072a864886fc6b03640b06092a864886fc6b040360"
    "640c060a2a864886fc6b04119b06"
)


def cplc():
    # 42-byte profile with an independent per-domain identifier. 0000 labels a
    # software platform; never claim the reference's 4090 Infineon chip identity.
    return (b"\0\0" + os.urandom(40)).hex()


def public_bytes(key):
    return key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def identity():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [
            x509.NameAttribute(
                x509.NameOID.COMMON_NAME,
                "Local software emulator SCP11 development identity",
            )
        ]
    )
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False
        )
        .add_extension(
            x509.KeyUsage(False, False, False, False, True, False, False, False, False),
            True,
        )
        .add_extension(
            x509.CertificatePolicies([x509.PolicyInformation(ROLE_SD, None)]), True
        )
        .sign(key, hashes.SHA256())
    )
    return {
        "private": dump_key(key),
        "certificates": cert.public_bytes(serialization.Encoding.DER).hex(),
        "retries": AUTHENTICATION_TRIES,
    }


def fresh_domain(legacy=None):
    legacy = legacy or {}
    return {
        "cplc": cplc(),
        "oce_policy_generation": os.urandom(16).hex(),
        "keys": {
            "01ff": {
                "enc": legacy.get("enc", DEVELOPMENT_KEY.hex()),
                "mac": legacy.get("mac", DEVELOPMENT_KEY.hex()),
                "dek": legacy.get("dek", DEVELOPMENT_KEY.hex()),
                "retries": AUTHENTICATION_TRIES,
            },
            "1301": identity(),
        },
    }


def state(card):
    if "domain" not in card.state.data:
        card.state.data["domain"] = fresh_domain(card.state.data.get("scp03"))
    domain = card.state.data["domain"]
    if "cplc" not in domain:
        # Add only absent metadata: never recreate stored keys/certificates.
        domain["cplc"] = cplc()
    if "oce_policy_generation" not in domain:
        # Persistent bookkeeping shares policy commit/rollback. A rejected or
        # failed mutation must not revoke another connection's validated OCE.
        domain["oce_policy_generation"] = os.urandom(16).hex()
    return domain


def get_row(card, kid, kvn):
    keys = state(card)["keys"]
    candidates = [
        (ref, row)
        for ref, row in keys.items()
        if int(ref[:2], 16) == kid and (not kvn or bytes.fromhex(ref)[1] == kvn)
    ]
    require(candidates, 0x6A88)
    if not kvn:
        usable = [item for item in candidates if item[1]["retries"] > 0]
        if usable:
            candidates = usable
    return max(candidates, key=lambda v: bytes.fromhex(v[0])[1])


def attempt(card, ref, row):
    if row["retries"] <= 0:
        if all(r["retries"] <= 0 for r in state(card)["keys"].values()):
            card.state.data["domain"] = fresh_domain()
            card.close_wrapping_channel = True
        raise CardError(0x6983, durable=True)
    row["retries"] -= 1
    # INIT UPDATE consumes a try until EXTERNAL AUTHENTICATE succeeds. This also
    # permits the documented Security Domain reset through blocking every key.
    # Reserve this attempt, including the last available one. A completed valid
    # handshake replenishes retries. A further attempt with zero retries blocks.


def trusted_host(card, requested, certificates, *, final=True):
    require(1 <= len(certificates) <= 8, 0x6982)
    kid, kvn = requested
    choices = [
        (ref, row)
        for ref, row in state(card)["keys"].items()
        if int(ref[:2], 16) in PUBLIC_KIDS
        and (not kid or int(ref[:2], 16) == kid)
        and (not kvn or bytes.fromhex(ref)[1] == kvn)
        and row["retries"] > 0
    ]
    require(choices, 0x6982)
    now = datetime.datetime.now(datetime.UTC)
    for cert in certificates:
        require(cert.not_valid_before_utc <= now <= cert.not_valid_after_utc, 0x6982)
        require(isinstance(cert.public_key(), ec.EllipticCurvePublicKey), 0x6982)
        require(cert.public_key().curve.name == "secp256r1", 0x6982)
        for extension in cert.extensions:
            # Unknown critical constraints must not silently grant authorization.
            require(
                not extension.critical
                or extension.oid
                in (
                    x509.ExtensionOID.BASIC_CONSTRAINTS,
                    x509.ExtensionOID.KEY_USAGE,
                    x509.ExtensionOID.CERTIFICATE_POLICIES,
                ),
                0x6982,
            )
    for ref, row in choices:
        parent = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), bytes.fromhex(row["public"])
        )
        accepted = True
        for index, cert in enumerate(certificates):
            try:
                try:
                    policies = cert.extensions.get_extension_for_class(
                        x509.CertificatePolicies
                    ).value
                    role = (
                        ROLE_OCE
                        if final and index == len(certificates) - 1
                        else ROLE_KLOC_CA
                        if index == 0
                        and public_bytes(cert.public_key()) == public_bytes(parent)
                        else ROLE_KLOC_KA
                    )
                    # GP role policies are meaningful authorization constraints,
                    # not an OID allowlist. Unsupported qualifiers remain denied.
                    if (
                        len(policies) != 1
                        or policies[0].policy_identifier != role
                        or policies[0].policy_qualifiers
                    ):
                        raise ValueError("SCP11 certificate role policy")
                except x509.ExtensionNotFound:
                    pass  # Preserve existing policy-free software identities.
                # A presented root is optional; when included its public key must
                # equal the provisioned anchor, then its signature is checked too.
                if index == 0 and row.get("ski"):
                    ski = bytes.fromhex(row["ski"])
                    akid = cert.extensions.get_extension_for_class(
                        x509.AuthorityKeyIdentifier
                    ).value.key_identifier
                    if akid != ski:
                        raise ValueError("issuer identifier mismatch")
                parent.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    ec.ECDSA(cert.signature_hash_algorithm),
                )
                if index:
                    cert.verify_directly_issued_by(certificates[index - 1])
                    try:
                        akid = cert.extensions.get_extension_for_class(
                            x509.AuthorityKeyIdentifier
                        ).value.key_identifier
                        ski = (
                            certificates[index - 1]
                            .extensions.get_extension_for_class(
                                x509.SubjectKeyIdentifier
                            )
                            .value.digest
                        )
                        if akid is not None and akid != ski:
                            raise ValueError("intermediate issuer identifier mismatch")
                    except x509.ExtensionNotFound:
                        pass
                if not final or index < len(certificates) - 1:
                    constraints = cert.extensions.get_extension_for_class(
                        x509.BasicConstraints
                    ).value
                    if not constraints.ca or (
                        constraints.path_length is not None
                        and len(certificates) - index - (2 if final else 1)
                        > constraints.path_length
                    ):
                        raise ValueError("CA constraint")
                    try:
                        if not cert.extensions.get_extension_for_class(
                            x509.KeyUsage
                        ).value.key_cert_sign:
                            raise ValueError("CA key usage")
                    except x509.ExtensionNotFound:
                        pass
                parent = cert.public_key()
            except (InvalidSignature, ValueError, TypeError, x509.ExtensionNotFound):
                accepted = False
                break
        if accepted:
            # Yubico's allowlist applies to every presented certificate in the
            # authentication chain. A wildcard must find one eligible anchor
            # whose policy accepts the whole prefix; policies cannot be united.
            if "allowlist" in row and any(
                cert.serial_number not in row["allowlist"] for cert in certificates
            ):
                continue
            if not final:
                # A verified intermediate is not an authorized OCE. Defer leaf
                # ECKA checks and keep wildcard candidates available.
                return ref, None
            leaf = certificates[-1]
            try:
                require(
                    not leaf.extensions.get_extension_for_class(
                        x509.BasicConstraints
                    ).value.ca,
                    0x6982,
                )
            except x509.ExtensionNotFound:
                pass
            try:
                require(
                    leaf.extensions.get_extension_for_class(
                        x509.KeyUsage
                    ).value.key_agreement
                    and not leaf.extensions.get_extension_for_class(
                        x509.KeyUsage
                    ).value.key_cert_sign,
                    0x6982,
                )
            except x509.ExtensionNotFound:
                pass
            return ref, leaf.public_key()
    fail(0x6982)


def handshake(card, apdu):
    require(card.selected is not None, 0x6999)
    if apdu.ins == 0x50:
        require(apdu.p2 == 0 and len(apdu.data) == 8, 0x6A86)
        # SCP03 INITIALIZE UPDATE specifies Le=00. The public SDK omits Le
        # for this data-bearing APDU; reject other response limits before an
        # authentication attempt is reserved or the current session is reset.
        require(apdu.le in (None, 256, 65536), 0x6700)
        card.reset_for_channel()
        ref, row = get_row(card, 1, apdu.p1)
        attempt(card, ref, row)
        channel = SecureChannel(
            apdu.data,
            bytes.fromhex(ref)[1],
            bytes.fromhex(row["enc"]),
            bytes.fromhex(row["mac"]),
            bytes.fromhex(row["dek"]),
        )
        channel.key_ref = ref
        channel.domain_id = state(card)["cplc"]
        card.secure_channel = channel
        return channel.initialization(bytes.fromhex(card.state.data["serial"]))
    if apdu.ins == 0x2A:
        # PERFORM SECURITY OPERATION uploads the OCE certificate chain.
        ref = bytes([apdu.p2 & 0x7F, apdu.p1])
        if not card.oce_chain:
            # PSO replaces the OCE cache, without ending ongoing secure
            # messaging or application PIN verification (GP SCP11 7.5.1).
            card.reset_oce_cache()
            card.oce_ref = ref
            card.oce_created = time.monotonic()
            card.oce_policy_generation = state(card)["oce_policy_generation"]
        require(
            len(card.oce_chain) < 8
            and card.oce_policy_generation == state(card)["oce_policy_generation"],
            0x6985,
        )
        # The initial PSO chooses the CA. Later P1/P2 references are ignored;
        # only P2's continuation bit controls certificate-chain completion.
        ref = card.oce_ref
        try:
            cert = x509.load_der_x509_certificate(apdu.data)
            extensions = cert.extensions
        except (ValueError, x509.DuplicateExtension):
            if ref[0] in PUBLIC_KIDS:
                name, row = get_row(card, ref[0], ref[1])
                attempt(card, name, row)
                raise CardError(0x6A80, durable=True)
            fail(0x6A80)
        require(
            all(e.oid != AUTHORIZATION_RULES_OID for e in extensions),
            0x6A81,
        )
        proposed = card.oce_chain + [cert]
        final = not apdu.p2 & 0x80
        trusted_ref, public = trusted_host(card, ref, proposed, final=final)
        card.oce_chain = proposed
        if final:
            card.oce_trusted_ref, card.oce_public = trusted_ref, public
            # The validated OCE key remains cached, but the completed chain is
            # not the prefix of a subsequent PSO certificate upload.
            card.oce_chain = []
        return b""
    kid = apdu.p2
    require(kid in PRIVATE_KIDS and apdu.ins == (0x88 if kid == 0x13 else 0x82), 0x6A86)
    ref, row = get_row(card, kid, apdu.p1)
    attempt(card, ref, row)
    try:
        request = Tlv.parse_list(apdu.data)
        require(
            len(request) == 2 and request[0].tag == 0xA6 and request[1].tag == 0x5F49,
            0x6A80,
        )
        host = None
        if kid != 0x13:
            require(
                card.oce_public is not None
                and time.monotonic() - card.oce_created < 30
                and card.oce_policy_generation == state(card)["oce_policy_generation"],
                0x6985,
            )
            host = card.oce_public
        channel, response = SecureChannel.scp11(
            apdu.data, kid, load_key(row["private"]), host
        )
    except (ValueError, CardError, ChannelError) as e:
        raise CardError(getattr(e, "sw", 0x6A80), durable=True) from e
    row["retries"] = AUTHENTICATION_TRIES
    card.reset_for_channel()
    channel.key_ref = ref
    channel.domain_id = state(card)["cplc"]
    if kid == 0x15:
        # Only one c context per SD. A successful new context supersedes the
        # previous one across connections. Token+handshake commit atomically;
        # failure rolls back the token and preserves the other peer's context.
        channel.session_generation = os.urandom(16).hex()
        state(card)["scp11c_session_generation"] = channel.session_generation
    card.secure_channel = channel
    return response


def insert(keys, ref, row, replace=0):
    kid, kvn = bytes.fromhex(ref)
    # Yubico reserves SCP03 255 for the factory set, allowing custom 1..254.
    # SCP11 uses a seven-bit version in GP MUTUAL AUTHENTICATE P1.
    require(1 <= kvn <= (0xFE if kid == 1 else 0x7F), 0x6A80)
    old = bytes([kid, replace]).hex()
    if replace:
        require(old in keys, 0x6A88)
        require(ref == old or ref not in keys, 0x6985)
        # GP SCP11 7.9 retains the allowlist across CA-key replacement. Other
        # key-bound metadata (CA identifier and private certificate store) is
        # discarded. A successful allowlist STORE, not PUT KEY, clears OCE.
        if kid in PUBLIC_KIDS and "allowlist" in keys[old]:
            row["allowlist"] = list(keys[old]["allowlist"])
        if kid in PUBLIC_KIDS and "allowlist_counter" in keys[old]:
            row["allowlist_counter"] = keys[old]["allowlist_counter"]
        del keys[old]
    else:
        require(ref not in keys, 0x6985)
    if kid == 1:
        keys.pop("01ff", None)
        require(sum(int(k[:2], 16) == 1 for k in keys) < 3, 0x6A84)
    else:
        require(
            sum(int(k[:2], 16) in PRIVATE_KIDS + PUBLIC_KIDS for k in keys) < 16, 0x6A84
        )
    row["retries"] = AUTHENTICATION_TRIES
    keys[ref] = row


def decrypt_dek(card, data):
    require(
        card.secure_channel.dek is not None and len(data) > 0 and len(data) % 16 == 0,
        0x6A80,
    )
    ctx = Cipher(
        algorithms.AES(card.secure_channel.dek), modes.CBC(bytes(16))
    ).decryptor()
    return ctx.update(data) + ctx.finalize()


def dispatch(card, apdu):
    keys = state(card)["keys"]
    if apdu.ins == 0xCA:
        tag = apdu.p1 * 256 + apdu.p2
        if tag == 0xE0:
            result = b""
            for ref, row in sorted(keys.items()):
                kid, kvn = bytes.fromhex(ref)
                if kid == 1:
                    result += b"".join(
                        Tlv(0xC0, bytes([k, kvn, 0x88, 16])) for k in (1, 2, 3)
                    )
                else:
                    kind = 0xB1 if "private" in row else 0xB0
                    result += Tlv(0xC0, bytes([kid, kvn, kind, 32, 0xF0, 0]))
            return result
        if tag == 0x66:
            return CARD_RECOGNITION_DATA
        if tag == 0x9F7F:
            return bytes.fromhex(state(card)["cplc"])
        if tag == 0xBF21:
            ref = Tlv.unpack(0x83, Tlv.unpack(0xA6, apdu.data)).hex()
            require(ref in keys and keys[ref].get("certificates"), 0x6A88)
            return bytes.fromhex(keys[ref]["certificates"])
        if tag in (0xFF33, 0xFF34):
            result = b"".join(
                Tlv(0x42, bytes.fromhex(r["ski"])) + Tlv(0x83, bytes.fromhex(k))
                for k, r in keys.items()
                if r.get("ski") and (int(k[:2], 16) in PRIVATE_KIDS) == (tag == 0xFF34)
            )
            require(result, 0x6A88)
            return result
        fail(0x6A88)
    require(
        card.secure_channel is not None
        and card.secure_channel.established
        and card.secure_channel.oce_authenticated
    )
    # Replayable SCP11c sessions must not change/delete keys or SET STATUS
    # (GP SCP11 4.6). The numeric denial is a model, not a measured YubiKey SW.
    require(
        card.secure_channel.scp_kid != 0x15 or apdu.ins not in (0xD8, 0xE4, 0xF0),
        0x6985,
    )
    if apdu.ins == 0xF1:
        require(apdu.p2 in PRIVATE_KIDS and apdu.data, 0x6A80)
        require(Tlv.unpack(0xF0, apdu.data[1:]) == b"\0", 0x6A80)
        key = ec.generate_private_key(ec.SECP256R1())
        insert(
            keys,
            bytes([apdu.p2, apdu.data[0]]).hex(),
            {"private": dump_key(key)},
            apdu.p1,
        )
        return Tlv(0xB0, public_bytes(key.public_key()))
    if apdu.ins == 0xD8:
        require(len(apdu.data) > 1, 0x6A80)
        kvn, kid = apdu.data[0], apdu.p2 & 0x7F
        rest = apdu.data[1:]
        if kid == 1:
            require(apdu.p2 & 0x80, 0x6A86)
            row = {}
            response = bytes([kvn])
            for label in ("enc", "mac", "dek"):
                value, rest = Tlv.parse_from(rest)
                require(value.tag == 0x88 and len(value.value) == 16, 0x6A80)
                require(len(rest) >= 4 and rest[0] == 3, 0x6A80)
                key = decrypt_dek(card, value.value)
                ctx = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).encryptor()
                kcv = (ctx.update(b"\1" * 16) + ctx.finalize())[:3]
                require(hmac.compare_digest(kcv, rest[1:4]), 0x6A80)
                row[label] = key.hex()
                response += kcv
                rest = rest[4:]
            require(not rest, 0x6A80)
        else:
            value, rest = Tlv.parse_from(rest)
            curve, rest = Tlv.parse_from(rest)
            require(
                curve.tag == 0xF0 and curve.value == b"\0" and rest == b"\0", 0x6A80
            )
            if value.tag == 0xB1:
                require(kid in PRIVATE_KIDS, 0x6A80)
                require(len(value.value) == 32, 0x6A80)
                key = ec.derive_private_key(
                    int.from_bytes(decrypt_dek(card, value.value), "big"),
                    ec.SECP256R1(),
                )
                row = {"private": dump_key(key)}
            else:
                require(value.tag == 0xB0 and kid in PUBLIC_KIDS, 0x6A80)
                key = ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256R1(), value.value
                )
                row = {"public": public_bytes(key).hex()}
            response = bytes([kvn])
        insert(keys, bytes([kid, kvn]).hex(), row, apdu.p1)
        return response
    if apdu.ins == 0xE2:
        require(apdu.p1 == 0x90 and apdu.p2 == 0, 0x6A86)
        values = tlvs(apdu.data)
        fields = tlvs(values[0xA6])
        ref = fields[0x83].hex()
        require(ref in keys, 0x6A88)
        row = keys[ref]
        is_c = card.secure_channel.scp_kid == 0x15
        require(0x92 not in values or 0x70 in values, 0x6A80)
        if 0x70 in values:
            require(
                set(values) == ({0xA6, 0x70, 0x92} if is_c else {0xA6, 0x70})
                and set(fields) == {0x83},
                0x6A80,
            )
        if 0xBF21 in values:
            require("private" in row, 0x6A80)
            certs = [
                x509.load_der_x509_certificate(c)
                for c in Tlv.parse_list(values[0xBF21])
            ]
            require(1 <= len(certs) <= 8, 0x6A80)
            require(
                public_bytes(certs[-1].public_key())
                == public_bytes(load_key(row["private"]).public_key()),
                0x6A80,
            )
            for i in range(1, len(certs)):
                try:
                    certs[i].verify_directly_issued_by(certs[i - 1])
                except (ValueError, TypeError, InvalidSignature):
                    fail(0x6A80)
            row["certificates"] = values[0xBF21].hex()
        elif 0x70 in values:
            require("public" in row, 0x6A80)
            counter = None
            if is_c:
                require(len(values[0x92]) == 2, 0x6A80)
                counter = int.from_bytes(values[0x92], "big")
                require(0 <= row.get("allowlist_counter", 0) < counter <= 32767, 0x6A80)
            serials = Tlv.parse_list(values[0x70])
            require(
                len(serials) <= 64
                and all(s.tag == 0x93 and 1 <= len(s.value) <= 21 for s in serials),
                0x6A80,
            )
            if serials:
                row["allowlist"] = [int.from_bytes(s.value, "big") for s in serials]
            else:
                row.pop("allowlist", None)
            if counter is not None:
                # List+counter share Card's atomic state commit/rollback. Clear
                # and non-c list updates never reset the remembered counter.
                row["allowlist_counter"] = counter
            # Every successful update, including clear/identical/another CA,
            # invalidates the SD's one cached OCE key (GP SCP11 7.6.1/7.9).
            state(card)["oce_policy_generation"] = os.urandom(16).hex()
            card.reset_oce_cache()
        elif 0x42 in fields:
            require(
                fields.get(0x80) == (b"\1" if "private" in row else b"\0")
                and len(fields[0x42]) == 20,
                0x6A80,
            )
            row["ski"] = fields[0x42].hex()
        else:
            fail(0x6A80)
        return b""
    if apdu.ins == 0xE4:
        require(apdu.p1 == 0 and apdu.p2 in (0, 1), 0x6A86)
        fields = tlvs(apdu.data)
        require(
            fields
            and set(fields) <= {0xD0, 0xD2}
            and all(len(v) == 1 for v in fields.values()),
            0x6A80,
        )
        kid, kvn = fields.get(0xD0, b"\0")[0], fields.get(0xD2, b"\0")[0]
        matches = [
            r
            for r in keys
            if (not kid or int(r[:2], 16) == kid)
            and (not kvn or bytes.fromhex(r)[1] == kvn)
        ]
        require(matches, 0x6A88)
        remaining_auth = [
            r
            for r in keys
            if r not in matches
            and (int(r[:2], 16) == 1 or int(r[:2], 16) in (0x11, 0x15))
        ]
        require(apdu.p2 == 1 or remaining_auth, 0x6985)
        for ref in matches:
            del keys[ref]
        if not remaining_auth:
            card.state.data["domain"] = fresh_domain()
            # The caller still holds the channel long enough to protect this
            # response, but it must not authorize another command after reset.
            card.reset_session()
            card.close_wrapping_channel = True
        return b""
    fail(0x6D00)
