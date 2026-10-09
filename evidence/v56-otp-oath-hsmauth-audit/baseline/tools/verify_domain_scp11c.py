#!/usr/bin/env python3
"""Verify own SCP11c static ECDH, replay restrictions and durable allowlist counter.

Fresh private socket/direct IFD fixtures only; no hardware discovery or writes.
Crypto expectations independently implement GP ECDH/X963/CMAC; unmodified SDK
checks encrypted responses. Numeric rejection/lifecycle behavior is an explicit
GP public-review model, not measured firmware-5.7.4 or formal conformance proof.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives import cmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import algorithms
from emucard.core import EncryptedState
from verify_domain_cache import GP_SOURCE, host
from verify_smartcard import Fixture
from yubikit.core import Tlv
from yubikit.core.smartcard import (
    ApduError,
    ScpProcessor,
    SmartCardConnection,
    SmartCardProtocol,
)
from yubikit.core.smartcard.scp import (
    KeyRef,
    Scp03KeyParams,
    Scp11KeyParams,
    ScpState,
    SessionKeys,
    StaticKeys,
)
from yubikit.securitydomain import SecurityDomainSession


def point(key):
    return key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def aes_cmac(key, data):
    ctx = cmac.CMAC(algorithms.AES(key))
    ctx.update(data)
    return ctx.finalize()


def x963(shared):
    # Independently form the counter blocks, without calling implementation/SDK
    # derivation helpers or importing their protocol constants.
    return b"".join(
        hashlib.sha256(shared + n.to_bytes(4, "big") + bytes.fromhex("3c8810")).digest()
        for n in (1, 2, 3)
    )[:80]


class RecordingConnection(SmartCardConnection):
    def __init__(self, backend):
        self.backend = backend
        self.sent = []

    @property
    def transport(self):
        return self.backend.transport

    def send_and_receive(self, apdu):
        self.sent.append(bytes(apdu))
        return self.backend.send_and_receive(apdu)

    def close(self):
        pass  # The fixture owns the underlying software socket/IFD handle.


def run(root, directory, report, ifd_driver=None):
    fixture = Fixture(root, directory, ifd_driver)
    tests = []
    passed = False

    def check(value, label):
        if not value:
            raise AssertionError(label)
        tests.append({"name": label, "passed": True})
        print("PASS", label, flush=True)

    def saved():
        return EncryptedState(directory / "state.bin").data

    def authenticate(kid=None):
        sd = SecurityDomainSession(conn)
        sd.authenticate(
            Scp11KeyParams(KeyRef(kid, 1), public[kid], anchor, host_key, chain)
            if kid
            else Scp03KeyParams()
        )
        return sd

    def secure_read(sd, label):
        check(sd.get_data(0x9F7F) == cplc, label)

    def denied(sw, operation, label):
        before = (directory / "state.bin").read_bytes()
        try:
            operation()
        except ApduError as error:
            check(
                error.sw == sw and (directory / "state.bin").read_bytes() == before,
                label + "; ciphertext unchanged",
            )
        else:
            raise AssertionError("accepted prohibited operation: " + label)

    def allowlist(ref, serials, counter=None):
        # Own fixtures use positive serials; include DER's sign-padding when
        # needed. Keep this encoding independent of the emulator's parser.
        values = b""
        for serial in serials:
            value = serial.to_bytes((serial.bit_length() + 7) // 8, "big")
            if value[0] & 0x80:
                value = b"\0" + value
            values += Tlv(0x93, value)
        return (
            Tlv(0xA6, Tlv(0x83, ref))
            + (Tlv(0x92, counter) if counter is not None else b"")
            + Tlv(0x70, values)
        )

    def manual_init(kid, ephemeral):
        sd = SecurityDomainSession(conn)
        if kid != 0x13:
            for index, cert in enumerate(chain):
                sd.protocol.send_apdu(
                    0x80,
                    0x2A,
                    anchor.kvn,
                    anchor.kid | (0x80 if index < len(chain) - 1 else 0),
                    cert.public_bytes(serialization.Encoding.DER),
                )
        usage = {0x11: 1, 0x13: 0, 0x15: 3}[kid]
        request = Tlv(
            0xA6,
            Tlv(0x90, bytes([0x11, usage]))
            + Tlv(0x95, b"\x3c")
            + Tlv(0x80, b"\x88")
            + Tlv(0x81, b"\x10"),
        ) + Tlv(0x5F49, point(ephemeral.public_key()))
        response = sd.protocol.send_apdu(
            0x80, 0x88 if kid == 0x13 else 0x82, 1, kid, request
        )
        items = Tlv.parse_list(response)
        check(
            len(items) == 2
            and [v.tag for v in items] == [0x5F49, 0x86]
            and len(items[0].value) == 65
            and len(items[1].value) == 16,
            f"SCP11 {kid:02x} independently checks public point/receipt response format",
        )
        static = public[kid]
        if kid == 0x15:
            check(
                items[0].value == point(static),
                "SCP11c response returns own static SD point",
            )
            shared = ephemeral.exchange(ec.ECDH(), static) + host_key.exchange(
                ec.ECDH(), static
            )
        else:
            dynamic = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), items[0].value
            )
            check(
                items[0].value != point(static),
                f"SCP11 {kid:02x} response keeps card ephemeral key",
            )
            shared = ephemeral.exchange(ec.ECDH(), dynamic) + (
                ephemeral if kid == 0x13 else host_key
            ).exchange(ec.ECDH(), static)
        keys = [x963(shared)[offset : offset + 16] for offset in range(0, 80, 16)]
        receipt = aes_cmac(keys[0], request + items[0])
        check(
            receipt == items[1].value,
            f"SCP11 {kid:02x} independent ECDH/SHA256 counter-KDF/CMAC receipt agrees",
        )
        protocol = SmartCardProtocol(conn)
        protocol._processor, formatter = protocol._build_base_processor()
        state = ScpState(SessionKeys(*keys[1:]), receipt)
        protocol._processor = ScpProcessor(protocol._processor, formatter, state)
        sd.protocol = protocol
        return sd, bytes(response), keys, receipt

    try:
        conn = RecordingConnection(fixture.start())
        sd = authenticate()
        cplc = sd.get_data(0x9F7F)
        b_cert = sd.get_certificate_bundle(KeyRef(0x13, 1))[-1]
        public = {0x13: b_cert.public_key()}
        public.update({kid: sd.generate_ec_key(KeyRef(kid, 1)) for kid in (0x11, 0x15)})
        anchor, other = KeyRef(0x10, 1), KeyRef(0x20, 1)
        ca, host_key, chain, _ = host("SCP11c independent", anchor)
        for ref in (anchor, other):
            sd.put_key(ref, ca.public_key())
        serials = [cert.serial_number for cert in chain]
        peers = {key: value for key, value in saved().items() if key != "domain"}

        # Old code fails here on the static-point check despite SDK success.
        fixed_ephemeral = ec.generate_private_key(ec.SECP256R1())
        for kid in (0x15, 0x11, 0x13):
            sd, first, _, _ = manual_init(kid, fixed_ephemeral)
            secure_read(
                sd,
                f"SCP11 {kid:02x} independently derived keys drive unchanged SDK encrypted/MAC read",
            )
            sd, second, _, _ = manual_init(kid, fixed_ephemeral)
            check(
                (first == second) == (kid == 0x15),
                f"SCP11 {kid:02x} repeated own request has correct static/re-randomized response",
            )
            secure_read(
                sd,
                f"SCP11 {kid:02x} repeated own request still passes SDK secure messaging",
            )
        for kid in (0x11, 0x15):
            sd = authenticate(kid)
            secure_read(
                sd,
                f"normal SDK SCP11 {kid:02x} authentication/receipt/KDF still interoperates",
            )

        sd = authenticate(0x15)
        private = ec.generate_private_key(ec.SECP256R1())
        static = StaticKeys(os.urandom(16), os.urandom(16), os.urandom(16))
        for operation, label in (
            (lambda: sd.put_key(KeyRef(0x13, 2), private), "encrypted private PUT KEY"),
            (
                lambda: sd.put_key(KeyRef(0x21, 2), private.public_key()),
                "public PUT KEY",
            ),
            (lambda: sd.put_key(KeyRef(1, 2), static), "AES-set PUT KEY"),
            (
                lambda: sd.delete_key(kid=0x15, kvn=1),
                "current c key DELETE (pinned vendor SDK expectation)",
            ),
            (lambda: sd.delete_key(kid=0x11, kvn=1), "other key DELETE"),
            (lambda: sd.delete_key(kid=0x13), "version-wildcard DELETE"),
            (lambda: sd.protocol.send_apdu(0x80, 0xF0, 0, 0), "SET STATUS"),
        ):
            denied(0x6985, operation, "SCP11c denies " + label)
        secure_read(
            sd, "SCP11c command rejections keep current SDK response MAC/channel usable"
        )

        sd = authenticate(0x11)
        sd.put_key(KeyRef(0x13, 2), private)
        check(
            KeyRef(0x13, 2) in sd.get_key_information(),
            "SCP11a still allows private PUT KEY with session DEK",
        )
        sd.delete_key(kid=0x13, kvn=2)
        check(
            KeyRef(0x13, 2) not in sd.get_key_information(),
            "SCP11a still allows key DELETE",
        )
        sd = authenticate(0x15)
        denied(
            0x6A80,
            lambda: sd.store_allowlist(anchor, serials),
            "SCP11c SDK allowlist without counter is denied",
        )
        for value in (b"", b"\1", b"\0\0", b"\0\0\1", b"\x80\0", b"\xff\xff"):
            denied(
                0x6A80,
                lambda value=value: sd.store_data(allowlist(anchor, serials, value)),
                "SCP11c rejects counter shape/range " + value.hex(),
            )
        sd.store_data(allowlist(anchor, serials, b"\0\1"))
        check(
            saved()["domain"]["keys"][anchor.hex()]["allowlist_counter"] == 1,
            "first SCP11c allowlist stores counter one atomically",
        )
        denied(
            0x6A80,
            lambda: sd.store_data(allowlist(anchor, [], b"\0\1")),
            "equal counter cannot clear a list",
        )
        sd.store_data(allowlist(other, serials, b"\0\1"))
        check(
            saved()["domain"]["keys"][other.hex()]["allowlist_counter"] == 1
            and saved()["domain"]["keys"][anchor.hex()]["allowlist_counter"] == 1,
            "separate CA anchors have independent anti-replay counters",
        )
        sd.store_data(allowlist(anchor, [], b"\0\2"))
        row = saved()["domain"]["keys"][anchor.hex()]
        check(
            row["allowlist_counter"] == 2 and "allowlist" not in row,
            "SCP11c list clear advances and retains counter",
        )
        sd = authenticate()
        sd.store_allowlist(anchor, serials)
        sd.store_allowlist(anchor, [])
        check(
            saved()["domain"]["keys"][anchor.hex()]["allowlist_counter"] == 2,
            "SCP03 list replacement/clear never resets remembered c counter",
        )

        # Store an exact protected packet, then re-establish identical own c
        # session keys. Replaying that packet must fail at the durable counter,
        # while its command MAC and the error's response MAC remain valid.
        sd, first_response, _, _ = manual_init(0x15, fixed_ephemeral)
        conn.sent.clear()
        sd.store_data(allowlist(anchor, serials, b"\0\3"))
        packet = conn.sent[-1]
        before = saved()
        sd, repeated_response, keys, receipt = manual_init(0x15, fixed_ephemeral)
        check(
            first_response == repeated_response,
            "own c replay fixture re-establishes identical static-key receipt",
        )
        after_handshake = saved()
        old_token = before["domain"]["scp11c_session_generation"]
        new_token = after_handshake["domain"]["scp11c_session_generation"]
        before["domain"]["scp11c_session_generation"] = new_token
        check(
            old_token != new_token
            and len(bytes.fromhex(new_token)) == 16
            and after_handshake == before,
            "successful same-key c handshake rotates only ownership token; keys/list/counter preserved",
        )
        before = after_handshake
        before_cipher = (directory / "state.bin").read_bytes()
        response, sw = conn.send_and_receive(packet)
        if packet[4] == 0:
            length = int.from_bytes(packet[5:7], "big")
            prefix, payload = packet[:7], packet[7 : 7 + length]
        else:
            prefix, payload = packet[:5], packet[5 : 5 + packet[4]]
        command_chain = aes_cmac(keys[2], receipt + prefix + payload[:-8])
        check(
            command_chain[:8] == payload[-8:],
            "replayed own packet has independently verified valid C-MAC",
        )
        check(
            sw == 0x6A80
            and response == aes_cmac(keys[3], command_chain + b"\x6a\x80")[:8],
            "valid encrypted own c replay receives counter rejection with independently verified R-MAC",
        )
        check(
            saved() == before
            and (directory / "state.bin").read_bytes() == before_cipher,
            "rejected authenticated replay never changes persistent list/counter",
        )

        conn = RecordingConnection(fixture.restart())
        sd = authenticate(0x15)
        check(
            saved()["domain"]["keys"][anchor.hex()]["allowlist_counter"] == 3,
            "service restart preserves replay counter",
        )
        malformed = allowlist(anchor, serials, b"\0\4")
        for payload, label in (
            (malformed + Tlv(0x92, b"\0\5"), "duplicate counter"),
            (
                Tlv(0xA6, Tlv(0x83, anchor))
                + Tlv(0x92, b"\0\4")
                + Tlv(0x70, Tlv(0x94, b"\1")),
                "bad serial tag with valid counter",
            ),
            (malformed + Tlv(0xBF21, b""), "ambiguous certificate/list envelope"),
            (
                Tlv(0xA6, Tlv(0x83, anchor)) + Tlv(0x92, b"\0\4"),
                "counter without allowlist",
            ),
        ):
            denied(
                0x6A80,
                lambda payload=payload: sd.store_data(payload),
                "SCP11c rejects " + label,
            )
        sd.store_data(malformed)
        check(
            saved()["domain"]["keys"][anchor.hex()]["allowlist_counter"] == 4,
            "rejected list data does not consume counter; corrected counter four succeeds",
        )
        for kid in (None, 0x11):
            sd = authenticate(kid)
            denied(
                0x6A80,
                lambda sd=sd: sd.store_data(allowlist(anchor, serials, b"\0\5")),
                "non-c session forbids tag92: "
                + ("SCP03" if kid is None else "SCP11a"),
            )
            sd.store_allowlist(anchor, serials)
        check(
            saved()["domain"]["keys"][anchor.hex()]["allowlist_counter"] == 4,
            "non-c allowlist writes retain per-CA replay counter",
        )
        sd = authenticate()
        sd.store_allowlist(anchor, [])
        sd.put_key(KeyRef(anchor.kid, 2), ca.public_key(), replace_kvn=1)
        anchor = KeyRef(anchor.kid, 2)
        row = saved()["domain"]["keys"][anchor.hex()]
        check(
            row["allowlist_counter"] == 4 and "allowlist" not in row,
            "CA replacement retains counter even while its list is absent",
        )
        conn = RecordingConnection(fixture.restart())
        sd = authenticate(0x15)
        denied(
            0x6A80,
            lambda: sd.store_data(allowlist(anchor, serials, b"\0\4")),
            "replacement/restart cannot resurrect an older list counter",
        )

        # Controlled pre-rename persistence failure, entirely inside this fresh
        # fixture. Test real service rollback rather than parser-only assertions.
        state_path = directory / "state.bin"
        backup = directory / "own-state-backup.bin"
        before = saved()
        raw = state_path.read_bytes()
        state_path.rename(backup)
        state_path.mkdir()
        try:
            try:
                sd.store_data(allowlist(anchor, serials, b"\0\5"))
            except ApduError as error:
                check(
                    error.sw == 0x6581,
                    "list/counter storage failure returns SDK-MAC-verified modeled 6581",
                )
            else:
                raise AssertionError("accepted controlled persistence failure")
        finally:
            state_path.rmdir()
            backup.rename(state_path)
        check(
            saved() == before and state_path.read_bytes() == raw,
            "pre-rename storage failure preserves encrypted prior list/counter atomically",
        )
        denied(
            0x6982,
            lambda: sd.get_data(0x9F7F),
            "failed commit terminates its old c channel",
        )
        sd = authenticate(0x15)
        sd.store_data(allowlist(anchor, serials, b"\0\5"))
        check(
            saved()["domain"]["keys"][anchor.hex()]["allowlist_counter"] == 5,
            "failed commit also rolls back live counter so same corrected counter succeeds",
        )
        sd.store_data(allowlist(anchor, serials, b"\x7f\xff"))
        check(
            saved()["domain"]["keys"][anchor.hex()]["allowlist_counter"] == 32767,
            "counter upper boundary 32767 is accepted",
        )
        for value in (b"\x7f\xff", b"\x7f\xfe", b"\x80\0"):
            denied(
                0x6A80,
                lambda value=value: sd.store_data(allowlist(anchor, [], value)),
                "exhausted counter never clears/decreases/wraps: " + value.hex(),
            )
        sd = authenticate()
        sd.store_allowlist(anchor, [])
        conn = RecordingConnection(fixture.restart())
        sd = authenticate(0x15)
        denied(
            0x6A80,
            lambda: sd.store_data(allowlist(anchor, serials, b"\0\1")),
            "SCP03 clear and restart cannot reset exhausted c counter",
        )
        check(
            peers == {key: value for key, value in saved().items() if key != "domain"},
            "SCP11c crypto/replay/counter/failure/restart tests preserve every peer application",
        )
        passed = True
    finally:
        fixture.stop()
        report.write_text(
            json.dumps(
                {
                    "passed": passed,
                    "tests": tests,
                    "transport": "direct IFD ABI"
                    if ifd_driver
                    else "private CCID socket",
                    "physical_device_access": False,
                    "manufacturer_trust_reproduced": False,
                    "system_pcsc_reader_registered": False,
                    "independent_crypto": "ECDH, explicit SHA256 counter-KDF, AES-CMAC receipt/command/response; unchanged SDK secure messaging",
                    "source": {
                        "url": GP_SOURCE,
                        "version": "1.3.0.13 public review",
                        "sections": ["4.6", "7.6.2.3", "7.6.3.1", "7.9"],
                    },
                    "vendor_sdk_expectation": "pinned Android/.NET c-session key-delete rejection; suites read only, never run on hardware",
                    "counter_range": [1, 32767],
                    "unverified": [
                        "physical KDF/response/rejection/lifecycle vs finalized GP1.4",
                        "firmware SCP11c proprietary GENERATE and SD content transaction/rollback",
                        "multi-connection one-c-session-per-SD enforcement",
                        "critical subject-ID and certificate/allowlist scope",
                        "actual OS reader/browser interoperability",
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
        prefix="ske-domain-scp11c-", dir=args.work_dir
    ) as directory:
        run(
            Path(__file__).resolve().parents[1],
            Path(directory),
            args.report,
            args.ifd_driver,
        )


if __name__ == "__main__":
    main()
