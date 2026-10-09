#!/usr/bin/env python3
"""A/B SCP03 INITIALIZE UPDATE malformed Le and authentication retry state."""

import argparse
import hashlib
import hmac
import json
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms
from yubikit.core.smartcard.scp import Scp03KeyParams
from yubikit.securitydomain import SecurityDomainSession


KEY = bytes(range(0x40, 0x50))
HOST = b"v64-host"


def kdf(key, constant, context, bits=128):
    block = bytes(11) + bytes([constant, 0]) + bits.to_bytes(2, "big") + b"\1" + context
    mac = cmac.CMAC(algorithms.AES(key))
    mac.update(block)
    return mac.finalize()[: bits // 8]


def check_response(response):
    assert len(response) == 29 and response[10:13] == bytes((255, 3, 0x60))
    context = HOST + response[13:21]
    expected = kdf(kdf(KEY, 6, context), 0, context, 64)
    assert hmac.compare_digest(expected, response[21:29])


def run(root, ifd, fixed):
    sys.path.insert(0, str(root))
    sys.path.insert(0, str(root / "tools"))
    from emucard.core import Apdu, EncryptedState
    from verify_smartcard import Fixture

    with tempfile.TemporaryDirectory(prefix="ske64-scp03-init-le-", dir="/tmp") as temp:
        directory = Path(temp)
        fixture = Fixture(root, directory, ifd)
        try:
            conn = fixture.start()
            SecurityDomainSession(conn)  # Unmodified SDK SELECT, no authentication.
            state_path = directory / "state.bin"
            state = lambda: EncryptedState(state_path).data["domain"]
            before = state()
            before_file = state_path.read_bytes()
            assert before["keys"]["01ff"]["retries"] == 64
            malformed = b"\x80\x50\xff\x00\x08" + HOST + b"\x01"
            assert Apdu.decode(malformed).le == 1
            first, sw = conn.send_and_receive(malformed)
            after = state()
            after_file = state_path.read_bytes()
            if fixed:
                assert not first and sw == 0x6700, hex(sw)
                assert after == before and after_file == before_file
                malformed_response_verified = False
            else:
                assert len(first) == 1 and sw & 0xff00 == 0x6100, hex(sw)
                response = bytearray(first)
                while sw != 0x9000:
                    fragment, sw = conn.send_and_receive(bytes.fromhex("00c0000000"))
                    response.extend(fragment)
                check_response(bytes(response))
                assert after["keys"]["01ff"]["retries"] == 63
                malformed_response_verified = True

            # Verify a genuine SDK handshake, not an emulator-generated proof.
            emitted = []
            original_send = conn.send_and_receive

            def capture(packet):
                emitted.append(bytes(packet))
                return original_send(packet)

            conn.send_and_receive = capture
            sdk = SecurityDomainSession(conn)
            sdk.authenticate(Scp03KeyParams())
            cplc = sdk.get_data(0x9F7F)
            sdk_init_wire = next(p for p in emitted if len(p) >= 4 and p[1] == 0x50)
            assert Apdu.decode(sdk_init_wire).le is None
            assert len(cplc) == 42 and state()["keys"]["01ff"]["retries"] == 64

            # GP's short Le=00 spelling must also remain interoperable.
            conn = fixture.restart()
            SecurityDomainSession(conn)
            spec_wire = b"\x80\x50\xff\x00\x08" + HOST + b"\x00"
            assert Apdu.decode(spec_wire).le == 256
            response, spec_sw = conn.send_and_receive(spec_wire)
            assert spec_sw == 0x9000
            check_response(response)
            assert state()["keys"]["01ff"]["retries"] == 63
            sdk = SecurityDomainSession(conn)
            sdk.authenticate(Scp03KeyParams())
            assert sdk.get_data(0x9F7F) == cplc
            assert state()["keys"]["01ff"]["retries"] == 64
            return {
                "passed": True,
                "fixed": fixed,
                "route": "direct IFD" if ifd else "private CCID socket",
                "malformed_apdu": malformed.hex(),
                "malformed_sw": "6700" if fixed else "61xx_then_9000",
                "malformed_response_cryptogram_independently_verified": malformed_response_verified,
                "retries_before": 64,
                "retries_after_malformed": after["keys"]["01ff"]["retries"],
                "malformed_domain_state_unchanged": after == before,
                "malformed_encrypted_state_bytes_unchanged": after_file == before_file,
                "normal_sdk_le_absent": True,
                "normal_sdk_authentication_and_cplc": True,
                "explicit_short_le_00_cryptogram_verified": True,
                "normal_sdk_after_restart_restores_retries": True,
                "domain_sha256": hashlib.sha256((root / "emucard/domain.py").read_bytes()).hexdigest(),
                "physical_or_host_device_access": False,
                "firmware_5_7_4_differential": False,
            }
        finally:
            fixture.stop()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--ifd", type=Path)
    parser.add_argument("--fixed", action="store_true")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.root.resolve(), args.ifd.resolve() if args.ifd else None, args.fixed)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"passed": result["passed"], "route": result["route"],
                      "fixed": result["fixed"], "retries_after_malformed": result["retries_after_malformed"]}))


if __name__ == "__main__":
    main()
