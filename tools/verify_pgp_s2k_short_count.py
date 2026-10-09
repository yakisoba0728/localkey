#!/usr/bin/env python3
"""Independent short-count S2K oracle over the SDK's private CCID fixture.

Only fresh software card sockets are used.  The vendor SDK transports APDUs;
hash expectations are calculated from RFC 4880 rather than emulator helpers.
"""

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from emucard.core import EncryptedState
from verify_smartcard import Fixture
from yubikit.core.smartcard import ApduError
from yubikit.openpgp import HASH_ALGORITHM, KdfIterSaltedS2k, OpenPgpSession


def oracle(salt, pin, count, hash_name):
    unit = salt + pin
    count = max(count, len(unit))
    return hashlib.new(hash_name, (unit * ((count + len(unit) - 1) // len(unit)))[:count]).digest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ifd-driver", type=Path)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    checks = []
    cases = [("sha256", n) for n in (1, 13, 14, 15, 16, 17)] + [
        ("sha512", n) for n in (1, 15, 17)
    ]
    args.work_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ske-pgp-s2k-", dir=args.work_dir) as base:
        for index, (hash_name, count) in enumerate(cases):
            directory = Path(base) / str(index)
            directory.mkdir()
            fixture = Fixture(root, directory, args.ifd_driver)
            try:
                pgp = OpenPgpSession(fixture.start())
                pgp.verify_admin("12345678")
                kdf = KdfIterSaltedS2k(
                    HASH_ALGORITHM.SHA256 if hash_name == "sha256" else HASH_ALGORITHM.SHA512,
                    count,
                    b"USERsalt",
                    None,
                    b"ADMINsal",
                    None,
                    None,
                )
                pgp.set_kdf(kdf)
                assert bytes(pgp.get_kdf()) == bytes(kdf)
                for reference, salt, pin in (
                    (0x81, b"USERsalt", b"123456"),
                    (0x83, b"ADMINsal", b"12345678"),
                ):
                    expected = oracle(salt, pin, count, hash_name)
                    pgp.protocol.send_apdu(0, 0x20, 0, reference, expected)
                    assert (pgp.get_pin_status().attempts_user if reference == 0x81 else pgp.get_pin_status().attempts_admin) == 3
                    checks.append(f"{hash_name} count={count} PW={reference:02x} independent RFC digest verified")
                    if count < len(salt + pin):
                        truncated = hashlib.new(hash_name, (salt + pin)[:count]).digest()
                        assert truncated != expected
                        try:
                            pgp.protocol.send_apdu(0, 0x20, 0, reference, truncated)
                        except ApduError as error:
                            assert error.sw == 0x6982
                        else:
                            raise AssertionError("truncated salt+PIN digest accepted")
                        pgp.protocol.send_apdu(0, 0x20, 0, reference, expected)
                        checks.append(f"{hash_name} count={count} PW={reference:02x} truncated digest rejected")
                pgp = OpenPgpSession(fixture.restart())
                assert bytes(pgp.get_kdf()) == bytes(kdf)
                assert pgp.get_pin_status().attempts_user == 3
                assert pgp.get_pin_status().attempts_admin == 3
                state = EncryptedState(directory / "state.bin").data["openpgp"]
                assert state["pin"] == state["admin"] == ""
                assert bytes.fromhex(state["pin_value"]) == oracle(b"USERsalt", b"123456", count, hash_name)
                assert bytes.fromhex(state["admin_value"]) == oracle(b"ADMINsal", b"12345678", count, hash_name)
                checks.append(f"{hash_name} count={count} stored hashes and retries survive restart")
            finally:
                fixture.stop()
    result = {
        "passed": True,
        "count": len(checks),
        "tests": [{"name": name, "passed": True} for name in checks],
        "cases": cases,
        "physical_key_accessed": False,
        "sdk_role": "unmodified yubikit OpenPgpSession APDU transport and KDF parse",
        "transport": "direct IFD ABI" if args.ifd_driver else "private CCID socket",
        "hash_oracle": "independent hashlib implementation of RFC 4880 section 3.7.1.3",
        "limit": "pinned SDK's own KDF process truncates when count < salt+PIN; raw SDK APDUs use independent conforming digest",
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"passed": True, "checks": len(checks)}))


if __name__ == "__main__":
    main()
