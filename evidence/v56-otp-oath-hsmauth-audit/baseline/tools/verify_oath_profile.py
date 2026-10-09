#!/usr/bin/env python3
"""Verify published OATH syntax, capacity and RFC vectors on fresh software cards.

Uses the independent Yubico SDK over a private CCID socket or direct IFD ABI.
No physical reader, existing credential or system PC/SC registration is used.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives import hashes
from emucard.core import EncryptedState
from verify_smartcard import Fixture
from yubikit.core import Tlv
from yubikit.core.smartcard import ApduError
from yubikit.oath import HASH_ALGORITHM, OATH_TYPE, CredentialData, OathSession
from yubikit.piv import SLOT, PivSession

TIMES = (59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000)
RFC6238 = {
    HASH_ALGORITHM.SHA1: (
        "94287082",
        "07081804",
        "14050471",
        "89005924",
        "69279037",
        "65353130",
    ),
    HASH_ALGORITHM.SHA256: (
        "46119246",
        "68084774",
        "67062674",
        "91819424",
        "90698825",
        "77737706",
    ),
    HASH_ALGORITHM.SHA512: (
        "90693936",
        "25091201",
        "99943326",
        "93441116",
        "38618901",
        "47863826",
    ),
}


def truncate(digest):
    offset = digest[-1] & 15
    return (int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF).to_bytes(
        4, "big"
    )


def put_data(name=b"raw HOTP", algorithm=0x11, secret=b"12345678901234567890"):
    return Tlv(0x71, name) + Tlv(0x73, bytes([algorithm, 6]) + secret)


def run(root, directory, report, ifd_driver=None):
    fixture = Fixture(root, directory, ifd_driver)
    tests = []
    passed = False

    def check(condition, name):
        if not condition:
            raise AssertionError(name)
        tests.append({"name": name, "passed": True})
        print("PASS", name, flush=True)

    def reject(sw, operation, name):
        before = (directory / "state.bin").read_bytes()
        try:
            operation()
        except ApduError as error:
            check(
                error.sw == sw and (directory / "state.bin").read_bytes() == before,
                name + "; persistent state unchanged",
            )
        else:
            raise AssertionError("accepted invalid OATH request: " + name)

    try:
        connection = fixture.start()
        oath = OathSession(connection)
        check(
            oath.version == (5, 7, 4)
            and not oath.has_key
            and not oath.list_credentials(),
            "fresh OATH published version with empty unlocked credential store",
        )

        def send(ins, data=b"", p1=0, p2=0):
            return oath.protocol.send_apdu(0, ins, p1, p2, data)

        validate_data = Tlv(0x75, bytes(20)) + Tlv(0x74, bytes(8))
        reject(
            0x6984,
            lambda: send(0xA3, validate_data),
            "VALIDATE without enabled access code reports auth-not-enabled",
        )
        raw = put_data()
        for size in (0, 1, 3, 5, 8):
            reject(
                0x6A80,
                lambda size=size: send(1, raw + Tlv(0x7A, bytes(size))),
                f"HOTP IMF rejects {size}-byte input instead of required four bytes",
            )
        reject(
            0x6A80,
            lambda: send(1, put_data(algorithm=0x21) + Tlv(0x7A, bytes(4))),
            "TOTP credential rejects HOTP-only IMF even when four bytes",
        )
        for label, body in (
            ("empty name", put_data(b"")),
            ("65-byte name", put_data(b"n" * 65)),
            ("missing name", Tlv(0x73, b"\x11\x06" + bytes(20))),
            ("missing key", Tlv(0x71, b"missing")),
            ("duplicate name", raw + Tlv(0x71, b"duplicate")),
            ("duplicate key", raw + Tlv(0x73, b"\x11\x06" + bytes(20))),
            ("duplicate IMF", raw + Tlv(0x7A, bytes(4)) * 2),
            ("duplicate property", raw + b"\x78\x02\x78\x01"),
            ("unknown property bits", raw + b"\x78\x80"),
            ("truncated property", raw + b"\x78"),
            ("unknown TLV", raw + Tlv(0x7B, b"\x01")),
            ("truncated key", Tlv(0x71, b"broken") + b"\x73\x10\x11\x06"),
        ):
            reject(0x6A80, lambda body=body: send(1, body), "PUT rejects " + label)
        for ins in (1, 2, 3, 5, 0xA1, 0xA2, 0xA3, 0xA4):
            reject(
                0x6A86,
                lambda ins=ins: send(ins, p1=1),
                f"command {ins:02x} rejects nonzero P1",
            )
            reject(
                0x6A86,
                lambda ins=ins: send(ins, p2=2),
                f"command {ins:02x} rejects unsupported P2",
            )
        reject(
            0x6A80,
            lambda: send(0xA1, Tlv(0x71, b"unused")),
            "LIST rejects unexpected body",
        )
        reject(0x6A86, lambda: send(4), "RESET requires DE/AD header")
        reject(
            0x6A80,
            lambda: send(4, Tlv(0x71, b"unused"), 0xDE, 0xAD),
            "RESET rejects unexpected body",
        )
        reject(
            0x6984,
            lambda: send(0xA2, Tlv(0x71, b"missing") + Tlv(0x74, bytes(8))),
            "CALCULATE missing credential returns documented missing-object status",
        )
        reject(
            0x6984,
            lambda: send(2, Tlv(0x71, b"missing")),
            "DELETE missing credential returns documented missing-object status",
        )
        reject(
            0x6A80,
            lambda: send(0xA2, Tlv(0x71, b"missing")),
            "CALCULATE requires explicit challenge tag",
        )
        reject(
            0x6A80, lambda: send(0xA4), "CALCULATE ALL requires explicit challenge tag"
        )

        secret = b"12345678901234567890"
        initial_counter = 12345
        send(1, raw + b"\x78\x00" + Tlv(0x7A, initial_counter.to_bytes(4, "big")))
        result = send(
            0xA2, Tlv(0x71, b"raw HOTP") + Tlv(0x74, b"ignored HOTP challenge")
        )
        check(
            Tlv.unpack(0x75, result)
            == b"\x06"
            + hmac.digest(secret, initial_counter.to_bytes(8, "big"), "sha1"),
            "four-byte IMF initializes HOTP moving factor; raw full HMAC independently verifies",
        )
        connection = fixture.restart()
        oath = OathSession(connection)
        result = send(0xA2, Tlv(0x71, b"raw HOTP") + Tlv(0x74), p2=1)
        check(
            Tlv.unpack(0x76, result)
            == b"\x06"
            + truncate(
                hmac.digest(secret, (initial_counter + 1).to_bytes(8, "big"), "sha1")
            ),
            "HOTP counter persists restart and truncated response independently verifies",
        )

        totp_credentials = []
        for algorithm, size in (
            (HASH_ALGORITHM.SHA1, 20),
            (HASH_ALGORITHM.SHA256, 32),
            (HASH_ALGORITHM.SHA512, 64),
        ):
            vector_secret = (secret * 4)[:size]
            credential = oath.put_credential(
                CredentialData(
                    "RFC " + algorithm.name,
                    OATH_TYPE.TOTP,
                    algorithm,
                    vector_secret,
                    digits=8,
                )
            )
            totp_credentials.append((credential, vector_secret, algorithm))
            for timestamp, expected in zip(TIMES, RFC6238[algorithm], strict=True):
                check(
                    oath.calculate_code(credential, timestamp).value == expected,
                    f"RFC6238 {algorithm.name} vector at {timestamp}",
                )
            challenge = b"arbitrary public OATH challenge"
            check(
                oath.calculate(credential.id, challenge)
                == hmac.digest(vector_secret, challenge, algorithm.name.lower()),
                f"SDK full {algorithm.name} TOTP response matches independent arbitrary-challenge HMAC",
            )
            hotp = oath.put_credential(
                CredentialData(
                    "HOTP " + algorithm.name,
                    OATH_TYPE.HOTP,
                    algorithm,
                    vector_secret,
                    digits=8,
                    counter=17,
                )
            )
            for count in (17, 18):
                digest = hmac.digest(
                    vector_secret, count.to_bytes(8, "big"), algorithm.name.lower()
                )
                expected = f"{int.from_bytes(truncate(digest), 'big') % 100000000:08d}"
                check(
                    oath.calculate_code(hotp).value == expected,
                    f"independent {algorithm.name} HOTP at durable counter {count}",
                )

        touch_credential = oath.put_credential(
            CredentialData(
                "touch fixture", OATH_TYPE.TOTP, HASH_ALGORITHM.SHA1, secret
            ),
            touch_required=True,
        )
        before = EncryptedState(directory / "state.bin").data["oath"]["credentials"]
        challenge = (59 // 30).to_bytes(8, "big")
        for p2 in (0, 1):
            items = Tlv.parse_list(send(0xA4, Tlv(0x74, challenge), p2=p2))
            pairs = {items[i].value: items[i + 1] for i in range(0, len(items), 2)}
            check(
                pairs[b"raw HOTP"].tag == 0x77
                and pairs[touch_credential.id].tag == 0x7C,
                f"CALCULATE ALL mode {p2} reports HOTP/touch placeholders",
            )
            for credential, vector_secret, algorithm in totp_credentials:
                digest = hmac.digest(vector_secret, challenge, algorithm.name.lower())
                result = pairs[credential.id]
                check(
                    result.tag == (0x76 if p2 else 0x75)
                    and result.value == b"\x08" + (truncate(digest) if p2 else digest),
                    f"CALCULATE ALL mode {p2} {algorithm.name} independent response",
                )
        after = EncryptedState(directory / "state.bin").data["oath"]["credentials"]
        check(
            all(
                after[name]["counter"] == row["counter"] for name, row in before.items()
            ),
            "CALCULATE ALL placeholders never consume HOTP counters",
        )
        check(
            oath.calculate_code(touch_credential, 59).value == "287082",
            "explicit SDK touch-required calculation completes in opted-in test presence mode",
        )

        increasing_name = b"increasing"
        send(1, put_data(increasing_name, 0x21) + b"\x78\x01")
        increasing_body = Tlv(0x71, increasing_name) + Tlv(0x74, (2).to_bytes(8, "big"))
        check(
            Tlv.unpack(0x75, send(0xA2, increasing_body))[1:]
            == hmac.digest(secret, (2).to_bytes(8, "big"), "sha1"),
            "only-increasing property accepts first challenge with independent HMAC",
        )
        connection = fixture.restart()
        oath = OathSession(connection)
        reject(
            0x6985,
            lambda: send(0xA2, increasing_body),
            "only-increasing challenge survives restart and rejects repeated value",
        )
        reject(
            0x6A80,
            lambda: send(0xA2, Tlv(0x71, increasing_name) + Tlv(0x74, bytes(7))),
            "only-increasing credential rejects malformed moving-factor length",
        )

        access_password = "local OATH 접근 코드"
        key = oath.derive_key(access_password)
        salt = bytes.fromhex(
            EncryptedState(directory / "state.bin").data["oath"]["salt"]
        )
        check(
            key
            == hashlib.pbkdf2_hmac("sha1", access_password.encode(), salt, 1000, 16),
            "independent PBKDF2-SHA1 verifies SDK access-key derivation from own SELECT salt",
        )
        for length in (7, 9):
            host_challenge = bytes(length)
            proof = hmac.digest(key, host_challenge, "sha1")
            reject(
                0x6A80,
                lambda host_challenge=host_challenge, proof=proof: send(
                    3,
                    Tlv(0x73, b"\x21" + key)
                    + Tlv(0x74, host_challenge)
                    + Tlv(0x75, proof),
                ),
                f"SET CODE rejects {length}-byte authentication challenge",
            )
        reject(
            0x6984,
            lambda: send(
                3, Tlv(0x73, b"\x21" + key) + Tlv(0x74, bytes(8)) + Tlv(0x75, bytes(20))
            ),
            "SET CODE incorrect proof returns documented mismatch status",
        )
        for length in (19, 21):
            reject(
                0x6A80,
                lambda length=length: send(
                    3,
                    Tlv(0x73, b"\x21" + key)
                    + Tlv(0x74, bytes(8))
                    + Tlv(0x75, bytes(length)),
                ),
                f"SET CODE rejects {length}-byte proof instead of SHA1 length",
            )
        reject(
            0x6A80,
            lambda: send(3, Tlv(0x73) + Tlv(0x74, bytes(8))),
            "access-code removal rejects unexpected challenge body",
        )
        oath.set_key(key)
        oath = OathSession(connection)
        reject(
            0x6982,
            oath.list_credentials,
            "reselected OATH session requires access-code validation",
        )
        for length in (7, 9):
            oath = OathSession(connection)
            result = send(
                0xA3,
                Tlv(0x75, hmac.digest(key, oath._challenge, "sha1"))
                + Tlv(0x74, bytes(length)),
            )
            check(
                Tlv.unpack(0x75, result) == hmac.digest(key, bytes(length), "sha1"),
                f"VALIDATE authenticates {length}-byte host challenge using independent HMAC",
            )
        oath = OathSession(connection)
        for length in (19, 21):
            reject(
                0x6A80,
                lambda length=length: send(
                    0xA3, Tlv(0x75, bytes(length)) + Tlv(0x74, bytes(8))
                ),
                f"VALIDATE rejects {length}-byte proof without consuming card challenge",
            )
        reject(
            0x6982,
            lambda: oath.validate(b"wrong key value!"),
            "incorrect access key leaves OATH session locked",
        )
        oath.validate(key)
        check(
            len(oath.list_credentials()) == len(after) + 1,
            "valid mutual SDK proof unlocks unchanged credentials after malformed attempts",
        )
        oath.unset_key()
        oath = OathSession(connection)
        check(
            not oath.has_key and len(oath.list_credentials()) == len(after) + 1,
            "SDK removes access code using empty KEY tag without deleting credentials",
        )

        piv = PivSession(connection)
        retained_issuer = piv.get_certificate(SLOT.ATTESTATION).fingerprint(
            hashes.SHA256()
        )
        oath = OathSession(connection)
        previous_id = oath.device_id
        oath.set_key(key)
        oath = OathSession(connection)
        oath.reset()
        check(
            not oath.has_key
            and not oath.list_credentials()
            and oath.device_id != previous_id,
            "RESET is permitted while locked, clears OATH credentials/access code and rotates own salt",
        )
        piv = PivSession(connection)
        check(
            piv.get_certificate(SLOT.ATTESTATION).fingerprint(hashes.SHA256())
            == retained_issuer,
            "OATH application reset preserves PIV own F9 issuer",
        )
        oath = OathSession(connection)
        for i in range(64):
            oath.put_credential(
                CredentialData(
                    f"capacity {i:02d}",
                    OATH_TYPE.HOTP,
                    HASH_ALGORITHM.SHA1,
                    secret,
                    counter=i,
                )
            )
        check(
            len(oath.list_credentials()) == 64,
            "firmware-5.7 published capacity accepts 64 OATH credentials",
        )
        reject(
            0x6A84,
            lambda: oath.put_credential(
                CredentialData(
                    "capacity overflow", OATH_TYPE.HOTP, HASH_ALGORITHM.SHA1, secret
                )
            ),
            "65th OATH credential returns documented no-space status",
        )
        replacement = oath.put_credential(
            CredentialData(
                "capacity 00", OATH_TYPE.HOTP, HASH_ALGORITHM.SHA256, secret, counter=9
            )
        )
        check(
            len(oath.list_credentials()) == 64
            and oath.calculate_code(replacement).value
            == f"{int.from_bytes(truncate(hmac.digest(secret, (9).to_bytes(8, 'big'), 'sha256')), 'big') % 1000000:06d}",
            "overwrite at full capacity succeeds and installs new algorithm/moving factor",
        )
        renamed_id = oath.rename_credential(replacement.id, "renamed full store")
        check(
            len(oath.list_credentials()) == 64
            and renamed_id in [row.id for row in oath.list_credentials()],
            "rename at full capacity does not allocate a new credential slot",
        )
        oath.delete_credential(renamed_id)
        oath.put_credential(
            CredentialData(
                "released capacity", OATH_TYPE.TOTP, HASH_ALGORITHM.SHA512, secret
            )
        )
        connection = fixture.restart()
        oath = OathSession(connection)
        check(
            len(oath.list_credentials()) == 64
            and b"released capacity" in [row.id for row in oath.list_credentials()],
            "deletion releases one slot and full capacity survives process restart",
        )
        passed = True
    finally:
        fixture.stop()
        report.write_text(
            json.dumps(
                {
                    "passed": passed,
                    "tests": tests,
                    "scope": "fresh software card; independent SDK/RFC/HMAC over direct IFD ABI"
                    if ifd_driver
                    else "fresh software card; independent SDK/RFC/HMAC over private CCID socket",
                    "physical_device_access": False,
                    "firmware_differential_verified": False,
                    "published_capacity": 64,
                    "unverified": [
                        "reference malformed-input rejection/order and unknown/duplicate tag tolerance",
                        "reference maximum HMAC-key/challenge lengths and counter rollover",
                        "actual OS PC/SC discovery and physical touch timing",
                    ],
                },
                indent=2,
            )
            + "\n"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--ifd-driver", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(
        prefix="ske-oathprof-", dir=args.work_dir or "/tmp"
    ) as directory:
        run(
            Path(__file__).resolve().parents[1],
            Path(directory),
            args.report.resolve(),
            args.ifd_driver,
        )


if __name__ == "__main__":
    main()
