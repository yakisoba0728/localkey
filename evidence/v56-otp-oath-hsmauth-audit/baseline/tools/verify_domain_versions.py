#!/usr/bin/env python3
"""Verify all documented SCP03 versions with fresh software keys and own crypto.

No physical reader is enumerated or opened. Card retry/reset behavior remains a
software model; SCP03's 1..254 custom range is from the published Yubico manual.
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import algorithms
from verify_smartcard import Fixture
from yubikit.core.smartcard import ApduError
from yubikit.core.smartcard.scp import (
    KeyRef,
    Scp03KeyParams,
    Scp11KeyParams,
    StaticKeys,
)
from yubikit.securitydomain import SecurityDomainSession

from emucard.core import EncryptedState


def own_keys():
    return StaticKeys(os.urandom(16), os.urandom(16), os.urandom(16))


def gp_derive(key, constant, context, bits=128):
    # Independent AES-CMAC implementation of GP SCP03 section 4.1.5. No emulator
    # helper or SDK key-derivation function is used for the card cryptogram check.
    block = bytes(11) + bytes([constant, 0]) + bits.to_bytes(2, "big") + b"\1" + context
    mac = cmac.CMAC(algorithms.AES(key))
    mac.update(block)
    return mac.finalize()[: bits // 8]


def run(root, directory, report, ifd_driver=None):
    fixture = Fixture(root, directory, ifd_driver)
    tests, verified_versions = [], []
    passed = False

    def check(value, label):
        if not value:
            raise AssertionError(label)
        tests.append({"name": label, "passed": True})
        print("PASS", label, flush=True)

    def saved():
        return EncryptedState(directory / "state.bin").data

    def denied(sw, operation, label):
        before = saved()
        try:
            operation()
        except ApduError as error:
            check(
                error.sw == sw and saved() == before,
                label + "; persistent state unchanged",
            )
        else:
            raise AssertionError("accepted: " + label)

    def authenticate(version=255, keys=None, *, requested=None):
        session = SecurityDomainSession(conn)
        session.authenticate(
            Scp03KeyParams(KeyRef(1, version if requested is None else requested), keys)
            if keys
            else Scp03KeyParams()
        )
        return session

    def init_response(requested, host):
        session = SecurityDomainSession(conn)
        return session.protocol.send_apdu(0x80, 0x50, requested, 0, host)

    def initialization(requested, actual, keys):
        host = os.urandom(8)
        response = init_response(requested, host)
        context = host + response[13:21]
        expected = gp_derive(gp_derive(keys.key_mac, 6, context), 0, context, 64)
        return (
            len(response) == 29
            and response[10:13] == bytes([actual, 3, 0x60])
            and hmac.compare_digest(expected, response[21:29])
        )

    try:
        conn = fixture.start()
        sd = authenticate()
        original = saved()
        cplc = sd.get_data(0x9F7F)
        original_b = original["domain"]["keys"]["1301"]
        probe = own_keys()
        denied(
            0x6A80,
            lambda: sd.put_key(KeyRef(1, 0), probe),
            "zero is invalid for custom SCP03 PUT KEY",
        )
        denied(
            0x6A80,
            lambda: sd.put_key(KeyRef(1, 255), probe),
            "factory SCP03 version 255 cannot be provisioned as custom",
        )
        for kid in (2, 3):
            denied(
                0x6A80,
                lambda kid=kid: sd.put_key(KeyRef(kid, 1), probe),
                f"SCP03 individual KID {kid} cannot be imported separately from its whole set",
            )
        check(
            saved()["domain"]["keys"] == original["domain"]["keys"],
            "invalid initial versions never remove the factory set or own SCP11b identity",
        )

        previous_version = 0
        for version in range(1, 255):
            keys = own_keys()
            sd.put_key(KeyRef(1, version), keys, replace_kvn=previous_version)
            expected_refs = {KeyRef(kid, version) for kid in (1, 2, 3)} | {
                KeyRef(0x13, 1)
            }
            check(
                set(sd.get_key_information()) == expected_refs,
                f"SCP03 KVN {version}: SDK PUT verifies all KCVs and complete key-table replacement",
            )
            check(
                initialization(version, version, keys),
                f"SCP03 KVN {version}: 29-byte INIT reports selected version/03/60 and independent AES-CMAC cryptogram",
            )
            sd = authenticate(version, keys)
            check(
                sd.get_data(0x9F7F) == cplc
                and saved()["domain"]["keys"][KeyRef(1, version).hex()]["retries"]
                == 64,
                f"SCP03 KVN {version}: unmodified SDK authenticates, decrypts, verifies response MAC and restores modeled retries",
            )
            verified_versions.append(version)
            previous_version = version
            if version in (127, 128, 254):
                before_restart = saved()
                conn = fixture.restart()
                sd = authenticate(version, keys)
                check(
                    set(sd.get_key_information()) == expected_refs
                    and sd.get_data(0x9F7F) == cplc,
                    f"SCP03 boundary KVN {version}: restart preserves keys, enumeration and own CPLC",
                )
                check(
                    saved()["domain"]["keys"] == before_restart["domain"]["keys"],
                    f"SCP03 boundary KVN {version}: no key material or certificate is replaced by restart",
                )
        high_keys = keys
        check(
            verified_versions == list(range(1, 255)),
            "all 254 documented custom SCP03 versions were independently imported and authenticated",
        )
        check(
            saved()["domain"]["keys"]["1301"] == original_b,
            "all 254 version rotations preserve the original own SCP11b key/certificate",
        )
        denied(
            0x6A80,
            lambda: sd.put_key(KeyRef(1, 0), own_keys(), replace_kvn=254),
            "replacement with zero version cannot delete its previous high-version set",
        )
        denied(
            0x6A80,
            lambda: sd.put_key(KeyRef(1, 255), own_keys(), replace_kvn=254),
            "replacement with factory version cannot delete its previous high-version set",
        )

        # Mixed versions still share the documented three-set budget, and KVN=0
        # remains numeric highest-usable selection rather than a provisioned set.
        low_keys, middle_keys = own_keys(), own_keys()
        sd.put_key(KeyRef(1, 1), low_keys)
        sd.put_key(KeyRef(1, 128), middle_keys)
        check(
            {ref.kvn for ref in sd.get_key_information() if ref.kid == 1}
            == {1, 128, 254},
            "low/high SCP03 versions coexist at documented three-set capacity",
        )
        denied(
            0x6A84,
            lambda: sd.put_key(KeyRef(1, 253), own_keys()),
            "fourth valid high-version SCP03 set is refused at capacity",
        )
        denied(
            0x6985,
            lambda: sd.put_key(KeyRef(1, 128), own_keys(), replace_kvn=254),
            "high-version replacement cannot collide with another stored version",
        )
        denied(
            0x6A88,
            lambda: sd.put_key(KeyRef(1, 253), own_keys(), replace_kvn=252),
            "high-version replacement of a missing set preserves all installed keys",
        )
        shifted_keys = own_keys()
        sd.put_key(KeyRef(1, 253), shifted_keys, replace_kvn=1)
        check(
            {ref.kvn for ref in sd.get_key_information() if ref.kid == 1}
            == {128, 253, 254},
            "full-capacity rotation from low to high SCP03 version is atomic",
        )
        check(
            initialization(0, 254, high_keys),
            "wildcard INIT UPDATE selects numeric highest KVN 254 with the correct independent cryptogram",
        )
        sd = authenticate(254, high_keys, requested=0)
        check(
            sd.get_data(0x9F7F) == cplc,
            "unmodified SDK authenticates KVN=0 against highest high-version static keys",
        )

        replacement_keys = own_keys()
        sd.put_key(KeyRef(1, 254), replacement_keys, replace_kvn=254)
        check(
            initialization(254, 254, replacement_keys),
            "same high-version rotation retains its reference with independently verified new key cryptogram",
        )
        sd = authenticate(254, replacement_keys)
        check(
            sd.get_data(0x9F7F) == cplc,
            "same-version replacement authenticates new keys without rotating Domain identity",
        )
        high_keys = replacement_keys
        sd.delete_key(kvn=253)
        check(
            {ref.kvn for ref in sd.get_key_information() if ref.kid == 1} == {128, 254},
            "high-version DELETE removes the complete set and frees capacity",
        )
        lower_keys = own_keys()
        sd.put_key(KeyRef(1, 127), lower_keys)
        check(
            set(sd.get_key_information()) >= {KeyRef(kid, 127) for kid in (1, 2, 3)},
            "capacity freed by high-version deletion accepts another complete custom set",
        )
        for version in (1, 253, 255):
            denied(
                0x6A88,
                lambda version=version: init_response(version, bytes(8)),
                f"removed or reserved SCP03 INIT version {version} does not consume another key's modeled retries",
            )
        sd = authenticate(254, high_keys)

        # The SCP03 expansion must not change SCP11's seven-bit key versions.
        private = ec.generate_private_key(ec.SECP256R1())
        for kid in (0x11, 0x13, 0x15):
            pub = sd.generate_ec_key(KeyRef(kid, 127))
            check(
                pub.key_size == 256 and KeyRef(kid, 127) in sd.get_key_information(),
                f"SCP11 KID {kid:02x} retains maximum seven-bit generation version 127",
            )
            for invalid in (0, 128, 255):
                denied(
                    0x6A80,
                    lambda kid=kid, invalid=invalid: sd.generate_ec_key(
                        KeyRef(kid, invalid)
                    ),
                    f"SCP11 KID {kid:02x} generation still rejects version {invalid}",
                )
                denied(
                    0x6A80,
                    lambda kid=kid, invalid=invalid: sd.put_key(
                        KeyRef(kid, invalid), private
                    ),
                    f"SCP11 KID {kid:02x} private import still rejects version {invalid}",
                )
            if kid == 0x13:
                b_params = Scp11KeyParams(KeyRef(kid, 127), pub)
        for kid in (0x10, 0x20, 0x2F):
            sd.put_key(KeyRef(kid, 127), private.public_key())
            check(
                KeyRef(kid, 127) in sd.get_key_information(),
                f"SCP11 public KID {kid:02x} retains maximum version 127",
            )
            for invalid in (0, 128, 255):
                denied(
                    0x6A80,
                    lambda kid=kid, invalid=invalid: sd.put_key(
                        KeyRef(kid, invalid), private.public_key()
                    ),
                    f"SCP11 public KID {kid:02x} import still rejects version {invalid}",
                )
        b = SecurityDomainSession(conn)
        b.authenticate(b_params)
        check(
            b.get_data(0x9F7F) == cplc,
            "SCP11b version 127 still completes independent SDK key agreement and encrypted metadata read",
        )
        sd = authenticate(254, high_keys)

        # Blocking setup edits only this private software fixture, never a real
        # card. Highest blocked KVN must not mask a lower usable high-byte set.
        fixture.stop()
        state = EncryptedState(directory / "state.bin")
        state.data["domain"]["keys"]["01fe"]["retries"] = 0
        state.flush()
        conn = fixture.start()
        denied(
            0x6983,
            lambda: authenticate(254, high_keys),
            "explicit blocked KVN 254 cannot fall back to another set",
        )
        check(
            initialization(0, 128, middle_keys),
            "wildcard INIT skips blocked 254 and selects usable high-byte version 128",
        )
        sd = authenticate(128, middle_keys, requested=0)
        check(
            sd.get_data(0x9F7F) == cplc
            and saved()["domain"]["keys"]["01fe"]["retries"] == 0,
            "wildcard SDK channel uses 128 while preserving blocked 254 state",
        )
        before_reset = saved()
        sd.reset()
        denied(
            0x6982,
            sd.get_key_information,
            "mixed high-version SDK reset terminates its old authenticated channel",
        )
        sd = SecurityDomainSession(conn)
        check(
            set(sd.get_key_information())
            == {KeyRef(kid, 255) for kid in (1, 2, 3)} | {KeyRef(0x13, 1)},
            "SDK reset reaches all low/high/blocked SCP03 sets and restores fresh defaults",
        )
        check(
            sd.get_data(0x9F7F) != cplc
            and saved()["domain"]["keys"]["1301"] != original_b,
            "mixed-version modeled reset rotates own CPLC and independent SCP11b identity",
        )
        after_reset = saved()
        check(
            {k: v for k, v in before_reset.items() if k != "domain"}
            == {k: v for k, v in after_reset.items() if k != "domain"},
            "mixed-version Domain reset preserves all peer application state",
        )
        check(
            authenticate().get_key_information(),
            "fresh default SCP03 keys authenticate after mixed-version reset",
        )
        passed = True
    finally:
        fixture.stop()
        report.write_text(
            json.dumps(
                {
                    "passed": passed,
                    "tests": tests,
                    "verified_scp03_custom_versions": verified_versions,
                    "scp03_custom_range": [1, 254],
                    "scp03_factory_reserved_version": 255,
                    "scp11_custom_range": [1, 127],
                    "transport": "direct IFD ABI"
                    if ifd_driver
                    else "private CCID socket",
                    "physical_device_access": False,
                    "manufacturer_trust_reproduced": False,
                    "system_pcsc_reader_registered": False,
                    "scp03_range_source": "published Yubico SCP technical manual, Key Sets",
                    "init_key_information_option": "60; GP response field agrees with saved public recognition option",
                    "independent_crypto": "GP SCP03 AES-CMAC derivation and card cryptogram; unmodified SDK verifies encrypted PUT KCV and secure messaging",
                    "physical_init_response_measured": False,
                    "unverified": [
                        "physical key-version boundary/error responses and INIT response",
                        "exact hardware retry/deletion timing",
                        "native OS reader/browser conformance",
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
        prefix="ske-domain-versions-", dir=args.work_dir
    ) as directory:
        run(
            Path(__file__).resolve().parents[1],
            Path(directory),
            args.report,
            args.ifd_driver,
        )


if __name__ == "__main__":
    main()
