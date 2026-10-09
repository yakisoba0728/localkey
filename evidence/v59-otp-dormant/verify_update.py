#!/usr/bin/env python3
"""YubiKit OTP dormant/update A/B over an owned private CCID Unix socket."""

import argparse
import hashlib
import hmac
import json
import sys
import tempfile
from pathlib import Path

from yubikit.core.smartcard import ApduError
from yubikit.yubiotp import (
    HmacSha1SlotConfiguration,
    SLOT,
    UpdateConfiguration,
    YubiOtpSession,
)


HERE = Path(__file__).resolve().parent
KEY = bytes(range(20))
CHALLENGE = b"v59-dormant"


def outcome(call):
    try:
        call()
    except ApduError as error:
        return f"rejected:{error.sw:04x}"
    return "accepted"


def scenario(root, initial_dormant, initial_updatable, expected):
    sys.path.insert(0, str(root))
    from tools.verify_smartcard import Fixture

    with tempfile.TemporaryDirectory(prefix="v59otp-", dir="/tmp") as tmp:
        fixture = Fixture(root, Path(tmp))
        connection = fixture.start()
        try:
            sdk = YubiOtpSession(connection)
            config = HmacSha1SlotConfiguration(KEY).allow_update(initial_updatable)
            config.dormant(initial_dormant)
            sdk.put_configuration(SLOT.ONE, config)
            before = sdk._status[3]
            initial_hmac = outcome(lambda: sdk.calculate_hmac_sha1(SLOT.ONE, CHALLENGE))
            if initial_dormant:
                assert initial_hmac == "rejected:6985", initial_hmac
            else:
                assert initial_hmac == "accepted", initial_hmac
            requested_dormant = not initial_dormant
            # The protocol aliases pacing-10ms and HMAC_LT64 to the same CFG
            # bit; retain it so the independent short-challenge HMAC remains
            # comparable before and after this settings update.
            update = UpdateConfiguration().dormant(requested_dormant).pacing(True, False)
            updated = outcome(lambda: sdk.update_configuration(SLOT.ONE, update))
            assert updated == expected, (initial_dormant, updated)
            fresh = YubiOtpSession(connection)
            after = fresh._status[3]
            assert after == before + (1 if expected == "accepted" else 0)
            assert fresh.get_config_state().is_configured(SLOT.ONE)
            final_hmac = outcome(lambda: fresh.calculate_hmac_sha1(SLOT.ONE, CHALLENGE))
            if initial_dormant and expected == "accepted":
                assert final_hmac == "accepted", final_hmac
                got = fresh.calculate_hmac_sha1(SLOT.ONE, CHALLENGE)
                want = hmac.digest(KEY, CHALLENGE, "sha1")
                assert got == want, (got.hex(), want.hex())
            elif initial_dormant or expected == "accepted":
                assert final_hmac == "rejected:6985", final_hmac
            else:
                assert final_hmac == "accepted", final_hmac
                assert fresh.calculate_hmac_sha1(SLOT.ONE, CHALLENGE) == hmac.digest(
                    KEY, CHALLENGE, "sha1"
                )
            return {"initial_dormant": initial_dormant,
                    "initial_allow_update": initial_updatable,
                    "requested_dormant": requested_dormant,
                    "initial_hmac": initial_hmac,
                    "update": updated, "sequence_before": before,
                    "sequence_after": after, "final_hmac": final_hmac,
                    "passed": True}
        finally:
            fixture.stop()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--variant", choices=("baseline", "fixed"), required=True)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    root = HERE / args.variant
    fixed = args.variant == "fixed"
    checks = [
        scenario(root, False, True, "accepted" if fixed else "rejected:6985"),
        scenario(root, True, False, "accepted" if fixed else "rejected:6985"),
        scenario(root, False, False, "rejected:6985"),
    ]
    result = {
        "variant": args.variant,
        "platform": sys.platform,
        "source_sha256": hashlib.sha256((root / "emucard/core.py").read_bytes()).hexdigest(),
        "unmodified_yubikit": True,
        "private_unix_ccid": True,
        "physical_or_host_device_access": False,
        "firmware_5_7_4_differential": False,
        "checks": checks,
    }
    args.result.write_text(json.dumps(result, indent=2) + "\n")
    print(f"{len(checks)}/{len(checks)} {args.variant} dormant update checks passed")


if __name__ == "__main__":
    main()
