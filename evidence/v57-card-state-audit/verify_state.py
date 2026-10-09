#!/usr/bin/env python3
"""Software-only OATH/HSM Auth APDU session-transition probe."""

import json
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parent / "baseline"
sys.path.insert(0, str(root))

from tools.verify_smartcard import Fixture  # noqa: E402
from yubikit.core import InvalidPinError  # noqa: E402
from yubikit.hsmauth import HsmAuthSession  # noqa: E402
from yubikit.oath import OathSession  # noqa: E402


def main():
    checks = []

    def check(name, passed):
        checks.append({"name": name, "passed": bool(passed)})
        if not passed:
            raise AssertionError(name)

    with tempfile.TemporaryDirectory(prefix="v57s", dir="/tmp") as directory:
        fixture = Fixture(root, Path(directory))
        connection = fixture.start()
        try:
            key = b"k" * 16
            oath = OathSession(connection)
            oath.set_key(key)
            check("OATH access key set in current SDK session", oath.has_key)
            oath = OathSession(connection)
            check("OATH SELECT requires authentication", oath.locked)
            oath.validate(key)
            check("OATH authenticates with challenge response", not oath.locked)

            hsm = HsmAuthSession(connection)
            check("HSM Auth selection succeeds", hsm.version == (5, 7, 4))
            oath = OathSession(connection)
            check("OATH loses authentication after app deselection", oath.locked)
            oath.validate(key)
            check("OATH can authenticate again", not oath.locked)

            hsm = HsmAuthSession(connection)
            hsm.put_credential_symmetric(
                bytes(16), "v57-state", b"a" * 16, b"b" * 16, "password"
            )
            check("HSM Auth credential created", len(hsm.list_credentials()) == 1)
            try:
                hsm.calculate_session_keys_symmetric(
                    "v57-state", bytes(range(16)), "incorrect"
                )
            except InvalidPinError as error:
                check("HSM Auth wrong password decrements retries", error.attempts_remaining == 7)
            else:
                check("HSM Auth wrong password rejected", False)
            OathSession(connection)
            hsm = HsmAuthSession(connection)
            check("HSM Auth retries persist across SELECT", hsm.list_credentials()[0].counter == 7)

            _, status = connection.send_and_receive(bytes.fromhex("00a4040005ffffffffff"))
            check("Unknown AID rejected", status == 0x6A82)
            hsm = HsmAuthSession(connection)
            check("HSM Auth retry count survives invalid SELECT", hsm.list_credentials()[0].counter == 7)
        finally:
            fixture.stop()

    result = {
        "passed": all(row["passed"] for row in checks),
        "checks": checks,
        "transport": "private Unix CCID socket",
        "host_pcsc_hid_keyboard_access": False,
        "physical_device_access": False,
        "firmware_differential_verified": False,
    }
    target = Path(__file__).resolve().parent / "state.json"
    target.write_text(json.dumps(result, indent=2) + "\n")
    print(f"{sum(row['passed'] for row in checks)}/{len(checks)} passed")


if __name__ == "__main__":
    main()
