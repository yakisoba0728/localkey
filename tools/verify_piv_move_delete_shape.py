#!/usr/bin/env python3
"""A/B PIV MOVE/DELETE KEY APDU shape over an owned private card service."""

import argparse
import copy
import hashlib
import json
import sys
import tempfile
from pathlib import Path

from yubikit.piv import DEFAULT_MANAGEMENT_KEY, KEY_TYPE, SLOT, PivSession


CASES = (
    ("move_extra_data", bytes.fromhex("00f6829a0101"), "move"),
    ("move_explicit_le", bytes.fromhex("00f6829a01"), "move"),
    ("delete_extra_data", bytes.fromhex("00f6ff9a0101"), "delete"),
    ("delete_explicit_le", bytes.fromhex("00f6ff9a01"), "delete"),
)


def run(root: Path, driver: Path | None, fixed: bool):
    sys.path.insert(0, str(root))
    sys.path.insert(0, str(root / "tools"))
    from verify_smartcard import Fixture
    from emucard.core import EncryptedState

    rows = []
    for name, command, operation in CASES:
        with tempfile.TemporaryDirectory(prefix="ske60-piv-f6-", dir="/tmp") as temporary:
            directory = Path(temporary)
            fixture = Fixture(root, directory, driver)
            try:
                connection = fixture.start()
                piv = PivSession(connection)
                piv.authenticate(DEFAULT_MANAGEMENT_KEY)
                piv.generate_key(SLOT.AUTHENTICATION, KEY_TYPE.ECCP256)
                before = copy.deepcopy(EncryptedState(directory / "state.bin").data["piv"]["keys"])
                assert str(int(SLOT.AUTHENTICATION)) in before
                _, sw = connection.send_and_receive(command)
                assert sw == (0x6700 if fixed else 0x9000), (name, hex(sw))
                after = copy.deepcopy(EncryptedState(directory / "state.bin").data["piv"]["keys"])
                assert (after == before) == fixed, name
                if not fixed:
                    assert str(int(SLOT.AUTHENTICATION)) not in after
                    assert (str(int(SLOT.RETIRED1)) in after) == (operation == "move")
                else:
                    piv = PivSession(fixture.restart())
                    assert piv.get_slot_metadata(SLOT.AUTHENTICATION).key_type == KEY_TYPE.ECCP256
                    piv.authenticate(DEFAULT_MANAGEMENT_KEY)
                    piv.move_key(SLOT.AUTHENTICATION, SLOT.RETIRED1)
                    assert piv.get_slot_metadata(SLOT.RETIRED1).key_type == KEY_TYPE.ECCP256
                    piv.delete_key(SLOT.RETIRED1)
                    try:
                        piv.get_slot_metadata(SLOT.RETIRED1)
                    except Exception as error:
                        assert getattr(error, "sw", None) == 0x6A88
                    else:
                        raise AssertionError("SDK delete left the key present")
                rows.append({"name": name, "command_hex": command.hex(),
                             "sw": f"{sw:04x}", "malformed_state_unchanged": fixed,
                             "normal_sdk_move_delete_after_restart": fixed,
                             "passed": True})
            finally:
                fixture.stop()
    return {"passed": True, "fixed": fixed,
            "route": "direct IFD" if driver else "private CCID socket",
            "rows": rows,
            "core_sha256": hashlib.sha256((root / "emucard/core.py").read_bytes()).hexdigest(),
            "physical_or_host_device_access": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--ifd", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--fixed", action="store_true")
    arguments = parser.parse_args()
    result = run(arguments.root.resolve(), arguments.ifd.resolve() if arguments.ifd else None,
                 arguments.fixed)
    arguments.report.parent.mkdir(parents=True, exist_ok=True)
    arguments.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
