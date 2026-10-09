#!/usr/bin/env python3
"""Read CTAP GetInfo from the attached YubiKey; no PIN or credential operations.

This tool sends CTAPHID INIT and authenticatorGetInfo only. Serial numbers and
opaque privacy identifiers are omitted from the saved public capability record.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import json
from pathlib import Path

from fido2 import cbor
from fido2.ctap2 import Info
from fido2.hid import CTAPHID, CtapHidDevice


def safe_value(value):
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {str(key): safe_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [safe_value(item) for item in value]
    return value


def observe():
    devices = []
    try:
        # Keep each opened device reachable even if enumeration later raises.
        for device in CtapHidDevice.list_devices():
            devices.append(device)  # noqa: PERF402
        matches = []
        for device in devices:
            descriptor = device.descriptor
            if descriptor.vid != 0x1050:
                continue
            response = device.call(CTAPHID.CBOR, b"\x04")
            if not response or response[0]:
                continue
            raw = cbor.decode(response[1:])
            info = Info.from_dict(raw)
            # Public AAGUID from the reference already observed in this project.
            if str(info.aaguid) != "ff4dac45-ede8-4ec2-aced-cf66103f4335":
                continue
            excluded = {"enc_identifier", "enc_cred_store_state"}
            fields = {
                field.name: safe_value(getattr(info, field.name))
                for index, field in enumerate(dataclasses.fields(info), 1)
                if index in raw and field.name not in excluded
            }
            matches.append(
                {
                    "product": descriptor.product_name,
                    "vid": descriptor.vid,
                    "pid": descriptor.pid,
                    "get_info_fields": fields,
                    "present_cbor_keys": sorted(raw),
                }
            )
        if len(matches) != 1:
            raise RuntimeError(
                f"expected one attached reference YubiKey, observed {len(matches)}"
            )
        return {
            "observed_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "reference": matches[0],
            "commands_sent": ["CTAPHID_INIT", "authenticatorGetInfo"],
            "pin_attempts_performed": 0,
            "credential_mutations_performed": 0,
            "device_config_writes_performed": 0,
            "serial_number_saved": False,
        }
    finally:
        for device in devices:
            device.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument(
        "--read-physical-reference",
        action="store_true",
        required=True,
        help="explicitly select the read-only attached reference operation",
    )
    args = parser.parse_args()
    record = observe()
    args.report.write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()
