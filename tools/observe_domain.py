#!/usr/bin/env python3
"""Observe public Security Domain capabilities without authenticating a key.

Explicit opt-in. Only fixed SELECT, public GET DATA and bounded GET RESPONSE
APDUs are allowed. GET VERSION is permitted only in selected OpenPGP: the same
INS generates a key in Security Domain. No PIN, handshake, PSO or write command.
"""

from __future__ import annotations

import argparse
import datetime
import json
from pathlib import Path

from smartcard.scard import SCARD_LEAVE_CARD, SCARD_SHARE_SHARED
from smartcard.System import readers
from yubikit.core import Tlv

OPENPGP_SELECT = bytes.fromhex("00a4040006d2760001240100")
OPENPGP_VERSION = bytes.fromhex("00f1000000")
DOMAIN_SELECT = bytes.fromhex("00a4040008a00000015100000000")
PUBLIC_DATA = (0x66, 0xE0, 0x9F7F)
GP_OID_PREFIX = bytes.fromhex("2a864886fc6b")


def layout(encoded):
    """Keep tag/length structure, never SELECT identity values."""
    result = []
    for field in Tlv.parse_list(encoded):
        entry = {"tag": f"{field.tag:x}", "value_length": len(field.value)}
        tag_bytes = field.tag.to_bytes((field.tag.bit_length() + 7) // 8, "big")
        if tag_bytes[0] & 0x20:
            entry["fields"] = layout(field.value)
        result.append(entry)
    return result


def public_recognition(encoded):
    """Reject unexpected identifying fields before retaining standard GP OIDs."""
    allowed_constructed = {0x73, 0x60, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68}

    def walk(data):
        for field in Tlv.parse_list(data):
            if field.tag == 6:
                if not field.value.startswith(GP_OID_PREFIX):
                    raise RuntimeError("Recognition contains an unexpected OID")
            elif field.tag in allowed_constructed:
                walk(field.value)
            else:
                raise RuntimeError("Recognition contains a non-public-profile field")

    Tlv.unpack(0x73, encoded)
    walk(encoded)
    return encoded.hex()


def public_select(encoded):
    # Retain this response only when all bytes are the fixed public application
    # AID and standard GP recognition OID; unknown values never reach the report.
    expected = Tlv(
        0x6F,
        Tlv(0x84, bytes.fromhex("a000000151000000"))
        + Tlv(0xA5, Tlv(0x73, Tlv(6, GP_OID_PREFIX + b"\1"))),
    )
    if encoded != expected:
        raise RuntimeError("SELECT contains a non-public-profile value")
    return encoded.hex()


def key_schema(encoded):
    rows = []
    for field in Tlv.parse_list(encoded):
        value = Tlv.unpack(0xC0, field)
        if len(value) < 4 or len(value) % 2:
            raise RuntimeError("Unexpected key information layout")
        rows.append(
            {
                "tag": "c0",
                "value_length": len(value),
                "type_lengths": [
                    {"type": f"{kind:02x}", "length": length}
                    for kind, length in zip(value[2::2], value[3::2])
                ],
            }
        )
    return {"entries": rows, "key_reference_values_retained": False}


def observe():
    candidates = [reader for reader in readers() if "yubikey" in str(reader).lower()]
    if len(candidates) != 1:
        raise RuntimeError(
            f"Expected one YubiKey PC/SC reader; found {len(candidates)}"
        )
    connection = candidates[0].createConnection()
    selected = None
    commands = []

    def exchange(command):
        nonlocal selected
        allowed = command in (OPENPGP_SELECT, DOMAIN_SELECT)
        allowed |= command == OPENPGP_VERSION and selected == "openpgp"
        allowed |= (
            selected == "domain"
            and len(command) == 5
            and command[0:2] == b"\0\xca"
            and command[4] == 0
            and int.from_bytes(command[2:4], "big") in PUBLIC_DATA
        )
        if not allowed:
            raise AssertionError(
                "Physical command outside public observation allowlist"
            )
        response, high, low = connection.transmit(list(command))
        data = bytes(response)
        continuations = 0
        while high == 0x61:
            if len(data) >= 4096 or continuations >= 32:
                raise RuntimeError("Public response exceeds observation budget")
            response, high, low = connection.transmit([0, 0xC0, 0, 0, low])
            data += bytes(response)
            continuations += 1
        if len(data) > 4096:
            raise RuntimeError("Public response exceeds observation budget")
        sw = high * 256 + low
        if command == OPENPGP_SELECT:
            selected = "openpgp" if sw == 0x9000 else None
        elif command == DOMAIN_SELECT:
            selected = "domain" if sw == 0x9000 else None
        commands.append(
            {
                "command": command.hex(),
                "status": f"{sw:04x}",
                "response_bytes": len(data),
                "get_response_count": continuations,
            }
        )
        return data, sw

    try:
        connection.connect(mode=SCARD_SHARE_SHARED, disposition=SCARD_LEAVE_CARD)
        _, sw = exchange(OPENPGP_SELECT)
        if sw != 0x9000:
            raise RuntimeError(
                "Cannot select OpenPGP; no activation or reset attempted"
            )
        version, sw = exchange(OPENPGP_VERSION)
        if sw != 0x9000 or version != b"\x05\x07\x04":
            raise RuntimeError("Reference firmware is not expected profile 5.7.4")
        selected_data, sw = exchange(DOMAIN_SELECT)
        if sw != 0x9000:
            raise RuntimeError(f"Cannot select Security Domain: {sw:04x}")
        result = {
            "observed_utc": datetime.datetime.now(datetime.UTC).isoformat(),
            "firmware_version": [5, 7, 4],
            "transport": "native system PC/SC; shared access; SCARD_LEAVE_CARD",
            "select_layout": layout(selected_data),
            "select_public_template": public_select(selected_data),
        }
        for tag in PUBLIC_DATA:
            data, sw = exchange(bytes([0, 0xCA, tag >> 8, tag & 255, 0]))
            if sw != 0x9000:
                continue
            if tag == 0x66:
                result["card_recognition_data"] = public_recognition(data)
            elif tag == 0xE0:
                result["key_information_schema"] = key_schema(data)
            else:
                # The remaining CPLC bytes are a per-card identifier. Discard.
                result["cplc_schema"] = {
                    "response_length": len(data),
                    "platform_prefix": data[:2].hex(),
                    "identifier_payload_retained": False,
                }
        result.update(
            commands=commands,
            pin_attempts=0,
            handshake_or_pso_commands=False,
            credential_or_configuration_writes=False,
            activation_or_reset_commands=False,
            volatile_application_selection_changed=True,
            reader_name_serial_certificates_public_keys_or_cplc_identity_retained=False,
            scope="public recognition bytes and SELECT/key/CPLC schema only; no authentication, retry, capacity or authorization measurement",
        )
        return result
    finally:
        connection.disconnect()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--read-physical-reference", action="store_true")
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    if not args.read_physical_reference:
        parser.error("Physical observation requires --read-physical-reference")
    report = observe()
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
