#!/usr/bin/env python3
"""Read only public OpenPGP capability metadata from a physical reference key.

Explicit opt-in; SELECT, GET VERSION, GET DATA and GET RESPONSE only. Never use
OpenPgpSession here: that SDK can ACTIVATE an inactive physical application.
No PIN command, reset, activation, credential or configuration write is allowed.
"""

from __future__ import annotations

import argparse
import datetime
import json
from pathlib import Path

from cryptography import x509
from smartcard.scard import SCARD_LEAVE_CARD, SCARD_SHARE_SHARED
from smartcard.System import readers
from yubikit.core import Tlv
from yubikit.openpgp import ExtendedCapabilities

PUBLIC_OBJECTS = (0xC0, 0x5F52, 0x7F66, 0x7F74)


def observe(
    include_algorithm_info=False,
    include_security_support=False,
    include_attestation_schema=False,
):
    candidates = [reader for reader in readers() if "yubikey" in str(reader).lower()]
    if len(candidates) != 1:
        raise RuntimeError(
            f"Expected one YubiKey PC/SC reader; found {len(candidates)}"
        )
    connection = candidates[0].createConnection()
    commands = []

    def exchange(command):
        instruction = command[1]
        allowed = instruction == 0xA4 and command == bytes.fromhex(
            "00a4040006d2760001240100"
        )
        allowed |= instruction == 0xF1 and command == bytes.fromhex("00f1000000")
        allowed |= (
            instruction == 0xCA
            and len(command) == 5
            and int.from_bytes(command[2:4], "big")
            in (
                *PUBLIC_OBJECTS,
                0x6E,
                *((0xFA,) if include_algorithm_info else ()),
                *((0x7A,) if include_security_support else ()),
                *((0xFC,) if include_attestation_schema else ()),
            )
        )
        if not allowed:
            raise AssertionError(
                "Physical command outside public observation allowlist"
            )
        response, high, low = connection.transmit(list(command))
        data = bytes(response)
        sw = high * 256 + low
        while high == 0x61:
            if len(data) >= 4096:
                raise RuntimeError(
                    "Public capability response exceeds observation budget"
                )
            remainder, high, low = connection.transmit([0, 0xC0, 0, 0, low])
            data += bytes(remainder)
            sw = high * 256 + low
        commands.append(
            {
                "command": command.hex(),
                "status": f"{sw:04x}",
                "response_bytes": len(data),
            }
        )
        return data, sw

    def get_data(oid):
        return exchange(bytes([0, 0xCA, oid >> 8, oid & 0xFF, 0]))

    try:
        connection.connect(mode=SCARD_SHARE_SHARED, disposition=SCARD_LEAVE_CARD)
        _, sw = exchange(bytes.fromhex("00a4040006d2760001240100"))
        if sw != 0x9000:
            raise RuntimeError(
                f"Reference OpenPGP SELECT status {sw:04x}; no activation/reset attempted"
            )
        version, sw = exchange(bytes.fromhex("00f1000000"))
        if sw != 0x9000 or version != b"\x05\x07\x04":
            raise RuntimeError("Reference firmware is not expected profile 5.7.4")
        objects = {}
        for oid in PUBLIC_OBJECTS:
            value, sw = get_data(oid)
            if sw == 0x9000:
                objects[f"{oid:x}"] = value.hex()
        layout = {}
        related_public_fields = {}
        algorithm_attributes = {}
        if "c0" not in objects:
            application, sw = get_data(0x6E)
            if sw != 0x9000:
                raise RuntimeError("Cannot read public capability template")
            data = Tlv.parse_dict(Tlv.unpack(0x6E, application))
            discretionary = Tlv.parse_dict(data[0x73])
            objects["c0"] = discretionary[0xC0].hex()
            layout = {
                "top_level_value_lengths": {
                    f"{tag:x}": len(value) for tag, value in data.items()
                },
                "discretionary_value_lengths": {
                    f"{tag:x}": len(value) for tag, value in discretionary.items()
                },
            }
            related_public_fields = {
                f"{tag:x}": data[tag].hex()
                for tag in (0x5F52, 0x7F66, 0x7F74)
                if tag in data
            }
            related_public_fields["discretionary_7f66"] = discretionary[0x7F66].hex()
            algorithm_attributes = {
                f"{tag:x}": discretionary[tag].hex()
                for tag in (0xC1, 0xC2, 0xC3, 0xDA)
                if tag in discretionary
            }
            for oid in (0x5F52, 0x7F66, 0x7F74):
                if f"{oid:x}" not in objects and oid in data:
                    objects[f"{oid:x}"] = data[oid].hex()
            # The complete template also contains identity and key metadata.
            # Retain only the four public capability fields, never the payload.
        caps = ExtendedCapabilities.parse(bytes.fromhex(objects["c0"]))
        result = {
            "observed_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "firmware_version": [5, 7, 4],
            "transport": "native system PC/SC; shared access; SCARD_LEAVE_CARD on disconnect",
            "public_objects": objects,
            "application_related_layout": layout,
            "application_related_public_fields": related_public_fields,
            "algorithm_attributes": algorithm_attributes,
            "extended_capabilities": {
                "flags": int(caps.flags),
                "sm_algorithm": caps.sm_algorithm,
                "challenge_max_length": caps.challenge_max_length,
                "certificate_max_length": caps.certificate_max_length,
                "special_do_max_length": caps.special_do_max_length,
                "pin_block_2_format": caps.pin_block_2_format,
                "mse_command": caps.mse_command,
            },
            "commands": commands,
            "pin_attempts": 0,
            "credential_or_configuration_writes": False,
            "activation_or_reset_commands": False,
            "volatile_application_selection_changed": True,
            "serial_cardholder_fingerprint_payloads_retained": False,
            "scope": "public OpenPGP capabilities only; no storage-boundary, crypto, PIN or touch validation",
        }
        if include_algorithm_info:
            algorithms, sw = get_data(0xFA)
            if sw != 0x9000:
                raise RuntimeError(
                    f"Cannot read public algorithm information: {sw:04x}"
                )
            # FA consists solely of public algorithm attributes, with no serial,
            # fingerprint, certificate or user key payloads.
            entries = Tlv.parse_list(Tlv.unpack(0xFA, algorithms))
            if not all(item.tag in (0xC1, 0xC2, 0xC3, 0xDA) for item in entries):
                raise RuntimeError("Unexpected data in public algorithm information")
            result["algorithm_information"] = algorithms.hex()
        if include_security_support:
            support, sw = get_data(0x7A)
            if sw != 0x9000:
                raise RuntimeError(f"Cannot read public security support: {sw:04x}")
            fields = Tlv.parse_dict(Tlv.unpack(0x7A, support))
            if set(fields) != {0x93} or len(fields[0x93]) != 3:
                raise RuntimeError("Unexpected public security support layout")
            result["security_support_template_layout"] = {
                "outer_tag": "7a",
                "value_lengths": {"93": 3},
                "counter_payload_retained": False,
            }
        if include_attestation_schema:
            encoded, sw = get_data(0xFC)
            if sw != 0x9000:
                raise RuntimeError(f"Cannot read public attestation template: {sw:04x}")
            cert = x509.load_der_x509_certificate(encoded)
            schema = []
            expected = {
                1: 0x0C,
                2: 2,
                3: 4,
                4: 4,
                5: 4,
                6: 2,
                7: 2,
                8: 4,
                9: 4,
                10: 4,
                11: 4,
            }
            for extension in cert.extensions:
                oid = extension.oid.dotted_string
                if not oid.startswith("1.3.6.1.4.1.41482.5.") or not isinstance(
                    extension.value, x509.UnrecognizedExtension
                ):
                    continue
                value = extension.value.value
                tag = expected.get(int(oid.rsplit(".", 1)[1]))
                encoding, length = "raw value or unrecognized encoding", len(value)
                if tag is not None:
                    try:
                        payload = Tlv.unpack(tag, value)
                    except ValueError:
                        pass
                    else:
                        encoding, length = f"DER tag {tag:02x}", len(payload)
                schema.append(
                    {
                        "oid": oid,
                        "critical": extension.critical,
                        "encoding": encoding,
                        "payload_length": length,
                    }
                )
            result["attestation_template_public_schema"] = {
                "certificate_bytes": len(encoded),
                "extensions": schema,
                "certificate_serial_subject_public_key_dates_and_payloads_retained": False,
                "scope": "template extension structure only; not a generated attestation statement",
            }
        return result
    finally:
        connection.disconnect()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--read-physical-reference", action="store_true")
    parser.add_argument("--include-algorithm-info", action="store_true")
    parser.add_argument("--include-security-support", action="store_true")
    parser.add_argument("--include-attestation-schema", action="store_true")
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    if not args.read_physical_reference:
        parser.error("Physical observation requires --read-physical-reference")
    report = observe(
        args.include_algorithm_info,
        args.include_security_support,
        args.include_attestation_schema,
    )
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
