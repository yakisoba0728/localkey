"""Device configuration APDUs and OTP management commands, USB Nano profile."""

import hmac

from yubikit.core import Tlv
from yubikit.core.smartcard import AID

from .core import VERSION, fail, require, tlvs

SUPPORTED = 0x033B
APPLICATIONS = {
    AID.OTP: 1,
    AID.OPENPGP: 8,
    AID.PIV: 0x10,
    AID.OATH: 0x20,
    AID.HSMAUTH: 0x100,
}


def state(card):
    return card.state.data.setdefault(
        "management",
        {
            "enabled": SUPPORTED,
            "lock": "",
            "auto_eject": 0,
            "challenge_timeout": 15,
            "flags": 0,
        },
    )


def application_enabled(card, aid):
    flag = APPLICATIONS.get(aid)
    return flag is None or bool(state(card)["enabled"] & flag)


def read_config(card, page=0):
    require(page == 0, 0x6A86)
    d = state(card)
    data = (
        Tlv(1, SUPPORTED.to_bytes(2, "big"))
        + Tlv(2, bytes.fromhex(card.state.data["serial"]))
        + Tlv(3, d["enabled"].to_bytes(2, "big"))
        + Tlv(4, b"\x04")  # USB-C Nano, no hardware/factory certificate claim
        + Tlv(5, VERSION)
        + Tlv(6, d["auto_eject"].to_bytes(2, "big"))
        + Tlv(7, bytes([d["challenge_timeout"]]))
        + Tlv(8, bytes([d["flags"]]))
        + Tlv(0x0A, bytes([bool(d["lock"])]))
    )
    return bytes([len(data)]) + data


def write_config(card, data):
    require(data and data[0] == len(data) - 1, 0x6A80)
    fields = tlvs(data[1:])
    require(set(fields) <= {3, 6, 7, 8, 0x0A, 0x0B, 0x0C}, 0x6A80)
    d = state(card)
    if d["lock"]:
        require(hmac.compare_digest(fields.get(0x0B, b""), bytes.fromhex(d["lock"])))
    if 0x0B in fields:
        require(len(fields[0x0B]) == 16, 0x6A80)
    if 0x0A in fields:
        require(len(fields[0x0A]) == 16, 0x6A80)
        d["lock"] = fields[0x0A].hex() if any(fields[0x0A]) else ""
    if 3 in fields:
        require(len(fields[3]) == 2, 0x6A80)
        enabled = int.from_bytes(fields[3], "big")
        require(enabled and enabled & ~SUPPORTED == 0, 0x6A80)
        d["enabled"] = enabled
    if 6 in fields:
        require(len(fields[6]) == 2, 0x6A80)
        d["auto_eject"] = int.from_bytes(fields[6], "big")
    if 7 in fields:
        require(len(fields[7]) == 1, 0x6A80)
        d["challenge_timeout"] = fields[7][0]
    if 8 in fields:
        require(len(fields[8]) == 1 and fields[8][0] & ~0xC0 == 0, 0x6A80)
        d["flags"] = fields[8][0]
    if 0x0C in fields:
        require(not fields[0x0C], 0x6A80)
        # Private lifecycle metadata, committed/rolled back with the settings.
        # Never expose this counter as manufacturer device information.
        d["reboot_generation"] = (d.get("reboot_generation", 0) + 1) % (1 << 64)
        # Defer software-touch release to the committed power-reset boundary,
        # so an RPC flush failure does not release the writer's active touch.
        card.reset_session(preserve_otp_touch=True)
        card.reset_otp_power_after_commit = True
    # OTP clients observe the programming sequence on successful writes.
    card.state.data["otp"]["sequence"] = (card.state.data["otp"]["sequence"] + 1) % 256


def dispatch(card, apdu):
    if apdu.ins == 0x1D:
        require(apdu.p2 == 0 and not apdu.data, 0x6A86)
        return read_config(card, apdu.p1)
    if apdu.ins == 0x1C:
        require(apdu.p1 == apdu.p2 == 0, 0x6A86)
        write_config(card, apdu.data)
        return b""
    fail(0x6D00)
