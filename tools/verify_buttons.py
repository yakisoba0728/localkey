#!/usr/bin/env python3
"""Verify software button output with published vectors and separate AES checks.
Uses fresh in-memory state only; no keyboard events or physical devices.
"""

import argparse
import json
import random
import sys
from pathlib import Path

from yubikit.core import Tlv
from yubikit.core.smartcard import ApduError
from yubikit.oath import OathSession
from yubikit.piv import PivSession

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from emucard import Card, EmulatorConnection, EncryptedState
from emucard.core import CardError
from yubikit.core.otp import check_crc, modhex_decode
from yubikit.yubiotp import (
    CFGFLAG,
    SLOT,
    TKTFLAG,
    HotpSlotConfiguration,
    StaticPasswordSlotConfiguration,
    StaticTicketSlotConfiguration,
    UpdateConfiguration,
    YubiOtpSession,
    YubiOtpSlotConfiguration,
)


def protocol_edges(check):
    from emucard.keyboard import SCAN_MAP, US

    state = EncryptedState()
    card = Card(state, lambda _: True)
    session = YubiOtpSession(EmulatorConnection(card))

    def denied(action, name, sw=0x6985):
        try:
            action()
        except (ApduError, CardError) as e:
            check(e.sw == sw, name)
        else:
            raise AssertionError(name)

    secret, uid = bytes(range(16)), bytes(range(1, 7))
    config = YubiOtpSlotConfiguration(b"", uid, secret)
    config._update_flags(TKTFLAG.CHAL_RESP, True)
    config._update_flags(CFGFLAG.CHAL_YUBICO, True)
    session.put_configuration(SLOT.ONE, config)
    challenge = b"abcdef"
    raw = session.backend.send_and_receive(0x20, challenge, 16)
    ctx = Cipher(algorithms.AES(secret), modes.ECB()).decryptor()
    plain = ctx.update(raw) + ctx.finalize()
    check(
        bytes(a ^ b for a, b in zip(plain[:6], uid, strict=True)) == challenge
        and check_crc(plain),
        "Yubico challenge-response independently decrypted with nonzero private UID",
    )
    session.put_configuration(SLOT.ONE, YubiOtpSlotConfiguration(b"", uid, secret))
    row = state.data["otp"]["slots"]["1"]
    card.otp_keypress(1)
    card.otp_sessions[1][0] = 256
    raw = modhex_decode(card.otp_keypress(1)["text"])
    ctx = Cipher(algorithms.AES(secret), modes.ECB()).decryptor()
    plain = ctx.update(raw) + ctx.finalize()
    check(
        int.from_bytes(plain[6:8], "little") == 2 and plain[11] == 0,
        "OTP session rollover advances persistent usage counter",
    )
    row["use_counter"] = 0x7FFF
    card.reset_power_session()
    raw = modhex_decode(card.otp_keypress(1)["text"])
    ctx = Cipher(algorithms.AES(secret), modes.ECB()).decryptor()
    plain = ctx.update(raw) + ctx.finalize()
    check(
        int.from_bytes(plain[6:8], "little") == 0x7FFF and plain[11] == 0,
        "OTP persistent counter saturates at its documented 15-bit limit",
    )
    session.put_configuration(
        SLOT.ONE, StaticPasswordSlotConfiguration(b"\x04").protect_slot2(True)
    )
    denied(
        lambda: session.put_configuration(
            SLOT.TWO, StaticPasswordSlotConfiguration(b"\x05")
        ),
        "slot 1 protection blocks initial slot 2 provisioning",
    )
    denied(session.swap_slots, "slot 1 protection also prevents swap into slot 2")
    session.put_configuration(SLOT.ONE, StaticPasswordSlotConfiguration(b"\x04"))
    session.put_configuration(
        SLOT.TWO, StaticPasswordSlotConfiguration(b"\x05").protect_slot2(True)
    )
    session.put_configuration(
        SLOT.ONE, StaticPasswordSlotConfiguration(b"\x04").protect_slot2(True)
    )
    session.update_configuration(SLOT.TWO, UpdateConfiguration().append_cr(False))
    check(
        not card.otp_keypress(2)["append_cr"],
        "preexisting slot 2 self-protection overrides slot 1 lock",
    )
    session.delete_slot(SLOT.TWO)
    denied(
        lambda: session.put_configuration(
            SLOT.TWO, StaticPasswordSlotConfiguration(b"\x05")
        ),
        "deleting self-protected slot 2 restores slot 1 provisioning lock",
    )
    session.put_configuration(
        SLOT.ONE, StaticPasswordSlotConfiguration(b"\x04").dormant(True)
    )
    denied(lambda: card.otp_keypress(1), "dormant slot produces no keyboard output")
    session.update_configuration(SLOT.ONE, UpdateConfiguration().dormant(False))
    check(
        card.otp_keypress(1)["scan_codes"] == [4],
        "authenticated configuration update wakes dormant slot",
    )
    session.update_configuration(SLOT.ONE, UpdateConfiguration().dormant(True))
    denied(
        lambda: card.otp_keypress(1),
        "flags-only update restores dormancy after activation",
    )
    session.put_configuration(
        SLOT.ONE, StaticPasswordSlotConfiguration(b"\x04").serial_api_visible(False)
    )
    denied(session.get_serial, "OTP serial API hidden when no slot opts in")
    session.put_configuration(SLOT.TWO, StaticPasswordSlotConfiguration(b"\x05"))
    check(
        session.get_serial() == int(state.data["serial"], 16),
        "OTP serial visibility is merged across slots",
    )
    session.put_configuration(SLOT.ONE, YubiOtpSlotConfiguration(b"\x00", uid, secret))
    mapping = bytes(
        usage | (0x80 if modifier else 0)
        for modifier, usage in (US[c] for c in SCAN_MAP)
    )
    mapping = bytes([0x84]) + mapping[1:]
    session.set_scan_map(mapping)
    rendered = card.otp_keyboard_events(1)
    check(
        bytes.fromhex(rendered[0]["report"])[:3] == b"\x02\0\x04",
        "SDK 45-byte scan map controls modhex keyboard usage and modifier",
    )
    session.put_configuration(SLOT.ONE, StaticPasswordSlotConfiguration(b"\x05"))
    check(
        bytes.fromhex(card.otp_keyboard_events(1)[0]["report"])[2] == 5,
        "scan map preserves explicitly stored static-password scan codes",
    )
    session.put_configuration(
        SLOT.ONE, StaticTicketSlotConfiguration(b"", uid, secret).manual_update(True)
    )
    before = card.otp_keypress(1)["text"]
    check(
        card.otp_button_events(10000) == [] and card.otp_keypress(1)["text"] == before,
        "long hold arms manual update without changing or typing the password",
    )
    card.touch = lambda _: False
    denied(
        lambda: card.otp_button_events(500),
        "manual update confirmation requires fresh user presence",
    )
    card.touch = lambda _: True
    check(
        card.otp_keypress(1)["text"] == before,
        "denied manual update preserves existing password",
    )
    card.otp_button_events(10000)
    confirmed = card.otp_button_events(500)
    after = card.otp_keypress(1)["text"]
    check(
        confirmed and before != after and card.otp_keypress(1)["text"] == after,
        "confirmed manual update randomizes static password and keeps new output stable",
    )
    card.otp_button_events(10000)
    session.put_configuration(
        SLOT.ONE, StaticTicketSlotConfiguration(b"", uid, secret).manual_update(True)
    )
    denied(
        lambda: card.otp_button_events(500),
        "manual update rejects a changed configuration after arming",
    )
    card.otp_button_events(10000)
    card.reset_session()
    check(
        card.otp_button_events(1500) and card.otp_keypress(1)["text"] == before,
        "session reset cancels pending manual password update",
    )
    check(
        bytes.fromhex(card.otp_button_events(3500)[0]["report"])[2] == 5,
        "documented long release window selects slot 2",
    )
    denied(
        lambda: card.otp_button_events(2750),
        "button duration between slot windows produces no output",
    )
    session.put_configuration(
        SLOT.TWO, StaticTicketSlotConfiguration(b"", uid, secret).manual_update(True)
    )
    denied(
        lambda: card.otp_button_events(10000),
        "ambiguous two-slot manual update changes neither password",
    )


def run():
    checks = []

    def check(value, name):
        if not value:
            raise AssertionError(name)
        checks.append({"name": name, "passed": True})
        print("PASS", name, flush=True)

    state = EncryptedState()
    card = Card(state, lambda _: True)
    session = YubiOtpSession(EmulatorConnection(card))
    session.put_configuration(SLOT.ONE, HotpSlotConfiguration(b"12345678901234567890"))
    check(
        [card.otp_keypress(1)["text"] for _ in range(3)]
        == ["755224", "287082", "359152"],
        "software button HOTP RFC4226 vectors",
    )
    secret = bytes(range(16))
    uid = bytes(range(6))
    fixed = b"\x10\x20\x30\x40\x50\x60"
    session.put_configuration(SLOT.TWO, YubiOtpSlotConfiguration(fixed, uid, secret))
    tokens = [card.otp_keypress(2)["text"] for _ in range(2)]
    plain = []
    for token in tokens:
        data = modhex_decode(token)
        ctx = Cipher(algorithms.AES(secret), modes.ECB()).decryptor()
        p = ctx.update(data[len(fixed) :]) + ctx.finalize()
        plain.append(p)
        check(
            data[: len(fixed)] == fixed and p[:6] == uid and check_crc(p),
            "software button Yubico OTP independently decrypted and CRC verified",
        )
    check(
        int.from_bytes(plain[0][6:8], "little")
        == int.from_bytes(plain[1][6:8], "little")
        and plain[1][11] == plain[0][11] + 1,
        "software button OTP session counter increases",
    )
    card.reset_power_session()
    data = modhex_decode(card.otp_keypress(2)["text"])
    ctx = Cipher(algorithms.AES(secret), modes.ECB()).decryptor()
    p = ctx.update(data[len(fixed) :]) + ctx.finalize()
    check(
        int.from_bytes(p[6:8], "little") > int.from_bytes(plain[1][6:8], "little"),
        "software button OTP use counter advances after power reset",
    )
    scan_codes = bytes([4, 5, 6, 0x1E])
    session = YubiOtpSession(EmulatorConnection(card))
    session.put_configuration(SLOT.ONE, StaticPasswordSlotConfiguration(scan_codes))
    check(
        card.otp_keypress(1)["scan_codes"] == list(scan_codes),
        "software button static password preserves HID scan codes",
    )
    from emucard.keyboard import events, strong_password

    card.touch = lambda _: True
    config = StaticTicketSlotConfiguration(b"", uid, secret)
    session.put_configuration(SLOT.ONE, config)
    static = [card.otp_keypress(1)["text"] for _ in range(2)]
    check(
        static[0] == static[1] and len(static[0]) == 32,
        "static ticket stays constant across button presses",
    )
    ctx = Cipher(algorithms.AES(secret), modes.ECB()).decryptor()
    decoded = ctx.update(modhex_decode(static[0])) + ctx.finalize()
    check(
        decoded[:6] == uid and decoded[6:14] == bytes(8) and check_crc(decoded),
        "static ticket independent AES and CRC verification",
    )
    published = "grjndvjfluejrjtlijukvgrrdhljjjgi"
    check(
        strong_password(published, 0x40) == "6rjn3vjfluejrjtlijukvgrrdhljjjgi",
        "Yubico manual static password digit transform example",
    )
    check(
        strong_password(published, 0x50) == "6RJn3vjfluejrjtlijukvgrrdhljjjgi",
        "Yubico manual static password combined uppercase transform example",
    )
    check(
        strong_password(published, 0x41) == "!6rjn3vjfluejrjtlijukvgrrdhljjjgi",
        "Yubico manual static password special-character example",
    )
    session.put_configuration(
        SLOT.ONE,
        config.short_ticket(True).strong_password(
            upper_case=True, digit=True, special=True
        ),
    )
    check(
        len(card.otp_keypress(1)["text"]) == 17,
        "short static ticket with strong-password prefix",
    )
    scan = bytes([0x84, 5, 6, 0x1E])
    session.put_configuration(SLOT.ONE, StaticPasswordSlotConfiguration(scan))
    keyboard = card.otp_keyboard_events(1)
    check(
        bytes.fromhex(keyboard[0]["report"]) == bytes([2, 0, 4, 0, 0, 0, 0, 0])
        and bytes.fromhex(keyboard[1]["report"]) == bytes(8),
        "USB keyboard shift, press and release reports",
    )
    check(
        bytes.fromhex(keyboard[-2]["report"])[2] == 40 and len(keyboard) == 10,
        "USB keyboard appends configured enter",
    )
    nav = bytearray(52)
    nav[46] = 0x3F
    nav[47] = 0x0C
    rendered = events({"text": "ab", "fixed_chars": 1, "append_cr": True}, nav)
    check(
        [
            bytes.fromhex(e["report"])[2]
            for e in rendered
            if bytes.fromhex(e["report"])[2]
        ]
        == [43, 4, 43, 5, 43, 40],
        "USB keyboard navigation ordering",
    )
    check(
        sum(e["delay_ms"] == 500 for e in rendered) == 2
        and sum(e["delay_ms"] == 30 for e in rendered) == 6,
        "USB keyboard pacing and half-second delays",
    )
    card.touch = lambda _: False
    try:
        card.otp_keypress(1)
    except CardError as e:
        check(e.sw == 0x6985, "software button denied user presence produces no output")
    else:
        raise AssertionError("button ignored user presence")
    # Malformed inputs must yield an ISO status instead of crashing the process.
    rng = random.Random(1234)
    for _ in range(400):
        data = rng.randbytes(rng.randrange(0, 512))
        response, sw = card.transmit(data)
        if not isinstance(response, bytes) or not 0 <= sw <= 65535:
            raise AssertionError("malformed APDU did not return a status")
    check(True, "400 malformed APDUs return bounded status responses")
    oath = OathSession(EmulatorConnection(card))
    name = b"increasing"
    oath.protocol.send_apdu(
        0, 1, 0, 0, Tlv(0x71, name) + Tlv(0x73, b"\x21\x06" + b"x" * 20) + b"\x78\x01"
    )
    oath.calculate(name, (1).to_bytes(8, "big"))
    try:
        oath.calculate(name, (1).to_bytes(8, "big"))
    except ApduError as e:
        check(
            e.sw == 0x6985, "OATH only-increasing property rejects repeated challenge"
        )
    else:
        raise AssertionError("OATH repeated monotonic challenge accepted")
    oath.calculate(name, (2).to_bytes(8, "big"))
    check(True, "OATH only-increasing property accepts newer challenge")
    piv = PivSession(EmulatorConnection(card))

    def unavailable():
        raise OSError("fixture disk unavailable")

    state.flush = unavailable
    try:
        piv.verify_pin("wrong")
    except ApduError as e:
        check(
            e.sw == 0x6581 and state.data["piv"]["pin_retries"] == 3,
            "failed PIN retry persistence returns storage error and restores memory",
        )
    else:
        raise AssertionError("fixture storage failure ignored")
    protocol_edges(check)
    return {
        "passed": True,
        "tests": checks,
        "physical_device_access": False,
        "transport": "software button API and serialized in-process APDUs",
        "os_keyboard_events": False,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--report", required=True, type=Path)
    a = p.parse_args()
    a.report.write_text(json.dumps(run(), indent=2) + "\n")


if __name__ == "__main__":
    main()
