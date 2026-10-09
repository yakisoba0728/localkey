#!/usr/bin/env python3
"""Decrypt OTP tickets around rejected config writes, ABORT, and reboot."""

import argparse
import json
import sys
from contextlib import contextmanager, nullcontext
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from yubikit.core.otp import check_crc
from yubikit.core.smartcard import ApduError
from yubikit.management import ManagementSession
from yubikit.yubiotp import SLOT, YubiOtpSession, YubiOtpSlotConfiguration


KEY = bytes(range(16))
UID = bytes(range(16, 22))
MODHEX = "cbdefghijklnrtuv"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    sys.path.insert(0, str(args.root.resolve()))
    from emucard import Card, EmulatorConnection, EncryptedState

    state = EncryptedState()
    card = Card(state, lambda _: True)
    sdk = YubiOtpSession(EmulatorConnection(card))
    config = YubiOtpSlotConfiguration(b"", UID, KEY)
    sdk.put_configuration(SLOT.ONE, config)
    sdk.put_configuration(SLOT.TWO, config)
    rows = []

    def check(name, actual, expected):
        rows.append({"name": name, "actual": actual, "expected": expected,
                     "matched": actual == expected})

    def ticket(slot, name, use_counter, session_counter, source_card=None):
        text = (source_card or card).otp_keypress(slot)["text"]
        raw = bytes((MODHEX.index(text[i]) << 4) | MODHEX.index(text[i + 1])
                    for i in range(0, len(text), 2))
        ctx = Cipher(algorithms.AES(KEY), modes.ECB()).decryptor()
        plain = ctx.update(raw) + ctx.finalize()
        actual = {"uid": plain[:6].hex(),
                  "use_counter": int.from_bytes(plain[6:8], "little"),
                  "session_counter": plain[11], "crc_valid": check_crc(plain)}
        expected = {"uid": UID.hex(), "use_counter": use_counter,
                    "session_counter": session_counter, "crc_valid": True}
        check(name, actual, expected)

    def failed_flush(call, name):
        original = state.flush
        def fail():
            raise OSError("injected software fixture storage fault")
        state.flush = fail
        try:
            try:
                call()
            except (ApduError, OSError) as exc:
                actual = hex(exc.sw) if isinstance(exc, ApduError) else "OSError"
            else:
                actual = "success"
        finally:
            state.flush = original
        check(name, actual, "OSError" if name == "ticket_flush_rejected" else "0x6581")

    ticket(1, "first_slot1", 1, 0)
    ticket(2, "first_slot2", 1, 0)
    failed_flush(lambda: sdk.put_configuration(SLOT.ONE, config), "reprogram_flush_rejected")
    ticket(1, "reprogram_failure_keeps_slot1_session", 1, 1)
    failed_flush(lambda: sdk.delete_slot(SLOT.ONE), "delete_flush_rejected")
    ticket(1, "delete_failure_keeps_slot1_session", 1, 2)
    failed_flush(sdk.swap_slots, "swap_flush_rejected")
    ticket(1, "swap_failure_keeps_slot1_session", 1, 3)
    ticket(2, "swap_failure_keeps_slot2_session", 1, 1)

    @contextmanager
    def cancel_commit():
        card.cancelled = lambda: True
        try:
            yield
        finally:
            card.cancelled = lambda: False

    card.commit_guard = cancel_commit
    try:
        try:
            sdk.swap_slots()
        except ApduError as exc:
            status = hex(exc.sw)
        else:
            status = "success"
    finally:
        card.commit_guard = nullcontext
    check("swap_abort_rejected", status, "0x6400")
    ticket(1, "swap_abort_keeps_slot1_session", 1, 4)
    ticket(2, "swap_abort_keeps_slot2_session", 1, 2)

    failed_flush(lambda: card.otp_keypress(1), "ticket_flush_rejected")
    ticket(1, "ticket_flush_failure_does_not_consume_counter", 1, 5)

    mgmt = ManagementSession(EmulatorConnection(card))
    failed_flush(lambda: mgmt.write_device_config(reboot=True), "reboot_flush_rejected")
    ticket(1, "reboot_flush_failure_keeps_session", 1, 6)
    card.commit_guard = cancel_commit
    try:
        try:
            mgmt.write_device_config(reboot=True)
        except ApduError as exc:
            status = hex(exc.sw)
        else:
            status = "success"
    finally:
        card.commit_guard = nullcontext
    check("reboot_abort_rejected", status, "0x6400")
    # This unrelated, committed APDU catches a stale deferred reboot flag.
    mgmt.write_device_config()
    ticket(1, "reboot_abort_then_unrelated_commit_keeps_session", 1, 7)
    mgmt.write_device_config(reboot=True)
    ticket(1, "committed_reboot_starts_new_session", 2, 0)
    ticket(2, "committed_reboot_resets_peer_slot_session", 2, 0)

    # A new configuration is a new credential with a reset nonvolatile counter.
    sdk = YubiOtpSession(EmulatorConnection(card))
    sdk.delete_slot(SLOT.ONE)
    sdk.put_configuration(SLOT.ONE, config)
    ticket(1, "delete_reconfigure_resets_credential_counter", 1, 0)
    other_card = Card(state, lambda _: True)
    ticket(1, "second_card_shares_new_credential_session", 1, 1,
           source_card=other_card)

    result = {"passed": all(row["matched"] for row in rows),
              "count": len(rows), "checks": rows,
              "physical_device_access": False,
              "firmware_5_7_4_differential_verified": False}
    args.result.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
