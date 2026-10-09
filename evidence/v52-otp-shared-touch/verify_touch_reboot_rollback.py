#!/usr/bin/env python3
"""Check shared touch survives a failed reboot commit but not a committed one."""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from emucard import Card, EmulatorConnection, EncryptedState
from emucard.core import CardError
from emucard.management import write_config
from yubikit.yubiotp import SLOT, StaticPasswordSlotConfiguration, YubiOtpSession

state = EncryptedState()
card = Card(state, lambda _: True)
YubiOtpSession(EmulatorConnection(card)).put_configuration(
    SLOT.ONE, StaticPasswordSlotConfiguration(bytes([0x84, 5, 30]))
)
checks = []

def check(name, value):
    checks.append({"name": name, "passed": bool(value)})

check("initial_touch_outputs", len(card.otp_button_press_events()) == 8)
prior = copy.deepcopy(state.data)
prior_flag = card.reset_otp_power_after_commit
real_flush = state.flush

def fail_flush():
    raise OSError("simulated fixture commit failure")

state.flush = fail_flush
try:
    write_config(card, b"\x02\x0c\x00")
    card._flush_committed_state()
except OSError:
    state.data = prior
    card.reset_otp_power_after_commit = prior_flag
    check("failed_reboot_keeps_owner", state.otp_touch_owner is card and state.otp_touch_mode == "fast")
else:
    check("failed_reboot_injected", False)
finally:
    state.flush = real_flush
check("owner_can_release_after_failed_reboot", card.otp_button_release_events(3500) == [])
check("new_touch_after_failed_reboot", len(card.otp_button_press_events()) == 8)
write_config(card, b"\x02\x0c\x00")
card._flush_committed_state()
check("committed_reboot_releases_owner", state.otp_touch_owner is None and state.otp_touch_mode is None)
try:
    card.otp_button_release_events(3500)
except CardError as exc:
    check("old_release_denied_after_reboot", exc.sw == 0x6985)
else:
    check("old_release_denied_after_reboot", False)
check("new_touch_after_reboot", len(card.otp_button_press_events()) == 8)
other_card = Card(state, lambda _: True)
other_card.reset_power_session()
check("other_card_power_cycle_clears_owner", state.otp_touch_owner is None and state.otp_touch_mode is None)
try:
    card.otp_button_release_events(3500)
except CardError as exc:
    check("old_release_denied_after_other_power_cycle", exc.sw == 0x6985)
else:
    check("old_release_denied_after_other_power_cycle", False)
result = {"passed": all(c["passed"] for c in checks), "count": len(checks), "tests": checks, "physical_key_access": False}
(Path(__file__).resolve().parent / "reboot-rollback-result.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps({"passed": result["passed"], "count": result["count"]}))
raise SystemExit(0 if result["passed"] else 1)
