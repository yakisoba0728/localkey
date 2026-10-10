# Catalog mapping: Management (`lk-mgmt`)

Source: `reference/BEHAVIOR_CATALOG.md`, section "Management". There is one line per bullet.
Test names refer to `crates/lk-mgmt/tests/mgmt.rs`, `crates/lk-mgmt/tests/fuzz.rs`, or the
unit tests in `crates/lk-mgmt/src/`.

## Management

- CCID and OTP HID device information/configuration — tested: `select_returns_version_string`, `device_info_own_profile_matches_expected_bytes`, `device_info_yubikey_profile_matches_expected_bytes`, `device_info_follows_the_profile`, `read_config_is_length_prefixed_device_info`, `real_device_info_pages_at_small_limits`, `write_config_round_trips_every_field`, `yubikit_get_bytes_requests_are_accepted_byte_exact`, `write_config_accepts_case_4_apdus`, `malformed_length_prefixes_are_rejected_on_every_transport`, `device_info_page_is_read_config_without_length_byte`, `otp_read_config_with_crc_frame`, `otp_write_config_from_padded_slot_data`, `otp_padded_write_length_edges`, `otp_device_info_fits_the_otp_response_capacity`. On OTP HID, `lk-otp` owns the feature-report framing, the programming-sequence counter, the response length byte and the CRC. `lk-device` implements `lk_otp::MgmtBridge` with `Management::device_info_page` (bare TLVs), `Management::write_config` (`len || TLVs`), `Management::serial`, `Management::challenge_response_timeout_secs` and `Management::legacy_set_mode`. The mapping table is in `crates/lk-mgmt/src/transport.rs`.
- CTAPHID vendor 0x42 / 0x43 commands — tested: `ctaphid_read_config`, `ctaphid_write_config`, `ctaphid_other_vendor_commands_are_not_management`, `malformed_length_prefixes_are_rejected_on_every_transport`, `disabling_every_application_is_rejected_on_every_transport`.
- shared own serial and USB application flags — tested: `configuration_is_shared_across_transports`, `device_info_yubikey_profile_matches_expected_bytes`, `device_info_follows_the_profile`. The serial always comes from `DeviceProfile` and is never stored. One `Management` value serves CCID, OTP HID and CTAPHID.
- configuration lock/unlock — tested: `lock_code_protects_configuration`, `lock_is_checked_before_values_and_covers_reboot`, `locked_device_rejects_lock_changes_without_the_code`, `lock_rejection_owes_no_reboot`, `unlock_tag_while_unlocked_must_be_the_zero_code`, `yubikit_get_bytes_requests_are_accepted_byte_exact` (set and `--clear` with `CLEAR_LOCK_CODE`), `non_minimal_tlv_lengths_are_accepted`, `lock_survives_reload`, `storage_failure_while_clearing_lock_keeps_lock`.
- FIDO/U2F and CCID application enable/disable — tested: `fido_and_ccid_applications_enable_and_disable`, `disabling_every_application_is_rejected`, `disabling_every_application_is_rejected_on_every_transport`, `enabling_unsupported_capability_is_rejected`, `enabling_undefined_capability_bits_is_rejected`, `enabled_usb_is_limited_to_the_supported_set`.
- fail-closed behavior when shared backend unavailable — intentional difference: the engine has no separate backend process. `lk-device` owns one in-process `Management`, so a backend can never be unavailable. The engine's fail-closed rule is that a failed persist rejects the write (`6581`) and keeps the previous state; this is tested by `storage_failure_keeps_previous_state` and `storage_failure_while_clearing_lock_keeps_lock`. Note: by the persistence contract (`docs/CONTRACTS.md`), an unreadable `Record::Device` gives factory state, which has no lock code (`unreadable_record_is_factory_state`).
- device launcher and lifecycle cleanup — intentional difference: launching and cleaning up processes belongs to the program stage (`docs/DESIGN.md` §13). The engine starts no processes.

Section count: 7 bullets, of which 5 are tested, 2 are intentional differences and 0 are deferred.

## Related items outside the section

- Appendix B `usb_management_reboot_reenumeration` (commit-failure and lock rejection, unchanged-profile reboot) — tested: `reboot_tag_requests_reboot`, `storage_failure_keeps_previous_state`, `lock_is_checked_before_values_and_covers_reboot`, `lock_rejection_owes_no_reboot`, `pending_reboot_survives_later_commands_until_taken`, `reset_drops_a_pending_effect`. deferred: the actual USB re-enumeration on `ConfigEffect::Reboot` is done by `lk-device`.
- `storage` "failure rollback" / "restart persistence" (for `Record::Device`) — tested: `storage_failure_keeps_previous_state`, `state_is_persisted_before_success`, `persisted_record_format`, `unreadable_record_is_factory_state`, `record_round_trips_and_keeps_unknown_fields`, `unreadable_records_give_factory_state`.
- Malformed input never panics — tested: `random_inputs_never_panic`, `random_stored_records_never_panic`, `random_sessions_are_deterministic`.

## Model policies (not measured on the 5.7.4 reference key)

`reference/yubikey-5c-nano-5.7.4/` holds no Management bytes, so every item below is this engine's choice.

- SELECT answers the bare version text `5.7.4`. yubikit's `Version.from_string` searches the text for `\b(\d+).(\d).(\d)\b`, so a longer text ending in the version would parse the same way. The exact text the 5.7.4 firmware sends is unmeasured.
- DeviceInfo reports these tags in this order: `01 02 03 04 05 06 07 08 0A 14 15 16 18`. A USB-only device has no NFC tags (`0D 0E 17`) and no Lightning tag (`0F`). Tags `14`, `15` and `18` are sent as two zero bytes and `16` as one zero byte. yubikit decodes these the same way as a missing tag. Whether a non-FIPS 5.7.4 key actually sends them has not been measured.
- deferred: part number (`13`), version qualifier (`19`), free form (`11`) and HID init delay (`12`) are not reported, because their values on the real device are unknown.
- On a fresh device the challenge-response timeout byte is `00`, the auto-eject timeout is `0000` and the device flags are `00`. `Management::challenge_response_timeout_secs` reads `0` as the documented 15-second default. A host writing `07 01 00` sets this same default value.
- READ CONFIG pages hold up to 255 TLV bytes, which is the limit of the length byte. Asking for a page after the last one returns `6A86`. This device's DeviceInfo (50 bytes) always fits page 0. `real_device_info_pages_at_small_limits` tests the page split on the real DeviceInfo with smaller page sizes. On OTP HID, the 51-byte page plus its CRC stays well inside the 224-byte limit of that response (`otp_device_info_fits_the_otp_response_capacity`).
- WRITE CONFIG checks run in this order:
  1. Framing: no data is `6700`. A length byte that does not equal the number of TLV bytes is `6A80`. On OTP HID the length byte selects the TLVs out of the zero-padded slot data, and the bytes after them are ignored.
  2. TLV structure: an unknown, read-only, NFC or repeated tag is `6A80`. Long length forms (`81`/`82`) are accepted.
  3. Lock: a missing or wrong lock code is `6982`. While a lock code is set, this also applies to a request that only reboots or is empty. A `0B` sent while the device is unlocked must be the all-zero code. There is no retry counter.
  4. Values: the wrong width, zero or unsupported applications, or device flags other than `0x40` and `0x80` are `6A80`.
  5. Persist: a storage failure is `6581`.
- A write that changes nothing is not persisted, and `REBOOT` is still honoured. The value of `0C` is ignored.
- Reboot effect on CCID: once a WRITE CONFIG carrying `REBOOT` is answered with `9000`, the reboot is owed until `MgmtApplet::take_effect` or a reset. A later failed write does not cancel it, and neither does a later successful write without `REBOOT` (`pending_reboot_survives_later_commands_until_taken`). A rejected write never owes a reboot (`lock_rejection_owes_no_reboot`).
- CTAPHID error mapping: `6700` gives `ERR_INVALID_LEN`, `6A80`/`6A86` give `ERR_INVALID_PAR`, and anything else gives `ERR_OTHER`.
- deferred: YubiKey 4 SET MODE is not implemented. `Management::legacy_set_mode` answers `6D00` and changes nothing. This covers CCID INS `16`, OTP slot `0x11` through `lk_otp::MgmtBridge::write_device_config`, and CTAPHID `0x40`, which is left to `lk-device` (`set_mode_is_not_implemented_on_any_transport`, `legacy_set_mode_is_refused_without_change`). yubikit translates mode changes into WRITE CONFIG on firmware 5.x. How the 5.7.4 firmware itself maps a legacy mode byte to capabilities is undocumented.
- intentional difference: DEVICE RESET (INS `1F`) exists only on YubiKey Bio and answers `6D00` here.
