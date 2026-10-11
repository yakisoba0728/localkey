# Catalog mapping: Management (`lk-mgmt`)

Source: `reference/BEHAVIOR_CATALOG.md`, section "Management". There is one line per bullet.
Test names refer to `crates/lk-mgmt/tests/mgmt.rs`, `crates/lk-mgmt/tests/fuzz.rs`, or the
unit tests in `crates/lk-mgmt/src/`.

## Management

- CCID and OTP HID device information/configuration — tested: `select_returns_version_string`, `device_info_own_profile_matches_expected_bytes`, `device_info_yubikey_profile_matches_expected_bytes`, `device_info_follows_the_profile`, `read_config_is_length_prefixed_device_info`, `read_config_serves_at_most_ne_with_get_response`, `secure_channel_collection_reaches_the_whole_page`, `unread_response_data_is_discarded_by_other_commands`, `select_serves_at_most_ne`, `apdu_header_errors`, `real_device_info_pages_at_small_limits`, `write_config_round_trips_every_field`, `yubikit_get_bytes_requests_are_accepted_byte_exact`, `yubikit_parse_tlvs_decodes_every_field`, `ykman_config_usb_mode_and_lock_flows_byte_exact`, `write_config_accepts_case_4_apdus`, `malformed_length_prefixes_are_rejected_on_every_transport`, `device_info_page_is_read_config_without_length_byte`, `otp_read_config_with_crc_frame`, `otp_write_config_from_padded_slot_data`, `otp_padded_write_length_edges`, `otp_device_info_fits_the_otp_response_capacity`. On OTP HID, `lk-otp` owns the feature-report framing, the programming-sequence counter, the response length byte and the CRC. `lk-device` implements `lk_otp::MgmtBridge` with `Management::device_info_page` (bare TLVs), `Management::write_config` (`len || TLVs`), `Management::serial`, `Management::challenge_response_timeout_secs` and `Management::legacy_set_mode`. The mapping table is in `crates/lk-mgmt/src/transport.rs`.
- CTAPHID vendor 0x42 / 0x43 commands — tested: `ctaphid_read_config`, `ctaphid_write_config`, `ctaphid_other_vendor_commands_are_not_management`, `malformed_length_prefixes_are_rejected_on_every_transport`, `disabling_every_application_is_rejected_on_every_transport`, `yubikit_parse_tlvs_decodes_every_field` (yubikit `_ManagementCtapBackend.read_config` sends `int2bytes(page)`), `ykman_config_usb_mode_and_lock_flows_byte_exact`, `storage_failure_is_rejected_on_every_transport`.
- shared own serial and USB application flags — tested: `configuration_is_shared_across_transports`, `device_info_yubikey_profile_matches_expected_bytes`, `device_info_follows_the_profile`, `yubikit_parse_tlvs_decodes_every_field`. The serial always comes from `DeviceProfile` and is never stored. One `Management` value serves CCID, OTP HID and CTAPHID.
- configuration lock/unlock — tested: `lock_code_protects_configuration`, `lock_is_checked_before_values_and_covers_reboot`, `locked_device_rejects_lock_changes_without_the_code`, `lock_rejection_owes_no_reboot`, `unlock_tag_while_unlocked_must_be_the_zero_code`, `yubikit_get_bytes_requests_are_accepted_byte_exact` (set and `--clear` with `CLEAR_LOCK_CODE`), `ykman_config_usb_mode_and_lock_flows_byte_exact` (`config set-lock-code`, `config usb -L`, a wrong code, `config mode` while locked, `--clear`, on CCID, CTAPHID and OTP HID), `non_minimal_tlv_lengths_are_accepted`, `lock_survives_reload`, `storage_failure_while_clearing_lock_keeps_lock`.
- FIDO/U2F and CCID application enable/disable — tested: `fido_and_ccid_applications_enable_and_disable`, `disabling_every_application_is_rejected`, `disabling_every_application_is_rejected_on_every_transport`, `enabling_unsupported_capability_is_rejected`, `enabling_undefined_capability_bits_is_rejected`, `enabled_usb_is_limited_to_the_supported_set`, `ykman_config_usb_mode_and_lock_flows_byte_exact` (`config usb -d PIV`, `-d OTP`, `config mode CCID`, `config mode OTP+FIDO+CCID`).
- fail-closed behavior when shared backend unavailable — intentional difference: the engine has no separate backend process. `lk-device` owns one in-process `Management`, so a backend can never be unavailable. The engine's fail-closed rule is that a failed persist rejects the write (`6581`, CTAPHID `ERR_OTHER`) and keeps the previous state; this is tested by `storage_failure_keeps_previous_state`, `storage_failure_while_clearing_lock_keeps_lock` and `storage_failure_is_rejected_on_every_transport`. Note: by the persistence contract (`docs/CONTRACTS.md`), an unreadable `Record::Device` gives factory state, which has no lock code (`unreadable_record_is_factory_state`).
- device launcher and lifecycle cleanup — intentional difference: launching and cleaning up processes belongs to the program stage (`docs/DESIGN.md` §13). The engine starts no processes.

Section count: 7 bullets, of which 5 are tested, 2 are intentional differences and 0 are deferred.
With the related items below, `tools/catalog_status.py` counts 8 tested, 2 intentional
differences and 0 deferred.

## Related items outside the section

- Appendix B `usb_management_reboot_reenumeration` (commit-failure and lock rejection, unchanged-profile reboot) — tested: `reboot_tag_requests_reboot`, `storage_failure_keeps_previous_state`, `storage_failure_is_rejected_on_every_transport`, `lock_is_checked_before_values_and_covers_reboot`, `lock_rejection_owes_no_reboot`, `pending_reboot_survives_later_commands_until_taken`, `reset_drops_a_pending_effect`. deferred: the actual USB re-enumeration on `ConfigEffect::Reboot` is done by `lk-device` (tested there, `docs/catalog/device.md`).
- `storage` "failure rollback" / "restart persistence" (for `Record::Device`) — tested: `storage_failure_keeps_previous_state`, `storage_failure_is_rejected_on_every_transport`, `state_is_persisted_before_success`, `persisted_record_format`, `unreadable_record_is_factory_state`, `record_round_trips_and_keeps_unknown_fields`, `unreadable_records_give_factory_state`.
- Malformed input never panics — tested: `random_inputs_never_panic`, `random_stored_records_never_panic`, `random_sessions_are_deterministic`.

## Host software checked (yubikit-python and ykman, `main` branch)

The request shapes the tests send come from the host source:

- `yubikit/management.py`:
  - `DeviceInfo.parse_tlvs`: every tag it reads and its default for an absent tag. `01` is required (a `KeyError` without it). `05` must be exactly three bytes. `0A` and `16` must be `01` to mean true. `14` and `15` are FIPS bit fields (bit 0 FIDO2, 1 PIV, 2 OpenPGP, 3 OATH, 4 HSM Auth). `19` absent means a final release, and `20`/`21` (Bio only) absent mean `None`.
  - `_do_read_device_info`: pages are read while the popped `MORE_DATA` value counts further pages, and each page is checked with `len(encoded) - 1 == encoded[0]`.
  - `DeviceConfig.get_bytes`: the request shape.
  - The three backends.
  - `set_mode`: on 5.x it writes WRITE CONFIG without `REBOOT` and without a lock code, masked with USB_SUPPORTED, and it adds `0x400` for CCID.
- `yubikit/core/smartcard/__init__.py`:
  - `ShortApduFormatter` sends a data-less command as `CLA INS P1 P2 00`.
  - After `configure()` on USB, `ExtendedApduFormatter` sends READ CONFIG as the case 1 `00 1D 00 00` and WRITE CONFIG as `00 1C 00 00 00 Lc(2) data`.
  - `ResponseChainingProcessor` follows `61xx` with `C0`.
- `ykman/_cli/config.py`:
  - `config usb` sets `reboot` exactly when the USB interface set changes. It sends `08` only for `--touch-eject` and `--no-touch-eject`.
  - ykman refuses to send a lock code to an unlocked key: "Configuration is not locked - remove the --lock-code option" and "No lock code is currently set".
  - It refuses to toggle applications while `reset_blocked` is non-zero.
  - It sends DEVICE RESET only to a key that reports `reset_blocked` or is a Bio key with PIV.

`yubikit_parse_tlvs_decodes_every_field` and `ykman_config_usb_mode_and_lock_flows_byte_exact` reimplement these rules and run them against the engine on every transport.

## Model policies (not measured on the 5.7.4 reference key)

`reference/yubikey-5c-nano-5.7.4/` holds no Management bytes, so every item below is this engine's choice.

- SELECT answers the bare version text `5.7.4`. yubikit's `Version.from_string` searches the text for `\b(\d+).(\d).(\d)\b` (`yubikit/core/__init__.py`), so a longer text containing the version would parse the same way. The exact text the 5.7.4 firmware sends is unmeasured.
- APDU conventions, from `docs/CONTRACTS.md` "Applications B" (binding):
  - Secure-messaging CLA bits are `6882`.
  - A logical channel number is `6881` (ISO/IEC 7816-4 §5.6, as in lk-piv and lk-oath).
  - Any other class from `20` to `FF` is `6E00`.
  - A response gives at most Ne bytes. Without Le that is 256 for a short command and 65 536 for an extended one. The rest follows with `61xx` and GET RESPONSE (`C0`, P1 = P2 = `00`, otherwise `6A86`; with nothing pending `6985`). This also applies to the SELECT text.
  - Any other command, SELECT, deselect or reset discards unread data.
  - While a command chain is open, `C0` is part of the chain check (`6883`).
  - lk-device depends on `C0`: under a secure channel it collects a `61xx` response with `00 C0 00 00 00`.
  - Tested by `apdu_header_errors`, `read_config_serves_at_most_ne_with_get_response`, `secure_channel_collection_reaches_the_whole_page`, `unread_response_data_is_discarded_by_other_commands` and `select_serves_at_most_ne`.
  - The first review had answered `6E00` for every non-`00` class, ignored Le and had no `C0`; the second review fixed this.
- DeviceInfo reports these tags in this order: `01 02 03 04 05 06 07 08 0A 14 15 16 18`. A USB-only device has no NFC tags (`0D 0E 17`) and no Lightning tag (`0F`). Tags `14`, `15` and `18` are sent as two zero bytes and `16` as one zero byte. yubikit decodes these the same way as a missing tag (`yubikit_parse_tlvs_decodes_every_field`). Whether a non-FIPS 5.7.4 key actually sends them has not been measured.
- deferred: part number (`13`), version qualifier (`19`), free form (`11`) and HID init delay (`12`) are not reported, because their values on the real device are unknown.
- yubikit also knows capability bits `0x0004` ("general CCID") and `0x0400` ("Management over CCID") in `CAPABILITY.usb_interfaces`. The engine neither reports them nor accepts them on write (`6A80`). No ykman path sends them to this device: `set_mode` masks its `0x400` with USB_SUPPORTED, and `config usb` starts from the reported enabled set.
- On a fresh device the challenge-response timeout byte is `00`, the auto-eject timeout is `0000` and the device flags are `00`. `Management::challenge_response_timeout_secs` reads `0` as the documented 15-second default. A host writing `07 01 00` sets this same default value.
- deferred: the device flags touch-eject (`0x80`) and remote wakeup (`0x40`) and the auto-eject timeout are stored, persisted and reported, but nothing acts on them yet. Touch-eject would toggle CCID card presence on a touch; remote wakeup belongs to the program stage. Neither `lk-device` nor `lk-ccid` reads them.
- READ CONFIG pages hold up to 255 TLV bytes, which is the limit of the length byte. Asking for a page after the last one returns `6A86`. This device's DeviceInfo (50 bytes) always fits page 0. `real_device_info_pages_at_small_limits` tests the page split on the real DeviceInfo with smaller page sizes. On OTP HID, the 51-byte page plus its CRC stays well inside the 224-byte limit of that response (`otp_device_info_fits_the_otp_response_capacity`).
- WRITE CONFIG checks run in this order:
  1. Framing: no data is `6700`. A length byte that does not equal the number of TLV bytes is `6A80`. On OTP HID the length byte selects the TLVs out of the zero-padded slot data, and the bytes after them are ignored.
  2. TLV structure: an unknown, read-only, NFC or repeated tag is `6A80`. Long length forms (`81`/`82`) are accepted.
  3. Lock: a missing or wrong lock code is `6982`. While a lock code is set, this also applies to a request that only reboots or is empty. A `0B` sent while the device is unlocked must be the all-zero code (ykman never sends one, see above). There is no retry counter, because none is documented and the code is 128 bits.
  4. Values: the wrong width, zero or unsupported applications, or device flags other than `0x40` and `0x80` are `6A80`.
  5. Persist: a storage failure is `6581`.
- A write that changes nothing is not persisted, and `REBOOT` is still honoured. The value of `0C` is ignored.
- Reboot effect on CCID: once a WRITE CONFIG carrying `REBOOT` is answered with `9000`, the reboot is owed until `MgmtApplet::take_effect` or a reset. A later failed write does not cancel it, and neither does a later successful write without `REBOOT` (`pending_reboot_survives_later_commands_until_taken`). A rejected write never owes a reboot (`lock_rejection_owes_no_reboot`).
- A write without `REBOOT` changes the configuration and DeviceInfo at once. The USB interfaces follow at the next enumeration.
  - ykman `config usb` asks for `REBOOT` exactly when the interface set changes. yubikit `set_mode` (ykman `config mode`) writes without it and tells the user "You must remove and re-insert your YubiKey for this change to take effect". This suggests that the firmware itself does not re-enumerate without `REBOOT`.
  - `lk-device` (`settle_management`) follows this: only `REBOOT` re-enumerates; an interface-set change without it applies at the next reboot or power cycle (`management::interface_change_without_reboot_waits_for_the_next_enumeration`).
  - Over OTP HID, `lk-device` reboots after the host's status read that follows the write (or after `OTP_REBOOT_DELAY_MS`), because yubikit needs that read to see the write succeed (`docs/catalog/device.md`).
- CTAPHID error mapping: `6700` gives `ERR_INVALID_LEN`, `6A80`/`6A86` give `ERR_INVALID_PAR`, and anything else gives `ERR_OTHER`.
- deferred: YubiKey 4 SET MODE is not implemented. `Management::legacy_set_mode` answers `6D00` and changes nothing.
  - This covers CCID INS `16`, OTP slot `0x11` through `lk_otp::MgmtBridge::write_device_config`, and CTAPHID `0x40`, which is left to `lk-device` (`set_mode_is_not_implemented_on_any_transport`, `legacy_set_mode_is_refused_without_change`).
  - yubikit translates mode changes into WRITE CONFIG on firmware 5.x (`ykman_config_usb_mode_and_lock_flows_byte_exact`).
  - How the 5.7.4 firmware itself maps a legacy mode byte to capabilities is undocumented.
- intentional difference: DEVICE RESET (INS `1F`) exists only on YubiKey Bio and answers `6D00` here.
- The lock code is wiped when the configuration holding it is dropped (`lk_crypto::wipe`, `docs/DESIGN.md` §8), the records this crate persists are passed from a `lk_crypto::SecretBytes` built at its final size (`config::tests::record_length_is_known_before_encoding`), and WRITE CONFIG data received over CCID is wiped by `lk_codec::apdu`'s types. `Management::to_record` still hands out a plain copy for the caller to wipe. The code is compared only with `lk_crypto::ct_eq`, and `Debug` never prints it (`config::tests::debug_does_not_print_lock_code`).
