# Catalog mapping: Management (`lk-mgmt`)

Source: `reference/BEHAVIOR_CATALOG.md`, section "Management". There is one line per bullet.
Test names refer to `crates/lk-mgmt/tests/mgmt.rs`, `crates/lk-mgmt/tests/fuzz.rs`, or the
unit tests in `crates/lk-mgmt/src/`.

## Management

- CCID and OTP HID device information/configuration — tested: `select_returns_version_string`, `device_info_own_profile_matches_expected_bytes`, `device_info_yubikey_profile_matches_expected_bytes`, `device_info_follows_the_profile`, `read_config_is_length_prefixed_device_info`, `read_config_serves_at_most_ne_with_get_response`, `secure_channel_collection_reaches_the_whole_page`, `unread_response_data_is_discarded_by_other_commands`, `select_serves_at_most_ne`, `apdu_header_errors`, `read_config_paging_bounds`, `config::tests::read_config_serves_the_two_measured_pages`, `info::tests::pages_match_the_measured_layout`, `cla_80_is_served_like_00`, `get_response_without_pending_data_is_6d00`, `write_config_round_trips_every_field`, `yubikit_get_bytes_requests_are_accepted_byte_exact`, `yubikit_parse_tlvs_decodes_every_field`, `ykman_config_usb_mode_and_lock_flows_byte_exact`, `write_config_accepts_case_4_apdus`, `malformed_length_prefixes_are_rejected_on_every_transport`, `device_info_page_is_read_config_without_length_byte`, `otp_read_config_with_crc_frame`, `otp_write_config_from_padded_slot_data`, `otp_padded_write_length_edges`, `otp_device_info_fits_the_otp_response_capacity`. On OTP HID, `lk-otp` owns the feature-report framing, the programming-sequence counter, the response length byte and the CRC. `lk-device` implements `lk_otp::MgmtBridge` with `Management::device_info_page` (bare TLVs), `Management::write_config` (`len || TLVs`), `Management::serial`, `Management::challenge_response_timeout_secs` and `Management::legacy_set_mode`. The mapping table is in `crates/lk-mgmt/src/transport.rs`. The SELECT text, the DeviceInfo pages, CLA `80`, READ CONFIG P1/P2 and GET RESPONSE with nothing pending are measured on the reference key (docs/MEASUREMENT.md, probes `select-mgmt`, `mgmt-read-config`, `bad-p1p2-mgmt`, `cla-variants-mgmt`, `get-response-idle-mgmt`; see "Model policies replaced by measurement" below). Form factor (DeviceInfo tag `04`, yubikit `FORM_FACTOR`): intentional difference (own identity): `DeviceProfile::own` reports `00`, `FORM_FACTOR.UNKNOWN`, because a software key has no physical shape and a USB shape code would make yubikit and ykman name the device after a Yubico product; the reference key reports `04`, USB-C Nano (docs/MEASUREMENT.md, "State of the key"), which the compatibility profile `yubikey_compat` keeps for host tools that accept nothing else. yubikit gates nothing on the form factor except its Bio checks. Tests: `device_info_own_profile_matches_expected_bytes` (`04 01 00`), `device_info_yubikey_profile_matches_expected_bytes` (`04 01 04`), `yubikit_parse_tlvs_decodes_every_field` (UNKNOWN for the own profile, USB_C_NANO for the compatibility profile), lk-core `profile::tests::form_factor_per_profile`.
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

## Model policies replaced by measurement (reference key)

Differential measurement of 2026-10-11 (docs/MEASUREMENT.md): the same read-only probes
(`tools/measure/probes.py`) sent to the physical key and to the engine. Each answer below
was a model policy and now follows the key: Management is a Yubico-proprietary protocol,
so Yubico's documentation and yubikit are its specification and the reference key their
best evidence (rule 3 of `docs/CONTRACTS.md` "Reference, not replica"), and none of these
answers is a reference defect (rule 4). The own profile still carries no Yubico identifier
(rule 5: empty part number, form factor `00`). A numbered list, so that
`tools/catalog_status.py` does not count these as catalog lines:

1. SELECT answers the 30 ASCII bytes `Virtual mgr - FW version <major>.<minor>.<patch>` (the profile's
  firmware version), with or without Le `00`: measured on the reference key
  (docs/MEASUREMENT.md, probes `select-mgmt`, `select-odd-p2`); it was the bare version string.
  yubikit's `Version.from_string` finds the version in either text. Tests:
  `select_returns_version_string`, `select_serves_at_most_ne`,
  `device_info_follows_the_profile`, `yubikit_version_search_reads_both_select_texts`,
  `yubikit_parse_tlvs_decodes_every_field`.
2. DeviceInfo comes in two fixed pages: measured on the reference key
  (docs/MEASUREMENT.md, probe `mgmt-read-config`). Page 0 holds `01 03 02 04 05 06 07 08
  0A 0F 20 21` and ends with `MORE_DATA` (`10 01 01`), 52 bytes with the length byte `33`;
  page 1 holds `11 12 13 14 15 16 17 18`, 42 bytes with `29`, and no `MORE_DATA`. The
  tags the engine has no state for carry the measured values: `0F 01 00`, `20 03 000000`,
  `21 03 000000`, `11 04 00000000`, `12 01 00`, `14 02 0000`, `15 02 0000`, `16 01 00`,
  `17 01 00`, `18 02 0000`; yubikit decodes each like an absent tag. It was one page
  `01 02 03 04 05 06 07 08 0A 14 15 16 18` filled greedily up to 255 bytes, without
  `0F`, `11`, `12`, `13`, `17`, `20`, `21`. Probe `lc-le-mgmt` follows: Le `01` gives the
  length byte and `6133`. The part number (`13`) is `DeviceProfile::part_number`: the key
  sent 12 ASCII bytes; the compatibility profile sends twelve ASCII zeros (the measured
  length, not the measured value, which may identify a production batch) and the own
  profile an empty value (yubikit: no part number). The same pages are served over
  CTAPHID `0x42` and OTP HID (unmeasured there). Tests:
  `info::tests::pages_match_the_measured_layout`,
  `info::tests::merged_is_both_pages_without_more_data`,
  `info::tests::empty_part_number_is_an_empty_value`,
  `config::tests::read_config_serves_the_two_measured_pages`,
  `device_info_own_profile_matches_expected_bytes`,
  `device_info_yubikey_profile_matches_expected_bytes`,
  `read_config_is_length_prefixed_device_info`, `device_info_has_no_nfc_tags_and_no_duplicates`,
  `device_info_page_is_read_config_without_length_byte`, `ctaphid_read_config`,
  `otp_read_config_with_crc_frame`, `otp_device_info_fits_the_otp_response_capacity`,
  `yubikit_parse_tlvs_decodes_every_field` (two pages on all three transports).
3. A fresh device stores the challenge-response timeout `0F` (15 s): measured on a YubiKey
  reference key (docs/MEASUREMENT.md, probe `mgmt-read-config`, DeviceInfo `07 01 0F`); it
  was `00`. A host may still write `00`, which `Management::challenge_response_timeout_secs`
  reads as the 15-second default (model policy); a stored record keeps its own value.
  Tests: `factory_challenge_response_timeout_means_default`,
  `malformed_length_prefixes_are_rejected_on_every_transport`, `yubikit_parse_tlvs_decodes_every_field`.
4. READ CONFIG over CCID: P1 alone selects the page (P2 is ignored), and a page past the
  last answers `9000` with no data at all, not even a length byte: measured on the reference key (docs/MEASUREMENT.md, probe `bad-p1p2-mgmt`: `00 1D 00 01` is page 0,
  `00 1D 02 00` and `00 1D FF 00` are a bare `9000`); all three were `6A86`.
  `Management::read_config` itself (CTAPHID `0x42`, OTP HID slot `0x13`, both unmeasured)
  keeps answering a page past the last with `6A86` (CTAPHID `ERR_INVALID_PAR`; model
  policy). Tests: `read_config_paging_bounds`, `ctaphid_read_config`,
  `otp_read_config_with_crc_frame`.
5. CLA `80` is served exactly like `00`: measured on the reference key
  (docs/MEASUREMENT.md, probe `cla-variants-mgmt`: `80 1D 00 00` answers page 0); it was
  `6E00`. `90` (`80` with the chaining bit), `84` and the other proprietary classes keep
  `6E00` (unmeasured). Tests: `cla_80_is_served_like_00`, `apdu_header_errors`.
6. GET RESPONSE with nothing pending answers `6D00`, also right after a chained part
  (`10 1D 00 00`, `9000`) left a chain open, which it drops: measured on the reference key (docs/MEASUREMENT.md, probes `get-response-idle-mgmt`, `cla-variants-mgmt`); it was
  `6985`, and `6883` during a chain. With data pending, P1/P2 other than `00 00` stays
  `6A86` (model policy). Tests: `get_response_without_pending_data_is_6d00`,
  `apdu_header_errors`, `read_config_serves_at_most_ne_with_get_response`,
  `unread_response_data_is_discarded_by_other_commands`.

These replace the `docs/CONTRACTS.md` "Applications B" conventions `6E00` for CLA `80`
and `6985` for an idle GET RESPONSE for this application. CLA `0C` came back without a
status word on the physical side (`none`, docs/MEASUREMENT.md "Host artifacts") and keeps
`6882`.

## Model policies (not measured on the reference key)

`reference/physical-key/` holds no Management bytes, and the measurement above
covered only CCID reads. Neither Yubico's documentation, yubikit nor the reference key fixes
the items below, so each is this engine's choice (a model policy).

- APDU conventions, from `docs/CONTRACTS.md` "Applications B" (binding), with the measured exceptions above:
  - Secure-messaging CLA bits are `6882`.
  - A logical channel number is `6881` (ISO/IEC 7816-4 §5.6, as in lk-piv and lk-oath).
  - Any other class from `20` to `FF` except `80` is `6E00`.
  - A response gives at most Ne bytes. Without Le that is 256 for a short command and 65 536 for an extended one. The rest follows with `61xx` and GET RESPONSE (`C0`; with data pending P1 = P2 = `00`, otherwise `6A86`; with nothing pending `6D00`, measured). This also applies to the SELECT text.
  - Any other command, SELECT, deselect or reset discards unread data.
  - `C0` while a command chain is open drops the chain and is answered like an idle GET RESPONSE (measured, item 6 above).
  - lk-device depends on `C0`: under a secure channel it collects a `61xx` response with `00 C0 00 00 00`.
  - Tested by `apdu_header_errors`, `read_config_serves_at_most_ne_with_get_response`, `secure_channel_collection_reaches_the_whole_page`, `unread_response_data_is_discarded_by_other_commands` and `select_serves_at_most_ne`.
  - The first review had answered `6E00` for every non-`00` class, ignored Le and had no `C0`; the second review fixed this.
- DeviceInfo tag order, page split and values: measured (item 2 above). No NFC capability tags (`0D`, `0E`) and no version qualifier (`19`) are sent, as on the measured key.
- yubikit also knows capability bits `0x0004` ("general CCID") and `0x0400` ("Management over CCID") in `CAPABILITY.usb_interfaces`. The engine neither reports them nor accepts them on write (`6A80`). The measured key reports supported and enabled `031E`, which includes `0004` (docs/MEASUREMENT.md, "State of the key"; state-dependent, not adopted). No ykman path sends them to this device: `set_mode` masks its `0x400` with USB_SUPPORTED, and `config usb` starts from the reported enabled set.
- On a fresh device the auto-eject timeout is `0000` and the device flags are `00` (the challenge-response timeout byte `0F` is measured, item 3 above). `Management::challenge_response_timeout_secs` reads a written `0` as the documented 15-second default.
- deferred: the device flags touch-eject (`0x80`) and remote wakeup (`0x40`) and the auto-eject timeout are stored, persisted and reported, but nothing acts on them yet. Touch-eject would toggle CCID card presence on a touch; remote wakeup belongs to the program stage. Neither `lk-device` nor `lk-ccid` reads them.
- READ CONFIG pages are the two measured pages (item 2 above), well within the 255 TLV bytes the length byte can express (`PAGE_LIMIT`). Over CTAPHID and OTP HID a page after the last one returns `6A86` (`ERR_INVALID_PAR` on CTAPHID); over CCID it is the measured bare `9000` (item 4). On OTP HID, each page plus its CRC (54 and 44 bytes) stays well inside the 224-byte limit of that response (`otp_device_info_fits_the_otp_response_capacity`).
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
  - How the reference firmware itself maps a legacy mode byte to capabilities is undocumented.
- intentional difference: DEVICE RESET (INS `1F`) exists only on YubiKey Bio and answers `6D00` here.
- The lock code is wiped when the configuration holding it is dropped (`lk_crypto::wipe`, `docs/DESIGN.md` §8), the records this crate persists are passed from a `lk_crypto::SecretBytes` built at its final size (`config::tests::record_length_is_known_before_encoding`), and WRITE CONFIG data received over CCID is wiped by `lk_codec::apdu`'s types. `Management::to_record` still hands out a plain copy for the caller to wipe. The code is compared only with `lk_crypto::ct_eq`, and `Debug` never prints it (`config::tests::debug_does_not_print_lock_code`).
