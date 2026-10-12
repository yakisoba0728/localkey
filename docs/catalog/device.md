# Catalog mapping: Device / transports (`lk-device`)

Source: `reference/BEHAVIOR_CATALOG.md` appendix A (`transports`, `Linux_native`,
`verification_fixtures`) and the `storage` section, one line per bullet; then the
FIDO, OTP, Management and Security Domain bullets whose catalog files leave a part to
`lk-device`, and the appendix B rows about the device. Long bullets are quoted by their
opening words.

Test names refer to `crates/lk-device/tests/<file>.rs` (`fido`, `ccid`,
`secure_channel`, `touch`, `management`, `persistence`, `determinism`; the end-to-end
`scenario_*` files; the adversarial `verify_*` files) and to the unit tests in
`crates/lk-device/src/` (`tests::`, `usb::tests::`, `card::tests::`, `storage::tests::`).
Where a framer crate owns the behaviour, its test is named with the crate
(`lk-ctaphid tests/<file>.rs`, `lk-ccid tests/<file>.rs`).

Scenario files (host side written from the specifications, every signature, MAC and
OTP checked cryptographically): `scenario_fido` (CTAPHID and CTAP 2.1/U2F flows,
GetInfo against the reference observation), `scenario_ccid` (CCID, every card applet,
SCP03, touch time extensions), `scenario_otp` (OTP HID programming and the button),
`scenario_mgmt` (Management over all three transports), `scenario_persistence`
(storage and sealing), `scenario_bus` (reset and power semantics),
`scenario_determinism`, `scenario_fuzz` (seeded inputs on every interface),
`scenario_cross_app` (each application's reset leaves the others' records alone, the
PIV/OpenPGP/Security Domain/OATH bullets in their own files).

Adversarial review files: `verify_timing` (periodic-message cadence under a late or
jittery host, deadlines that coincide with inputs, four-way touch races, late replies
after every way a request can end, WINK, keyboard report order, extra Ticks),
`verify_state` (CCID power-off and abort during a touch wait, the secure channel after
errors, aborts and SELECT, re-enumeration and reboot state, disabled interfaces, USB
descriptors byte for byte), `verify_persistence` (one failing save at every save point
of a script that commits in every application, then a restart).

"deferred: program phase" marks items that only make sense for an OS program (USB
gadget drivers, IFD handlers, sockets, daemons, browsers, kernels): `docs/DESIGN.md`
§4 and §13 put them outside the engine. The engine part of such a bullet, if any, is
named after it. These labels retain the scope of the legacy fixtures: a deferred native
fixture does not mean its transport is missing. `lk-uhid`, `lk-gadget`, `lk-wire` and
`lk-vpcd` are implemented; the current host-tool coverage is in `docs/STATUS.md`
"Program phase". Exact legacy AIO, IFD and browser suites remain distinct from those runs.

## Appendix A: transports

- compiled IFD Handler 3.0 native reader ABI with private persistent CCID sessions — deferred: program phase (PC/SC IFD driver, §13). Engine part: the CCID session lives in `Device` and persists across messages (`ccid::piv_reselect_keeps_pin_verification`).
- compiled public IOUSBHost synthetic composite-controller source — deferred: program phase (macOS IOUSBHost, §13).
- USB device/configuration/HID/CCID descriptors and control/endpoint routing — tested (descriptors): `verify_state::usb_descriptors_match_the_reference_byte_for_byte` (device descriptor fields and the whole 125-byte FIDO+CCID configuration descriptor equal to the reference), `verify_state::every_interface_combination_has_a_consistent_configuration_descriptor`, `management::usb_identity_matches_the_reference_configuration`, `usb::tests::fido_descriptor_matches_the_reference`, `usb::tests::otp_descriptor_is_boot_keyboard_with_feature_report`; deferred: program phase for routing control/endpoint traffic. `Device::usb_identity` gives the IDs, strings, class descriptors, and `UsbIdentity::device_descriptor` / `configuration_descriptor` for the enabled interfaces.
- FIDO/PIV/OATH/OTP SDK flows through compiled USB wire-test model — tested at the engine boundary with byte-level flows instead of SDKs (`docs/DESIGN.md` §12-3): `fido::*`, `ccid::*`, `touch::*`, `secure_channel::*`; SDK runs are program phase.
- USB class matching IDs for seven interface combinations; explicit software product labels — tested: `management::seven_interface_combinations` (product ID and `"<product> OTP+FIDO+CCID"`-style string for each set), `management::own_profile_identity` (own labels).
- keyboard boot/report protocol, LED, idle-repeat and paced button reports — tested (paced reports): `touch::button_windows_select_the_slot_on_release`, `touch::single_slot_types_at_contact` (lk-otp's report sequence, pacing as idle reports, reaches `Output::OtpKeyboard` in order); deferred: program phase for the HID class requests (SET_PROTOCOL, SET_IDLE, LED output report). The OTP report descriptor is a boot keyboard (`usb::tests::otp_descriptor_is_boot_keyboard_with_feature_report`).
- CCID T=1 parameter negotiation/reset with atomic validation and clock/rate/error replies — tested: `ccid::get_parameters_reports_t1`; lk-ccid `tests/messages.rs`: `set_parameters_is_atomic`, `set_then_reset_parameters`, `set_data_rate_accepts_only_the_advertised_values`, `failed_parameter_replies_report_the_parameters_in_force`.
- control/bulk ABORT in either delivery order, session-scoped private cancellation RPC — tested: `ccid::control_abort_then_bulk_abort`, `ccid::bulk_abort_cancels_the_waiting_command` (the waiting applet operation is cancelled and never answers), `verify_timing::ended_requests_never_answer_late` (no late answer or time extension after either abort, the FIDO request keeps going), `verify_state::abort_of_a_wrapped_touch_command_keeps_the_channel_in_step`; lk-ccid `tests/abort.rs`: `bulk_then_control_abort`, `late_control_abort_does_not_wedge_the_slot`. `Input::CcidControlAbort` was added so the program can deliver the control request; the private cancellation RPC is program phase.
- asynchronous native CCID worker with busy-slot replies and USB generation reset — tested: `ccid::busy_slot_while_waiting_for_touch`, `verify_state::power_off_and_warm_reset_are_refused_while_a_card_command_waits` (IccPowerOff and warm IccPowerOn answer `CMD_SLOT_BUSY` and change nothing), `ccid::usb_reset_deactivates_the_slot` (no late reply after the reset: `ccid::resume_cancels_a_waiting_card_command`, `verify_timing::ended_requests_never_answer_late`). The engine has no worker thread (`docs/DESIGN.md` §4): a waiting command is state with a deadline.
- cancellable actual terminal presence; atomic commit/abort boundary and durable authentication retries — tested: `ccid::bulk_abort_cancels_the_waiting_command`, `ccid::card_touch_timeout_answers`, `ccid::resume_cancels_a_waiting_card_command` (an aborted touch never completes the operation), `verify_persistence::every_failed_save_leaves_memory_and_store_in_agreement` (a failing save at every save point, two-save PIN verifications and touch-gated commits included, leaves the state a restart finds); retries are each applet's (`docs/CONTRACTS.md` "Retry counters").
- measured FIDO+CCID configuration and FIDO HID report bytes — tested: `verify_state::usb_descriptors_match_the_reference_byte_for_byte` (`device_fields` and `configuration_descriptor_hex` byte for byte), `management::usb_identity_matches_the_reference_configuration` (idVendor 4176, idProduct 1030, bcdDevice 1396, "YubiKey FIDO+CCID", the 34-byte report descriptor, the CCID class descriptor inside the measured configuration descriptor).
- measured endpoints, CCID 3072-byte messages, 4000 kHz and 307200 bps profile — tested: `ccid::long_response_uses_ccid_response_chaining` (3062 data bytes per message), `management::usb_identity_matches_the_reference_configuration` (class descriptor with 4000 kHz, 307200 bps, 3072-byte messages), `verify_state::usb_descriptors_match_the_reference_byte_for_byte` (endpoint descriptors `04`/`84`, `02`/`82`/`83`); moving data over the endpoints is program phase.
- CCID command/response chaining with independent socket, IFD and native wire clients — tested: `ccid::ccid_command_chaining_assembles_one_apdu`, `ccid::long_response_uses_ccid_response_chaining`, `secure_channel::chained_secure_messaging_is_reassembled`; the socket/IFD clients are program phase.
- native CCID waiting-time extensions and private peer-EOF cancellation recovery — tested: `ccid::card_touch_sends_time_extensions_and_resolves` (one time extension every `WTX_INTERVAL_MS` = 500 ms, model policy), `verify_timing::time_extensions_stay_on_the_grid_with_a_late_host` (the cadence never drifts with a late host); peer EOF is program phase (its engine equivalent, an abort, is `ccid::bulk_abort_cancels_the_waiting_command`).
- read-only public USB registry/cached descriptor collector without device open — deferred: program phase (an observation tool, not device behaviour).
- FunctionFS all-endpoint Linux AIO native candidate validated in private no-NIC QEMU … — deferred: program phase (Linux FunctionFS, §13).
- FunctionFS asynchronous OUT negative completion EPIPE/ESHUTDOWN/ECONNRESET retry … — deferred: program phase.
- PIV generate/import/PUT DATA absent-Le guards with 12 before/after cases … — not a device item: lk-piv owns it (`docs/catalog/piv.md`); the device delivers the APDU unchanged.
- OATH binary credential name touch-label safe display with original credential bytes and HMAC preserved — not a device item: lk-oath (`docs/catalog/oath.md`); the touch label UI is program phase.
- OpenPGP TERMINATE DF and ACTIVATE FILE explicit-Le guards … — not a device item: lk-openpgp (`docs/catalog/openpgp.md`); the device keeps a terminated OpenPGP selected (`ccid::terminated_openpgp_stays_selected`).
- Linux FunctionFS binds full-speed by default on a high-speed-capable dummy_hcd … — deferred: program phase.
- FIDO interrupt IN socket reads now stop at the 256-report model queue boundary; … four 7609-byte PINGs after delayed host reads … — tested (engine part): lk-ctaphid `tests/arbitration.rs::delayed_host_reads_four_maximum_pings_come_back_complete_and_in_order` with four maximum PINGs of 1536 bytes, the longest the key echoes (measured on the reference key, docs/MEASUREMENT.md, probe `ping-max`); intentional difference: no 7609-byte PING; the device returns every report in order and drops none (`fido::*`); queue bounds are program phase.
- Linux FunctionFS bridge reconnects the private CTAPHID stream on USB bus reset; … discard old assembly, pending responses, and late worker replies — tested (engine part): `fido::usb_reset_drops_the_waiting_command_and_channels` (pending command dropped without a reply, old channels invalid); lk-ctaphid `tests/reset.rs`; the bridge is program phase.
- macOS IOHIDUserDevice FIDO output accepts only a full 64-byte report with optional zero Report ID prefix; … — intentional difference: `Input::FidoReport` takes exactly `&[u8; 64]` by type; stripping a Report ID prefix and inbox limits are program phase.

## Appendix A: Linux_native

- actual distro kernel UHID/hidraw discovery via stock python-fido2; 75 existing SDK items on native transport — deferred: program phase (UHID, §13).
- native OTP feature ioctls, own serial visibility policy and independently verified HMAC with shared CCID state — tested (engine part): `touch::otp_state_is_shared_between_hid_and_ccid`, `touch::hid_challenge_response_waits_for_touch` (HMAC verified independently), `management::usb_serial_follows_the_otp_flag`; ioctls are program phase.
- real guest evdev Shift+A, b, 1, Enter events and matching release for every key/modifier; clean HID/evdev teardown — tested (engine part): `touch::button_windows_select_the_slot_on_release` (press and release reports decoded), `verify_timing::keyboard_reports_come_in_press_release_pairs_at_the_right_edge` (every press report followed by its release, at contact for one slot and at release for two); evdev is program phase.
- actual private pcscd, stock pyscard/Yubico SDK, T=1, PIV crypto, OATH, OpenPGP and SCP03 encrypted long APDU/MAC/restart — tested (engine part): `secure_channel::long_wrapped_response_is_split_and_fetched`, `secure_channel::chained_secure_messaging_is_reassembled`, `persistence::state_survives_restart`; pcscd/SDK runs are program phase.
- native Linux IFD Handler 3.0 platform headers and ctypes ABI; 32 independent direct ABI checks — deferred: program phase.
- GCC14 Linux ARM64 build and same120 C++ cases/11620 assertions; no physical key or host devices in guest — intentional difference: the engine is Rust and builds with `cargo` on every platform; no C++ code exists.
- actual single OTP/FIDO/CCID USB composite on private dummy_hcd controller; 75 CTAP items and 3 lifecycle cycles — deferred: program phase; the composite model itself is `Device` (all three interfaces in one value, `determinism::same_seed_same_outputs_and_store` drives them together).
- stock ykman HID vendor discovery and grouping into one own serial; actual USB keyboard and key releases — tested (engine part): one serial on every transport: `fido::vendor_commands` (CTAPHID `0x42`), `touch::otp_hid_reads_device_info_through_the_bridge` (OTP HID `0x13`); discovery is program phase.
- stock libccid/pcscd and USB-classified independent ATR; PIV/OATH/OpenPGP/SCP03/long APDU/restart via actual USB CCID — tested (engine part): `ccid::power_on_returns_the_profile_atr` (`DeviceProfile::atr`), `ccid::*`, `secure_channel::*`; libccid is program phase.
- same shared composite backend compiled on macOS and Linux; entire main regression verified — intentional difference: the engine has no OS code, so one build serves every platform (`docs/DESIGN.md` §4).
- automatic management reboot and all seven USB interface combinations, plus unchanged-profile reboot, … persistent credentials retained and old PIN token rejected — tested: `management::ccid_write_config_with_reboot` (unchanged-profile reboot, credentials kept, PIV PIN dropped), `verify_state::reboot_resets_volatile_state_on_every_interface` (CTAPHID channel, U2F latch, CCID slot and secure channel, OTP HID read state reset; OATH credential and OTP slot kept), `management::ctaphid_write_config_with_reboot`, `management::otp_hid_write_config_with_reboot`, `management::seven_interface_combinations`, `management::disabling_ccid_reenumerates_and_ignores_ccid`; a reboot calls `Authenticator::power_cycle` (lk-fido drops PIN tokens there).
- optional virtual UDC allocation policy preserves requested endpoint addresses … — deferred: program phase.
- stock Firefox native USB WebAuthn: … — deferred: program phase (browser over a native transport); the CTAP behaviour is lk-fido's (`docs/catalog/fido.md`).
- stock Firefox resident/PIN/UV actual native USB: … — deferred: program phase.
- stock Firefox native USB PRF/credProps: … — deferred: program phase.
- stock Firefox actual attestation consent Allow/Block for all three algorithms: … — deferred: program phase.
- stock Chromium actual USB largeBlob: … — deferred: program phase.
- 91 native USB state checks: six HALT/EPIPE/CLEAR_HALT, … real CCID terminal wait concurrent FIDO GetInfo/PING, cancellation without HOTP mutation and fresh approval — tested (engine part): `touch::fido_works_while_a_card_command_waits`, `ccid::bulk_abort_cancels_the_waiting_command`; endpoint HALT and USBDEVFS_RESET are program phase (a bus reset is `ccid::usb_reset_deactivates_the_slot`).
- 50 actual kernel device-PM checks: … queued CCID IN/terminal-presence cycle … retained PIN/UV credential and OTP key … — tested (engine part): `ccid::resume_cancels_a_waiting_card_command`, `fido::suspend_and_resume_keep_fido_state`; kernel PM is program phase.
- 52 actual kernel USB runtime PM checks: … same address/services/bindings/exact bytes while suspended … — tested: `fido::suspend_and_resume_keep_fido_state` (`BusEvent::Suspend` loses nothing); remote wakeup is program phase.
- 113 real same-generation native CCID data/ZLP interruption checks: … — deferred: program phase (kernel write interruption and ZLPs).
- 205 actual profile6 runtime PM and CCID resume checks over six real cycles: … each occupied slot becomes inactive, insertion5003 once, no unpowered APDU, new PowerOn/ATR required; PIV PIN/admin revoked … terminal touch canceled without commit … — tested: `ccid::resume_reports_insertion_and_requires_power_on`, `ccid::resume_cancels_a_waiting_card_command`; kernel-buffered replies are program phase.
- 86 actual profile6->FIDO-only->profile6 pending Management checks: … — tested (engine part): `management::reenumeration_drops_a_waiting_card_command`, `verify_state::reenumeration_ends_a_waiting_fido_command_without_an_answer`, `management::disabling_ccid_reenumerates_and_ignores_ccid`, `fido::other_channels_are_busy_while_a_command_waits`; control ABORT ordering in the gadget is program phase.
- 328 actual large/partial CCID cutover checks: 2047/2048/2049/3071/3072/3073 total-response boundaries, … — tested (engine part): `ccid::long_response_uses_ccid_response_chaining`; lk-ccid `tests/chaining.rs`: `response_boundaries`, `response_of_exactly_two_full_messages`, `largest_extended_response_is_reassembled`; partial USB buffers across a cutover are program phase.
- Current40 fixes actual39 full-buffer replay after an original64-byte large CCID prefix. … — deferred: program phase (native AIO).
- Current42 verifies original large prefix64 across real USB runtime PM: … — deferred: program phase.
- Current42 standard libccid/PCSC USB: 122 checks, … 4 oversized PIV PUTs 6700 … — deferred: program phase; oversized PIV objects are lk-piv's (`docs/catalog/piv.md`).
- final v0.52 combined no-NIC dummy_hcd guest passes software touch to evdev, OTP, stock libccid, X.509, CTAP enterprise/empty allowList, and seven USB profile checks; USB reset discards queued touch reports; … — tested (engine part): `touch::usb_reset_ends_the_hid_wait`, `verify_timing::ended_requests_never_answer_late`, `management::seven_interface_combinations`; the guest is program phase. Keyboard reports already returned are the program's to queue or discard on reset.
- v0.53 combined no-NIC dummy_hcd guest passes reset boundary, OTP, stock libccid, X.509, CTAP and seven USB profile checks … — tested (engine part): `fido::usb_reset_drops_the_waiting_command_and_channels`, `ccid::usb_reset_deactivates_the_slot`; the guest is program phase.
- FunctionFS bridge backpressures CCID bulk OUT/IN when the guest stops reading replies, … — intentional difference: the engine returns every reply in order from `Device::handle` and never drops one; backpressure is the program's.

## Appendix A: verification_fixtures

- Safe wire response commit precondition corrected: … — deferred: program phase (a fixture of the legacy wire tooling).

## storage

- AES-256-GCM — tested: `persistence::records_are_sealed_with_the_storage_key`, `storage::tests::matches_independent_format_vectors`, `tests::host_persists_sealed_and_reports_time`.
- atomic writes — tested (engine part): one `Store::save` per record and per commit (`persistence::failed_save_rolls_back_only_that_command`), and a failing save at every save point never leaves memory and store disagreeing (`verify_persistence::every_failed_save_leaves_memory_and_store_in_agreement`); atomic replacement on disk is the program's `Store` (`lk_core::Store` contract).
- mode0600 — tested: lk-host `state::tests::a_saved_record_loads_back_and_the_next_save_replaces_it` (each record is mode 0600), `state::tests::a_missing_state_directory_is_created_with_mode_0700`; localkeyd `daemon::a_state_directory_open_to_others_is_a_startup_failure`.
- process lock — tested: lk-host `state::tests::a_second_open_is_locked_until_the_first_store_is_dropped`, `state::tests::a_lock_file_left_by_a_dead_process_does_not_block_open`; localkeyd `daemon::a_second_daemon_on_the_same_state_exits_at_once_naming_the_lock`.
- failure rollback — tested: `persistence::failed_save_rolls_back_only_that_command`, `ccid::storage_failure_reaches_the_applet`, `scenario_persistence::store_failure_leaves_state_unchanged`, `verify_persistence::every_failed_save_leaves_memory_and_store_in_agreement`, `verify_persistence::constructor_state_is_saved_once_the_store_recovers`, `tests::constructor_saves_are_protected_or_retried`.
- restart persistence — tested: `persistence::state_survives_restart`, `persistence::restart_does_not_rewrite_records`, `persistence::one_corrupt_record_gives_factory_state_for_that_application_only`, `persistence::wrong_storage_key_gives_factory_state`, `persistence::unconfirmed_key_writes_no_identity_for_absent_records`, `persistence::confirmed_key_saves_absent_identities_next_to_a_damaged_record`, `tests::records_protected_at_open`, `scenario_persistence::every_application_survives_a_restart`, `scenario_persistence::wrong_storage_key_gives_factory_state_without_destroying_records`.

Section count: appendix A 55 bullets and storage 6 bullets. Over every mapping section of
this file, `tools/catalog_status.py` counts 98 lines (71 tested, 5 of them partly deferred
or different, 5 intentional differences, 22 deferred) plus the 3 appendix A bullets owned by
lk-piv, lk-oath and lk-openpgp.

## FIDO bullets left to lk-device by `docs/catalog/fido.md`

- CTAPHID — tested: `fido::init_reports_profile_version_and_cbor_wink`, `fido::waiting_command_sends_keepalives_and_resolves_on_touch` (KEEPALIVE `STATUS_UPNEEDED` every 95 ms from one interval after the request, CTAP 2.1 §11.2.9.1.7; measured on the reference key, docs/MEASUREMENT.md, probes `selection-keepalive-cancel` and `selection-no-touch`), `verify_timing::keepalive_cadence_stays_on_the_grid_with_a_late_host`, `verify_timing::keepalive_cadence_survives_jitter`, `verify_timing::selection_without_touch_sends_315_keepalives_then_times_out_at_30_s` (315 KEEPALIVEs, then the timeout answer alone at 30 s, the CTAP 2.1 §5 user action timeout), `fido::late_tick_sends_one_keepalive`, `fido::presence_timeout_answers_the_command`, `fido::cancel_ends_the_waiting_command`, `fido::ctaphid_message_timeout_is_a_device_deadline` (470 ms, measured: probe `message-timeout`), `fido::empty_cbor_request_is_invalid_len_and_holds_nothing` (`ERR_INVALID_LEN` at once, CTAP 2.1 §11.2.9.1.2 and §11.2.9.1.6), `fido::ping_longer_than_1536_bytes_is_invalid_len_and_the_rest_is_ignored` (measured: probe `ping-max`), `scenario_fido::ctaphid_lock_is_invalid_cmd_and_reserves_nothing` (CTAPHID_LOCK is `ERR_INVALID_CMD`, measured: probes `lock` and `lock-expiry`; lk-ctaphid `tests/lock.rs::measured_probe_other_channels_are_served_right_after_a_lock`); intentional difference (reference defect not copied, docs/MEASUREMENT.md "Revised by principle"): the reference key never answers an empty `CTAPHID_CBOR` and holds the device until INIT on its channel (probe `empty-cbor`), which CTAP 2.1 §11.2.4 ("A request always triggers a response") and §11.2.5.2 rule out, and its presence timeout of 28 451.8 ms after 300 KEEPALIVEs (probe `selection-no-touch`) is the 30 s design value on a clock that runs about 5.4 % fast.
- CTAPHID final legal sequence 127 completes a maximum 7609-byte PING; … — intentional difference: measured on the reference key (docs/MEASUREMENT.md, probes `ping-max` and `ping-7609`), the longest request is 1536 bytes (last SEQ 25) and a longer BCNT is `ERR_INVALID_LEN` at the initialization packet, its late packets ignored: lk-ctaphid `tests/framing.rs::maximum_ping_is_1536_bytes_and_ends_on_sequence_25`, `bcnt_above_1536_is_invalid_len_at_once_and_the_late_fragments_are_ignored`, `tests/commands.rs::every_request_above_1536_bytes_is_invalid_len`, device `fido::ping_longer_than_1536_bytes_is_invalid_len_and_the_rest_is_ignored`. SEQ 127 and the 7550/7551/7609 boundaries stay tested for the device's responses: `tests/framing.rs::maximum_response_ends_on_sequence_127`, `response_of_7550_bytes_ends_on_sequence_126_with_a_full_packet`, `response_of_7551_bytes_needs_sequence_127_for_one_byte`.
- Allocated CTAPHID INIT now discards late replies from an aborted same-CID operation. … — tested: `fido::init_resynchronisation_drops_the_late_reply`, `verify_timing::ended_requests_never_answer_late`.
- CTAPHID WINK rejects nonzero BCNT with ERR_INVALID_LEN … — tested in lk-ctaphid: `tests/commands.rs::wink_with_payload_is_invalid_len_and_the_channel_recovers`; device indication: `fido::wink_pulses_the_indicator`, `verify_timing::wink_pulses_after_a_request_ends_in_the_same_input`.
- An orphan CTAPHID continuation frame is ignored without occupying a channel; … — tested in lk-ctaphid: `tests/arbitration.rs::orphan_continuation_packets_are_ignored_without_occupying_a_channel`, `unknown_channel_initial_fragment_is_invalid_channel_while_a_valid_channel_pings`.
- A concurrent CTAPHID CBOR operation reserves the device for its CID: … — tested: `fido::other_channels_are_busy_while_a_command_waits`.
- CTAPHID_CANCEL during a U2F MSG is ignored while same-CID INIT still aborts; … — tested: `fido::cancel_after_u2f_does_nothing`, `fido::init_resynchronisation_drops_the_late_reply`.
- A processing CTAPHID CID rejects an interleaved PING or WINK with CHANNEL_BUSY, while INIT resynchronization, CANCEL, original completion and idle PING remain functional; … — tested: `fido::other_channels_are_busy_while_a_command_waits`, `fido::cancel_ends_the_waiting_command` (PING works afterwards), `fido::init_resynchronisation_drops_the_late_reply`.
- U2F presence (docs/CONTRACTS.md "lk-fido") — tested: `fido::u2f_touch_latch_lets_the_next_request_succeed`, `fido::u2f_latch_expires`, `fido::u2f_window_closes_when_the_client_stops_asking`.
- reset power-up window — tested: `fido::reset_window_counts_from_power_up` (`Device::open` and `BusEvent::PowerCycle` are power-ups).

## Other bullets that name lk-device

- OTP "documented short/long hold release windows over socket and compiled native bridge" and "documented two-slot short/long touch windows" — tested: `touch::button_windows_select_the_slot_on_release` (300–1500 ms → slot 1, 2500–5000 ms → slot 2, other durations nothing); the socket/native bridge is program phase.
- OTP "private touch_down/touch_up events return single-slot 1 FAST_TRIG reports at modeled contact, defer two-slot selection to release" — tested: `touch::single_slot_types_at_contact`, `touch::button_windows_select_the_slot_on_release`.
- OTP "device-shared touch ownership prevents … duplicate OTP reports" — tested: `touch::hid_challenge_response_waits_for_touch` (a touch that satisfies a request never types), `touch::idle_press_without_slots_is_silent` (repeated edges are ignored), `verify_timing::four_pending_requests_get_touches_in_start_order`, `verify_timing::an_expired_request_drops_out_of_the_race`, `verify_timing::touch_at_the_earliest_requests_timeout_goes_to_the_next_one`, `verify_timing::touch_exactly_at_the_otp_hid_timeout_is_a_button_press`.
- OTP "OTP volatile session rollback and committed device-reboot behavior" — tested (device part): a Management reboot is a power cycle (`management::ccid_write_config_with_reboot`; `Device::restart` calls `CardApplet::reset(PowerCycle)` for the OTP applet).
- Management "fail-closed behavior when shared backend unavailable" — tested: the device owns one in-process `Management` for CCID, OTP HID and CTAPHID (`touch::otp_hid_reads_device_info_through_the_bridge`, `fido::vendor_commands`, `ccid::select_management`).
- Management appendix B `usb_management_reboot_reenumeration` ("deferred: the actual USB re-enumeration on `ConfigEffect::Reboot` is done by `lk-device`") — tested: `management::ccid_write_config_with_reboot`, `management::ctaphid_write_config_with_reboot`, `management::otp_hid_write_config_with_reboot`, `management::rejected_write_does_not_reboot`; over OTP HID the reboot follows the host's status read (`management::otp_hid_write_config_reboots_after_the_host_read_the_status`, `management::otp_hid_write_config_reboots_after_a_delay_without_a_status_read`, `management::a_power_cycle_before_the_status_read_takes_the_owed_reboot_over`).
- Management SET MODE over CTAPHID `0x40` ("left to `lk-device`") — tested: `fido::vendor_commands` (`ERR_INVALID_CMD`, the CTAPHID form of `6D00`).
- Security Domain "PIV PIN/admin and OATH access revoked" and "malformed plaintext SELECT clears OCE and PIV PIN/admin before validation" (`docs/catalog/sd.md`: "lk-device must clear applet authorizations when a channel ends") — tested: `secure_channel::plaintext_command_is_rejected_and_revokes_piv_pin`; the device calls `CardApplet::deselect` on the selected applet when a channel ends on a rejected or plaintext command.
- Security Domain "plaintext in a channel rejected before dispatch" — tested: `secure_channel::plaintext_command_is_rejected_and_revokes_piv_pin`, `secure_channel::plaintext_handshake_inside_a_channel_is_rejected`, `secure_channel::bad_mac_ends_the_channel`; a warning or error status keeps the session (`verify_state::secure_channel_survives_applet_warnings_and_errors`), an aborted wrapped command leaves the MAC chain in step (`verify_state::abort_of_a_wrapped_touch_command_keeps_the_channel_in_step`).
- Security Domain handoff "not-yet-authenticated SCP03 INIT retain outer transport" — tested: `secure_channel::nested_initialize_update_keeps_the_outer_channel`.
- Security Domain "old response remains SDK MAC-verified while reset and encrypted SELECT terminate authorization" — tested: `secure_channel::encrypted_select_answer_is_wrapped_then_the_channel_ends`; "SELECT remains an explicit session boundary" also for an unknown AID, which keeps the selection (`verify_state::wrapped_select_of_an_unknown_aid_ends_the_channel_and_keeps_the_selection`).
- PIV "A SELECT of the PIV AID while PIV is selected keeps PIN verification" — tested: `ccid::piv_reselect_keeps_pin_verification`.

## Appendix B rows about the device

- `composite_usb_protocol_model` — tested (engine model): `determinism::same_seed_same_outputs_and_store`, `scenario_determinism::same_script_and_seed_give_byte_identical_outputs`, `verify_timing::extra_early_ticks_change_nothing`; macOS registration is program phase.
- `ccid_parameters_errors_and_cancellation` — tested: `ccid::get_parameters_reports_t1`, `ccid::control_abort_then_bulk_abort`, `ccid::busy_slot_while_waiting_for_touch`, `verify_state::power_off_and_warm_reset_are_refused_while_a_card_command_waits`.
- `measured_fido_ccid_usb_descriptors` — tested: `verify_state::usb_descriptors_match_the_reference_byte_for_byte`, `management::usb_identity_matches_the_reference_configuration`.
- `ccid_extended_chaining_wtx_and_eof` — tested: `ccid::long_response_uses_ccid_response_chaining`, `ccid::card_touch_sends_time_extensions_and_resolves`, `verify_timing::time_extensions_stay_on_the_grid_with_a_late_host`; reference timing unmeasured (WTX cadence is model policy).
- `usb_management_reboot_reenumeration` — tested: see above.
- `native_usb_halt_reset_configuration_and_pending_ccid_fido_concurrency` — tested (engine part): `touch::fido_works_while_a_card_command_waits`, `ccid::usb_reset_deactivates_the_slot`, `verify_timing::ended_requests_never_answer_late`, `verify_timing::overdue_deadlines_are_processed_in_time_order`.
- `ccid_post_resume_deactivation_slot_change_and_explicit_reactivation` — tested: `ccid::resume_reports_insertion_and_requires_power_on`.
- `native_pending_ccid_configuration_generation_cutover` — tested (engine part): `management::reenumeration_drops_a_waiting_card_command`, `verify_state::reenumeration_ends_a_waiting_fido_command_without_an_answer`.
- `linux_functionfs_same_generation_usb_reset_clears_touch_queue` — tested (engine part): `touch::usb_reset_ends_the_hid_wait`, `fido::usb_reset_drops_the_waiting_command_and_channels`.
- `fido_usb_bus_reset_old_report_isolation` — tested: `fido::usb_reset_drops_the_waiting_command_and_channels`.
- `ctaphid_allocated_init_late_reply_flush` — tested: `fido::init_resynchronisation_drops_the_late_reply`.
- `ctaphid_cross_channel_arbitration` — tested: `fido::other_channels_are_busy_while_a_command_waits`.
- `ctaphid_cancel_during_u2f` — tested: `fido::cancel_after_u2f_does_nothing`.
- `ctaphid_orphan_cont_unknown_channel`, `ctaphid_wink_zero_length_only`, `ctaphid_max_7609_byte_ping` — tested in lk-ctaphid (named above; for `ctaphid_max_7609_byte_ping` the response side up to SEQ 127); intentional difference for `ctaphid_max_7609_byte_ping`: requests stop at 1536 bytes, measured on the reference key (docs/MEASUREMENT.md, probe `ping-max`).
- `fido_same_cid_transaction` — tested: `fido::other_channels_are_busy_while_a_command_waits` (same CID PING busy while the command waits).
- `otp_two_slot_touch_windows`, `otp_single_slot1_fast_trigger`, `otp_explicit_touch_events_and_counter_exclusivity`, `otp_shared_touch_ownership` — tested: `touch::button_windows_select_the_slot_on_release`, `touch::single_slot_types_at_contact`, `touch::hid_challenge_response_waits_for_touch`.
- `all_firmware_edge_cases_and_timing` — deferred: the KEEPALIVE cadence and the CTAPHID message timeout are measured on the reference key (docs/MEASUREMENT.md, probes `selection-keepalive-cancel`, `selection-no-touch`, `message-timeout`; see below), and the FIDO presence timeout is the 30 s of CTAP 2.1 §5 (the key's 28.45 s is that value on a fast clock, see below); the other device timings below stay model policy until measured on hardware.
- Rows naming macOS, FunctionFS, UDCs, kernels, browsers or stock host stacks — deferred: program phase.

## Model policies (not measured on the reference device unless a bullet says it was measured)

A model policy is a choice where neither a specification nor the reference key fixes the
behaviour (`docs/CONTRACTS.md` "Reference, not replica"; `docs/DESIGN.md` §2 and §12
decision 8). A bullet that says "measured" follows the reference because the specification
leaves the value open (rule 2); one that says "intentional difference" departs from the
reference because a specification defines the behaviour (rule 1) or because the reference's
behaviour is a defect (rule 4).

- KEEPALIVE: measured on the reference key (docs/MEASUREMENT.md, probes `selection-keepalive-cancel` and `selection-no-touch`): `STATUS_UPNEEDED` on the grid `start + k * 95 ms`, k ≥ 1, none at once, while a CTAP2 command waits for a touch (`KEEPALIVE_INTERVAL_MS` 95; the key: first after 93.8 and 85.9 ms, mean interval 94.86 ms; CTAP 2.1 §11.2.9.1.7 "at least every 100ms"); the presence timeout (lk-fido `TOUCH_TIMEOUT_MS`) is 30 000 ms, the CTAP 2.1 §5 user action timeout ("Thirty seconds is a reasonable value"), so a host sees 315 KEEPALIVEs, the last at 29 925 ms, and then the answer alone (`verify_timing::selection_without_touch_sends_315_keepalives_then_times_out_at_30_s`). Intentional difference (reference defect not copied): the key answers 28 451.8 ms after the request, after 300 KEEPALIVEs, its 30 s design value on a clock that runs about 5.4 % fast (docs/MEASUREMENT.md "Revised by principle"); the engine used 28 500 ms, 300 intervals, between the measurement and that revision. Before the measurement: one at once, then every 100 ms, and a 30 s timeout. Model policy (not measured): the grid does not move when the host's Tick comes late, so lateness never stretches the cadence; a Tick late by several intervals sends one, not a burst. A periodic message due at the instant its request times out goes out just before the timeout answer (timer order); the 30 s FIDO timeout is not on the 95 ms grid, so this shows on the CCID time extension (`verify_timing::time_extensions_stay_on_the_grid_with_a_late_host`).
- CCID time extension: on the grid `start + k * 500 ms` (k ≥ 1) while a card command waits (`WTX_INTERVAL_MS`), with the same rules.
- Deadlines due at the time of an input are processed before it, in time order: a touch at the exact instant a request times out comes after the timeout and goes to the next pending request, or is a button press.
- U2F: the request window stays open 3 s after the last `6985` that asked for presence; a touch in it stays latched 3 s (`U2F_REQUEST_WINDOW_MS`, `U2F_LATCH_MS`).
- OTP HID reboot timing: a Management write with `REBOOT` over OTP HID reboots right after the host's next status read, or 1 s later if none comes (`OTP_REBOOT_DELAY_MS`). Rebooting at once made ykman `config usb` over OTP HID report a failed write on a real kernel (`tools/linux-guest/tests/uhid.sh`); the firmware's own delay is unmeasured.
- WINK: a `PresenceIndicator(true)`, `PresenceIndicator(false)` pulse when no request is pending at the time the WINK is processed (a request that ended earlier in the same input is reported off first).
- OTP button: no device timer; `lk-otp` classifies the hold at release (0.3–1.5 s slot 1, 2.5–5 s slot 2) and types a single configured slot 1 at contact. A press that began with nothing pending stays an OTP press even if a request starts during the hold.
- No application selected: `6D00`. Unknown or disabled AID: `6A82`, selection unchanged. SELECT matches when the applet AID is a prefix of the DF name (longest match). A truncated DF name selects too: when no AID is a prefix of a non-empty DF name, the first enabled applet in table order (Management, OTP, OATH, PIV, OpenPGP, HSM Auth, Security Domain) whose AID starts with the name is selected, measured on the reference key (docs/MEASUREMENT.md, probe `select-partial-aid`: `A0000005` and `A000000527` select Management, `A0000003` PIV, `D276000124` OpenPGP, `A0000005272107` HSM Auth; truncated names were `6A82` before). Which applet wins when several AIDs start with the name and the key has OTP or OATH enabled, or another applet selected, was not measured; table order reproduces the measurement (`tests::applet_lookup_by_df_name`, `tests::partial_df_names_select_as_measured`, `ccid::select_by_partial_df_name`). The FIDO AID is not offered on CCID. An empty DF name (`00 A4 04 00 00`) selects the Security Domain, the issuer security domain (GP Card Specification v2.3.1 §11.9.2.3: "The Lc and data field of the SELECT command may be omitted if the Issuer Security Domain is being selected"; §H.1.3), whatever the capabilities; it was `6A82` (unmeasured on the reference key; `tests::empty_df_name_selects_the_issuer_security_domain`, `ccid::empty_df_name_selects_the_security_domain`). Only the basic logical channel is served: a SELECT whose (unwrapped) CLA codes another channel (b2-b1 not `00` in `00`-`3F`/`80`-`BF`, or any of `40`-`7F`/`C0`-`FE`, channels 4-19) answers `6881` before anything else and changes neither the selection nor the secure channel session (ISO/IEC 7816-4:1995 §5.5.2-§5.5.3, Table 16 "Logical channel not supported"; the ATR's card capabilities say "no logical channel"; GP 2.3.1 Table 11-10); CLA `FF` (reserved for PTS, ISO/IEC 7816-4:1995 Table 8) answers `6E00`. Before, the class was ignored and such a SELECT moved the basic channel's selection and ended the session (unmeasured on the reference key; `card::tests::select_on_another_logical_channel_is_refused`, `ccid::select_on_another_logical_channel_answers_6881_and_changes_nothing`, `secure_channel::encrypted_select_on_another_logical_channel_keeps_the_session`).
- Card answers owned by the applet crates and checked end to end over CCID, measured on the reference key (docs/MEASUREMENT.md): the Management SELECT text, the two DeviceInfo pages, CLA `80`, READ CONFIG P1/P2 and GET RESPONSE with nothing pending (probes `select-mgmt`, `mgmt-read-config`, `bad-p1p2-mgmt`, `cla-variants-mgmt`, `get-response-idle-mgmt`; `ccid::select_management`, `ccid::management_reads_as_measured`, `docs/catalog/mgmt.md`); the Security Domain's `6982` for unknown instructions and idle GET RESPONSE and its `66`-wrapped `80 CA 00 66` (the GlobalPlatform class returns whole data objects for every GET DATA, GP 2.3.1 §11.3.3.1, also `84` under a channel: `secure_channel::security_domain_commands_under_its_own_channel`; its SELECT answer carries the `9F65` of GP 2.3.1 Table 11-82, which the reference omits: `scenario_ccid::select_routes_between_all_seven_applications`), HSM Auth's CLA `80` and idle GET RESPONSE `6D00` (probes `undefined-ins-sd`, `get-response-idle-sd`, `cla-variants-sd`, `cla-variants-hsmauth`, `get-response-idle-hsmauth`; `ccid::security_domain_and_hsm_auth_statuses_as_measured`, `scenario_ccid::select_routes_between_all_seven_applications`, `docs/catalog/sd.md`, `docs/catalog/hsmauth.md`).
- Application gating: a SELECT of an application whose Management capability is disabled answers `6A82`; capability changes apply at the next enumeration (reboot or power cycle), and so does a change of the enabled interface set: only a write with `REBOOT` re-enumerates at once (model policy following ykman `config usb` and yubikit `set_mode`; `management::interface_change_without_reboot_waits_for_the_next_enumeration`).
- CTAPHID capabilities: `WINK`, plus `CBOR` while FIDO2 is enabled and `NMSG` while U2F is disabled.
- CTAPHID_LOCK: measured on the reference key (docs/MEASUREMENT.md, probes `lock` and `lock-expiry`): not implemented. LOCK with 0, 1 or 2 s is `ERR_INVALID_CMD` (`01`), and other channels and broadcast INIT are never locked out (lk-ctaphid `tests/lock.rs`, `scenario_fido::ctaphid_lock_is_invalid_cmd_and_reserves_nothing`); `ERR_LOCK_REQUIRED` (`0A`) is never sent. Before the measurement the engine implemented the lock as model policy (1 to 10 s, other channels `ERR_CHANNEL_BUSY` until it lapsed, the code Chromium and python-fido2 retry). Model policy (not measured): a LOCK sent while the device is busy with another channel is `ERR_CHANNEL_BUSY` (busy is checked before the command).
- CTAPHID request length: measured on the reference key (docs/MEASUREMENT.md, probe `ping-max`): at most 1536 bytes (`lk_ctaphid::MAX_MESSAGE_LEN`); a longer BCNT is `ERR_INVALID_LEN` at the initialization packet and its continuation packets are ignored. Only PING was measured; CBOR, MSG and vendor requests get the same limit (GetInfo `maxMsgSize` 1536). Responses are framed up to 7609 bytes.
- CTAPHID empty CBOR request: `CTAPHID_CBOR` with BCNT 0 is `ERR_INVALID_LEN` at its initialization packet and holds nothing, like an empty `CTAPHID_MSG` (CTAP 2.1 §11.2.9.1.2 "BCNT 1..(n + 1)", §11.2.9.1.6; `fido::empty_cbor_request_is_invalid_len_and_holds_nothing`, lk-ctaphid `tests/commands.rs::empty_cbor_request_is_invalid_len`, `empty_cbor_request_holds_nothing_on_any_channel`). Intentional difference (reference defect not copied): measured on the reference key (docs/MEASUREMENT.md, probe `empty-cbor` and "The stuck-channel incident"), the key never answers it (no KEEPALIVE either) and holds the device until INIT on that channel: other channels get `ERR_CHANNEL_BUSY`, CANCEL changes nothing, no timeout ends it. CTAP 2.1 §11.2.4 ("A request always triggers a response"), §11.2.5 and §11.2.5.2 rule that out; the engine copied the stall between the measurement and the revision of 2026-10-12 (docs/MEASUREMENT.md "Revised by principle").
- CTAPHID message timeout: measured on the reference key (docs/MEASUREMENT.md, probe `message-timeout`): `ERR_MSG_TIMEOUT` 470 ms after the last packet of an incomplete message (`lk_ctaphid::TRANSACTION_TIMEOUT_MS`; the key: 469.8 ms; 3000 ms model policy before). Model policy (not measured): every accepted packet restarts it.
- USB serial string only while a configured OTP slot sets `EXTFLAG_SERIAL_USB_VISIBLE`.
- OTP HID report descriptor: HID 1.11 Appendix E.6 boot keyboard plus an 8-byte vendor-page feature report (no OTP-interface bytes were measured).
- Configuration descriptor (`UsbIdentity::configuration_descriptor`): interfaces numbered from 0 in the order OTP, FIDO, CCID; FIDO and CCID keep the measured endpoints (`04`/`84`, `02`/`82`/`83`) and bytes in every combination; the OTP interface is a boot keyboard (class `03`, subclass `01`, protocol `01`) with interrupt IN endpoint `81`, 8 bytes, `bInterval` 10; `bmAttributes` `80` and `bMaxPower` `0F` in every combination. Device descriptor string indices: manufacturer 1, product 2, serial 3 (0 while no serial is shown).
- Storage at open: a constructor save the store rejects (Security Domain, PIV and OpenPGP generate their identity in their constructors) is saved again before every later input until the store takes it; records that exist but cannot be read are never written at open. When no record opens and at least one is unreadable, the storage key is unconfirmed (AES-GCM authenticates the key, so one record that opens proves it right) and no constructor writes anything at open: an identity sealed under a wrong key would be unreadable once the right key is given, and that application could then never save its identity at open again. Those applications keep their factory identity in memory until their own first mutating command persists it. The program should check `Device::unreadable_records` after open: an application's first mutating command replaces an unreadable record (`docs/DESIGN.md` §7), so serving a device opened with a wrong key loses the records it replaces.
- Resume after suspend ends the card session (card power-off) and sends one `50 03` slot-change; FIDO and OTP state are kept. A bus reset ends a suspend.
- Under a secure channel the device collects the applet's whole response (following `61xx` with GET RESPONSE, or SEND REMAINING for OATH), wraps it once and splits it into Ne-sized `61xx` pieces itself; plaintext `00 C0` (and `00 A5` with OATH) fetch them. A channel that ends on a rejected or plaintext command drops the selected applet's selection-scoped authorization with `deselect()`.

## Adversarial review (device:verify)

Findings fixed in `lk-device` (no application crate changed):

- Periodic messages drifted with a late host: KEEPALIVE and time extensions were
  rescheduled from the time a Tick was processed, so a host timer that fires a little
  late (as OS timers do) stretched every KEEPALIVE gap beyond CTAP 2.1 §11.2.9.1.7's
  100 ms. They now run on a grid from the request's start (`presence.rs`
  `next_on_grid`): `verify_timing::keepalive_cadence_stays_on_the_grid_with_a_late_host`,
  `verify_timing::keepalive_cadence_survives_jitter`,
  `verify_timing::time_extensions_stay_on_the_grid_with_a_late_host`.
- A WINK was swallowed when a timer ended the last pending request in the same input
  (the check used the indicator state of the previous input): `fido.rs` now looks at the
  pending set; `verify_timing::wink_pulses_after_a_request_ends_in_the_same_input`.
- A constructor save that failed at open (Security Domain, PIV, OpenPGP identity) was
  lost, so the identity the host read changed at the next open: `host.rs` keeps it and
  saves it again before each later input;
  `verify_persistence::every_failed_save_leaves_memory_and_store_in_agreement`,
  `verify_persistence::constructor_state_is_saved_once_the_store_recovers`,
  `tests::constructor_saves_are_protected_or_retried`.
- Gap closed: the USB identity could not be compared byte for byte with the measured
  configuration (only the class and report descriptors were exposed).
  `UsbIdentity::device_descriptor` and `configuration_descriptor` now build the
  descriptors (`verify_state::usb_descriptors_match_the_reference_byte_for_byte`).

Checked and found correct (each now pinned by a test): touch at the exact instant of
every kind of deadline, four-way touch races with and without an expiry, overdue
deadlines processed in time order, no late answer, KEEPALIVE or time extension after
an abort, INIT resynchronisation, CANCEL, USB reset, power cycle or reboot, IccPowerOff
and warm IccPowerOn refused while a card command waits, the secure channel after
warnings, errors, an aborted wrapped command and a SELECT of an unknown AID, what a
reboot resets on each interface, disabled interfaces, keyboard press/release pairs, and
extra early Ticks. Remaining model questions are listed under "Model policies" above.

## Second review (device:verify-2)

Interop lens: the request shapes of libfido2 (Linux hidraw), python-fido2, Chromium and
macOS IOHID clients on CTAPHID; pcscd with libccid, GnuPG's internal CCID driver and the
macOS CCID driver on CCID; and the program that will wrap `Device`.

Findings fixed:

- CTAPHID_LOCK kept other channels out with `ERR_LOCK_REQUIRED`. Chromium treats any
  error but `CHANNEL_BUSY` as a device error and python-fido2 raises it, so a WebAuthn
  ceremony that would have succeeded once the lock lapsed (at most 10 s) failed. Now
  `ERR_CHANNEL_BUSY` (sources under "Model policies"; `lk-ctaphid` `framer.rs`):
  lk-ctaphid `tests/lock.rs::locked_out_client_retrying_on_busy_gets_through_when_the_lock_lapses`,
  the lock tests and fuzz oracle of lk-ctaphid, and
  `scenario_fido::ctaphid_lock_reserves_the_device_until_it_expires`. Superseded by the
  measurement: the key does not implement CTAPHID_LOCK (`ERR_INVALID_CMD`, docs/MEASUREMENT.md,
  probes `lock` and `lock-expiry`), so the engine no longer has a lock; those tests were
  replaced by lk-ctaphid `tests/lock.rs` (LOCK refused) and
  `scenario_fido::ctaphid_lock_is_invalid_cmd_and_reserves_nothing`.
- Opening with a wrong storage key wrote the constructor identities (Security Domain,
  PIV, OpenPGP) of applications whose record was absent, sealed under the wrong key; with
  the right key those records were then unreadable and the identities changed at every
  start. Decision: when no record opens and some are unreadable, nothing is written at
  open (`apps::protected_at_open`); one record that opens confirms the key, and absent
  identities are then saved as before. `persistence::unconfirmed_key_writes_no_identity_for_absent_records`,
  `persistence::confirmed_key_saves_absent_identities_next_to_a_damaged_record`,
  `tests::records_protected_at_open`.
- Hardening (`docs/DESIGN.md` §8): the plaintext records loaded at open (every
  application's keys) and the deferred constructor copies are wiped when they are
  released, not only when the device is dropped (`host::wipe`).
- Documentation: the time-extension cadence rationale (`presence.rs`) cited a "3 s read
  timeout" that libccid does not use for this ATR; `Device::set_unix_time` now says the
  device never advances the value; stale "change request" notes on lk-ccid
  `control_abort` and `storage::seal` point at `docs/CONTRACTS.md` "Phase 0 as
  implemented".

Checked and found correct, against the host sources read for this review: libfido2
`src/io.c` (it filters other CIDs and KEEPALIVE only before the first packet of a reply,
and the device never interleaves another channel's report inside a response; every
CTAPHID_ERROR fails the call) and `src/u2f.c` (`U2F_PACE_MS` 100: U2F requests repeat
every 100 ms while they answer `6985`, inside the 3 s request window); python-fido2
`CtapHidDevice.call` and Chromium `FidoHidDevice` (retry on `CHANNEL_BUSY` only); CTAP 2.1
§11.2.5 (busy and INIT resynchronisation) and §11.2.9.1.5 (CANCEL never answered);
libccid `ifdhandler.c` (no SetParameters for this descriptor, whose `dwFeatures` has
automatic parameter negotiation `0x40`; T=1 read timeout `T1_card_timeout`, the card's
waiting times plus 1000 ms, about 1.5 to 2.5 s for the profile ATR, so the 500 ms
time-extension cadence keeps reads alive); GnuPG `scd/ccid-driver.c` (GetParameters then
SetParameters echoing the returned block, or its default block with ATR bytes:
lk-ccid `tests/messages.rs::gnupg_parameter_exchange_is_accepted`; command parts with
`wLevelParameter` 1, 3, 2 and response parts fetched with `0010`; a time extension
re-reads with `bError` times its timeout, 1 here).

Public API beyond `docs/CONTRACTS.md` (which names only `Device::open`, `handle`,
`next_deadline`): `Device::open_at`, `set_unix_time` (the contract asks for "a way"),
`usb_identity` with `UsbIdentity` (fields plus `device_descriptor` and
`configuration_descriptor`), `interfaces`, `profile`, `unreadable_records`,
`presence_pending`; `Input::CcidControlAbort`; the constants `KEEPALIVE_INTERVAL_MS`,
`WTX_INTERVAL_MS`, `U2F_REQUEST_WINDOW_MS`, `U2F_LATCH_MS`, `OTP_REBOOT_DELAY_MS`, `FIDO_REPORT_DESCRIPTOR`,
`OTP_REPORT_DESCRIPTOR`; the `storage` module (`seal`, `open`, `record_id`,
`SealError`, `FORMAT_VERSION`, `NONCE_LEN`, `TAG_LEN`, `OVERHEAD`); and the
constructor-save retry before each input.

