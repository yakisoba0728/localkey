# YubiHSM Auth catalog status (lk-hsmauth)

One line per bullet of the `## YubiHSMAuth` section of `reference/BEHAVIOR_CATALOG.md`,
plus the YubiHSM Auth bullet filed under `## FIDO` and the YubiHSM Auth rows of
Appendix B. Test names refer to `crates/lk-hsmauth`: `tests/derivation.rs`,
`tests/credentials.rs`, `tests/robustness.rs`, and the unit tests in `src/`
(`kdf::tests::`, `state::tests::`, `request::tests::`).

## YubiHSMAuth

- symmetric SCP03 derivation: tested: `symmetric_session_keys_match_yubico_published_vector` (Yubico's published hardware test vector, yubikey-manager `tests/device/test_hsmauth.py`), `kdf::tests::scp03_kdf_reproduces_yubico_published_vector`, `symmetric_session_keys_match_independent_sp800_108_kdf` (test-side SP 800-108 / AES-CMAC with the Amendment D §4.1.5 layout, PRF anchored by `test_side_prf_matches_rfc4493_example`)
- asymmetric dual ECDH derivation: tested: `kdf::tests::asymmetric_session_keys_match_independent_vector` and `asymmetric_calculate_matches_independent_known_answer` (known-answer vector computed with pyca/cryptography from the yubihsm-shell `yh_create_session_asym` layout; end to end through GET CHALLENGE and CALCULATE), `kdf::tests::x963_kdf_matches_nist_cavp_vector` (NIST CAVP X9.63 KDF SHA-256), `asymmetric_dual_ecdh_session_keys_match_yubihsm_side`, `asymmetric_generated_credential_derives_with_exported_public_key`
- receipt verification: tested: `asymmetric_receipt_mismatch_is_rejected`, `asymmetric_calculate_matches_independent_known_answer` (a receipt over `EPK.OCE || EPK.SD` instead of `EPK.SD || EPK.OCE`, and a flipped bit, are `6984`), `correct_password_with_bad_receipt_restores_tries_without_touch`, `symmetric_card_cryptogram_is_verified_when_supplied` (optional symmetric card cryptogram, model decision)
- single-use ephemeral challenges: tested: `asymmetric_challenge_is_single_use`, `used_challenge_cannot_be_replayed` (after success, re-SELECT, a newer challenge, and a power cycle), `declined_touch_consumes_the_ephemeral_challenge`, `asymmetric_calculate_without_challenge_is_rejected`, `asymmetric_context_must_carry_the_issued_challenge`, `outstanding_challenge_survives_unrelated_failures`, `deselect_and_reset_clear_volatile_state`
- generate/import/delete: tested: `generate_accepts_yubikit_empty_private_key_object` (the exact yubikit `generate_credential_asymmetric` data field with `7D 00`), `generate_without_private_key_object_is_accepted`, `generate_asymmetric_credential_and_get_public_key`, `import_asymmetric_credential_public_key_matches`, `put_symmetric_credential_and_list`, `delete_credential_requires_management_key`, `delete_unknown_label_is_file_not_found`, `get_public_key_of_symmetric_credential_is_rejected`
- password retries: tested: `wrong_credential_password_decrements_and_correct_resets`, `wrong_password_counter_is_persisted_before_response`, `password_tries_are_spent_before_comparison`, `failing_store_is_not_a_guessing_oracle`, `get_challenge_with_password_verifies_it`, `declined_touch_leaves_password_tries_unchanged`, `touch_completion_restores_tries_before_keys`, `storage_failure_after_touch_reveals_no_keys`, `last_try_spent_before_touch_does_not_wipe_the_record`, `abandoned_or_declined_last_try_touch_keeps_the_credential`, `failed_restore_of_the_last_try_deletes_only_that_credential`, `state::tests::zero_tries_credential_loads_as_deleted`
- management key: tested: `management_key_change_and_retries`, `management_key_blocks_after_eight_wrong_attempts_until_reset`, `management_key_tries_are_persisted_for_every_command`, `blocked_management_key_writes_nothing`, `syntax_errors_do_not_consume_management_key_retries`
- credential deleted on eighth wrong password with ephemeral state cleared, label recoverable after restart; symmetric/asymmetric YubiKit socket and direct IFD verified: tested: `eighth_wrong_password_deletes_credential_and_clears_challenge`, `deleted_label_is_reusable_after_restart`, `eighth_wrong_password_with_failed_deletion_keeps_the_rest` (the deletion cannot be stored: `6581`, the record still loads with only that credential gone, the label is reusable), `finished_deletion_forgets_the_ephemeral_key`; intentional difference: no YubiKit/socket/IFD run at engine level (`docs/DESIGN.md` §4, §12-3, §13); the behaviour is tested through `CardApplet` with `lk_testkit::TestHost`
- RESET application rejects unexpected data or explicit Le before clearing credentials; normal SDK reset and ambiguous short-zero formatter preserved: tested: `reset_requires_dead_p1p2_and_rejects_data_or_le` (data, a short Le other than `00` or any non-zero extended Le `6700`, P1P2 other than `DE AD` `6A86`, nothing cleared or written), `reset_accepts_sdk_and_ambiguous_short_zero_forms` (`00 06 DE AD` from YESDK and current yubikit; `00 06 DE AD 00` from ykhsmauth `send_data`, which always writes Lc, and yubikit `ShortApduFormatter`'s "explicit Lc"; `00 06 DE AD 00 00 00` from yubikit 5.0 `_encode_extended_apdu`, i.e. `ykman hsmauth reset` 5.0 over USB, accepted per `docs/CONTRACTS.md` "APDU conventions" — answered `6700` before the second review), `reset_clears_credentials_and_management_key`
- ADD CREDENTIAL rejects duplicate labels with 6983, malformed algorithm length and invalid UTF-8 labels with 6A80, without corrupting SDK listing: tested: `duplicate_label_is_rejected_with_6983`, `malformed_algorithm_is_rejected_without_storage`, `invalid_utf8_label_is_rejected_without_storage`, `label_length_bounds`, `label_rules_count_utf8_bytes_and_compare_exactly`, `label_rules_apply_to_every_command`, `malformed_tlv_is_6a80_for_every_command`, `put_rejects_wrong_key_material_for_algorithm`
- YubiHSM Auth symmetric GET CHALLENGE returns an eight-byte host challenge without touch; CALCULATE still requires touch. Unmodified YubiKit Mac/Linux socket/direct IFD checks pass; physical timing remains unmeasured.: tested: `symmetric_challenge_is_eight_random_bytes_without_touch`, `get_challenge_never_requires_touch`, `touch_is_requested_by_calculate_only`, `touch_required_calculate_waits_for_touch`, `touch_declined_or_timed_out_returns_6982`, `asymmetric_touch_required_calculate_waits_for_touch`; intentional difference: touch timing belongs to the host program (`Outcome::NeedTouch { timeout_ms: 15000 }`, a model value) and no YubiKit run happens at engine level

## Filed under FIDO

- YubiHSM Auth Add Credential accepts touch policy tag 7A only as a one-byte 00 or 01 and rejects malformed values without storage; FunctionFS OTP IN input is backpressured when the guest HID reader pauses: tested: `touch_policy_tag_accepts_only_one_byte_00_or_01`, `absent_touch_tag_means_no_touch` (absent `7A` = no touch, model decision); deferred: the FunctionFS OTP IN half is a Linux transport concern of the program stage (`docs/DESIGN.md` §13), not this crate

## Appendix B rows

- `piv_pin_apdu_headers_and_hsmauth_exhaustion` (YubiHSM Auth half): tested: `capacity_is_32_credentials_then_no_space` (33rd PUT `6A84`, duplicates reported first, a freed slot is reusable), `eighth_wrong_password_deletes_credential_and_clears_challenge`, `management_key_blocks_after_eight_wrong_attempts_until_reset`; the PIV half belongs to lk-piv
- `hsmauth_reset_apdu_shape`: tested: `reset_requires_dead_p1p2_and_rejects_data_or_le`, `reset_accepts_sdk_and_ambiguous_short_zero_forms` (short and extended data-less zero forms both reset)
- `yubihsm_auth_touch_policy_syntax`: tested: `touch_policy_tag_accepts_only_one_byte_00_or_01`
- `yubihsm_auth_add_input_syntax_and_duplicates`: tested: `duplicate_label_is_rejected_with_6983`, `malformed_algorithm_is_rejected_without_storage`, `invalid_utf8_label_is_rejected_without_storage`
- `hsmauth_symmetric_challenge_touch`: tested: `symmetric_challenge_is_eight_random_bytes_without_touch`, `get_challenge_never_requires_touch`, `touch_is_requested_by_calculate_only`

## Behaviours fixed by a public Yubico source (beyond the catalog)

- On-device generation is a PUT with an empty `7D` (yubikit `generate_credential_asymmetric`: "Empty byte will generate key"): `generate_accepts_yubikit_empty_private_key_object`
- A failed touch leaves the credential password tries unchanged (YESDK `GetAes128SessionKeysResponse` / `GetEccP256SessionKeysResponse`); a correct password's return to 8 is committed with the touch, before the keys: `declined_touch_leaves_password_tries_unchanged`, `touch_completion_restores_tries_before_keys`, `storage_failure_after_touch_reveals_no_keys`
- `6984` means invalid authentication data (YESDK maps `ReferenceDataUnusable` `6984` to it; ykhsmauth `SW_DATA_INVALID`); `6982` means not touched (ykman `handle_error` `SECURITY_CONDITION_NOT_SATISFIED` "The device was not touched", ykhsmauth `translate_error` touch error, YESDK `RetryWithTouch`); `6983` for GET PUBLIC KEY of a symmetric credential (ykman `credentials export`: "The entry is not an asymmetric credential")
- Labels are 1–64 UTF-8 bytes and may contain NUL (YESDK `Credential.Label`): `label_rules_count_utf8_bytes_and_compare_exactly`
- 32 credentials (YESDK `AddCredentialCommand`): `capacity_is_32_credentials_then_no_space`

## Model decisions (neither Yubico's documentation, yubikit nor the reference key fixes these)

- Which mismatches give `6984`: a card cryptogram or receipt that does not verify, or a context that does not carry the outstanding ephemeral key: `asymmetric_receipt_mismatch_is_rejected`, `asymmetric_calculate_without_challenge_is_rejected`
- An optional `78` card cryptogram on a symmetric CALCULATE is verified (ykhsmauth `ykhsmauth_calculate_ex` adds `78` only when `card_crypto_len > YKHSMAUTH_CARD_CRYPTO_LEN` (8), so never for a symmetric session; YESDK never sends one; yubikit `calculate_session_keys_symmetric` sends it only when the caller passes `card_crypto`): `symmetric_card_cryptogram_is_verified_when_supplied`
- A well-formed CALCULATE naming an existing asymmetric credential consumes the outstanding ephemeral key whatever the outcome; syntax errors, unknown labels and symmetric CALCULATEs leave it. A well-formed GET CHALLENGE naming an existing credential replaces it (even with a wrong password); one for an unknown label does not: `asymmetric_challenge_is_single_use`, `outstanding_challenge_survives_unrelated_failures`
- A correct password restores the tries even when the receipt or cryptogram then fails (`6984`), persisted before the answer: `correct_password_with_bad_receipt_restores_tries_without_touch`
- An alg 39 PUT without `7D` also generates: `generate_without_private_key_object_is_accepted`
- PUT order: syntax `6A80`, management key `63Cx`, duplicate `6983`, capacity `6A84`; DELETE checks the management key before the label: `capacity_is_32_credentials_then_no_space`, `blocked_management_key_writes_nothing`
- A command arriving while a CALCULATE waits for touch abandons it (tries unchanged); `touch_resolved(false)` is `6982` even after a reset dropped the command; a touch with nothing waiting is `6985`: `new_command_while_touch_pending_cancels_it`, `deselect_and_reset_clear_volatile_state`, `declined_touch_leaves_password_tries_unchanged`
- Command data objects may come in any order; unknown or repeated tags are `6A80`; P1/P2 are ignored except for RESET: `put_rejects_wrong_key_material_for_algorithm`, `malformed_tlv_is_6a80_for_every_command`
- A credential stored with zero password tries — the state between spending the last try and storing the deletion (wrong password) or the return to eight (right password), which spend-before-compare (`docs/CONTRACTS.md` "Retry counters") makes reachable by a power loss or a failed save — is deleted: the loader drops it and keeps the rest of the record, and the running card deletes it at the next command (its outstanding ephemeral key with it). While the store keeps failing it is listed with zero tries and every password attempt on it is refused (`63C0` or `6581`) without a comparison. Source for "no tries left = deleted": YESDK overview "a limit of 8 retries, after which the credential will be permanently deleted" and the catalog bullet above: `last_try_spent_before_touch_does_not_wipe_the_record`, `abandoned_or_declined_last_try_touch_keeps_the_credential`, `failed_restore_of_the_last_try_deletes_only_that_credential`, `eighth_wrong_password_with_failed_deletion_keeps_the_rest`, `finished_deletion_forgets_the_ephemeral_key`, `state::tests::zero_tries_credential_loads_as_deleted`
- A declined or abandoned touch on the last try gives the try back before the zero-tries cleanup runs (in memory and in the record), so the credential keeps its one try: `abandoned_or_declined_last_try_touch_keeps_the_credential`
- GET RESPONSE with nothing pending is `6D00`: measured on the reference key (docs/MEASUREMENT.md, probe `get-response-idle-hsmauth`; it was the model decision `6985`): `list_longer_than_256_bytes_uses_get_response`, `proprietary_class_80_is_served_like_00`. GET RESPONSE during an unfinished chain stays part of the chain check (`6883`, unmeasured for this application)
- Touch timeout 15 000 ms: `touch_required_calculate_waits_for_touch` (model value; the host program owns the timing)

## Fixed by `docs/CONTRACTS.md` (binding conventions)

- CLA (ISO/IEC 7816-4 §5.1.1): `00` and the chaining bit `10` are accepted, and so is `80`, exactly like `00` (measured on the reference key, docs/MEASUREMENT.md, probe `cla-variants-hsmauth`: `80 5E 00 00` answers `6D00` like `00 5E 00 00`; it was `6E00`; `proprietary_class_80_is_served_like_00`); any other class outside the first interindustry range (`84`, `90`, …; unmeasured) is `6E00`; secure-messaging bits are `6882` (the device's secure channel clears them after unwrapping, so a command still carrying them was never verified); a logical channel is `6881` (as lk-piv and lk-oath; ykhsmauth names both statuses): `unknown_instruction_class_and_malformed_apdus`
- At most Ne bytes per response, the rest with `61xx` and GET RESPONSE; no Le field means 256 (short) or 65 536 (extended). Also for the keys of a touch-required CALCULATE. The real continuation shapes work: yubikit `00 C0 00 00 00` (and yubikit 5.0's extended `00 C0 00 00 00 00 00`), ykhsmauth `00 C0 00 00 XX` with XX from `61XX`: `short_le_limits_each_response_piece`, `list_longer_than_256_bytes_uses_get_response`
- The data-less forms `CLA INS P1 P2 00` and `CLA INS P1 P2 00 00 00` are not an explicit Le (RESET): `reset_accepts_sdk_and_ambiguous_short_zero_forms`

## Model policies replaced by measurement (reference key)

Differential measurement of 2026-10-11 (docs/MEASUREMENT.md): the same read-only probes
(`tools/measure/probes.py`) sent to the physical key and to the engine. Each answer below
was a model decision and now follows the key: YubiHSM Auth is a Yubico-proprietary
protocol, so Yubico's documentation and yubikit are its specification and the reference
key their best evidence (rule 3 of `docs/CONTRACTS.md` "Reference, not replica"), and
neither answer is a reference defect (rule 4). A numbered list, so that
`tools/catalog_status.py` does not count these as catalog lines:

1. GET RESPONSE with nothing pending answers `6D00`: measured on the reference key
  (docs/MEASUREMENT.md, probe `get-response-idle-hsmauth`); it was `6985`. Tests:
  `proprietary_class_80_is_served_like_00`, `list_longer_than_256_bytes_uses_get_response`,
  lk-device `ccid::security_domain_and_hsm_auth_statuses_as_measured`.
2. CLA `80` is served exactly like `00`: measured on the reference key
  (docs/MEASUREMENT.md, probe `cla-variants-hsmauth`, with the undefined instruction `5E`:
  `6D00` in both classes); it was `6E00`. That defined instructions behave alike under
  `80` follows by extension (derived). `90`, `84` and the other proprietary classes keep
  `6E00` (unmeasured); CLA `0C` came back without a status word on the physical side
  (`none`, docs/MEASUREMENT.md "Host artifacts") and keeps `6882`. Tests:
  `proprietary_class_80_is_served_like_00`, `unknown_instruction_class_and_malformed_apdus`.

These replace the `docs/CONTRACTS.md` "Applications B" conventions `6E00` for CLA `80`
and `6985` for an idle GET RESPONSE for this application.

## Second review (interop lens: yubikit/ykman, ykhsmauth, YubiHSM 2 session keys)

Bugs found and fixed, each with a regression test that fails on the previous code:

- Spending the last password try persisted a credential with zero tries, which the loader rejected as a whole record: factory state, every credential deleted and the management key back to sixteen zero bytes after a power loss during a last-try touch, or after a failed save of the deletion or of the restored count. Now the record loads with only that credential deleted (model decision above): `last_try_spent_before_touch_does_not_wipe_the_record`, `abandoned_or_declined_last_try_touch_keeps_the_credential`, `failed_restore_of_the_last_try_deletes_only_that_credential`, `eighth_wrong_password_with_failed_deletion_keeps_the_rest`, `finished_deletion_forgets_the_ephemeral_key`, `state::tests::zero_tries_credential_loads_as_deleted`
- RESET answered `6700` to `00 06 DE AD 00 00 00`, the frame yubikit 5.0 (`_encode_extended_apdu`) sends for `ykman hsmauth reset` over USB, contrary to the contract's data-less extended form: `reset_accepts_sdk_and_ambiguous_short_zero_forms`
- Secure-messaging CLA bits were accepted, so a `04`/`0C` command that bypassed the secure channel (none open) ran as plaintext; now `6882`, and logical channels `6881` instead of `6E00`: `unknown_instruction_class_and_malformed_apdus`
- A short Le was ignored (up to 256 bytes were served whatever Ne was): `short_le_limits_each_response_piece`

Checked against the public host sources and found consistent: yubikit `hsmauth.py` request layouts (PUT tag order and `7A` as `int2bytes(0|1)`, the empty `7D` for generation, CALCULATE `71 77 [7C] [78] 73`, GET CHALLENGE `71 [73]` from 5.7.1, PUT MANAGEMENT KEY `7B 7B`, LIST parsing, `_retries_from_sw`, the 5.8.0 gate on `0B`); ykhsmauth `ykhsmauth.c`/`.h` (tags, lengths, `send_data` always writing Lc, the 48-byte CALCULATE answer it requires, LIST parsing that rejects trailing bytes, `translate_error`); yubihsm-shell `yh_create_session_asym` (context `EPK.OCE || EPK.SD`, `ShSee = ECDH(eSK.OCE, EPK.SD)`, `ShSss = ECDH(SK.OCE, PK.SD)`, X9.63-KDF-SHA-256 with shared info `3C 88 10`, receipt key / S-ENC / S-MAC / S-RMAC split, receipt over `EPK.SD || EPK.OCE`) and its symmetric card cryptogram from S-MAC; yubikey-manager `tests/device/test_hsmauth.py` expectations (symmetric GET CHALLENGE without a password, 8 bytes; asymmetric with a password, 65 bytes; duplicate import, missing delete and symmetric export are errors; management key retries 8 then 7). Secret comparisons use `ct_eq`; the assembled command buffer (keys, passwords) is wiped after each command.
