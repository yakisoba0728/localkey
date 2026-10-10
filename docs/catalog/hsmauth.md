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
- password retries: tested: `wrong_credential_password_decrements_and_correct_resets`, `wrong_password_counter_is_persisted_before_response`, `get_challenge_with_password_verifies_it`, `declined_touch_leaves_password_tries_unchanged`, `touch_completion_restores_tries_before_keys`, `storage_failure_after_touch_reveals_no_keys`
- management key: tested: `management_key_change_and_retries`, `management_key_blocks_after_eight_wrong_attempts_until_reset`, `management_key_tries_are_persisted_for_every_command`, `blocked_management_key_writes_nothing`, `syntax_errors_do_not_consume_management_key_retries`
- credential deleted on eighth wrong password with ephemeral state cleared, label recoverable after restart; symmetric/asymmetric YubiKit socket and direct IFD verified: tested: `eighth_wrong_password_deletes_credential_and_clears_challenge`, `deleted_label_is_reusable_after_restart`; intentional difference: no YubiKit/socket/IFD run at engine level (`docs/DESIGN.md` §4, §12-3, §13); the behaviour is tested through `CardApplet` with `lk_testkit::TestHost`
- RESET application rejects unexpected data or explicit Le before clearing credentials; normal SDK reset and ambiguous short-zero formatter preserved: tested: `reset_requires_dead_p1p2_and_rejects_data_or_le` (data or explicit Le `6700`, P1P2 other than `DE AD` `6A86`, nothing cleared or written), `reset_accepts_sdk_and_ambiguous_short_zero_forms` (`00 06 DE AD` and the `00 06 DE AD 00` that ykhsmauth `send_data` emits), `reset_clears_credentials_and_management_key`
- ADD CREDENTIAL rejects duplicate labels with 6983, malformed algorithm length and invalid UTF-8 labels with 6A80, without corrupting SDK listing: tested: `duplicate_label_is_rejected_with_6983`, `malformed_algorithm_is_rejected_without_storage`, `invalid_utf8_label_is_rejected_without_storage`, `label_length_bounds`, `label_rules_count_utf8_bytes_and_compare_exactly`, `label_rules_apply_to_every_command`, `malformed_tlv_is_6a80_for_every_command`, `put_rejects_wrong_key_material_for_algorithm`
- YubiHSM Auth symmetric GET CHALLENGE returns an eight-byte host challenge without touch; CALCULATE still requires touch. Unmodified YubiKit Mac/Linux socket/direct IFD checks pass; physical timing remains unmeasured.: tested: `symmetric_challenge_is_eight_random_bytes_without_touch`, `get_challenge_never_requires_touch`, `touch_is_requested_by_calculate_only`, `touch_required_calculate_waits_for_touch`, `touch_declined_or_timed_out_returns_6982`, `asymmetric_touch_required_calculate_waits_for_touch`; intentional difference: touch timing belongs to the host program (`Outcome::NeedTouch { timeout_ms: 15000 }`, a model value) and no YubiKit run happens at engine level

## Filed under FIDO

- YubiHSM Auth Add Credential accepts touch policy tag 7A only as a one-byte 00 or 01 and rejects malformed values without storage; FunctionFS OTP IN input is backpressured when the guest HID reader pauses: tested: `touch_policy_tag_accepts_only_one_byte_00_or_01`, `absent_touch_tag_means_no_touch` (absent `7A` = no touch, model decision); deferred: the FunctionFS OTP IN half is a Linux transport concern of the program stage (`docs/DESIGN.md` §13), not this crate

## Appendix B rows

- `piv_pin_apdu_headers_and_hsmauth_exhaustion` (YubiHSM Auth half): tested: `capacity_is_32_credentials_then_no_space` (33rd PUT `6A84`, duplicates reported first, a freed slot is reusable), `eighth_wrong_password_deletes_credential_and_clears_challenge`, `management_key_blocks_after_eight_wrong_attempts_until_reset`; the PIV half belongs to lk-piv
- `hsmauth_reset_apdu_shape`: tested: `reset_requires_dead_p1p2_and_rejects_data_or_le`, `reset_accepts_sdk_and_ambiguous_short_zero_forms`
- `yubihsm_auth_touch_policy_syntax`: tested: `touch_policy_tag_accepts_only_one_byte_00_or_01`
- `yubihsm_auth_add_input_syntax_and_duplicates`: tested: `duplicate_label_is_rejected_with_6983`, `malformed_algorithm_is_rejected_without_storage`, `invalid_utf8_label_is_rejected_without_storage`
- `hsmauth_symmetric_challenge_touch`: tested: `symmetric_challenge_is_eight_random_bytes_without_touch`, `get_challenge_never_requires_touch`, `touch_is_requested_by_calculate_only`

## Behaviours fixed by a public Yubico source (beyond the catalog)

- On-device generation is a PUT with an empty `7D` (yubikit `generate_credential_asymmetric`: "Empty byte will generate key"): `generate_accepts_yubikit_empty_private_key_object`
- A failed touch leaves the credential password tries unchanged (YESDK `GetAes128SessionKeysResponse` / `GetEccP256SessionKeysResponse`); a correct password's return to 8 is committed with the touch, before the keys: `declined_touch_leaves_password_tries_unchanged`, `touch_completion_restores_tries_before_keys`, `storage_failure_after_touch_reveals_no_keys`
- `6984` means invalid authentication data (YESDK maps `ReferenceDataUnusable` `6984` to it; ykhsmauth `SW_DATA_INVALID`); `6982` means not touched (ykman, ykhsmauth, YESDK `RetryWithTouch`)
- Labels are 1–64 UTF-8 bytes and may contain NUL (YESDK `Credential.Label`): `label_rules_count_utf8_bytes_and_compare_exactly`
- 32 credentials (YESDK `AddCredentialCommand`): `capacity_is_32_credentials_then_no_space`

## Model decisions (no public source fixes these)

- Which mismatches give `6984`: a card cryptogram or receipt that does not verify, or a context that does not carry the outstanding ephemeral key: `asymmetric_receipt_mismatch_is_rejected`, `asymmetric_calculate_without_challenge_is_rejected`
- An optional `78` card cryptogram on a symmetric CALCULATE is verified (ykhsmauth and YESDK never send one for symmetric credentials): `symmetric_card_cryptogram_is_verified_when_supplied`
- A well-formed CALCULATE naming an existing asymmetric credential consumes the outstanding ephemeral key whatever the outcome; syntax errors, unknown labels and symmetric CALCULATEs leave it. A well-formed GET CHALLENGE naming an existing credential replaces it (even with a wrong password); one for an unknown label does not: `asymmetric_challenge_is_single_use`, `outstanding_challenge_survives_unrelated_failures`
- A correct password restores the tries even when the receipt or cryptogram then fails (`6984`), persisted before the answer: `correct_password_with_bad_receipt_restores_tries_without_touch`
- An alg 39 PUT without `7D` also generates: `generate_without_private_key_object_is_accepted`
- PUT order: syntax `6A80`, management key `63Cx`, duplicate `6983`, capacity `6A84`; DELETE checks the management key before the label: `capacity_is_32_credentials_then_no_space`, `blocked_management_key_writes_nothing`
- A command arriving while a CALCULATE waits for touch abandons it (tries unchanged); `touch_resolved(false)` is `6982` even after a reset dropped the command; a touch with nothing waiting is `6985`: `new_command_while_touch_pending_cancels_it`, `deselect_and_reset_clear_volatile_state`, `declined_touch_leaves_password_tries_unchanged`
- Command data objects may come in any order; unknown or repeated tags are `6A80`; P1/P2 are ignored except for RESET; CLA secure-messaging bits are tolerated: `put_rejects_wrong_key_material_for_algorithm`, `unknown_instruction_class_and_malformed_apdus`
- GET RESPONSE with nothing pending is `6985`: `list_longer_than_256_bytes_uses_get_response`
- Touch timeout 15 000 ms: `touch_required_calculate_waits_for_touch`
