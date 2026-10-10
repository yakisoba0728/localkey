# OpenPGP catalog status (lk-openpgp)

One line per bullet of the `## OpenPGP`, `## OpenPGP_algorithms` and
`## OpenPGP_attestation` sections of `reference/BEHAVIOR_CATALOG.md`.
Test names refer to `crates/lk-openpgp`: the scenario tests in `tests/applet/`
(`public_objects`, `passwords`, `data_objects`, `framing`, `lifecycle`, `kdf`,
`generation`, `import`, `operations`, `touch`, `attestation`, `variants`, `robustness`,
and `review`, the independent reviewer's scenarios)
and the unit tests in `src/` (`objects::tests::`, `state::tests::`, `kdf::tests::`,
`keys::tests::`, `attest::tests::`, `tests::` in `lib.rs`).

The one systematic gap: lk-crypto implements ECDSA/ECDH on P-256 and P-384 only, so the
20 FA variants on P-521, secp256k1, brainpoolP256r1, brainpoolP384r1 and brainpoolP512r1
can be selected (C1/C2/C3/DA) but GENERATE and import answer `6A81` and no key of them can
exist. Lines that are only partly done because of this start with `deferred:`.

## OpenPGP

- SIG/DEC/AUT separation: tested: `every_advertised_variant`, `mse_selects_keys_for_decipher_and_authenticate`, `cds_requires_pw1_mode_81`, `sig_generation_resets_counter_only_for_sig`, `attest_dec_and_aut_keys`
- RSA/EC/Ed25519/X25519: deferred: ECC keys on P-521, secp256k1 and the brainpool curves (lk-crypto lacks them; `6A81` in `unsupported_curves_answer_6a81`); RSA 2048/3072/4096, ECDSA/ECDH on P-256/P-384, Ed25519 and X25519 are tested in `every_advertised_variant`, `generate_rsa2048_sig_and_sign`, `generate_ecdsa_sign_and_authenticate`, `generate_ecdh_and_decipher`, `generate_ed25519_sign_and_authenticate`, `generate_x25519_and_decipher`
- generate/import: deferred: generation/import on P-521, secp256k1 and the brainpool curves (lk-crypto); every other variant is imported and generated in `every_advertised_variant`, plus `rsa_import_standard_and_crt_formats`, `rsa4096_import_with_chaining`, `ec_import_with_and_without_public_key`, `edwards_import`, `generate_rsa3072_dec_and_decipher`, `generate_rsa4096_aut_and_authenticate`
- sign/decrypt/ECDH: deferred: operations with keys on the curves lk-crypto lacks (no such key can exist); PSO:CDS, PSO:DECIPHER (RSA PKCS #1 v1.5, ECDH, X25519) and INTERNAL AUTHENTICATE for every other algorithm are tested in `every_advertised_variant`, `rsa_decipher_rules`, `ecdh_decipher_rules`, `internal_authenticate_rules`, `cds_header_and_input_rules`, `ecdsa_signatures_are_hedged`; ECDH and X25519 peer-key validation (wrong curve, small-order point, wrong length) in `ecdh_point_must_match_the_curve`, `x25519_decipher_rejects_low_order_and_bad_lengths`
- separate certificate slots: tested: `certificate_occurrences`, `attest_dec_and_aut_keys`
- user/admin PIN: tested: `verify_default_pins`, `change_reference_data_pw1_and_pw3`, `wrong_pin_decrements_and_blocks`, `pw3_blocks`, `cds_requires_pw1_mode_81`, `pw1_mode_access_matrix`, `storage_failure_reveals_nothing_and_changes_nothing`, `right_pin_with_failed_counter_restore_stays_spent`
- blocked PIN/admin reset: tested: `reset_retry_counter_with_pw3`, `reset_retry_counter_with_resetting_code`, `reset_retry_counter_wrong_code_and_headers`, `wrong_rc_or_pw3_keeps_pw1_access`, `pw3_blocks`
- SHA256/SHA512 iterated salted S2K KDF: tested: `kdf_card_derives_initial_hashes`, `kdf::tests::s2k_sha256_vectors`, `kdf::tests::s2k_sha512_vectors`, `operations_with_kdf_pins`
- hash-only PIN state when KDF enabled: tested: `kdf_with_initial_hashes`, `operations_with_kdf_pins`
- KDF PIN change, retry and reset-code recovery: tested: `kdf_pin_change_retry_and_reset_code`, `kdf_resetting_code_must_be_hash_length`
- fourth attestation key/certificate slot: tested: `fresh_applet_provisions_rsa2048_issuer`, `generate_attestation_slot_keys`, `import_counter_and_attestation_slot`, `certificate_occurrences`, `activate_retains_attestation_slot`
- own software attestation and imported-key provenance rejection: tested: `attest_generated_sig_key`, `imported_key_is_not_attested`
- certificate iteration: tested: `certificate_occurrences`, `exhausted_get_next_data_keeps_selection`
- 15-second cached/fixed touch: tested: `cached_touch_lasts_15_seconds`, `cached_touch_cleared_by_power_cycle`, `uif_on_requires_touch_for_each_signature`, `touch_denied_answers_6982_and_changes_nothing`, `uif_for_decipher_authenticate_and_attest`, `uif_put_rules` (the per-key cache kept until power is removed and `6982` on timeout are model policy); a cached touch does not survive the application reset: `application_reset_forgets_cached_touches`
- wrong PIN invalidates both PW1 authorization modes: tested: `wrong_pin_invalidates_both_pw1_modes`, `pw1_mode_access_matrix`, `wrong_rc_or_pw3_keeps_pw1_access`
- read-only PC/SC observation of public firmware-5.7.4 metadata; no PIN or persistent writes: tested: `public_objects_match_observation` (the bullet describes how the reference was captured; the engine reproduces the captured bytes)
- exact captured C0/5F52/7F66/7F74 bytes and direct-C0 6B00 response: tested: `public_objects_match_observation`, `direct_c0_answers_6b00`, `application_related_data_layout_matches_observation`, `extended_capabilities_fields`
- captured application-related tag layout/lengths, discretionary 7F66 and public RSA2048 attributes: tested: `application_related_data_layout_matches_observation`
- fresh independent own RSA2048 attestation issuer; legacy own EC issuer and user keys preserved: tested: `fresh_applet_provisions_rsa2048_issuer`, `issuer_survives_failed_first_save`; preserving legacy issuers and keys is an intentional difference (no legacy state is migrated, docs/DESIGN.md §1)
- observed 3070-byte challenge, 2048-byte certificate and 255-byte special-object ceiling model: tested: `get_challenge`, `certificate_size_limit`, `special_do_limit`, `extended_length`, `oversized_attestation_rejected`
- private-use write access requires PW1 reference 82 or PW3; protected reads remain PIN scoped: tested: `private_do_access_rules`, `pw1_mode_access_matrix`
- name 39, language eight bytes in pairs, ASCII sex, fingerprint 20 and generation-time four-byte checks: tested: `name_language_sex_checks`, `fingerprint_and_generation_time_checks`
- read-only and undeclared PUT rejection; Resetting Code and unsupported legacy objects never exposed: tested: `read_only_and_undeclared_put_rejected`, `resetting_code_rules`
- four certificate occurrences, ceiling/clear/restart and deliberate issuer certificate deletion retained: tested: `certificate_occurrences`, `certificate_size_limit`, `deleted_attestation_certificate_not_restored`
- bounded replacement/deletion with legacy oversized reads preserved; independently verified retained keys: tested: `certificate_size_limit`, `keys_survive_restart`, `rsa_decipher_rules`, `generation_storage_failure_keeps_previous_key`, `import_storage_failure_keeps_previous_key`; preserving legacy oversized reads is an intentional difference (no legacy state is migrated, docs/DESIGN.md §1)
- socket and direct IFD independent SDK/crypto; physical write/challenge/touch boundaries unmeasured: intentional difference: transport and SDK interoperability belong to the program phase (docs/DESIGN.md §13); engine tests drive the applet through `CardApplet` with `TestHost` and verify all cryptography independently with lk-crypto
- RFC4880 low-count iterated-salted S2K hashes one complete salt-plus-PIN block; independent digest and SDK APDU verified over socket and direct IFD: tested: `kdf_low_count_hashes_one_full_block`, `kdf::tests::s2k_low_count_hashes_one_full_block`
- OpenPGP 3.4.1 VERIFY and CHANGE REFERENCE DATA P1/data validation before PIN retry or state mutation over socket and direct IFD; exact physical statuses unmeasured: tested: `verify_header_validation_before_retry`, `change_reference_data_validation_before_retry`
- explicit Le guards on VERIFY/CHANGE and zero P1/P2 guard on INTERNAL AUTHENTICATE over socket and direct IFD; physical 5.7.4 status/tolerance unmeasured: tested: `verify_header_validation_before_retry`, `change_reference_data_validation_before_retry`, `internal_authenticate_rules`
- RESET RETRY COUNTER, PUT DATA, GENERATE, PSO SIGN and INTERNAL AUTHENTICATE Le mutation guards verified over private socket and direct IFD: tested: `reset_retry_counter_wrong_code_and_headers`, `put_data_le_guard`, `import_access_and_header_rules`, `generate_le_guard_keeps_previous_key`, `cds_header_and_input_rules`, `internal_authenticate_rules`, `touch_requested_after_access_and_input_checks`, `chained_signature_le_guard_keeps_counter`
- GET RESPONSE rejects unsupported plaintext CLA before consuming a pending response; unmodified YubiKit chaining and private socket/direct IFD pass: tested: `get_response_rejects_bad_cla_without_consuming`
- OpenPGP GET RESPONSE during unfinished command chaining returns 6883; unmodified YubiKit chained PUT DATA and subsequent SDK read pass over private CCID socket and direct IFD: tested: `get_response_during_chain_returns_6883`, `terminate_drops_pending_work`
- OpenPGP GET DATA rejects unsupported command-chain CLA 10 with 6E00, leaving the next YubiKit GET DATA unaffected over private CCID socket and direct IFD: tested: `get_data_chained_cla_rejected`
- GET NEXT DATA with unexpected command data returns 6700 before advancing certificate occurrence, verified over private CCID socket and direct IFD: tested: `get_next_data_with_data_rejected`
- Exhausted GET NEXT DATA returns 6A88 without clearing the current certificate occurrence, preventing subsequent PUT DATA from writing an unreachable object; private socket and direct IFD pass: tested: `exhausted_get_next_data_keeps_selection`
- GET ATTESTATION with explicit Le=1 is rejected before replacing a SIG certificate; private CCID socket/direct IFD and unmodified YubiKit attestation verified.: tested: `attest_header_rules`
- Operational ACTIVATE FILE succeeds without semantic state change or lazy attestation creation; terminated ACTIVATE still resets. Mac/Linux private socket/direct IFD SDK A/B and restart checks pass.: tested: `operational_activate_is_noop`, `terminated_state_answers_6285`, `blocked_pw3_terminate_and_activate_resets`, `activate_restores_every_factory_value`, `terminate_drops_pending_work`
- SELECT DATA rejects explicit Le=1 with 6700 before changing the selected certificate occurrence; absent or zero Le and unmodified YubiKit certificate reads remain valid. Mac/Linux private socket/direct IFD A/B and restart checks pass; physical status remains unmeasured.: tested: `select_data_syntax`
- SET RETRIES F2 rejects malformed P1/P2 or explicit Le before changing encrypted retry state. Mac/Linux private CCID socket/direct IFD A/B, unmodified YubiKit and persistence checks pass; physical status remains unmeasured.: tested: `set_retries_rules`, `set_retries_storage_failure`

## OpenPGP_algorithms

- exact measured 421-byte FA inventory including curve order and 43 slot/algorithm variants: tested: `algorithm_information_matches_observation`, `objects::tests::fa_inventory_counts`, `every_advertised_variant`
- measured 7A outer wrapper and three-byte 93 counter schema; physical counter payload discarded: tested: `security_support_template_layout`, `signature_counter_persisted_before_signature`, `tests::signature_counter_saturates`
- advertised canonical RSA2048/3072/4096, seven prime curves, Ed25519 SIG/AUT and X25519 DEC restrictions: tested: `algorithm_attributes_put`, `objects::tests::attribute_support_rules`, `keys::tests::attributes_decode_every_fa_entry`
- all 43 variants generated and imported via independent SDK/crypto on fresh cards: deferred: the 20 variants on P-521, secp256k1 and brainpoolP256r1/P384r1/P512r1 (lk-crypto has no arithmetic for them; GENERATE and import answer `6A81`, `unsupported_curves_answer_6a81`); the other 23 are imported in every slot and generated (RSA 3072/4096 once each, same code path) with independent verification in `every_advertised_variant`, `generate_rsa3072_dec_and_decipher`, `generate_rsa4096_aut_and_authenticate`
- independent RSA/ECDSA/Ed25519 signatures, PKCS1 decryption, ECDH/X25519 secret comparison and ten attestation issuers: deferred: the five attestation issuer variants on P-521, secp256k1 and brainpool (lk-crypto); the rest is tested in `every_advertised_variant` (five issuer variants: RSA 2048/3072/4096, P-256, P-384), `replacement_ec_issuer_signs`, `generate_ecdh_and_decipher`, `generate_x25519_and_decipher`, `rsa_decipher_rules`
- standard RSA e/p/q widths, exponent/modulus consistency and duplicate/order/unknown-field rejection: tested: `rsa_import_rejections`, `rsa_import_standard_and_crt_formats`, `rsa4096_import_with_chaining`, `keys::tests::import_list_parsing` (CRT values are width-checked and recomputed from p, q, e rather than cross-checked; model policy in `keys::import_material`)
- standard EC/Ed25519/X25519 import widths; 66-byte zero-padded P521 with raw SDK APDU workaround: deferred: P-521 import (lk-crypto lacks the curve; answers `6A81`); P-256/P-384/Ed25519/X25519 widths are tested in `ec_import_rejections`, `ec_import_with_and_without_public_key`, `edwards_import`
- SIG generation/import resets digital-signature counter; other slots leave it unchanged: tested: `sig_generation_resets_counter_only_for_sig`, `import_counter_and_attestation_slot`
- short and extended CRT matching for SIG/DEC/AUT; mismatched reference and nonzero generation P2 rejection: tested: `generate_header_and_crt_rules`, `rsa_import_rejections`, `keys::tests::crt_forms`
- invalid request ciphertext unchanged; retained independent RSA/P521 private keys verified after rejection/restart: deferred: P-521 keys (lk-crypto); RSA and ECC keys retained after rejected requests and restarts are tested in `rsa_decipher_rules`, `ecdh_decipher_rules`, `keys_survive_restart`; rejected ECDH/X25519 peer keys leave the key usable in `ecdh_point_must_match_the_curve`, `x25519_decipher_rejects_low_order_and_bad_lengths`
- socket and direct IFD fixtures; physical import/rejection/counter/touch behavior unmeasured: intentional difference: transport fixtures belong to the program phase (docs/DESIGN.md §13); import, rejection, counter and touch rules are tested through `CardApplet` (see the lines above)

## OpenPGP_attestation

- app reset retains current independent ATT key/certificate, attributes and modeled metadata; no factory restoration: tested: `reset_retains_issuer_and_signs_new_keys`, `activate_retains_attestation_slot`, `deleted_issuer_key_not_resurrected`, `state::tests::reset_keeps_attestation_slot_only`, `activate_restores_every_factory_value`
- deliberately deleted key/certificate and opaque mismatched/malformed issuer are not resurrected/repaired: tested: `deleted_issuer_key_not_resurrected`, `deleted_attestation_certificate_not_restored`, `opaque_issuer_certificate_not_repaired`, `replacement_ec_issuer_signs`
- default/replacement RSA/EC issuer survives reset/restart and independently signs new generated keys: tested: `fresh_applet_provisions_rsa2048_issuer`, `reset_retains_issuer_and_signs_new_keys`, `replacement_ec_issuer_signs`, `every_advertised_variant`
- PIV issuer and OATH private key/durable HOTP state survive OpenPGP reset: tested: `reset_leaves_other_records`
- copied template validity/subject, random 16-byte positive serial input and SHA256 RSA/EC signatures: tested: `attest_generated_sig_key`, `replacement_ec_issuer_signs`, `attest::tests::serial_is_positive`, `attest::tests::copied_fields_from_built_certificate`
- DER name/source/version/fingerprint/date/counter/own serial/UIF/form-factor metadata; uncertified flags are zero: tested: `attest_generated_sig_key`, `attest_dec_and_aut_keys`, `yubikey_profile_names`
- Latin1-to-UTF8 name encoding, positive DER serial sign and SIG-only counter field independently parsed: tested: `attest_generated_sig_key`, `attest_dec_and_aut_keys`
- proprietary CLA/header validation and bounded generated certificate with immutable failure state: tested: `attest_header_rules`, `oversized_attestation_rejected`, `attest_storage_failure_keeps_certificate`, `imported_key_is_not_attested`
- physical template firmware extension DER OCTET STRING wrapper measured; original certificate/identifying payloads discarded: tested: `fresh_applet_provisions_rsa2048_issuer` (the own issuer certificate carries 1.3.6.1.4.1.41482.5.3 as a DER OCTET STRING of three bytes, the measured wrapper), `attest_generated_sig_key`; no physical certificate payload is used (docs/DESIGN.md §9)
- generated leaf extensions and exact metadata/UIF reset/tolerance are public-document models, not physical proof: intentional difference: the extension encodings follow Yubico's public description and are modelled (table in `crates/lk-openpgp/src/attest.rs`), tested in `attest_generated_sig_key`; they are not compared with a physical leaf
