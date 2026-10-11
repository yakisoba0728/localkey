# OpenPGP catalog status (lk-openpgp)

One line per bullet of the `## OpenPGP`, `## OpenPGP_algorithms` and
`## OpenPGP_attestation` sections of `reference/BEHAVIOR_CATALOG.md`.
Test names refer to `crates/lk-openpgp`: the scenario tests in `tests/applet/`
(`public_objects`, `passwords`, `data_objects`, `framing`, `lifecycle`, `kdf`,
`generation`, `import`, `operations`, `touch`, `attestation`, `variants`, `curves`,
`robustness`, `review`, the first independent reviewer's scenarios, `interop`, the
second reviewer's host request shapes of GnuPG scdaemon, OpenSC and yubikit, and
`measured`, the answers measured on a YubiKey 5C Nano 5.7.4, docs/MEASUREMENT.md)
and the unit tests in `src/` (`objects::tests::`, `state::tests::`, `kdf::tests::`,
`keys::tests::`, `attest::tests::`, `tests::` in `lib.rs`).

The one systematic gap: lk-crypto implements ECDSA/ECDH on P-256, P-384, P-521,
secp256k1, brainpoolP256r1 and brainpoolP384r1 (RustCrypto `p256`, `p384`, `p521`, `k256`,
`bp256`, `bp384`), but not brainpoolP512r1, for which no RustCrypto crate exists. Its 4 FA
variants (C1/C2/C3/DA) can be selected, but GENERATE and import answer `6A81` and no key
of it can exist. Lines that are only partly done because of this start with `deferred:`.
The other 39 variants are fully usable.

## OpenPGP

- SIG/DEC/AUT separation: tested: `every_advertised_variant`, `mse_selects_keys_for_decipher_and_authenticate`, `cds_requires_pw1_mode_81`, `sig_generation_resets_counter_only_for_sig`, `attest_dec_and_aut_keys`
- RSA/EC/Ed25519/X25519: deferred: ECC keys on brainpoolP512r1 only (no RustCrypto crate; `6A81` in `only_brainpool_p512r1_answers_6a81`, `brainpool_p512r1_stays_unsupported_in_every_slot`); RSA 2048/3072/4096, ECDSA/ECDH on P-256/P-384/P-521/secp256k1/brainpoolP256r1/brainpoolP384r1, Ed25519 and X25519 are tested in `every_advertised_variant`, `generate_on_the_new_curves`, `generate_rsa2048_sig_and_sign`, `generate_ecdsa_sign_and_authenticate`, `generate_ecdh_and_decipher`, `generate_ed25519_sign_and_authenticate`, `generate_x25519_and_decipher`
- generate/import: deferred: generation/import on brainpoolP512r1 (no RustCrypto crate); every other variant is imported and generated in `every_advertised_variant`, plus `only_brainpool_p512r1_answers_6a81`, `generate_on_the_new_curves`, `p521_import_is_66_byte_zero_padded`, `rsa_import_standard_and_crt_formats`, `rsa4096_import_with_chaining`, `ec_import_with_and_without_public_key`, `edwards_import`, `generate_rsa3072_dec_and_decipher`, `generate_rsa4096_aut_and_authenticate`
- sign/decrypt/ECDH: deferred: operations with brainpoolP512r1 keys (no such key can exist); PSO:CDS, PSO:DECIPHER (RSA PKCS #1 v1.5, ECDH, X25519) and INTERNAL AUTHENTICATE for every other algorithm are tested in `every_advertised_variant`, `generate_on_the_new_curves`, `rsa_decipher_rules`, `ecdh_decipher_rules`, `internal_authenticate_rules`, `cds_header_and_input_rules`, `ecdsa_signatures_are_hedged`; published ECDH vectors through the card (RFC 5903 §8.3 P-521, RFC 7027 A.1/A.2 brainpool, Wycheproof secp256k1) in `published_ecdh_vectors_through_the_card`; ECDH and X25519 peer-key validation (wrong curve, small-order point, wrong length) in `ecdh_point_must_match_the_curve`, `p521_keys_retained_after_rejected_requests_and_restart`, `x25519_decipher_rejects_low_order_and_bad_lengths`
- separate certificate slots: tested: `certificate_occurrences`, `attest_dec_and_aut_keys`
- user/admin PIN: tested: `verify_default_pins`, `change_reference_data_pw1_and_pw3`, `wrong_pin_decrements_and_blocks`, `pw3_blocks`, `cds_requires_pw1_mode_81`, `pw1_mode_access_matrix`, `storage_failure_reveals_nothing_and_changes_nothing`, `right_pin_with_failed_counter_restore_stays_spent`
- blocked PIN/admin reset: tested: `reset_retry_counter_with_pw3`, `reset_retry_counter_with_resetting_code`, `reset_retry_counter_wrong_code_and_headers`, `wrong_rc_or_pw3_keeps_pw1_access`, `pw3_blocks`
- SHA256/SHA512 iterated salted S2K KDF: tested: `kdf_card_derives_initial_hashes`, `kdf_locked_while_a_key_exists` (F9 answers `6985` and changes nothing while the SIG, DEC or AUT slot holds a key, until TERMINATE DF / ACTIVATE FILE; source: Yubico "YubiKey 5.2.3 Enhancements to OpenPGP 3.4", Key Derived Format, "Conditions of use not satisfied"; the factory attestation key does not count, since `kdf-setup` runs on a fresh YubiKey; checked after PW3 access and before the F9 contents, model policy for the order; removing every SIG/DEC/AUT key, for example by an attribute change as yubikit `delete_key` does, lifts the lock: the reading of the document's "while a key exists" sentence, where its "until the OpenPGP application has been reset" sentence would keep the lock; the physical behaviour is unmeasured), `kdf::tests::s2k_sha256_vectors`, `kdf::tests::s2k_sha512_vectors`, `kdf::tests::streaming_matches_a_buffered_derivation_at_every_alignment`, `operations_with_kdf_pins`; the F9 count is the raw 32-bit byte count of spec §4.3.2 and is honoured whatever its size (streamed through `lk_crypto::Hasher`, no cap): `kdf::tests::counts_above_the_coded_maximum_are_derived_on_the_card`, `kdf_count_above_the_coded_maximum_is_derived`, `kdf::tests::initial_hashes_avoid_any_derivation` (model policy: the largest count hashes about 4 GiB and PUT DATA F9 waits for it; only PW3 can write F9)
- hash-only PIN state when KDF enabled: tested: `kdf_with_initial_hashes`, `operations_with_kdf_pins`
- KDF PIN change, retry and reset-code recovery: tested: `kdf_pin_change_retry_and_reset_code`, `kdf_resetting_code_must_be_hash_length`
- fourth attestation key/certificate slot: tested: `fresh_applet_provisions_rsa2048_issuer`, `generate_attestation_slot_keys`, `import_counter_and_attestation_slot`, `certificate_occurrences`, `activate_retains_attestation_slot`
- own software attestation and imported-key provenance rejection: tested: `attest_generated_sig_key`, `imported_key_is_not_attested`
- certificate iteration: tested: `certificate_occurrences`, `exhausted_get_next_data_keeps_selection`, `gnupg_and_opensc_select_data_forms` (GnuPG `iso7816_select_data` and OpenSC `pgp_select_data` send `60 04 5C 02 7F 21`; yubikit's leading length byte applies only up to firmware 5.4.3 and is `6A80` here)
- 15-second cached/fixed touch: tested: `cached_touch_lasts_15_seconds`, `cached_touch_ends_with_the_session`, `uif_on_requires_touch_for_each_signature`, `touch_denied_answers_6982_and_changes_nothing`, `uif_for_decipher_authenticate_and_attest`, `uif_put_rules`, `application_reset_forgets_cached_touches`; the cached touch lasts "up to 15 seconds or until the OpenPGP session ends" (Yubico "YubiKey 5.2.3 Enhancements to OpenPGP 3.4", Touch Cache), so SELECT, deselection, every reset kind and the application reset forget it (the second review replaced the earlier model policy "kept until power is removed", which that document contradicts); a per-key cache and `6982` on timeout remain model policy
- wrong PIN invalidates both PW1 authorization modes: tested: `wrong_pin_invalidates_both_pw1_modes`, `pw1_mode_access_matrix`, `wrong_rc_or_pw3_keeps_pw1_access`
- read-only PC/SC observation of public firmware-5.7.4 metadata; no PIN or persistent writes: tested: `public_objects_match_observation` (the bullet describes how the reference was captured; the engine reproduces the captured bytes)
- exact captured C0/5F52/7F66/7F74 bytes and direct-C0 6B00 response: tested: `public_objects_match_observation`, `direct_c0_answers_6b00`, `application_related_data_layout_matches_observation`, `extended_capabilities_fields`
- captured application-related tag layout/lengths, discretionary 7F66 and public RSA2048 attributes: tested: `application_related_data_layout_matches_observation`; the AID 4F (alone and inside 6E) carries `DeviceProfile::openpgp_manufacturer` as its manufacturer ID, `0006` in the compatibility profile and `FF00` in the own profile, never inferred from the manufacturer string (docs/CONTRACTS.md "lk-core additions"): `aid_contains_profile_serial_and_manufacturer`, `aid_manufacturer_follows_the_profile_field`, `objects::tests::full_aid_layout`, `objects::tests::manufacturer_comes_from_the_profile_field_not_the_string`
- fresh independent own RSA2048 attestation issuer; legacy own EC issuer and user keys preserved: tested: `fresh_applet_provisions_rsa2048_issuer`, `issuer_survives_failed_first_save`, `factory_attestation_key_status_is_imported` (its key information status is `02`, imported, measured on a YubiKey 5C Nano 5.7.4: docs/MEASUREMENT.md, probe `openpgp-get-006e`); preserving legacy issuers and keys is an intentional difference (no legacy state is migrated, docs/DESIGN.md §1)
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
- RESET RETRY COUNTER, PUT DATA, GENERATE, PSO SIGN and INTERNAL AUTHENTICATE Le mutation guards verified over private socket and direct IFD: tested: `reset_retry_counter_wrong_code_and_headers`, `put_data_le_guard`, `import_access_and_header_rules`, `generate_le_guard_keeps_previous_key`, `cds_header_and_input_rules`, `internal_authenticate_rules`, `touch_requested_after_access_and_input_checks`, `chained_signature_le_guard_keeps_counter`; an Le equal to the result passes, which GnuPG relies on (its GENERATE Le `determine_rsa_response` is exactly the 7F49 length, 270/398/526 for RSA 2048/3072/4096, and its PSO:CDS / INTERNAL AUTHENTICATE Le is exactly n/8): `gnupg_generate_rsa2048_with_exact_le`, `gnupg_rsa3072_and_4096_le_values`
- GET RESPONSE rejects unsupported plaintext CLA before consuming a pending response; unmodified YubiKit chaining and private socket/direct IFD pass: tested: `get_response_rejects_bad_cla_without_consuming` (with `A0` and `90`: CLA `80` is a supported class since it was measured on a YubiKey 5C Nano 5.7.4, docs/MEASUREMENT.md, probe `cla-variants-openpgp`, and serves the pending response like `00`, `class_variants`)
- OpenPGP GET RESPONSE during unfinished command chaining returns 6883; unmodified YubiKit chained PUT DATA and subsequent SDK read pass over private CCID socket and direct IFD: intentional difference: measured on a YubiKey 5C Nano 5.7.4 (docs/MEASUREMENT.md, probe `cla-variants-openpgp`), GET RESPONSE during an unfinished chain answers 6D00, not the catalog's 6883 (the physical measurement ranks above the legacy catalog, docs/DESIGN.md §2); the chain is still dropped (model policy, unmeasured) and a later chained PUT DATA, as YubiKit sends it, works: `get_response_during_chain_returns_6d00`, `class_variants`, `terminate_drops_pending_work`
- OpenPGP GET DATA rejects unsupported command-chain CLA 10 with 6E00, leaving the next YubiKit GET DATA unaffected over private CCID socket and direct IFD: intentional difference: measured on a YubiKey 5C Nano 5.7.4 (docs/MEASUREMENT.md, probe `cla-variants-openpgp`), GET DATA with CLA 10 answers 9000 with no data and leaves the chain open, not the catalog's 6E00; the next GET DATA of the same object completes the chain and is answered as usual, one of another object answers 6883 and is not executed, and a SELECT clears it: `get_data_accepts_chaining_cla_10`, `class_variants`; the other data-less commands keep 6E00 (model policy, unmeasured)
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
- all 43 variants generated and imported via independent SDK/crypto on fresh cards: deferred: the 4 brainpoolP512r1 variants (no RustCrypto crate; GENERATE and import answer `6A81`, `only_brainpool_p512r1_answers_6a81`, `brainpool_p512r1_stays_unsupported_in_every_slot`); the other 39 are imported in every slot and generated (RSA 3072/4096 once each, same code path) with independent verification in `every_advertised_variant`, `generate_rsa3072_dec_and_decipher`, `generate_rsa4096_aut_and_authenticate`
- independent RSA/ECDSA/Ed25519 signatures, PKCS1 decryption, ECDH/X25519 secret comparison and ten attestation issuers: deferred: the brainpoolP512r1 issuer (no RustCrypto crate); the rest is tested in `every_advertised_variant` (nine issuer variants: RSA 2048/3072/4096, P-256, P-384, P-521, secp256k1, brainpoolP256r1, brainpoolP384r1; EC issuers sign with ecdsa-with-SHA256 whatever the curve, per the catalog's "SHA256 RSA/EC signatures"), `attestation_names_the_new_curves`, `generate_on_the_new_curves`, `replacement_ec_issuer_signs`, `published_ecdh_vectors_through_the_card`, `generate_ecdh_and_decipher`, `generate_x25519_and_decipher`, `rsa_decipher_rules`
- standard RSA e/p/q widths, exponent/modulus consistency and duplicate/order/unknown-field rejection: tested: `rsa_import_rejections`, `rsa_import_standard_and_crt_formats`, `rsa4096_import_with_chaining`, `keys::tests::import_list_parsing` (CRT values are width-checked and recomputed from p, q, e rather than cross-checked; model policy in `keys::import_material`)
- standard EC/Ed25519/X25519 import widths; 66-byte zero-padded P521 with raw SDK APDU workaround: tested: `p521_import_is_66_byte_zero_padded` (RFC 6979 A.2.7 key: the 66-byte form imports, the 65-byte and 67-byte forms are `6A80`), `ec_import_rejections`, `ec_import_with_and_without_public_key`, `edwards_import`, `only_brainpool_p512r1_answers_6a81`; the SDK workaround belongs to the program phase (docs/DESIGN.md §13)
- SIG generation/import resets digital-signature counter; other slots leave it unchanged: tested: `sig_generation_resets_counter_only_for_sig`, `import_counter_and_attestation_slot`
- short and extended CRT matching for SIG/DEC/AUT; mismatched reference and nonzero generation P2 rejection: tested: `generate_header_and_crt_rules`, `rsa_import_rejections`, `keys::tests::crt_forms`
- invalid request ciphertext unchanged; retained independent RSA/P521 private keys verified after rejection/restart: tested: `p521_keys_retained_after_rejected_requests_and_restart` (P-521 DEC and SIG keys answer the RFC 5903 §8.3 shared secret and verifiable signatures after rejected points and a restart), `rsa_decipher_rules`, `ecdh_decipher_rules`, `keys_survive_restart`; rejected ECDH/X25519 peer keys leave the key usable in `ecdh_point_must_match_the_curve`, `x25519_decipher_rejects_low_order_and_bad_lengths`
- socket and direct IFD fixtures; physical import/rejection/counter/touch behavior unmeasured: intentional difference: transport fixtures belong to the program phase (docs/DESIGN.md §13); import, rejection, counter and touch rules are tested through `CardApplet` (see the lines above)

## OpenPGP_attestation

- app reset retains current independent ATT key/certificate, attributes and modeled metadata; no factory restoration: tested: `reset_retains_issuer_and_signs_new_keys`, `activate_retains_attestation_slot`, `deleted_issuer_key_not_resurrected`, `state::tests::reset_keeps_attestation_slot_only`, `activate_restores_every_factory_value`
- deliberately deleted key/certificate and opaque mismatched/malformed issuer are not resurrected/repaired: tested: `deleted_issuer_key_not_resurrected`, `deleted_attestation_certificate_not_restored`, `opaque_issuer_certificate_not_repaired`, `replacement_ec_issuer_signs`
- default/replacement RSA/EC issuer survives reset/restart and independently signs new generated keys: tested: `fresh_applet_provisions_rsa2048_issuer`, `reset_retains_issuer_and_signs_new_keys`, `replacement_ec_issuer_signs`, `every_advertised_variant`
- PIV issuer and OATH private key/durable HOTP state survive OpenPGP reset: tested: `reset_leaves_other_records`, lk-device `tests/scenario_cross_app.rs::each_application_reset_keeps_the_other_applications` (through `Device`: TERMINATE + ACTIVATE, then the next HOTP code and the same PIV `F9` certificate)
- copied template validity/subject, random 16-byte positive serial input and SHA256 RSA/EC signatures: tested: `attest_generated_sig_key`, `replacement_ec_issuer_signs`, `attest::tests::serial_is_positive`, `attest::tests::copied_fields_from_built_certificate`
- DER name/source/version/fingerprint/date/counter/own serial/UIF/form-factor metadata; uncertified flags are zero: tested: `attest_generated_sig_key`, `attest_dec_and_aut_keys`, `yubikey_profile_names`
- Latin1-to-UTF8 name encoding, positive DER serial sign and SIG-only counter field independently parsed: tested: `attest_generated_sig_key`, `attest_dec_and_aut_keys`
- proprietary CLA/header validation and bounded generated certificate with immutable failure state: tested: `attest_header_rules`, `oversized_attestation_rejected`, `attest_storage_failure_keeps_certificate`, `imported_key_is_not_attested`
- physical template firmware extension DER OCTET STRING wrapper measured; original certificate/identifying payloads discarded: tested: `fresh_applet_provisions_rsa2048_issuer` (the own issuer certificate carries 1.3.6.1.4.1.41482.5.3 as a DER OCTET STRING of three bytes, the measured wrapper), `attest_generated_sig_key`; no physical certificate payload is used (docs/DESIGN.md §9)
- generated leaf extensions and exact metadata/UIF reset/tolerance are public-document models, not physical proof: intentional difference: the extension encodings follow Yubico's public description and are modelled (table in `crates/lk-openpgp/src/attest.rs`), tested in `attest_generated_sig_key`; they are not compared with a physical leaf

## Interop notes (second review)

Request shapes of GnuPG scdaemon (`scd/app-openpgp.c`, `scd/iso7816.c`), OpenSC
(`src/libopensc/card-openpgp.c`) and yubikit (`yubikit/openpgp.py`) that are not catalog
bullets of their own (a numbered list, so that assembling `docs/CATALOG_STATUS.md` does
not count them as catalog lines):

1. secure-messaging CLA bits: tested: `secure_messaging_bits_answer_6882`. lk-device clears
  the bits after unwrapping a secure channel and forwards them unchanged when no channel is
  open, so the applet answers `6882` (docs/CONTRACTS.md "APDU conventions"; C0 announces no
  secure messaging), before the logical-channel check as lk-piv does, without consuming a
  pending response; GET ATTESTATION with `84` (the GlobalPlatform secure-messaging form of
  `80`) is `6882` too (it was `6E00`; no earlier test pinned that value). The crate used
  to ignore the bits of interindustry classes and execute such a command.
2. RSA attributes with a 32-bit exponent length: accepted (model policy; physical
  behaviour unmeasured). GnuPG `change_rsa_keyattr` (gnupg master, `scd/app-openpgp.c`)
  writes `01 nnnn 0020 00` when it switches a slot from ECC back to RSA (an RSA size
  change keeps the card's `0011`), and OpenSC `pgp_update_new_algo_attr` always writes
  `SC_OPENPGP_MAX_EXP_BITS` = `0020` before it generates an RSA key (`cardctl.h`). FA
  advertises only `0011`; the crate accepts an exponent length of 17 to 32 bits for any
  advertised RSA size and import format and stores the attribute as written
  (`objects::RSA_E_BITS`), so those flows work: GnuPG reads 32 back, sizes Le and the
  imported e from it, and the card still generates e = 65537
  (`rsa_attributes_with_32_bit_exponent_length_are_accepted`,
  `objects::tests::attribute_support_rules`). yubikit writes `0011`
  (`RsaAttributes.create`) and is unaffected. Whether a physical 5.7.4 accepts `0020` is
  not known from any public source found (a 2018 gnupg-devel report shows `6A80` from an
  unnamed card); accepting it follows the spec's variable exponent-length field and keeps
  the common GnuPG and OpenSC flows working.
3. attestation extensions `.10` (FIPS) and `.11` (CSPN): Yubico's OpenPGP attestation page
  lists them as markers of certified devices; this uncertified engine omits them and keeps
  the certification bits of `.9` zero (the catalog's "uncertified flags are zero").

## Model policies replaced by measurement (YubiKey 5C Nano 5.7.4)

Differential measurement of 2026-10-11 (docs/MEASUREMENT.md): the same read-only probes
(`tools/measure/probes.py`) sent to the physical key and to the engine. Each answer below
was a model policy and now follows the key; "derived" marks the cases the read-only probes
could not send. The two catalog lines the measurement contradicts (GET RESPONSE during a
chain, GET DATA with CLA 10) are marked as intentional differences above. A numbered list,
so that assembling `docs/CATALOG_STATUS.md` does not count these as catalog lines:

1. GET RESPONSE with nothing to serve answers 6D00, right after SELECT and after a long
  response was read to its end: measured on a YubiKey 5C Nano 5.7.4 (docs/MEASUREMENT.md,
  probes `get-response-idle-openpgp`, `chain-61xx`); it was 6985. During an unfinished
  chain it is 6D00 too (probe `cla-variants-openpgp`), and the chain is dropped (model
  policy). P1-P2 other than `0000` (6A86) and command data (6700) stay model policy.
  Tests: `get_response_with_nothing_pending_answers_6d00`,
  `response_chaining_and_the_end_of_it`, `class_variants`,
  `get_response_serves_long_data`, `other_command_discards_pending_response`,
  `terminate_drops_pending_work`.
2. CLA `80` is taken like `00` by every command: measured on a YubiKey 5C Nano 5.7.4 for
  GET DATA (docs/MEASUREMENT.md, probe `cla-variants-openpgp`: `80 CA 00 C4` answers the
  PW status bytes with 9000); it was 6E00. The other commands follow by extension (derived);
  GET ATTESTATION keeps its CLA `80`-only rule, and `90` (`80` with the chaining bit) and
  the other proprietary classes keep 6E00 (unmeasured). Tests: `class_variants`,
  `unsupported_cla_and_ins`, `get_response_rejects_bad_cla_without_consuming`,
  `header_change_mid_chain_returns_6883`.
3. GET DATA with CLA `10` is a chain part (9000, no data): measured on a YubiKey 5C Nano
  5.7.4 (docs/MEASUREMENT.md, probe `cla-variants-openpgp`); see the catalog line above.
4. The factory attestation key's key information status (DE, tag `81`) is `02`
  ("imported"): measured on a YubiKey 5C Nano 5.7.4 (docs/MEASUREMENT.md, probes
  `openpgp-get-006e`, `chain-61xx`, `chain-extended-le`: `DE 08 01 00 02 00 03 00 81 02`);
  the model said `01` (generated). Only the attested slot's status decides whether a key
  can be attested, so the issuer keeps signing. A stored state that already holds `01`
  for its factory issuer keeps it (it cannot be told apart from an attestation key
  generated on the card). Tests: `factory_attestation_key_status_is_imported`,
  `application_related_data_layout_matches_observation`,
  `fresh_applet_provisions_rsa2048_issuer`.
