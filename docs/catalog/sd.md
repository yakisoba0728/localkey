# Security Domain catalog status (lk-sd)

One line per bullet of the `## SCP03`, `## SCP11`, `## SecurityDomain` and every
`## SecurityDomain_*` section of `reference/BEHAVIOR_CATALOG.md`. Test names refer to
`crates/lk-sd`:
- `tests/scp03.rs`, `tests/domain.rs`, `tests/scp11.rs` and `tests/fuzz.rs`;
- the independent SCP03 host (`tests/common/mod.rs`) and SCP11 OCE
  (`tests/common/scp11.rs`);
- the unit tests in `src/` (`scp03::tests::`, `scp11::tests::`, `cert::tests::`,
  `state::tests::`, `channel::tests::`, `tests::`).

Counting convention: each bullet has exactly one label, the first word after the colon.

- `tested`: the named tests pass and exercise everything in the bullet that the
  Security Domain crate can show. Notes in parentheses record model-policy choices.
- `intentional difference`: the engine deliberately behaves or verifies differently
  from the bullet. The reason comes first, then the tests that cover what does apply.
- `deferred`: something the bullet needs is missing. The usual causes:
  - socket and direct-IFD SDK runs belong to the program phase (`docs/DESIGN.md` §13);
  - PIV/OATH authorization state belongs to `lk-device`/`lk-piv`;
  - a GP element is not described in the sources available to this clean-room work.

Model decisions that apply throughout (sources in the crate docs):

- **Security level.** Only `33` by default (Yubico yk5-apps-scp: "Turning anything off
  is not an option"). `LevelPolicy::AmendmentD` enables every Amd D Table 7-3 level for
  conformance tests. SCP11 requests must ask for key usage `3C`, AES (`88`) and 16-byte
  keys.
- **Error statuses** (`64xx`-`6Fxx`) are returned without R-MAC/R-ENC (Amd D §6.2.5,
  reused by Amd F). `9000`, `61xx`, `62xx` and `63xx` are protected. yubikit unmacs only
  responses that carry data, so bare errors interoperate.
- **Tries.** 64 per key (legacy profile value; Yubico only says "for example, 32 times
  in a row").
  - An INITIALIZE UPDATE uses one SCP03 try. A failed SCP11 request uses one try of the
    SCP11 key. A malformed OCE certificate uses one try of the CA key the chain started
    with.
  - Tries are persisted before the response; success restores them all.
  - A key without tries is deleted when next selected (`6983`); an SCP03 set is also
    deleted when the EXTERNAL AUTHENTICATE after its last try fails. When no key of any
    kind remains, the domain resets to a fresh factory state.
- **SCP11 request checks, in this order:**
  1. unknown key: `6A88`;
  2. exhausted key: deleted, `6983`;
  3. malformed request or wrong variant: `6A80`, uses a try;
  4. SCP11a/c without a verified OCE: `6985`, uses a try;
  5. bad host point: `6A80`, uses a try.

  This order keeps yubikit's blocking reset working: it continues on `6A80` and stops on
  `6983`.
- **Management rights.** SCP03 and SCP11a sessions may manage keys. SCP11b gets `6982`.
  SCP11c gets `6985` for PUT KEY, DELETE, GENERATE, SET STATUS and every STORE DATA
  except an allowlist with a fresh `92` counter.
- **PSO statuses.** A malformed certificate answers `6A80`. A well-formed certificate
  that fails a check answers `6982` and changes no persistent state. An unknown CA
  answers `6A88`, a non-CA KID `6A86`, and an exhausted CA `6983`.
- **Certificate validity and the clock.** The engine reads no clock (`docs/DESIGN.md`
  §4); the program may lend one through `Host::unix_time` (docs/CONTRACTS.md
  "Applications B": "for certificate validity"). Every OCE certificate is checked for
  form and order (notBefore <= notAfter), and then:
  - with a lent reading, the certificate must be valid at that instant, both bounds
    inclusive (RFC 5280 §4.1.2.5, §6.1.3 (a)(2)): a notBefore in the future is refused
    like an expired notAfter (`6982`), and the profile date below plays no part;
  - without one, notAfter must not be before the earliest the current time can be: the
    profile's certificate start date (`DeviceProfile::cert_not_before`, 2026-01-01 in
    both profiles). A certificate that expired before that date is refused (`6982`); a
    notBefore in the future cannot be detected.

  The reading is taken for each PSO command, so each certificate is checked at the
  instant it arrives. A reading after 9999-12-31T23:59:59Z (beyond GeneralizedTime)
  saturates to that instant. A time naming a date that does not exist in the Gregorian
  calendar (30 February, 31 April) is malformed (X.680 GeneralizedTime/UTCTime name
  calendar dates): `6A80`, using a try of the initial CA like any malformed certificate.
- **Plaintext response chaining.** A long plaintext answer is served in pieces of at
  most Ne with `61xx` and GET RESPONSE `00 C0` (ISO/IEC 7816-4 §5.1.3). Any other
  command, handshakes included, discards what is left (§7.6.1), after which GET RESPONSE
  answers `6985` (model status).
- **Certificate policies.** A critical certificatePolicies extension is processed as
  RFC 5280 §6.1 does with initial policy anyPolicy: any identifier is accepted and
  qualifiers are refused. GP role policy identifiers (CA-KLOC, KA-KLOC, OCE, SD) are not
  mapped to chain positions, because their arcs are not in the available sources.
- **Single instance.** The OCE cache, the partial chain and the SCP11c-session ownership
  live in the one `SecurityDomain`, so "across clients" is the same object. Multiplexing
  several host connections onto it is `lk-device`/program-phase work.

Totals: 96 tested, 9 intentional differences, 15 deferred (120 bullets).

## SCP03

- SDK handshake: tested: `wrapped_exchange_matches_independent_known_answers`, `init_update_response_matches_independent_known_answer`, `extended_external_authenticate_macs_the_extended_lc`, `full_handshake_at_every_security_level`, `yubikit_request_shapes_on_extended_and_short_sessions`, `scp03::tests::kdf_matches_independent_known_answers` (yubikit-style INITIALIZE UPDATE without Le, EXTERNAL AUTHENTICATE `33`, encrypted empty data field; expected bytes computed independently with OpenSSL; on a USB session yubikit sends everything extended and without Le and MACs the extended Lc `00 00 10` of EXTERNAL AUTHENTICATE, which is accepted, with and without an outer channel; on a short NFC session data-less commands end in `00`)
- command encryption and MAC: tested: `wrapped_exchange_matches_independent_known_answers`, `full_handshake_at_every_security_level`, `interindustry_class_is_unwrapped_to_plain_class`
- response encryption and MAC: tested: `wrapped_exchange_matches_independent_known_answers`, `full_handshake_at_every_security_level`, `long_responses_are_protected_whole`, `channel::tests::protected_status_words` (error statuses bare per Amd D §6.2.5)
- long APDU: tested: `extended_length_commands_mac_the_extended_lc`, `extended_external_authenticate_macs_the_extended_lc`, `reassembled_short_chain_of_a_long_protected_command_verifies`, `long_responses_are_protected_whole`, `chained_parts_each_with_their_own_mac`, `ec_key_management`, `yubikit_request_shapes_on_extended_and_short_sessions`, `get_response_is_discarded_by_an_intervening_command` (MAC covers Lc in the form sent; whole responses wrapped before `61xx` splitting; extended certificate stores; yubikit's short-session chaining of certificate bundles and PSO certificates and its plaintext `61xx`/GET RESPONSE on both session forms; leftover response data discarded by any other command)
- wrong keys/MAC rejection: tested: `wrong_static_keys_are_rejected`, `wrong_host_cryptogram_with_valid_mac_is_6300`, `wrong_cmac_ends_the_session`, `tampered_or_truncated_commands_are_refused`, `replayed_handshakes_and_commands_are_refused`, `key_changes_drop_a_half_open_handshake` (C-MAC failure `6982`, host cryptogram failure `6300`, session ends; a recorded EXTERNAL AUTHENTICATE replayed after a new INITIALIZE UPDATE with the same host challenge fails, a recorded command fails in the same and in a new session; a handshake begun under a key set that is then replaced or deleted cannot be completed)
- plaintext downgrade rejection: tested: `plaintext_commands_end_the_session_before_dispatch`, `plaintext_select_ends_the_session_and_passes_through`, `only_select_by_name_is_a_session_boundary`, `management_commands_need_a_session` (only `xx A4 04 xx` is SELECT; a plaintext YKOATH CALCULATE ALL `00 A4 00 01` is refused like any plaintext command)
- INITIALIZE UPDATE explicit-Le guard: tested: `init_update_le_guard` (non-maximum explicit Le `6700` before the pending handshake or a try is touched; absent, short `00` and extended `0000` pass; status is a model choice)

## SCP11

- SCP11a/b/c SDK handshake and receipt: tested: `scp11b_matches_independent_known_answers`, `scp11a_and_scp11c_match_independent_known_answers`, `scp11b_with_the_factory_certificate`, `scp11a_with_full_omitted_root_and_direct_chains`, `scp11a_card_ephemeral_is_fresh_for_every_handshake`, `yubikit_request_shapes_on_extended_and_short_sessions`, `scp11::tests::request_parsing_is_exact` (yubikit request layout, sent extended on USB and short with command chaining on NFC; the independent OCE verifies every receipt; Python/OpenSSL known answers; a fresh card ephemeral key for every SCP11a/b handshake)
- dual ECDH / X963KDF / AES session keys: tested: `scp11::tests::x963_kdf_matches_independent_known_answer`, `scp11::tests::x963_kdf_layout`, `scp11b_matches_independent_known_answers`, `scp11a_and_scp11c_match_independent_known_answers` (ShSee || ShSes, X9.63 SHA-256, SharedInfo `3C 88 10`, keys in the order receipt, S-ENC, S-MAC, S-RMAC, S-DEK)
- encrypted commands and response MAC: tested: `scp11b_matches_independent_known_answers` (first wrapped command and its R-ENC/R-MAC response byte for byte, receipt as the first MAC chaining value), `protected_handoff_in_every_combination`, `scp11a_session_survives_allowlist_updates`
- OCE certificate signatures, validity, CA constraints and serial allowlist: tested: `certificate_chain_checks`, `allowlist_rules`, `pso_validity_follows_a_lent_wall_clock`, `cert::tests::times_parse_and_order`, `cert::tests::times_name_real_calendar_dates`, `cert::tests::unix_seconds_convert_to_utc_calendar_time`, `cert::tests::validity_is_checked_against_a_lent_wall_clock`, `cert::tests::expiry_is_checked_against_the_earliest_current_time` (validity: form, order, then the current time as far as it is known: with `Host::unix_time` the period must include that instant, so not-yet-valid and expired certificates are both refused with `6982`; without it, notAfter not before the profile's certificate start date, the earliest possible current time, and a future notBefore is not detected)
- SCP11b cannot provision Security Domain keys: tested: `scp11b_with_the_factory_certificate` (PUT KEY, DELETE, GENERATE, STORE DATA answer `6982`)
- SCP03/SCP11a private-key import with session DEK; c PUT KEY prohibited: tested: `scp11b_matches_independent_known_answers` (import under SCP03 with K-DEK), `scp11a_with_full_omitted_root_and_direct_chains` (an SCP11b private key and an SCP03 key set imported under SCP11a with S-DEK, both then authenticate), `scp11c_restrictions_and_replay` (`6985`)

## SecurityDomain

- key information and GP recognition data: tested: `key_information_matches_reference_schema`, `card_recognition_data_matches_reference`, `select_response_matches_reference`, `ec_key_management` (CA keys listed as `C0 06 KID KVN B0 41 F0 00`)
- SCP03 key-set provisioning / KCV / default replacement: tested: `put_key_installs_a_set_and_replaces_the_default`, `put_key_accepts_length_prefixed_key_data_and_absent_kcv`, `put_key_refusals`, `key_changes_drop_a_half_open_handshake`, `scp03::tests::key_check_value_of_default_key`
- P-256 SCP11 key generation and import: tested: `ec_key_management`, `scp11a_with_full_omitted_root_and_direct_chains`, `scp11_tries_last_attempt_exhaustion_and_wildcard`, `scp11a_and_scp11c_match_independent_known_answers`
- certificate bundles / CA SKI / allowlist: tested: `ec_key_management` (STORE DATA / GET DATA `BF21`, `FF33`, `FF34`), `allowlist_rules`, `oce_cache_invalidation`, `scp11b_with_the_factory_certificate`
- authenticated deletion: tested: `delete_key_rules`, `deleting_the_last_key_set_needs_p2_1_and_resets`, `management_commands_need_a_session`, `ec_key_management` (EC keys with their certificates, CA identifier and allowlist), `scp11c_restrictions_and_replay`
- blocking-based reset and fresh own SCP11b identity: tested: `blocking_reset_like_yubikit`, `blocking_reset_over_every_key_kind`, `scp11b_with_the_factory_certificate` (fresh key, self-signed certificate and CPLC after the reset)
- durable key and metadata persistence: tested: `restart_and_record_migration`, `restart_keeps_scp11_material`, `persistence_failures_keep_the_previous_state`, `persistence_failures_in_scp11_commands`, `failed_exhaustion_removal_is_retried`, `state::tests::factory_state_round_trips`, `state::tests::full_state_round_trips`, `state::tests::invariant_violations_are_unreadable` (a record without any key is unreadable and gives the factory state)

## SecurityDomain_profile

- fresh independent software SCP11b certificate with critical SD role and ECKA usage, self signature verified: intentional difference: the GP "SD role" policy identifier is not in the available sources, so the role is expressed by critical keyUsage keyAgreement (ECKA) and critical basicConstraints (not a CA) only; the fresh self-signed certificate and its independent verification are tested by `scp11b_with_the_factory_certificate`, `cert::tests::own_certificate_is_self_signed_and_parses`
- critical GP CA/KA/OCE certificate policies by chain role; unknown critical constraints and unsupported qualifiers denied: deferred: GP role policy identifiers are not mapped to chain positions (arcs not in the available sources; RFC 5280 §6.1 anyPolicy processing instead); unknown critical extensions and policy qualifiers are denied and plain critical policies accepted: `certificate_chain_checks`
- intermediate/leaf AKI-SKI binding, CA/leaf constraints, no PIV management authorization from host channel authentication: tested: `certificate_chain_checks` (AKI mismatch and match, cA, keyCertSign, leaf not a CA, keyAgreement; a `SecureChannel` carries no applet authorization, PIV rules stay with lk-piv/lk-device)
- explicit anchor allowlist isolation and wildcard anchor selection: tested: `allowlist_rules`
- last available attempt can succeed; failure durable; zero retries block: intentional difference: Yubico's manual says a key that fails repeatedly "is deleted", so a key at zero tries is deleted when next selected (`6983`) instead of staying as a blocked row; last-try success and durability are tested by `tries_are_used_by_init_update_and_restored_by_authentication`, `failed_last_try_deletes_the_set`, `scp11_tries_last_attempt_exhaustion_and_wildcard`, `scp11_request_errors_and_try_accounting`, `failed_exhaustion_removal_is_retried`
- wildcard KVN skips blocked newer rows; SDK reset covers three custom SCP03 sets and sixteen EC rows: intentional difference: the first wildcard selection of an exhausted newer row deletes it and answers `6983` (as above; yubikit's reset needs that status), later selections use the next row (`exhausted_set_is_deleted_and_wildcard_moves_on`, `scp11_tries_last_attempt_exhaustion_and_wildcard`); the SDK reset of three SCP03 sets and sixteen EC rows is tested by `blocking_reset_over_every_key_kind`
- full-capacity replacement/deletion/restart and immutable failures for SCP03, EC, allowlist and certificate store: tested: `three_set_capacity_replacement_and_collision`, `put_key_refusals`, `ec_key_management` (16 EC keys, 64 serials, 8 certificates, replacement without room), `persistence_failures_keep_the_previous_state`, `persistence_failures_in_scp11_commands`, `restart_keeps_scp11_material`
- eight-certificate host/store boundary fixtures: tested: `certificate_chain_checks` (eight-certificate chain accepted, ninth refused), `ec_key_management` (nine stored certificates `6A84`; the SD reassembles ISO chaining up to 8 KiB, so no test-only MAC envelope is needed)
- Domain reset retains independent PIV issuer and OATH secret/HOTP progression: tested: `reset_touches_only_the_security_domain_record`, lk-device `tests/scenario_cross_app.rs::each_application_reset_keeps_the_other_applications` (through `Device`: the yubikit blocking reset, a rotated CPLC, then the next HOTP code and the same PIV `F9` certificate)
- socket and direct native IFD SDK verification; physical retry/delete/certificate constraints and BF20 subject authorization pending: deferred: SDK runs over sockets/IFD are program phase; BF20 subject authorization is not implemented (its encoding is not in the available sources)
- socket and direct native IFD SDK verification; critical SD subject-ID handling pending; BF20 option measured: deferred: program phase; a critical GP subject-ID extension is refused as an unknown critical extension (`6982`) rather than interpreted (the measured option bytes are returned verbatim: `card_recognition_data_matches_reference`)

## SecurityDomain_metadata

- observation of fixed public SELECT and GET DATA 0066/E0/9F7F: tested: `select_response_matches_reference`, `card_recognition_data_matches_reference`, `key_information_matches_reference_schema`, `cplc_layout_and_stability`
- exact SELECT 25 bytes and recognition 63 bytes; GP 2.3.1, SCP03 option 60, SCP11 option 9b06: tested: `select_response_matches_reference`, `card_recognition_data_matches_reference`, `init_update_response_matches_independent_known_answer` (INITIALIZE UPDATE reports `03 60`)
- reference option advertises SCP11a/b/c, transient OCE, chains, S8, X509; no BF20: tested: `card_recognition_data_matches_reference`, `scp11a_and_scp11c_match_independent_known_answers`, `scp11b_matches_independent_known_answers`, `scp11a_with_full_omitted_root_and_direct_chains`, `oce_cache_invalidation` (the OCE is transient: SELECT and restart drop it)
- unsupported BF20 X509 extension denied with 6A81 before chain/authentication: deferred: the encoding of the GP `BF20` element is not in the available sources, so it is not recognised; a certificate carrying an unrecognised critical extension is refused with `6982` (`certificate_chain_checks`)
- 42-byte own CPLC with marker 0000 and random identifier: tested: `cplc_layout_and_stability`, `state::tests::cplc_layout` (IC serial and batch identifier random, other fields zero, same in both profiles)
- CPLC stable through selection, SCP03/SCP11b reads, ordinary deletion and restart; absent metadata added: tested: `cplc_layout_and_stability`, `scp11b_with_the_factory_certificate` (CPLC read through SCP11b), `restart_and_record_migration`, `records_before_scp11_support_gain_a_certificate`
- explicit last-management-key deletion restores fresh identity and rotates CPLC; peer keys/HOTP retained: tested: `deleting_the_last_key_set_needs_p2_1_and_resets`, `reset_touches_only_the_security_domain_record`, `reset_and_failed_commits_across_sessions` (needs P2 `01`, else `6985`)
- old response remains MAC-verified while reset and encrypted SELECT end later commands: tested: `explicit_reset_protects_the_last_response_then_closes`, `encrypted_select_protects_its_response_then_closes`, `blocking_reset_like_yubikit`
- saved byte/schema comparison and lifecycle over socket and direct IFD: deferred: socket/IFD runs are program phase (engine-level comparison: `select_response_matches_reference`, `key_information_matches_reference_schema`)

## SecurityDomain_versions

- SCP03 custom versions 1..254; 255 and 0 rejected: tested: `put_key_refusals`, `every_custom_version_imports_and_authenticates`
- all 254 versions imported with KCV verification, enumeration and secure messaging: tested: `every_custom_version_imports_and_authenticates`
- INIT UPDATE version/03/60 header and card cryptogram recomputed for every version: tested: `every_custom_version_imports_and_authenticates` (the test host's `open` checks the header and recomputes the cryptogram)
- SCP03 INIT option 60 agrees with the recognition data: tested: `init_update_response_matches_independent_known_answer`, `card_recognition_data_matches_reference`
- boundary 127/128/254 restart preserves keys, own SCP11b certificate and CPLC: tested: `every_custom_version_imports_and_authenticates`, `restart_keeps_scp11_material` (KVN 127 CA key, own SCP11b certificate byte for byte, CPLC)
- numeric wildcard selects highest usable version; explicit exhausted version never falls back: tested: `three_set_capacity_replacement_and_collision`, `exhausted_set_is_deleted_and_wildcard_moves_on`, `scp11_tries_last_attempt_exhaustion_and_wildcard`
- three-set capacity across versions; whole-set import, replacement/collision/delete, immutable failures: tested: `three_set_capacity_replacement_and_collision`, `put_key_refusals`, `delete_key_rules`, `persistence_failures_keep_the_previous_state`
- SCP11 private/public generation/import with versions 1..127; 0/128/255 rejected; 127 works: tested: `ec_key_management`, `scp11_tries_last_attempt_exhaustion_and_wildcard` (SCP11b session with KVN 127), `state::tests::invariant_violations_are_unreadable`
- mixed versions and EC rows recovered by SDK reset; old channel ends; peer state preserved: tested: `blocking_reset_over_every_key_kind`, `blocking_reset_like_yubikit`, `reset_touches_only_the_security_domain_record`
- private socket and direct IFD ABI: deferred: program phase

## SecurityDomain_oce_cache

- successful allowlist updates clear the cached OCE, including identical, clear and another CA update: tested: `oce_cache_invalidation`
- missing/incomplete/stale OCE denies MUTUAL AUTHENTICATE with 6985; retry consumption durable: tested: `mutual_authenticate_needs_a_verified_oce`, `persistence_failures_in_scp11_commands` (the try is committed before the answer)
- SDK MUT request, ECDH receipt, session keys, encrypted MAC responses; fixture skips only already-presented PSO: tested: `scp11a_with_full_omitted_root_and_direct_chains`, `scp11a_and_scp11c_match_independent_known_answers`, `latest_scp11c_session_supersedes_older_ones` (a verified OCE stays cached after MUTUAL AUTHENTICATE, so a second one needs no new PSO)
- rejected allowlist updates preserve data and prior OCE; fresh PSO enforces the current list: tested: `oce_cache_invalidation`, `allowlist_rules`, `persistence_failures_in_scp11_commands`
- second complete PSO replaces its predecessor; new partial chain cannot reuse the previous host: tested: `oce_cache_invalidation`, `mutual_authenticate_needs_a_verified_oce`
- CA-key replacement keeps allowlist and cached OCE, discards old SKI; deletion discards list; restart keeps replacement data: tested: `oce_cache_invalidation`, `ca_replacement_drops_a_partial_chain`, `restart_keeps_scp11_material` (a chain still being presented under the replaced key is dropped)
- SCP03/SCP11a messaging and management survive cache invalidation; SELECT/restart clear OCE: tested: `oce_cache_invalidation`, `scp11a_session_survives_allowlist_updates`, `mutual_authenticate_needs_a_verified_oce`
- own SCP11a/c identities over private socket/direct IFD: deferred: socket/IFD paths are program phase (own SCP11a/c identities: `scp11a_and_scp11c_match_independent_known_answers`)
- GP 1.3.0.13 public-review model; GP 1.4 and firmware statuses unverified: tested: `mutual_authenticate_needs_a_verified_oce` (`6985` public-review model status, unchanged)

## SecurityDomain_scp11c

- SCP11c static SD point and static key for both ECDH terms; a/b keep a fresh card ephemeral: tested: `scp11a_and_scp11c_match_independent_known_answers`, `scp11b_with_the_factory_certificate`
- independent ECDH, SHA-256 counter KDF and AES-CMAC receipt for a/b/c; SDK encrypts and verifies response MAC: tested: `scp11b_matches_independent_known_answers`, `scp11a_and_scp11c_match_independent_known_answers`, `scp11::tests::x963_kdf_matches_independent_known_answer`, `protected_handoff_in_every_combination`
- identical c request gives identical response; a/b re-randomize: tested: `scp11a_and_scp11c_match_independent_known_answers`, `scp11c_restrictions_and_replay`, `scp11b_with_the_factory_certificate`, `scp11a_card_ephemeral_is_fresh_for_every_handshake`
- c denies private/public/AES PUT KEY, current/other/wildcard DELETE and SET STATUS with 6985; a keeps private PUT/delete: tested: `scp11c_restrictions_and_replay` (also GENERATE and non-allowlist STORE DATA), `scp11a_with_full_omitted_root_and_direct_chains`
- Android/.NET suites expect current c key deletion failure: tested: `scp11c_restrictions_and_replay` (DELETE of the current SCP11c key 15/01 answers `6985`; the suites themselves are not run)
- tag 92 counter exactly two bytes 1..32767, mandatory for c allowlist STORE, forbidden elsewhere: tested: `scp11c_restrictions_and_replay`, `allowlist_rules`
- per-CA monotonic list counter kept through clear/non-c writes/CA replacement/restart; exhausted never resets or wraps: tested: `scp11c_restrictions_and_replay`, `restart_keeps_scp11_material`
- valid-MAC replay in an identical c session denied by the durable counter; independent C-MAC and rejection R-MAC verified: intentional difference: the rejection status is returned without R-MAC, as Amd D §6.2.5 requires for error statuses (reused by Amd F) and as yubikit accepts; the replayed session passes the C-MAC check and is refused by the counter, also after a restart: `scp11c_restrictions_and_replay`
- malformed/duplicate/ambiguous list envelopes do not consume the counter; list and counter commit together: tested: `scp11c_restrictions_and_replay`
- persistence failure keeps state, rolls back the live counter and closes the old channel; retry with the same counter succeeds: tested: `persistence_failures_in_scp11_commands`
- fresh own keys over private socket/direct IFD; physical protocol/status, GP 1.4, content transactions pending: deferred: program phase; GP card content transactions are not part of this model

## SecurityDomain_shared_state

- allowlist changes invalidate cached OCE and partial chains across clients for a/c: tested: `oce_cache_invalidation` (the cache and the partial chain belong to the single Security Domain instance every client reaches)
- identical/clear/other-CA/SCP11c counter commits revoke the cache; durable modeled retries only: tested: `oce_cache_invalidation`, `scp11c_restrictions_and_replay`
- peer SCP03/a/c messaging survives allowlist updates: tested: `oce_cache_invalidation`, `scp11a_session_survives_allowlist_updates`, `scp11c_restrictions_and_replay`
- CA public-key replacement keeps validated OCE; fresh PSO enforces the new CA: tested: `oce_cache_invalidation`, `ca_replacement_drops_a_partial_chain` (a partial chain started under the old key is not continued)
- internal independent generation persists atomically with policy and rolls back on failure: intentional difference: there is no persisted policy-generation token; the single instance clears its cache directly on each commit, and every policy commit is atomic and rolls back on a persistence failure (`persistence_failures_in_scp11_commands`)
- rejected/failed peer policy mutations preserve caches, key material and stored state: tested: `oce_cache_invalidation`, `persistence_failures_in_scp11_commands`
- shared Domain reset closes old SCP03/c channels and a/c caches even after identical reprovisioning: tested: `reset_and_failed_commits_across_sessions`, `blocking_reset_over_every_key_kind`
- failed shared reset restores everything together; channels and cached authorization stay valid: tested: `reset_and_failed_commits_across_sessions`, `persistence_failures_keep_the_previous_state`
- missing generation metadata added on load without recreating keys/certificates/retries/CPLC: tested: `records_before_scp11_support_gain_a_certificate`, `restart_and_record_migration` (the missing metadata is the SCP11 revision object and its own certificate, or the CPLC)
- unchanged SDK verifies receipts/KDF/encrypted responses over private sockets and separate IFD handles: deferred: program phase (engine level: `protected_handoff_in_every_combination`)
- GP public-review lifecycle; transient OCE/logical-channel policy and transactions pending: deferred: logical channels are refused (`6881`) and multi-connection transport is lk-device/program phase

## SecurityDomain_handoff

- protected a/c MUT and b INTERNAL AUTH keep the new context after the old-wrapper response: tested: `protected_handoff_in_every_combination`, `handoff_old_wrapper_and_nested_failures`
- 12 outer 03/a/b/c to a/b/c combinations: tested: `protected_handoff_in_every_combination`
- old-wrapper requests denied after the new context; stored state unchanged: tested: `handoff_old_wrapper_and_nested_failures`
- nested invalid reset authentication and not-yet-authenticated SCP03 INIT keep the outer transport: tested: `handoff_old_wrapper_and_nested_failures`, `nested_handshake_through_an_outer_channel`, `init_update_le_guard`, `blocking_reset_over_every_key_kind`
- latest committed c context supersedes older ones: tested: `latest_scp11c_session_supersedes_older_ones`
- a/b/03 peer channels survive c establishment; rejecting the obsolete c wrapper does not close the current owner: tested: `latest_scp11c_session_supersedes_older_ones`
- failed c commit rolls back and preserves the other c context: tested: `reset_and_failed_commits_across_sessions`
- malformed c request only consumes a retry; SELECT/disconnect/new-session ownership and peer applications preserved: tested: `latest_scp11c_session_supersedes_older_ones`, `scp11_request_errors_and_try_accounting`, `session_ends_on_deselect_and_reset`
- reference 9b06 has the persistent-OCE bit unset: tested: `card_recognition_data_matches_reference`, `oce_cache_invalidation` (the OCE is transient)
- physical logical-channel replacement, failed-MUT termination, GP 1.4 pending: deferred: logical channels are refused (`6881`); a failed nested request keeps the outer session (`handoff_old_wrapper_and_nested_failures`), a model choice the physical device may not share

## SecurityDomain_incremental_pso

- every nonfinal certificate prefix verified before acknowledgement: tested: `certificate_chain_checks`, `pso_validity_follows_a_lent_wall_clock` (signature, role, key type, validity against the lent clock or the profile floor, critical extensions at every prefix)
- CA, keyCertSign and path length enforced per intermediate; no OCE from an incomplete chain: tested: `certificate_chain_checks`, `mutual_authenticate_needs_a_verified_oce`
- later P1/P2 CA references ignored; initial anchor binding; wildcard alternatives kept: tested: `certificate_chain_checks`, `allowlist_rules`
- failed prefix clears chain/OCE; transport preserved; state unchanged on crypto-policy denial: tested: `certificate_chain_checks`, `handoff_old_wrapper_and_nested_failures`, `allowlist_rules`
- malformed DER uses the initial CA retry; duplicate extensions malformed: tested: `certificate_chain_checks`
- optional-root/intermediate/direct-leaf SDK interoperability; policy-free profile preserved: tested: `scp11a_with_full_omitted_root_and_direct_chains`
- software 6982/date/critical role/qualifier/budget model; physical statuses pending: intentional difference: GP role policies are not mapped (see SecurityDomain_profile), and dates are only fully checked when the program lends a wall clock (`Host::unix_time`): without one the engine knows only the earliest possible current time (the profile's certificate start date), so expiry before it is refused but a notBefore in the future passes; `6982` for expired and (with a clock) not-yet-valid certificates, policy failures, qualifiers, critical extensions and the eight-certificate budget is tested by `certificate_chain_checks`, `pso_validity_follows_a_lent_wall_clock`, `cert::tests::expiry_is_checked_against_the_earliest_current_time`
- protected PSO keeps messaging and the PIV PIN; plaintext in a channel rejected before dispatch and revokes authorization: deferred: the PIV PIN is lk-device/lk-piv state, and no device test runs a protected PSO followed by PIV commands; protected PSO keeping the session and plaintext revoking the OCE are tested by `protected_handoff_in_every_combination`, `plaintext_ends_scp11_sessions_before_dispatch`
- PIV signatures verified after protected PSO: deferred: lk-device/lk-piv integration (no device test runs SCP11 PSO and then PIV signing; SCP03-wrapped PIV signing is tested in lk-device `scenario_ccid::scp03_then_wrapped_piv_commands`)

## SecurityDomain_plaintext

- plaintext termination at transport entry for SCP03/11a/11b/11c; SELECT is a session boundary: tested: `plaintext_commands_end_the_session_before_dispatch`, `plaintext_ends_scp11_sessions_before_dispatch`, `plaintext_select_ends_the_session_and_passes_through`, `encrypted_select_protects_its_response_then_closes`, `only_select_by_name_is_a_session_boundary`, `only_select_by_name_selects_the_domain`, `session_ends_on_deselect_and_reset` (SELECT means `xx A4 04 xx`, docs/CONTRACTS.md; an encrypted CALCULATE ALL keeps the session)
- PSO/INIT UPDATE/MUT/INTERNAL, chained CLA 90, GET DATA/RESPONSE, unsupported CLA rejected before dispatch: tested: `plaintext_commands_end_the_session_before_dispatch`, `plaintext_ends_scp11_sessions_before_dispatch` (`6982`, model status)
- no transport rejection consumes retries or rewrites persistent state: tested: `plaintext_commands_end_the_session_before_dispatch`, `plaintext_ends_scp11_sessions_before_dispatch`, `wrong_cmac_ends_the_session`
- closed wrapper and revoked OCE verified separately; peer channel and own material preserved: tested: `plaintext_ends_scp11_sessions_before_dispatch`, `wrong_cmac_ends_the_session`
- PIV PIN/admin and OATH access revoked: deferred: lk-device clears the selected applet's authorization (`CardApplet::deselect`) when a channel ends; the PIV part is tested there (`secure_channel::plaintext_command_is_rejected_and_revokes_piv_pin`), no device test checks the OATH access state after a channel ends
- normal SDK establishment, encrypted PSO and protected handoff: tested: `protected_handoff_in_every_combination`, `wrapped_exchange_matches_independent_known_answers`, `scp11b_matches_independent_known_answers`
- prior v21 ZIP fails first plaintext PSO rejection; 326 items: intentional difference: a legacy release-artifact regression check, not device behaviour; the rejection itself is `plaintext_ends_scp11_sessions_before_dispatch`
- vendor prose is the source model; physical status unmeasured: tested: `plaintext_commands_end_the_session_before_dispatch`, `plaintext_ends_scp11_sessions_before_dispatch` (Yubico yk5-apps-scp wording; `6982` model status)
- prior v21 ZIP fails first plaintext PSO rejection; 394 items: intentional difference: a legacy release-artifact regression check, not device behaviour; covered as above
- malformed plaintext SELECT clears OCE and PIV PIN/admin before validation: deferred: the PIV PIN/admin is lk-device state (lk-device revokes it when a plaintext command ends a channel, `secure_channel::plaintext_command_is_rejected_and_revokes_piv_pin`; not tested for a malformed SELECT); the Security Domain part (session ended and OCE revoked before the SELECT is validated; an unparsable one answers `6700`) is tested by `plaintext_ends_scp11_sessions_before_dispatch`, `plaintext_select_ends_the_session_and_passes_through`

## SecurityDomain_allowlist

- every presented certificate serial checked under one CA policy: tested: `allowlist_rules`
- wildcard candidates kept across prefixes; no union across anchors: tested: `allowlist_rules`
- initial CA policy binding despite later P1/P2: tested: `certificate_chain_checks`, `allowlist_rules`
- optional-root omission and direct-leaf chains need only presented serials: tested: `allowlist_rules`
- listed serial never bypasses validation; sign-padded serials compare as integers: tested: `allowlist_rules`, `cert::tests::serials_compare_as_integers`
- rejected prefix wipes prior OCE without touching retries or channels: tested: `certificate_chain_checks`, `allowlist_rules`, `oce_cache_invalidation`
- failed subset commit keeps list/cache; successful subset commit revokes the cache, keeps transport: tested: `persistence_failures_in_scp11_commands`, `oce_cache_invalidation`, `scp11a_session_survives_allowlist_updates`
- empty clear list has no restriction; restart keeps policy/key/SKI/cert/CPLC: tested: `allowlist_rules`, `restart_keeps_scp11_material`
- 81 checks per socket/IFD; v22 ZIP fails omitted-root check: intentional difference: legacy release-artifact and transport checks, not device behaviour; the omitted-root rule is tested by `allowlist_rules`
- vendor prose model; physical serial scope and timing unmeasured: tested: `allowlist_rules` (every presented certificate checked when its PSO arrives; `6982` model status)
