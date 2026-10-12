# 동작 카탈로그 (legacy v0.64에서 추출)

이 문서는 이전 구현(태그 `legacy-v0.64.0`)이 **어떻게 동작하도록 정했고 무엇을 검증했는지**를 서술로만 옮긴 것입니다.
코드가 아니며, 새 엔진은 이 문서를 규격 문서와 함께 *기대 동작 목록*으로 사용합니다. 각 항목은 당시 소프트웨어 모델과
SDK 상호운용 테스트 기준이며, 실물 reference key와의 명령 단위 비교로 확정된 것이 아닙니다.
실물 키에서 읽은 공개 바이트는 `physical-key/`, 앱별 초기 프로필 값은 `legacy-v0.64-profiles.json`에 있습니다.

원문(영어)은 legacy 저장소의 `implementation-status.json` `implemented_and_verified`와 `compatibility-matrix.json`입니다.

## FIDO

- CTAPHID
- CTAP2.1
- U2F
- ES256
- Ed25519
- ES384
- PIN1
- PIN2
- permission and RP scoped tokens
- credProtect
- credBlob
- hmac-secret
- largeBlobKey
- CredentialManagement0A/41
- LargeBlobs0C
- Config0D
- reset power-up window
- durable state migration
- measured 1536-byte message / 128-byte ID / one minimum-PIN RP profile
- 1472-byte large-blob fragments with boundary checks
- saved read-only reference GetInfo comparison
- stateless software nonresident ES256/Ed25519/ES384 and U2F registration with authenticated RP-bound 128-byte IDs
- initialized store remains constant across 10001 software nonresident registrations; full resident capacity permits further nonresident registration
- derived dual hmac-secret, protected wrapped credentials and independent SDK signature verification across restart
- durable shared wrapped counter with persistence rollback and rollover refusal; reset rotates root
- legacy store v1/v2 reads with first mutation to v3; previous keys retained and old writers refuse new format
- published discoverable-only credBlob profile; reference boundary response unmeasured
- CTAP 2.1 empty minPinLengthRPIDs preserves previous allowlist while updating supplied minPinLength; baseline failure and 121-case C++ regression verified
- CTAP 2.1 makeCredential enterpriseAttestation parses CBOR unsigned integer 0/1/2/3; unsupported capability returns 02 and wrong boolean type returns 11 without credential mutation on macOS/Linux private socket and no-NIC guest USB
- CTAP 2.1 explicitly present empty allowList returns NoCredentials without consuming a signature counter; matching and absent lists still work through unmodified python-fido2 and C++ regression
- CTAP 2.1 getAssertion with hmac-secret and up=false rejects with UnsupportedOption (0x2B), without advancing the signature counter; independently checked with python-fido2 over private CTAPHID
- CTAP2.1 canonical half/float/double CBOR values in unknown request fields are skipped rather than rejected; private CTAPHID and Mac/Linux C++ regression pass
- Credential management delete/update of a missing resident credential returns CTAP2_ERR_NO_CREDENTIALS (0x2e), verified with an unmodified FIDO2 SDK over private CTAPHID.
- CTAPHID final legal sequence 127 completes a maximum 7609-byte PING; 7550/7551/7609-byte boundaries verified through owned no-NIC dummy_hcd USB and Mac/Linux C++ tests.
- Unknown CTAP option values are skipped while recognized rk/up/uv remain boolean-typed; unmodified pyfido2 private CTAPHID Mac/Linux checks verify before/after.
- Three wrong PINs now return PIN_AUTH_BLOCKED with powerCycleState true; further PIN attempts consume no durable retry until a power cycle, while eight failures across cycles hard-block. Unmodified pyfido2, Mac/Linux C++ and private CTAPHID tests verify.
- Forced-PIN-change token commands now verify the supplied old PIN and update retries before policy status; legacy token returns PIN_INVALID for a correct PIN under forced change. Unmodified pyfido2 Mac/Linux verifies ordering.
- Malformed encrypted PIN proofs now decrement durable retries before decryption and participate in the three-attempt soft block. Unmodified pyfido2 Mac/Linux verifies retry state and power-cycle recovery.
- Allocated CTAPHID INIT now discards late replies from an aborted same-CID operation. Deterministic private-socket and real dummy_hcd FIDO HID A/B, Mac/Linux C++ and no-NIC integrated USB regression pass.
- CTAPHID WINK rejects nonzero BCNT with ERR_INVALID_LEN while zero-length WINK and subsequent PING succeed. Mac/Linux C++ and private-socket A/B pass; physical firmware error precedence remains unmeasured.
- An orphan CTAPHID continuation frame is ignored without occupying a channel; an unknown-CID initial fragment returns INVALID_CHANNEL immediately while a valid CID can PING. Mac/Linux private-socket A/B, C++ and no-NIC guest checks pass; physical firmware behavior remains unmeasured.
- A concurrent CTAPHID CBOR operation reserves the device for its CID: PING, WINK and INIT on another or broadcast CID return CHANNEL_BUSY until the worker completes. Mac/Linux private HID socket A/B, C++ and no-NIC guest pass; physical timing remains unmeasured.
- CTAPHID_CANCEL during a U2F MSG is ignored while same-CID INIT still aborts; Mac/Linux private socket, C++ and owned no-NIC USB A/B pass. Physical firmware timing remains unmeasured.
- CTAP 2.1 large-blob write validates fragment sequence before PIN/UV auth and restarts a sequence on offset zero; Mac/Linux private socket A/B and C++ regression pass. Physical error precedence remains unmeasured.
- A processing CTAPHID CID rejects an interleaved PING or WINK with CHANNEL_BUSY, while INIT resynchronization, CANCEL, original completion and idle PING remain functional; Mac/Linux private socket and owned no-NIC USB A/B pass. Physical error byte remains unmeasured.

## PIV

- management mutual authentication
- PIN/PUK/retries
- RSA/EC/Ed25519/X25519
- generate/import/move/delete
- sign/decrypt/ECDH
- certificates
- local software CA attestation
- PIN/touch policies
- blocked PIN/PUK reset
- assembled plaintext APDU data buffer budget and shared object storage budget
- atomic out-of-space replacement/deletion and restart accounting
- documented protected data-object reads and tag/header validation
- published PIV SELECT application template, fixed Discovery and unsupported biometric group object
- read-only object PUT rejection with unchanged persistent state
- 1..255 PIN/PUK retry limits, saturated four-bit status and complete eight-bit metadata across restart
- preinitialized own F9 issuer; five supported generation algorithms and imported RSA/EC issuers
- independent issuer signatures, copied validity and public-profile extensions with own serial
- 16-byte random attestation serial profile; no manufacturer certification claims
- F9 key/certificate retained through PIV reset/restart; deleted certificate is not regenerated
- opaque mismatched/malformed issuer storage, independent failed verification and immutable failure state
- legacy lazy-CA migration preserves original issuer and user private keys
- PIV reset preserves independent OATH key and durable HOTP counter
- socket and native direct IFD SDK verification; physical differential validation pending
- published 3052-byte tag70 certificate limit, valid X.509 SDK boundary and immutable rejection over private socket and stock Linux libccid; exact physical status unmeasured
- VERIFY/CHANGE/RESET RETRY PIN-command P1/P2/Le guards before state changes; independent YubiKit focused and combined full regression verified
- YubiKey 5.7 PIV F9 DELETE KEY is accepted while MOVE F9 stays forbidden; SDK socket/direct IFD tests verify issuer loss and persistence over restart/PIV reset.
- Malformed PIV RESET P1/P2, command data, or explicit Le are rejected before erasing keys or retries; unmodified YubiKit socket/direct IFD and SCP03 reset pass on Mac/Linux.
- Malformed SET PIN RETRIES Le and SET MANAGEMENT KEY P1/P2/Le are rejected before changing encrypted PIN, PUK or management key state. Unmodified YubiKit socket/direct IFD, SCP03 and restart checks pass on Mac/Linux.
- MOVE KEY and DELETE KEY reject extra APDU data or explicit Le with 6700 before changing key state. Mac/Linux private socket/direct IFD A/B and unmodified YubiKit restart checks pass; physical status remains unmeasured.
- GENERATE KEY PAIR rejects nonzero P1 before replacing an occupied private key; Mac/Linux private socket/direct IFD A/B and unmodified YubiKit restart checks pass. Physical malformed-header status remains unmeasured.
- GENERAL AUTHENTICATE INS 87 rejects explicit Le before parsing a handshake or consuming PIN_ALWAYS signing authorization; Mac/Linux private socket/direct IFD A/B, unmodified YubiKit signatures, unchanged encrypted state and restart checks pass. Physical malformed-Le status remains unmeasured.

## OpenPGP

- SIG/DEC/AUT separation
- RSA/EC/Ed25519/X25519
- generate/import
- sign/decrypt/ECDH
- separate certificate slots
- user/admin PIN
- blocked PIN/admin reset
- SHA256/SHA512 iterated salted S2K KDF
- hash-only PIN state when KDF enabled
- KDF PIN change, retry and reset-code recovery
- fourth attestation key/certificate slot
- own software attestation and imported-key provenance rejection
- certificate iteration
- 15-second cached/fixed touch
- wrong PIN invalidates both PW1 authorization modes
- read-only PC/SC observation of public reference-key metadata; no PIN or persistent writes
- exact captured C0/5F52/7F66/7F74 bytes and direct-C0 6B00 response
- captured application-related tag layout/lengths, discretionary 7F66 and public RSA2048 attributes
- fresh independent own RSA2048 attestation issuer; legacy own EC issuer and user keys preserved
- observed 3070-byte challenge, 2048-byte certificate and 255-byte special-object ceiling model
- private-use write access requires PW1 reference 82 or PW3; protected reads remain PIN scoped
- name 39, language eight bytes in pairs, ASCII sex, fingerprint 20 and generation-time four-byte checks
- read-only and undeclared PUT rejection; Resetting Code and unsupported legacy objects never exposed
- four certificate occurrences, ceiling/clear/restart and deliberate issuer certificate deletion retained
- bounded replacement/deletion with legacy oversized reads preserved; independently verified retained keys
- socket and direct IFD independent SDK/crypto; physical write/challenge/touch boundaries unmeasured
- RFC4880 low-count iterated-salted S2K hashes one complete salt-plus-PIN block; independent digest and SDK APDU verified over socket and direct IFD
- OpenPGP 3.4.1 VERIFY and CHANGE REFERENCE DATA P1/data validation before PIN retry or state mutation over socket and direct IFD; exact physical statuses unmeasured
- explicit Le guards on VERIFY/CHANGE and zero P1/P2 guard on INTERNAL AUTHENTICATE over socket and direct IFD; reference key status/tolerance unmeasured
- RESET RETRY COUNTER, PUT DATA, GENERATE, PSO SIGN and INTERNAL AUTHENTICATE Le mutation guards verified over private socket and direct IFD
- GET RESPONSE rejects unsupported plaintext CLA before consuming a pending response; unmodified YubiKit chaining and private socket/direct IFD pass
- OpenPGP GET RESPONSE during unfinished command chaining returns 6883; unmodified YubiKit chained PUT DATA and subsequent SDK read pass over private CCID socket and direct IFD
- OpenPGP GET DATA rejects unsupported command-chain CLA 10 with 6E00, leaving the next YubiKit GET DATA unaffected over private CCID socket and direct IFD
- GET NEXT DATA with unexpected command data returns 6700 before advancing certificate occurrence, verified over private CCID socket and direct IFD
- Exhausted GET NEXT DATA returns 6A88 without clearing the current certificate occurrence, preventing subsequent PUT DATA from writing an unreachable object; private socket and direct IFD pass
- GET ATTESTATION with explicit Le=1 is rejected before replacing a SIG certificate; private CCID socket/direct IFD and unmodified YubiKit attestation verified.
- Operational ACTIVATE FILE succeeds without semantic state change or lazy attestation creation; terminated ACTIVATE still resets. Mac/Linux private socket/direct IFD SDK A/B and restart checks pass.
- SELECT DATA rejects explicit Le=1 with 6700 before changing the selected certificate occurrence; absent or zero Le and unmodified YubiKit certificate reads remain valid. Mac/Linux private socket/direct IFD A/B and restart checks pass; physical status remains unmeasured.
- SET RETRIES F2 rejects malformed P1/P2 or explicit Le before changing encrypted retry state. Mac/Linux private CCID socket/direct IFD A/B, unmodified YubiKit and persistence checks pass; physical status remains unmeasured.

## OpenPGP_algorithms

- exact measured 421-byte FA inventory including curve order and 43 slot/algorithm variants
- measured 7A outer wrapper and three-byte 93 counter schema; physical counter payload discarded
- advertised canonical RSA2048/3072/4096, seven prime curves, Ed25519 SIG/AUT and X25519 DEC restrictions
- all 43 variants generated and imported via independent SDK/crypto on fresh cards
- independent RSA/ECDSA/Ed25519 signatures, PKCS1 decryption, ECDH/X25519 secret comparison and ten attestation issuers
- standard RSA e/p/q widths, exponent/modulus consistency and duplicate/order/unknown-field rejection
- standard EC/Ed25519/X25519 import widths; 66-byte zero-padded P521 with raw SDK APDU workaround
- SIG generation/import resets digital-signature counter; other slots leave it unchanged
- short and extended CRT matching for SIG/DEC/AUT; mismatched reference and nonzero generation P2 rejection
- invalid request ciphertext unchanged; retained independent RSA/P521 private keys verified after rejection/restart
- socket and direct IFD fixtures; physical import/rejection/counter/touch behavior unmeasured

## OpenPGP_attestation

- app reset retains current independent ATT key/certificate, attributes and modeled metadata; no factory restoration
- deliberately deleted key/certificate and opaque mismatched/malformed issuer are not resurrected/repaired
- default/replacement RSA/EC issuer survives reset/restart and independently signs new generated keys
- PIV issuer and OATH private key/durable HOTP state survive OpenPGP reset
- copied template validity/subject, random 16-byte positive serial input and SHA256 RSA/EC signatures
- DER name/source/version/fingerprint/date/counter/own serial/UIF/form-factor metadata; uncertified flags are zero
- Latin1-to-UTF8 name encoding, positive DER serial sign and SIG-only counter field independently parsed
- proprietary CLA/header validation and bounded generated certificate with immutable failure state
- physical template firmware extension DER OCTET STRING wrapper measured; original certificate/identifying payloads discarded
- generated leaf extensions and exact metadata/UIF reset/tolerance are public-document models, not physical proof

## OATH

- RFC4226 HOTP
- RFC6238 TOTP
- SHA1/256/512 implementation
- list/calculate/calculate-all/rename/delete
- access key mutual challenge-response
- only-increasing property
- reset
- four-byte HOTP-only IMF, singleton property and required/allowed TLV syntax
- command P1/P2/body validation and documented missing-object/auth-not-enabled responses
- eight-byte SET CODE challenge, variable VALIDATE challenge and SHA1 proof length; incorrect SET CODE proof returns 6984
- all 18 published RFC6238 SHA1/SHA256/SHA512 vectors and independent HOTP/full/truncated HMAC
- full/truncated CALCULATE ALL and HOTP/touch placeholders without HOTP counter consumption
- durable IMF/only-increasing state, mutual SDK access-code validation and independent PBKDF2 derivation
- published 64-credential capacity; overflow, overwrite/rename at full capacity, release/restart
- locked app reset rotates OATH salt while retaining PIV own F9 issuer
- socket and direct IFD SDK fixtures; no physical differential or OS reader validation
- 64-bit HOTP terminal counter rejects the exhausted next-counter sentinel without crashing a private socket; physical status unmeasured
- PUT credential secret minimum 14 wire bytes; unpadded 13-byte APDU rejected before persistent write and SDK padded one-byte source verified
- SEND REMAINING rejects nonzero CLA before consuming a pending response. Mac/Linux private CCID socket/direct IFD A/B and unmodified YubiKit 504-byte list continuation pass; physical rejection status remains unmeasured.
- Per-client OATH authorization is bound to current salt, access key and rotation revision; stale PUT and pending LIST continuation reject after another client changes the code. Mac/Linux private socket/direct IFD and unmodified YubiKit A/B pass. Physical concurrent-session behavior remains unmeasured.

## OTP

- serialized 8-byte HID reports with frame CRC
- CCID APDU control
- slot configurations/settings/delete/swap
- access codes
- HMAC-SHA1 challenge-response
- software button HOTP/Yubico OTP/static password output
- static-ticket AES/CRC output and short ticket
- documented uppercase/digit/special-character transforms
- HOTP fixed token identifiers
- keyboard modifier/press/release reports
- navigation and pacing event encoding
- compiled macOS OTP HID bridge wire test
- nonzero private UID XOR in Yubico challenge-response, independently decrypted
- persistent counter saturation and session rollover
- slot 1 / slot 2 protection precedence and swap restriction
- dormant activation without flags-only redormancy
- merged OTP serial API visibility
- 45-byte SDK scan map applied to keyboard reports
- documented short/long hold release windows over socket and compiled native bridge
- two-step static-ticket manual update with fresh presence, configuration binding and session cancellation
- LT64 empty HMAC challenge maps to a single zero byte over SDK APDU and OTP HID
- documented two-slot short/long touch windows with independent SDK-written slot fixtures; physical debounce timing unmeasured
- LT64 direct short-APDU and OTP HID abort/orphan-frame boundaries in isolated software candidate; exact reference key response unmeasured
- touch-trigger status bits distinguish keyboard OTP from challenge-response across APDU/HID, swap, delete and restart
- Yubico OTP volatile power session survives logical SELECT and private socket reconnect; independent AES/CRC ticket counter verification
- OTP volatile session rollback and committed device-reboot behavior verified across APDU, private management RPC and software button paths
- single configured slot 1 FAST_TRIG output survives a modeled 300..5000 ms completed hold with or without the legacy flag; actual contact-time emission remains unmodeled
- private touch_down/touch_up events return single-slot 1 FAST_TRIG reports at modeled contact, defer two-slot selection to release, and reject legacy software button calls during an active touch without duplicate YubiOTP counter consumption
- device-shared touch ownership prevents concurrent private clients from issuing duplicate OTP reports or consuming extra YubiOTP use counters; Linux FunctionFS bridge emits touch-origin OTP keyboard events to isolated guest evdev
- YubiHSM Auth Add Credential accepts touch policy tag 7A only as a one-byte 00 or 01 and rejects malformed values without storage; FunctionFS OTP IN input is backpressured when the guest HID reader pauses
- OTP swap requires both slots configured; empty/single-slot swaps preserve the original credential and sequence. Unmodified YubiKit Mac/Linux checks pass.
- OTP UPDATE accepts a configured slot with Allow Update or Dormant and permits toggling Dormant. Unmodified YubiKit Mac/Linux A/B and regression pass; physical firmware status remains unmeasured.
- An empty OTP slot cannot be deleted as an existing slot; raw and unmodified YubiKit Mac/Linux CCID A/B verify 6985 rejection without consuming configured-slot state, with normal deletion retained. Physical firmware status remains unmeasured.

## YubiHSMAuth

- symmetric SCP03 derivation
- asymmetric dual ECDH derivation
- receipt verification
- single-use ephemeral challenges
- generate/import/delete
- password retries
- management key
- credential deleted on eighth wrong password with ephemeral state cleared, label recoverable after restart; symmetric/asymmetric YubiKit socket and direct IFD verified
- RESET application rejects unexpected data or explicit Le before clearing credentials; normal SDK reset and ambiguous short-zero formatter preserved
- ADD CREDENTIAL rejects duplicate labels with 6983, malformed algorithm length and invalid UTF-8 labels with 6A80, without corrupting SDK listing
- YubiHSM Auth symmetric GET CHALLENGE returns an eight-byte host challenge without touch; CALCULATE still requires touch. Unmodified YubiKit Mac/Linux socket/direct IFD checks pass; physical timing remains unmeasured.

## Management

- CCID and OTP HID device information/configuration
- CTAPHID vendor 0x42 / 0x43 commands
- shared own serial and USB application flags
- configuration lock/unlock
- FIDO/U2F and CCID application enable/disable
- fail-closed behavior when shared backend unavailable
- device launcher and lifecycle cleanup

## SCP03

- SDK handshake
- command encryption and MAC
- response encryption and MAC
- long APDU
- wrong keys/MAC rejection
- plaintext downgrade rejection
- INITIALIZE UPDATE rejects a non-maximum explicit Le before resetting a session or decrementing authentication retries; an absent or maximum Le and unmodified YubiKit secure-channel exchange pass on Mac/Linux socket/direct IFD. Physical status remains unmeasured.

## SCP11

- SCP11a/b/c SDK handshake and receipt
- dual ECDH / X963KDF / AES session keys
- encrypted commands and response MAC
- OCE certificate signatures, validity, CA constraints and serial allowlist
- SCP11b cannot provision Security Domain keys
- SCP03/SCP11a private-key import with session DEK; c PUT KEY prohibited

## SecurityDomain

- key information and GP recognition data
- SCP03 key-set provisioning / KCV / default replacement
- P-256 SCP11 key generation and import
- certificate bundles / CA SKI / allowlist
- authenticated deletion
- blocking-based reset and fresh own SCP11b identity
- durable key and metadata persistence

## SecurityDomain_profile

- fresh independent software SCP11b certificate has critical SD role and ECKA usage with self signature independently verified
- critical GP CA/KA/OCE Certificate Policies interpreted by chain role; unknown critical constraints and unsupported qualifiers denied
- intermediate/leaf AKI-SKI binding, CA/leaf constraints and no PIV management authorization from host channel authentication
- explicit anchor allowlist isolation and wildcard selection continues to another usable matching own anchor
- last available modeled SCP03/SCP11a/b/c attempt can succeed; failure remains durable and zero retries block
- wildcard KVN selection skips blocked newer rows; SDK reset covers all three custom SCP03 sets and sixteen EC rows
- full-capacity replacement/deletion/restart and immutable failures for SCP03, EC, allowlist and certificate-store models
- eight-certificate host/store boundary fixtures; larger store uses explicit per-instance test MAC envelope and short chaining, normal SDK limit unchanged
- Domain reset retains independent PIV issuer and OATH secret/HOTP progression
- socket and direct native IFD SDK verification; physical retry/delete/certificate constraints and BF20 subject authorization remain pending
- socket and direct native IFD SDK verification; physical retry/delete/certificate constraints and critical SD subject-ID handling remain pending; BF20 unsupported option is now measured

## SecurityDomain_metadata

- native shared PC/SC observation of fixed public SELECT and GET DATA 0066/E0/9F7F; no PIN, handshake, PSO or writes
- exact captured public SELECT 25 bytes and recognition 63 bytes; GP 2.3.1, SCP03 option 60 and SCP11 option 9b06
- reference option advertises SCP11a/b/c, transient OCE, chains, S8 and X509; neither variant advertises BF20
- unsupported BF20 X509 extension denied as GP-public-review model 6A81 before chain/authentication; physical rejection status unmeasured
- 42-byte own CPLC: software platform marker 0000 and independent random identifier; physical 4090 silicon identity not claimed
- CPLC stable through selection, SCP03/SCP11b reads, ordinary deletion and restart; absent legacy metadata added without replacing keys/certificates
- explicit last-management-key deletion restores fresh default Domain identity and rotates CPLC; peer keys/HOTP retained
- old response remains SDK MAC-verified while reset and encrypted SELECT terminate authorization for subsequent commands
- saved byte/schema comparison and documented lifecycle model verified over socket and direct IFD; physical reset/error behavior remains unmeasured

## SecurityDomain_versions

- SCP03 custom versions 1..254 from the published Yubico manual; factory version 255 and custom zero rejected
- all 254 versions independently imported with fresh software static keys, SDK KCV verification, enumeration and secure messaging
- INIT UPDATE selected version/03/60 header checked and AES-CMAC card cryptogram independently recomputed for every version
- SCP03 INIT option 60 agrees with the measured public recognition; actual physical INIT response remains unmeasured
- boundary 127/128/254 restart preserves all key material, own SCP11b certificate and CPLC
- numeric wildcard selects highest usable high-byte version; explicitly blocked version never falls back
- documented three-set capacity still applies across low/high versions; whole-set import, replacement/collision/delete and immutable failures
- SCP11 private/public generation/import retains separate seven-bit 1..127 profile; 0/128/255 rejected and 127 SDK agreement works
- mixed low/high/blocked versions and EC rows recovered by SDK reset; old channel ends and peer state preserved
- private socket and direct IFD ABI verified; no physical reader/authentication/provisioning used in this checkpoint

## SecurityDomain_oce_cache

- all successful allowlist updates clear the SD cached OCE, including identical, clear and another CA update
- missing/incomplete/stale OCE denies MUTUAL AUTHENTICATE with GP-public-review modeled 6985; modeled retry consumption remains durable
- unchanged SDK generates MUT request, verifies ECDH receipt, derives session keys and verifies encrypted MAC responses; explicit fixture skips only already-presented PSO
- rejected allowlist updates preserve persistent data and prior validated OCE; fresh SDK PSO enforces current list
- a second complete PSO replaces its predecessor; a newly started partial chain cannot reuse the previous host
- CA-key replacement retains linked allowlist and cached OCE while discarding old SKI; deletion discards list and restart retains replacement data
- current SCP03/SCP11a secure messaging and management survive allowlist cache invalidation; SELECT/restart clear volatile OCE
- own SCP11a/c identities and private socket/direct IFD paths; no physical key access in this checkpoint
- GP1.3.0.13 public-review model; finalized GP1.4 and firmware lifecycle/error statuses remain unverified

## SecurityDomain_scp11c

- SCP11c returns static SD point and uses static SD key for both ECDH terms; a/b retain fresh card ephemeral
- independent ECDH, explicit SHA256 counter KDF and AES-CMAC receipt across all a/b/c; unchanged SDK encrypts and verifies response MAC
- same own c request gives identical static-key response; a/b same request re-randomizes card contribution
- c denies private/public/AES PUT KEY, current/other/wildcard key DELETE and SET STATUS with modeled 6985; a private PUT/delete remain supported
- pinned Android/.NET integration suites explicitly expect current c key deletion failure; source read only, never executed on hardware
- tag92 exactly two bytes positive 1..32767, mandatory for c allowlist STORE and forbidden in non-c sessions
- per-CA monotonically increasing list counter retained through clear/non-c writes/CA replacement/restart; exhausted counter never resets or wraps
- valid-MAC exact own packet replay in identical c session denied by durable counter; independent C-MAC and rejection R-MAC verified
- malformed/duplicate/ambiguous list envelopes do not consume counter; list+counter commit together
- controlled pre-rename persistence failure preserves encrypted state, rolls back live counter and closes old channel; retry same counter succeeds
- fresh own keys over private socket and direct IFD; physical protocol/status, final GP1.4, SD content transaction and physical concurrent/logical-channel semantics pending

## SecurityDomain_shared_state

- successful allowlist changes invalidate cached OCE and partial chains across independent clients for a/c
- identical/clear/other-CA/SCP11c counter commits all revoke old peer cache; durable modeled retries only
- established peer SCP03/a/c secure messaging survives ordinary allowlist updates
- CA public-key replacement retains previously validated OCE; fresh PSO enforces the replacement CA
- internal independent generation persists atomically with policy and rolls back on persistence failure
- rejected/failed peer policy mutations preserve prior caches, key material and stored ciphertext
- shared Domain reset closes other connections old SCP03/c channels and old a/c caches even after identical own SD-key reprovision
- failed shared reset restores key/policy/identity/ciphertext together; other clients channels and cached authorization remain valid
- missing generation metadata is added on legacy load without recreating keys/certificates/retries/CPLC
- unchanged SDK verifies new handshake receipts/KDF/encrypted responses over private sockets and separate direct IFD handles
- GP public-review lifecycle model; physical/final GP14 transient OCE/logical-channel policy and transaction behavior pending

## SecurityDomain_handoff

- valid protected a/c MUT and b INTERNAL AUTH retain new established context after old-wrapper response
- unchanged SDK validates protected receipt/KDF and new-context encrypted/MAC responses across 12 outer03/a/b/c to a/b/c combinations
- old-wrapper requests denied after new context was independently verified; stored ciphertext unchanged on denial
- nested invalid SDK reset authentication and not-yet-authenticated SCP03 INIT retain outer transport; full Domain reset regression preserved
- shared SD c-session model: latest committed successful c context supersedes older c contexts across private connections
- a/b/03 peer channels survive c establishment; rejecting obsolete c wrapper does not close current owner
- plain/protected failed c commit rolls back session token/keys/ciphertext and preserves other peer c context
- malformed c request only consumes modeled retry; SELECT/disconnect/new-session ownership and peer applications preserved
- reference9b06 has persistent-OCE bit3 unset; GP single PERSISTENT OCE rule is not a required reference feature
- physical logical-channel replacement policy/status, failed-MUT termination, final GP14 and SD transactions remain pending

## SecurityDomain_incremental_pso

- every nonfinal certificate prefix verifies CA signature/role/key type/date/critical constraints before acknowledgement
- CA and keyCertSign plus accumulated path-length limit enforced when an intermediate arrives; no OCE authorized by an incomplete chain
- later P1/P2 CA references ignored as GP7.5.1 specifies; initial anchor remains binding and wildcard alternatives retained through each presented prefix and final serial check
- failed prefix clears chain/OCE authorization while preserving current transport/application verification; state/ciphertext unchanged on crypto-policy denial
- malformed DER uses initial CA retry even if a continuation changes references; duplicate certificate extensions treated as malformed instead of escaping handler
- optional-root/intermediate/direct-leaf a/c SDK receipt/KDF/encrypted MAC interoperability and existing policy-free profile preserved
- software6982/date/critical role/qualifier/budget model preserved; physical statuses/constraint tolerance/chain allowlist scope and finalGP14 pending
- protected PSO preserves ongoing secure messaging and PIV verified PIN; plaintext in an established channel rejects before dispatch and revokes all local authorization
- PIV signatures independently verified after valid/failed protected PSO and complete protected PSO; no real key or manufacturer identity used

## SecurityDomain_plaintext

- Yubico documented plaintext termination applied at transport entry across SCP03/11a/11b/11c; SELECT remains an explicit session boundary
- PSO/INIT UPDATE/MUT/INTERNAL, ISO chained CLA90, GET DATA/RESPONSE and unsupported CLA reject before command dispatch
- no transport rejection consumes key retries, changes session owner token, or reencrypts persistent state
- closed wrapper and revoked cached OCE verified separately; peer secure channel and own CA/SD material preserved
- PIV verified PIN/admin and OATH access authorization revoked; explicit new PIN/access validation restores operations
- normal unmodified SDK establishment, encrypted PSO and protected handoff remain verified
- prior v21 ZIP independently fails first plaintext PSO rejection; new socket/direct IFD suites each verify 326 items
- vendor prose is the source model; physical exact status and possible handshake exceptions remain unmeasured
- prior v21 ZIP independently fails first plaintext PSO rejection; new socket/direct IFD suites each verify 394 items
- malformed plaintext SELECT clears OCE and PIV PIN/admin before validation; OCE probe precedes stale-wrapper probe to avoid masking retained authorization

## SecurityDomain_allowlist

- Yubico CLI each-certificate scope: every presented root/intermediate/leaf serial checked under one CA policy before prefix/final acceptance
- wildcard candidates retained across prefixes and final leaf; lists cannot be united across different anchors
- initial CA policy remains binding even if a later PSO changes P1/P2
- optional-root omission and direct-leaf chain require only serials actually presented, not a stored CA certificate serial
- listed serial never bypasses signature/role/CA/key usage validation; positive ASN.1 sign-padded serials compare as integers
- rejected prefix wipes prior complete OCE without changing ciphertext/key retries or independent protected channels
- peer failed subset commit preserves all-cert list/cache; successful subset commit revokes cached OCE while preserving transport
- emptyclearlist retains no restriction; restart retains policy/key/SKI/cert/CPLC and explicit repair restores SDK a/c interoperability
- 81 checks per socket/direct IFD; original final v22 ZIP fails new omitted-root check; no physical key accessed
- vendor prose model; physical serial scope/status and immediate-prefix timing remain unmeasured

## storage

- AES-256-GCM
- atomic writes
- mode0600
- process lock
- failure rollback
- restart persistence

## 부록 A: 전송 계층 기록 (프로그램화 단계 참고용)

### transports

- compiled IFD Handler 3.0 native reader ABI with private persistent CCID sessions
- compiled public IOUSBHost synthetic composite-controller source
- USB device/configuration/HID/CCID descriptors and control/endpoint routing
- FIDO/PIV/OATH/OTP SDK flows through compiled USB wire-test model
- USB class matching IDs for seven interface combinations; explicit software product labels
- keyboard boot/report protocol, LED, idle-repeat and paced button reports
- CCID T=1 parameter negotiation/reset with atomic validation and clock/rate/error replies
- control/bulk ABORT in either delivery order, session-scoped private cancellation RPC
- asynchronous native CCID worker with busy-slot replies and USB generation reset
- cancellable actual terminal presence; atomic commit/abort boundary and durable authentication retries
- measured FIDO+CCID configuration and FIDO HID report bytes
- measured endpoints, CCID 3072-byte messages, 4000 kHz and 307200 bps profile
- CCID command/response chaining with independent socket, IFD and native wire clients
- native CCID waiting-time extensions and private peer-EOF cancellation recovery
- read-only public USB registry/cached descriptor collector without device open
- FunctionFS all-endpoint Linux AIO native candidate validated in private no-NIC QEMU with seven USB profiles, OTP keyboard, stock libccid, long cutovers and PIV X.509 boundary; rare kernel panic elimination unproven
- FunctionFS asynchronous OUT negative completion EPIPE/ESHUTDOWN/ECONNRESET retry with IN fail-stop; private no-NIC QEMU fault injection and combined stock Linux card paths verified
- PIV generate/import/PUT DATA absent-Le guards with 12 before/after cases, 60 SDK socket and 60 SDK direct-IFD checks
- OATH binary credential name touch-label safe display with original credential bytes and HMAC preserved
- OpenPGP TERMINATE DF and ACTIVATE FILE explicit-Le guards with socket/direct-IFD SDK lifecycle verification
- Linux FunctionFS binds full-speed by default on a high-speed-capable dummy_hcd; 12 Mbps official product profile and 28/122/8 native checks
- FIDO interrupt IN socket reads now stop at the 256-report model queue boundary; owned no-NIC dummy_hcd echoes four 7609-byte PINGs after delayed host reads without bridge overflow.
- Linux FunctionFS bridge reconnects the private CTAPHID stream on USB bus reset; daemon connection generations discard old assembly, pending responses, and late worker replies. Owned no-NIC dummy_hcd before/after and full integrated regressions pass.
- macOS IOHIDUserDevice FIDO output accepts only a full 64-byte report with optional zero Report ID prefix; its 256-report inbox reports overflow rather than discarding an accepted fragment. The code builds and pure input tests pass; entitled OS registration remains unverified.

### Linux_native

- actual distro kernel UHID/hidraw discovery via stock python-fido2; 75 existing SDK items on native transport
- native OTP feature ioctls, own serial visibility policy and independently verified HMAC with shared CCID state
- real guest evdev Shift+A, b, 1, Enter events and matching release for every key/modifier; clean HID/evdev teardown
- actual private pcscd, stock pyscard/Yubico SDK, T=1, PIV crypto, OATH, OpenPGP and SCP03 encrypted long APDU/MAC/restart
- native Linux IFD Handler 3.0 platform headers and ctypes ABI; 32 independent direct ABI checks
- GCC14 Linux ARM64 build and same120 C++ cases/11620 assertions; no physical key or host devices in guest
- actual single OTP/FIDO/CCID USB composite on private dummy_hcd controller; 75 CTAP items and 3 lifecycle cycles
- stock ykman HID vendor discovery and grouping into one own serial; actual USB keyboard and key releases
- stock libccid/pcscd and USB-classified independent ATR; PIV/OATH/OpenPGP/SCP03/long APDU/restart via actual USB CCID
- same shared composite backend compiled on macOS and Linux; entire main regression verified
- automatic management reboot and all seven USB interface combinations, plus unchanged-profile reboot, through stock FIDO/OTP/CCID SDK in same live processes; persistent credentials retained and old PIN token rejected
- optional virtual UDC allocation policy preserves requested endpoint addresses across all seven profiles and unchanged-profile reboot; actual host configuration125 and FIDO report34 bytes equal saved reference; exact source/patch/module provenance recorded
- stock Firefox native USB WebAuthn: ES256/Ed25519/ES384 own registrations and independent RP signature/challenge/origin/counter verification; native core counters, browser restart and same live browser after USB management reboot
- stock Firefox resident/PIN/UV actual native USB: two accounts per ES256/Ed25519/ES384, six registrations, eighteen independently verified discoverable assertions across initial/browser-restart/live-USB-reboot phases; actual wrong/correct PIN UI, notification button/menu and security delay respected; thirty RP tampering rejections
- stock Firefox native USB PRF/credProps: six resident keys, eighteen dual outputs over browser/USB restart plus six single and six evalByCredential outputs; per-credential inputs override different fallback; unmodified SDK UV-bound ECDH/AES/HMAC and credential signatures independently match all thirty browser results
- stock Firefox actual attestation consent Allow/Block for all three algorithms: own packed self signatures and six tamper rejections, denied empty none statements retaining own model AAGUID, all six granted/denied resident credentials independently sign before/after browser restart; direct-attestation bypass preference remains false and manufacturer trust is not reproduced
- stock Chromium actual USB largeBlob: ES256/Ed25519 two browser writes792 bytes, independent protocol2 UV SDK signatures/decrypt/isolation/replacement1056 bytes, four browser reads over same-profile restart/live USB reboot; no PIN errors; actual ES384 curve2/48-byte client parser rejection and independently verified rejected credential signature remain explicit
- 91 native USB state checks: six HALT/EPIPE/CLEAR_HALT, three idle plus one pending USBDEVFS_RESET, configuration0/1, seven retained credential PIN/UV signatures and OTP HMAC; real CCID terminal wait concurrent FIDO GetInfo/PING, cancellation without HOTP mutation and fresh approval SDK recovery
- 50 actual kernel device-PM checks: three idle and one queued CCID IN/terminal-presence cycle, stock HID drivers, same three services, retained PIN/UV credential and OTP key, actual ESHUTDOWN recovery, old handle ENODEV and fresh native SDK sequence/approval/independent HOTP single commit
- 52 actual kernel USB runtime PM checks: reference-equal FIDO+CCID profile6, three manual/FIDO SDK/CCID SDK suspend-resume cycles, same address/services/bindings/exact bytes while suspended, four independent UV signatures and one independent HOTP commit. Stock profile7 zero-usage refusal traced to missing remote wakeup with stock drivers retained; descriptors were not changed to force suspension.
- 113 real same-generation native CCID data/ZLP interruption checks:12 targeted kernel SIGUSR1/write EINTR, same buffer/thread/processes/USB address,3 independently verified HOTP results/single commits,64byte PIV object plus only retried ZLP/no duplicate data, following native SDK sequences and5 independent FIDO PIN/UV signatures/OTP HMAC; exact original32 failures and same-helper fixed33 pairs retained
- 205 actual profile6 runtime PM and CCID resume checks over six real cycles: original blocked data/ZLP and independently traced kernel-buffered replies preserved; each occupied slot becomes inactive, insertion5003 once, no unpowered APDU, new PowerOn/ATR required; PIV PIN/admin revoked, fresh PIN original key signature verified; real terminal touch canceled without commit, new actual approval yields one independent HOTP; seven independent FIDO UVp2 signatures.
- 86 actual profile6->FIDO-only->profile6 pending Management checks: original kernel-buffered HOTP, blocked19byte data, blocked ZLP and actual terminal touch; eight cutovers/nine reenumerations, same original processes/card credentials, old CCID ENODEV and worker absent in new generation, fresh PowerOn/SDK recovery and nine original-key PIN/UVp2 signatures. Pending config waits for native controlABORT; real CHANNEL_BUSY and PING observed on peer CID via byte-preserving host router. Existing37 behavior retained; physical timing and separate stock SDK process concurrency unverified.
- 328 actual large/partial CCID cutover checks:2047/2048/2049/3071/3072/3073 total-response boundaries,6 wholly unread and6 partly read original buffers plus2 large unread ZLPs with positive native-zero controls and actual completed-write traces;7 native CCID command-chain and2 response-chain cases,28 cutovers/29 reenumerations/signatures, original services/objects/HOTP retained, fresh PowerOn/SDK recovery with no old tail/continuation. Stock PIV/OATH SDK uses owned native CCID driver; stock libccid large transport unverified. Current40 large FunctionFS IN uses native AIO after the actual39 partial-signal replay defect; original synchronous path and exact prior observer/SDK trials preserved.
- Current40 fixes actual39 full-buffer replay after an original64-byte large CCID prefix. One native AIO submission survives completion-wait EINTR;108 current-source native checks cover six reply boundaries, exact remaining data/same generation, native chaining, seven original FIDO signatures and HOTP6. Original14 failure/same-helper candidate108 and subsequent113/328/108 proofs preserved. Whole current Endpoint differs33 while the old synchronous path is preserved.
- Current42 verifies original large prefix64 across real USB runtime PM:534 checks,18 size/mode combinations, exact original AIO first-packet tail/same generation, revoked PIN/admin, original PIV/FIDO keys with19 signatures each and HOTP18. A3073 reply preserves its first3072 packet; subsequent chain is denied inactive after card reset. Linux transport source equals40, only CMake/IFD version metadata changed. Original40 setup and161/534 scopes preserved.
- Current42 standard libccid/PCSC USB:122 checks,8 accepted boundary replies through3079,4 oversized PIV PUTs6700 preserving previous object/keys, original13FIDO/12PIV signatures/HOTP12, actual raw input/output CCID chains/ZLP/single AIO. Unmodified stock driver/SDK; Info.plist log level only. Same Linux/card/USB source as41; two source version metadata changes.
- final v0.52 combined no-NIC dummy_hcd guest passes software touch to evdev, OTP, stock libccid, X.509, CTAP enterprise/empty allowList, and seven USB profile checks; USB reset discards queued touch reports; separate final-card UHID/PCSC guest passes 25 checks
- v0.53 combined no-NIC dummy_hcd guest passes reset boundary, OTP, stock libccid, X.509, CTAP and seven USB profile checks with the new Linux daemon, card and FunctionFS bridge
- FunctionFS bridge backpressures CCID bulk OUT/IN when the guest stops reading replies, preserving ordered responses and process liveness in isolated no-NIC dummy_hcd

### verification_fixtures

- Safe wire response commit precondition corrected: original35-check failure had no recorded packet; identical-command logging helper captured active and CMD_ABORTED. Original async OUT does not prove card reply committed. Actual prefix1 before suspend then original tail9 survives; unchanged source/binaries24x68 and fresh full5841 passed. This case does not prove wholly unread10; native unread scopes remain separate.

## 부록 B: 호환성 기준 128개 (legacy 판정)

| 기준 | legacy 상태 |
| --- | --- |
| `public_get_info` | verified_with_identity_and_fresh_state_differences |
| `fido_crypto_pin_extensions_management` | implemented_sdk_cases_verified |
| `smartcard_crypto_applications` | implemented_sdk_cases_verified |
| `native_ifd_abi` | verified_direct_call_only |
| `composite_usb_protocol_model` | verified_wire_model_and_actual_Linux_guest_USB_sdk; macOS_entitled_registration_pending |
| `ccid_parameters_errors_and_cancellation` | verified_software_model_and_native_wire_path |
| `measured_fido_ccid_usb_descriptors` | exact_configuration_and_hid_report_bytes_in_wire_model |
| `ccid_extended_chaining_wtx_and_eof` | verified_transport_fixtures_and_native_wire_path; reference_timing_unverified |
| `piv_buffer_and_storage_capacity` | published_ceiling_model_verified; exact_hardware_boundaries_unverified |
| `piv_initial_objects_retries_and_f9_lifecycle` | published_profile_sdk_verified_over_socket_and_direct_ifd; hardware_differential_pending |
| `oath_syntax_capacity_crypto_and_reset` | published_protocol_and_rfc_sdk_verified_over_socket_and_direct_ifd; reference_boundaries_pending |
| `openpgp_public_metadata` | captured_public_bytes_and_schema_match; identity_and_key_contents_independent |
| `openpgp_object_limits_access_and_legacy_data` | specification_and_observed_ceiling_model_sdk_verified_over_socket_and_direct_ifd; physical_write_and_challenge_boundaries_pending |
| `openpgp_full_advertised_algorithm_generation_import_and_counters` | public_FA_and_7A_schema_measured; all_43_variants_sdk_crypto_verified_over_socket_and_direct_ifd; physical_write_counter_semantics_pending |
| `openpgp_issuer_reset_metadata_and_certificate_format` | published_profile_sdk_crypto_verified_over_socket_and_direct_ifd; template_firmware_wrapper_measured; physical_leaf_and_reset_boundaries_pending |
| `security_domain_role_policy_capacity_retry_and_reset` | GP_role_and_documented_SCP03_profile_plus_explicit_software_models_sdk_verified_over_socket_and_direct_ifd; critical_subject_ID_and_physical_limits_pending; measured_option_advertises_no_BF20 |
| `security_domain_public_metadata_and_reset` | public_SELECT_and_recognition_exact; key_and_CPLC_schema_measured; own_identity_lifecycle_and_no_BF20_model_SDK_verified_socket_direct_IFD; physical_reset_rejection_pending |
| `security_domain_full_scp03_version_range` | all_254_published_custom_versions_SDK_and_independent_crypto_verified_socket_direct_IFD; SCP11_seven_bit_range_preserved; physical_boundary_and_INIT_pending |
| `security_domain_oce_cache_and_allowlist_lifecycle` | GP_public_review_model_SDK_receipt_KDF_secure_messaging_verified_socket_direct_IFD; hardware_status_final_GP14_chain_serial_scope_counter_pending |
| `security_domain_scp11c_static_ecdh_replay_and_counter` | GP_public_review_model_independent_crypto_SDK_authenticated_replay_and_atomic_failure_verified_socket_direct_IFD; hardware_final_GP14_transaction_logical_channel_policy_pending |
| `security_domain_shared_policy_reset_and_rollback` | GP_public_review_model_cross_client_SDK_cache_channel_reset_failure_and_migration_verified_socket_separate_direct_IFD_handles; transient_OCE_logical_channel_transaction_physical_final_GP14_pending |
| `security_domain_protected_handoff_and_sole_c_context` | GP_public_review_12_outer_target_combinations_SDK_new_context_and_sole_c_latest_commit_rollback_SELECT_disconnect_verified_socket_separate_direct_IFD; hardware_logical_channel_policy_failed_MUT_finalGP14_transactions_pending |
| `security_domain_incremental_pso_validation_and_lifecycle` | GP_public_review_prefix_signature_role_CA_path_reference_scope_SDK_a_c_and_PIV_PIN_crypto_lifecycle_verified_socket_direct_IFD; hardware_status_tolerance_chain_serial_finalGP14_pending |
| `security_domain_vendor_plaintext_boundary` | vendor_rule_model_plain_PSO_INIT_MUT_INTERNAL_chaining_reject_before_dispatch_session_OCE_PIV_admin_OATH_revocation_recovery_verified_socket_direct_IFD; physical_status_handshake_exceptions_pending |
| `security_domain_each_certificate_allowlist` | vendor_each_presented_serial_model_prefix_final_one_anchor_wildcard_optionalroot_directleaf_padding_cache_peer_rollback_restart_sdk_verified_socket_direct_IFD; physical_scope_status_timing_pending |
| `usb_management_reboot_reenumeration` | Linux_native_stock_SDK_all_seven_interface_combinations_and_same_profile_reboot_verified; commit_failure_lock_rejection_and_volatile_auth_crypto_verified; macOS_runtime_and_firmware_timing_pending |
| `native_macos_composite_enumeration` | pending_entitlement_and_actual_os_validation |
| `stock_sdk_os_discovery_and_pcsc` | Linux_guest_composite_USB_stock_OTP_FIDO_libccid_pcscd_and_grouping_verified; macOS_pending |
| `modified_engine_native_browser_flow` | Linux_Firefox_native_USB_all_three_algorithms_basic_and_resident_PIN_UV_multi_account_RP_crypto_browser_restart_live_USB_reboot_verified; remaining_extension_attestation_edge_cases_other_browsers_and_macOS_pending |
| `modified_engine_native_browser_prf` | Linux_Firefox_native_USB_all_three_algorithms_six_resident_PRF_keys_dual_single_evalByCredential_30outputs_independent_UV_SDK_reference_and_restarts_verified; remaining_extension_edge_cases_largeBlob_other_browsers_macOS_pending |
| `modified_engine_native_browser_attestation_consent` | Linux_Firefox_native_USB_all_three_algorithms_real_Allow_Block_UI_own_packed_signature_and_tamper_rejections_none_statement_with_model_AAGUID_preserved_six_resident_keys_and_browser_restart_verified; manufacturer_trust_false_other_browsers_macOS_pending |
| `modified_engine_native_browser_largeblob` | Linux_stock_Chromium_ES256_Ed25519_real_PIN_native_USB_largeBlob_browser_write_SDK_UV_signature_decrypt_key_isolation_replacement_four_reads_browser_restart_live_USB_reboot_verified; actual_ES384_client_parser_rejection_and_same_credential_SDK_signature_recorded; other_algorithms_extensions_platforms_pending |
| `native_keyboard_input` | Linux_guest_evdev_keys_and_releases_verified; macOS_pending |
| `all_firmware_edge_cases_and_timing` | incomplete |
| `nonresident_storage_semantics` | software_stateless_sdk_verified; hardware_backend_and_legacy_rows_remain_stored |
| `nonresident_reference_counter_and_credential_blob` | published_profile_and_software_model_only; differential_validation_pending |
| `full_standards_and_differential_conformance` | incomplete |
| `manufacturer_trust_and_hardware_guarantees` | inherently_not_reproduced |
| `native_usb_halt_reset_configuration_and_pending_ccid_fido_concurrency` | isolated_Linux_native_six_HALT_EPIPE_clear_three_idle_one_pending_reset_config0_1_retained_UV_keys_real_CCID_prompt_GetInfo_PING_no_HOTP_mutation_fresh_approval_verified; production_UDC_power_management_firmware_timing_token_semantics_and_macOS_pending |
| `native_kernel_device_pm_and_queued_ccid_udc_reenumeration` | isolated_Linux_actual_kernel_devices_PM_three_idle_one_pending_queued_bulk_IN_ESHUTDOWN_same_processes_keys_and_sdk_HOTP_recovery_verified; runtime_PM_full_platform_sleep_production_UDCs_physical_firmware_and_macOS_pending |
| `native_fido_ccid_reference_profile_runtime_autosuspend_and_sdk_autoresume` | isolated_Linux_profile6_actual_auto_suspend_manual_and_native_FIDO_CCID_SDK_resume_same_address_services_keys_rpm_returns_zero_verified; profile7_stock_remote_wakeup_refusal_confirmed; other_profiles_remote_wakeup_pending_IO_physical_UDCs_full_sleep_and_macOS_pending |
| `native_configured_ccid_data_and_bulk_zlp_eintr_recovery` | isolated_Linux_real_targeted_SIGUSR1_write_EINTR_same_generation_buffer_thread_three_HOTP_single_commits_and64byte_PIV_plus_only_ZLP_retries_nativeSDK_FIDO_isolation_verified; production_UDC_physical_timing_and_other_backpressure_error_cases_pending |
| `native_profile6_queued_ccid_data_and_zero_length_terminator_runtime_pm` | isolated_Linux_real_runtime_suspend_resume_same_generation_worker_buffer_data_and_ZLP_nativeSDK_FIDO_HOTP_verified; other_profiles_concurrent_full_message_errors_remote_wakeup_physical_and_macOS_pending |
| `ccid_post_resume_deactivation_slot_change_and_explicit_reactivation` | actual_Linux_profile6_six_runtime_cycles_inactive_slot_insertion_once_explicit_poweron_committed_replies_preserved_PIV_revocation_terminal_cancel_fresh_approval_verified; macOS_route_compiled_only_physical_UDCs_other_profiles_pending |
| `compiled_common_usb_resume_backend` | compiled_macOS_controller_route_and_common_wire_13_resume_checks_verified; entitled_macOS_native_and_GadgetFS_runtime_pending |
| `native_pending_ccid_configuration_generation_cutover` | actual_Linux_86_checks_four_original_unread_or_terminal_pending_modes_eight_native_FIDO_Management_cutovers_nine_reenumerations_and_original_UVp2_signatures_verified; peer_CHANNEL_BUSY_PING_uses_byte_preserving_CID_router; other_profiles_full_messages_production_UDCs_physical_and_macOS_pending |
| `native_large_partial_ccid_configuration_cutover` | actual_Linux_328_checks_14_cases_six_large_response_boundaries_partial64_and_ZLP_28_cutovers_29_generations_signatures_native_command_response_chains_verified; owned_CCID_driver_stock_libccid_large_transport_broader_runtime_PM_and_physical_macOS_pending |
| `native_large_partial_same_generation_signal_recovery` | actual_Linux_108_checks_six_prefix64_cases_single_original_AIO_submission_same_generation_exact_tail_seven_signatures_verified; profile6_prefix64_large_runtime_PM_verified534_other_errors_stock_libccid_GadgetFS_physical_macOS_pending |
| `native_large_partial_ccid_actual_runtime_pm_and_original_keys` | actual_Linux_534_checks_18_size_mode_cycles_original_prefix64_first_packet_single_AIO_exact_tail_same_generation_PIN_admin_revoked_19_PIV_FIDO_signatures_each_HOTP18_verified;3073_following_chain_inactive_after_card_reset;broader_errors_stock_libccid_physical_macOS_pending |
| `native_stock_libccid_large_ccid_original_crypto_state` | actual_Linux_stock_libccid_PCSc122_8_positive_4_oversized_rejections_raw_chains_ZLP_original_AIO_original13FIDO12PIV_HOTP12_verified;stock_PM_cutover_errors_exact_physical_PIV_boundary_pending |
| `safe_wire_resume_response_committed_prefix_precondition` | original35_failure_and_actual_active_CMD_ABORTED_packets_preserved;prefix1_tail9_24x68_and_full5841_verified;whole_unread10_not_claimed_native_scopes_separate |
| `actual_chromium_pin_ui_input_precondition` | original_full23_failure_unrecorded_count_and_logging_only_count22_failure_original29_pass_preserved;private_Xvfb_repeat_guard9x15_actual_PIN_inputs_restored_controls_current_native29_verified;original_failure_repeat_root_cause_unclassified |
| `piv_published_3052_certificate_limit` | valid_X509_SDK_and_stock_Linux_libccid_verified; physical_status_unmeasured |
| `otp_lt64_empty_hmac` | SDK_APDU_and_OTP_HID_independent_HMAC_verified; physical_firmware_unmeasured |
| `otp_two_slot_touch_windows` | published_windows_software_verified; exact_physical_debounce_unmeasured |
| `openpgp_rfc4880_low_count_s2k` | independent_digest_SDK_APDU_socket_and_direct_IFD_verified; physical_acceptance_unmeasured |
| `openpgp_verify_change_apdu_headers` | OpenPGP_3_4_1_header_guard_independent_SDK_APDU_socket_and_direct_IFD_verified; physical_status_unmeasured |
| `otp_short_apdu_and_hid_abort` | software_sdk_and_private_socket_verified_physical_unmeasured |
| `openpgp_explicit_le_and_internal_auth_headers` | private_socket_and_direct_ifd_verified_physical_unmeasured |
| `functionfs_all_endpoint_aio` | private_linux_native_smoke_and_repeats_verified_rare_failure_not_proven_eliminated |
| `oath_hotp_terminal_counter` | software_model_and_private_socket_verified; physical_status_pending |
| `otp_power_session_and_touch_status` | software_ticket_AES_CRC_commit_and_reboot_SDK_verified; physical_USB_power_mapping_pending |
| `openpgp_mutating_command_le` | private_socket_and_direct_IFD_verified; physical_status_pending |
| `functionfs_out_negative_completion_recovery` | three_synthetic_out_errors_and_combined_no_nic_guest_verified; real_kernel_incidence_and_production_UDC_pending |
| `piv_mutating_command_absent_le` | isolated_software_and_native_guest_verified; physical_firmware_and_entitled_macos_pending |
| `oath_binary_name_touch_calculation` | isolated_software_and_native_guest_verified; physical_firmware_and_entitled_macos_pending |
| `openpgp_lifecycle_explicit_le` | isolated_software_and_native_guest_verified; physical_firmware_and_entitled_macos_pending |
| `linux_queued_reset_stress_v47` | isolated_software_and_native_guest_verified; physical_firmware_and_entitled_macos_pending |
| `ctap_min_pin_empty_rp_allowlist` | standard_aligned_software_tested |
| `piv_pin_apdu_headers_and_hsmauth_exhaustion` | sdk_socket_ifd_tested_physical_unmeasured |
| `linux_default_controller_remap` | isolated_dummy_hcd_verified_high_speed_pending |
| `oath_put_secret_minimum` | sdk_socket_ifd_tested_physical_unmeasured |
| `hsmauth_reset_apdu_shape` | sdk_socket_ifd_tested_physical_unmeasured |
| `high_speed_capable_udc_full_speed_policy` | isolated_dummy_hcd_28_122_8_verified_production_udc_pending |
| `ctap_enterprise_attestation_unsigned_integer` | spec_aligned_private_socket_and_isolated_guest_USB_verified; physical_status_unmeasured |
| `openpgp_get_response_cla_pending_buffer` | spec_aligned_socket_and_direct_IFD_verified; physical_status_unmeasured |
| `otp_single_slot1_fast_trigger` | modeled_completed_hold_output_verified; physical_contact_time_unmodeled |
| `linux_seven_profiles_and_integrated_usb` | no_NIC_dummy_hcd_verified; production_UDC_and_external_host_pending |
| `openpgp_get_response_interrupts_command_chain` | private_socket_and_direct_IFD_verified; exact_physical_status_unmeasured |
| `otp_explicit_touch_events_and_counter_exclusivity` | private_software_socket_verified; native_event_producer_and_physical_timing_pending |
| `v51_integrated_linux_guest_usb` | no_NIC_dummy_hcd_28_122_8_6_verified; production_UDC_external_host_pending |
| `ctap_present_empty_allowlist_no_credentials` | private_unmodified_sdk_and_cpp_verified; physical_firmware_unmeasured |
| `openpgp_getdata_command_chain_rejected` | private_socket_and_direct_IFD_verified; physical_status_unmeasured |
| `otp_shared_touch_ownership` | private_multi_client_verified; physical_simultaneous_timing_unmeasured |
| `linux_functionfs_software_touch_keyboard` | no_NIC_dummy_hcd_evdev_verified; physical_sensor_and_external_host_pending |
| `linux_functionfs_same_generation_usb_reset_clears_touch_queue` | no_NIC_dummy_hcd_before_after_verified; production_UDC_pending |
| `ctap_hmac_secret_up_false_rejected` | private_unmodified_sdk_and_cpp_verified; physical_firmware_unmeasured |
| `openpgp_get_next_data_command_data_rejected` | private_socket_and_direct_IFD_verified; physical_status_unmeasured |
| `yubihsm_auth_touch_policy_syntax` | private_unmodified_sdk_and_direct_APDU_verified; physical_status_unmeasured |
| `linux_functionfs_otp_in_backpressure` | no_NIC_dummy_hcd_before_after_and_combined_guest_verified; production_UDC_pending |
| `ctap_unknown_canonical_float_ignored` | private_CTAPHID_and_cpp_verified; physical_firmware_unmeasured |
| `openpgp_exhausted_next_data_preserves_selection` | private_socket_and_direct_IFD_verified; physical_firmware_unmeasured |
| `yubihsm_auth_add_input_syntax_and_duplicates` | private_socket_unmodified_sdk_verified; physical_firmware_unmeasured |
| `linux_functionfs_ccid_bulk_backpressure` | no_NIC_dummy_hcd_before_after_and_combined_guest_verified; production_UDC_pending |
| `ctap_credential_management_missing_no_credentials` | private_CTAPHID_unmodified_SDK_and_cpp_verified; physical_firmware_unmeasured |
| `openpgp_attestation_bad_le_no_certificate_overwrite` | private_socket_and_direct_IFD_verified; physical_firmware_unmeasured |
| `ctaphid_max_7609_byte_ping` | owned_no_NIC_dummy_hcd_USB_and_cpp_verified; external_host_pending |
| `piv_printed_raw_put_data` | unresolved_official_source_conflict; candidate_not_promoted; physical_firmware_unmeasured |
| `ctap_unknown_options_arbitrary_values` | private_CTAPHID_pyfido2_Mac_Linux_verified; physical_firmware_unmeasured |
| `piv_f9_delete_key_5_7` | private_socket_and_IFD_unmodified_YubiKit_verified; physical_firmware_unmeasured |
| `fido_in_delayed_host_reads` | owned_no_NIC_dummy_hcd_USB_verified; production_UDC_unverified |
| `ctap_pin_soft_block_and_power_cycle` | private_CTAPHID_pyfido2_Mac_Linux_verified; physical_firmware_unmeasured |
| `ctap_forced_change_pin_retry_order` | private_CTAPHID_pyfido2_Mac_Linux_verified; physical_firmware_unmeasured |
| `ctap_malformed_pin_proof_retry_accounting` | private_CTAPHID_pyfido2_Mac_Linux_verified; physical_firmware_unmeasured |
| `piv_reset_malformed_command_guard` | private_socket_and_IFD_unmodified_YubiKit_Mac_Linux_verified; physical_firmware_unmeasured |
| `fido_usb_bus_reset_old_report_isolation` | owned_no_NIC_dummy_hcd_USB_verified; production_UDC_unverified |
| `ctaphid_allocated_init_late_reply_flush` | private_socket_Mac_Linux_and_noNIC_dummy_hcd_FIDO_HID_AB_verified; physical_firmware_unmeasured |
| `piv_set_retries_and_management_key_header_guard` | private_socket_direct_IFD_YubiKit_SCP03_Mac_Linux_verified; physical_firmware_unmeasured |
| `otp_swap_requires_two_configured_slots` | private_CCID_YubiKit_Mac_Linux_verified; physical_firmware_status_unmeasured |
| `macos_fido_hid_report_input_preservation` | compiled_and_pure_unit_verified; entitled_OS_registration_unverified |
| `ctaphid_wink_zero_length_only` | spec_syntax_Mac_Linux_CPP_private_socket_verified; physical_firmware_status_unmeasured |
| `otp_update_dormant_or_allow_update` | unmodified_YubiKit_Mac_Linux_private_CCID_verified; physical_firmware_status_unmeasured |
| `openpgp_operational_activate_noop` | unmodified_YubiKit_Mac_Linux_socket_direct_IFD_verified; physical_firmware_unmeasured |
| `ctaphid_orphan_cont_unknown_channel` | Mac_Linux_CPP_private_socket_no_NIC_guest_verified; physical_firmware_unmeasured |
| `otp_empty_slot_delete` | unmodified_YubiKit_Mac_Linux_private_CCID_verified; physical_firmware_status_unmeasured |
| `openpgp_select_data_explicit_le` | unmodified_YubiKit_Mac_Linux_socket_direct_IFD_verified; physical_firmware_status_unmeasured |
| `piv_f6_move_delete_apdu_shape` | unmodified_YubiKit_Mac_Linux_socket_direct_IFD_verified; physical_firmware_status_unmeasured |
| `ctaphid_cross_channel_arbitration` | Mac_Linux_CPP_private_socket_no_NIC_guest_verified; physical_firmware_timing_unmeasured |
| `oath_send_remaining_cla` | unmodified_YubiKit_Mac_Linux_socket_direct_IFD_verified; physical_firmware_status_unmeasured |
| `openpgp_set_retries_f2_header` | unmodified_YubiKit_Mac_Linux_socket_direct_IFD_verified; physical_firmware_status_unmeasured |
| `ctaphid_cancel_during_u2f` | Mac_Linux_private_socket_and_no_NIC_USB_verified; physical_firmware_unmeasured |
| `oath_cross_client_authorization` | Mac_Linux_socket_direct_IFD_unmodified_YubiKit_verified; physical_concurrency_unmeasured |
| `piv_generate_p1` | Mac_Linux_socket_direct_IFD_unmodified_YubiKit_verified; physical_status_unmeasured |
| `ctap_largeblob_sequence` | Mac_Linux_private_socket_and_CPP_verified; physical_error_precedence_unmeasured |
| `piv_general_authenticate_le` | Mac_Linux_socket_direct_IFD_unmodified_YubiKit_verified; physical_status_unmeasured |
| `fido_same_cid_transaction` | Mac_Linux_software_and_owned_USB_as_applicable_verified; physical_reference_unmeasured |
| `hsmauth_symmetric_challenge_touch` | Mac_Linux_software_and_owned_USB_as_applicable_verified; physical_reference_unmeasured |
| `scp03_initialize_update_le` | Mac_Linux_software_and_owned_USB_as_applicable_verified; physical_reference_unmeasured |

## 부록 C: 남은 과제와 본질적 차이 (legacy 기준)

- Fresh software keys; no extraction or cloning of real YubiKey private keys.
- Software self attestation/local CA; no factory manufacturer identity or hardware attestation trust.
- No security-chip or physical-touch guarantee; same-user file access can expose software keys.
- Public default development PINs/management key and public SCP03 development keys.
