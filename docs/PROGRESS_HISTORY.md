# Progress and evidence history

This document is a compact map, not a substitute for the full machine-readable history. `../implementation-status.json` records every implemented feature, historical release field, check inventory and remaining-work statement. `../compatibility-matrix.json` has one entry per claim boundary. `../manifest.json` hashes every delivered file. `../evidence/` preserves isolated before/after tests, raw logs and version integrations. Historical work directories outside the release contain additional build intermediates; the published archive contains the reviewable evidence.

## Foundation through v0.43

The project began from the MIT `madeye/swpasskey` FIDO HID daemon and expanded into a software security-key stack. It added broad CTAP2.1/U2F credential, PIN/UV, extension, resident and nonresident flows; encrypted software state and lifecycle rules; OTP and keyboard/feature HID; PIV, OpenPGP, OATH, YubiHSM Auth, SCP03/SCP11, management, direct IFD/CCID; Linux FunctionFS USB composition and re-enumeration; and independent browser/SDK checks in an owned no-network guest. Early versions also established captured read-only public 5.7.4 profile bytes and full-speed descriptor comparison. The precise historical checkpoints, checks and limits are in the version fields of `../implementation-status.json` and the evidence index. A saved public metadata comparison is narrower than a physical behavioral differential.

## Versioned protocol and transport work

| Version | Principal reviewed change | Evidence |
| --- | --- | --- |
| 0.44 | FunctionFS AIO completion handling and OTP/OpenPGP guards. | `../evidence/v44-native/` |
| 0.45 | OATH exhaustion, OTP power-session/reboot integrity, and OpenPGP mutating-command boundaries. | `../evidence/v45-card-fidelity/` |
| 0.46 | FunctionFS negative OUT-completion recovery using injected faults. | `../evidence/v46-functionfs-out-error/` |
| 0.47 | PIV/OpenPGP APDU shape guards and binary OATH names. | `../evidence/v47-card-boundaries/` |
| 0.48 | CTAP minimum-PIN RP list, PIV PIN headers, YubiHSM Auth capacity, and default dummy_hcd endpoint behavior. | `../evidence/v48-protocol-and-transport/` |
| 0.49 | OATH PUT/YubiHSM Auth RESET guards and FunctionFS full-speed policy. | `../evidence/v49-card-guards/`, `../evidence/v49-fullspeed-controller/` |
| 0.50 | CTAP enterpriseAttestation type, OpenPGP GET RESPONSE CLA, OTP FAST_TRIG model. | `../evidence/v50-integration/` and v50 candidate directories |
| 0.51 | OpenPGP command chaining and explicit OTP touch-down/up events. | `../evidence/v51-integration/` and v51 candidates |
| 0.52 | CTAP empty allowList, OpenPGP GET DATA chaining, shared touch, USB keyboard delivery/reset cleanup. | `../evidence/v52-integration/` and v52 candidates |
| 0.53 | CTAP hmac-secret with up=false, OpenPGP GET NEXT DATA syntax, YubiHSM Auth touch-policy input, OTP backpressure. | `../evidence/v53-integration/` and v53 candidates |
| 0.54 | CBOR unknown float fields, OpenPGP GET NEXT DATA exhaustion, YubiHSM Auth ADD input and CCID backpressure. | `../evidence/v54-integration/` and v54 candidates |
| 0.55 | CTAP missing-credential status, 7609-byte CTAPHID PING, OpenPGP attestation Le. PIV Printed-write candidate was left unpromoted because documentation conflicted. | `../evidence/v55-integration/` and v55 candidates |
| 0.56 | CTAP unknown options, PIV F9 deletion and USB FIDO IN backpressure. | `../evidence/v56-integration/` and v56 candidates |
| 0.57 | PIN soft-block/forced-change/malformed-proof ordering, PIV RESET header, USB reset report replay. | `../evidence/v57-integration/` and v57 candidates |
| 0.58 | CTAPHID INIT resynchronization, PIV mutation guards, OTP swap, macOS FIDO HID input preservation. | `../evidence/v58-integration/` and v58 candidates |
| 0.59 | CTAPHID WINK length, OTP dormant UPDATE, OpenPGP ACTIVATE FILE. | `../evidence/v59-integration/` and v59 candidates |
| 0.60 | OTP empty-delete, OpenPGP SELECT DATA Le, PIV MOVE/DELETE shape, CTAPHID unknown/orphan frames. | `../evidence/v60-integration/` and v60 candidates |
| 0.61 | CTAPHID cross-channel arbitration, OATH SEND REMAINING CLA, OpenPGP SET RETRIES header. | `../evidence/v61-integration/` and v61 candidates |
| 0.62 | U2F CANCEL, OATH cross-client authorization, PIV GENERATE P1, CTAP large-blob sequence. | `../evidence/v62-integration/` and v62 candidates |
| 0.63 | PIV GENERAL AUTHENTICATE explicit-Le guard preserving PIN_ALWAYS authorization. | `../evidence/v63-integration/`, `../evidence/v63-piv-auth-le/` |
| 0.64 | Same-CID CTAPHID transaction atomicity; symmetric YubiHSM Auth challenge/touch separation; SCP03 INITIALIZE UPDATE Le/retry guard. | `../evidence/v64-integration/` and three v64 candidate directories |

Each row describes the software model and its stated tests. It does **not** assert bit-for-bit or timing parity with a physical YubiKey. A version's integration JSON and raw logs give the actual result; older results must not be silently counted as reruns of the latest source.

## Verification history and practical interpretation

The independent Python tests use unmodified `python-fido2`, YubiKit and card SDK calls against private software transports. Mac/Linux compiled C++ suites exercise the native daemon and device logic. The Linux guest uses its own `dummy_hcd` USB controller and no network interface; native HID, OTP keyboard/feature, CCID/pcscd/libccid and browser paths have been exercised in earlier versioned suites. These tests are meaningful interoperability evidence, but each run has a bounded scope and software-generated identities. See `../tools/linux-native/README.md` for the wider guest/browser history and `REPRODUCE_VALIDATION.md` for the current release gates.

The present full-compatibility goal remains open because physical command behavior, timing, production USB hosts/controllers, Apple-entitled macOS virtual-device registration and manufacturer security properties are unverified or unavailable. `../implementation-status.json` has the exhaustive current gaps.
