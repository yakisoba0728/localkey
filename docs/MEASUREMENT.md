# Comparison with the reference key

localkey is its own software security key. A physical security key provides its
comparison **reference** (`docs/DESIGN.md` §2 and §12
decision 8, `docs/CONTRACTS.md` "Reference, not replica"). Where a public specification
defines a behaviour, the engine follows the specification and records the reference's
behaviour as a known difference (unless a widely used host stack depends on the reference);
where the specification leaves it open, the engine follows the reference; Yubico's own
protocols follow Yubico's documentation and yubikit, with the reference as their best
evidence; the reference's defects are never copied; and the default identity is the
engine's own.

On 2026-10-11, with the user's explicit permission (`docs/DESIGN.md` §13), one inserted
reference key was probed command by command with strictly read-only
requests, and the same requests were sent to the engine (`localkeyd --profile
yubikey`) with the key's observable state mirrored. This file records what
was measured, how, what differs, and what was decided about each difference. It contains no
serial number, key, fingerprint, name or other identifier of the key; the measurement files
it refers to are the redacted ones (`tools/measure/normalize.py`).

Model names and firmware text are omitted; version strings use `<major>.<minor>.<patch>`.
Every status word, length and timing below is quoted from those files. "Physical" is the
key, "engine" is `localkeyd` at commit a7c9a06 (branch `engine`) before any change this
measurement led to. The measured tables are kept as they were recorded. The last sections
describe what followed: "Engine changes" (every behavioural difference was adopted on
2026-10-11; the review of 2026-10-12 under the decision order kept most of those changes
and reverted five), "Comparison after the changes", "Revised by principle, 2026-10-12", and
"Comparison after the revision", which describes the engine as it is now.

## How it was measured

### Tool

`tools/measure/` (see its `README.md`): `probes.py` holds the probe sets, `physical.py` and
`engine.py` the two targets, `normalize.py` the redaction and `compare.py` the probe-by-probe
verdicts. The same probe code runs against both targets: 116 probes in six sets
(`ccid-basic` 39, `ccid-errors` 37, `fido-hid` 21, `fido-cbor` 15, `fido-timing` 3,
`fido-presence-timeout` 1).

- **Physical CCID** goes through the macOS PC/SC service (CryptoTokenKit's CCID driver),
  reader opened exclusively. The harness never powers the card off or resets it
  (`SCARD_LEAVE_CARD`), so the application selected at the end of one probe is still
  selected when the next one starts. Raw CCID messages are not visible on this path; a
  failed `SCardTransmit`, or a reply without a status word, is recorded as status `none`
  and the harness then selects the probe's applet again (this extra SELECT shifts the
  exchange indexes, which is why `compare.py` lists many positional differences for the
  CLA probes).
- **Physical FIDO** goes through python-fido2's macOS HID backend. Report timestamps are
  taken in the IOKit callback. The host writes one output report about every 2 ms (a
  7609-byte message, 129 reports, takes about 257 ms to write) and a one-report
  request/answer round trip is 3 to 4 ms.
- **Engine**: `localkeyd` over its private wire socket, fresh state directory, with
  `--engine-setup usb-enabled=0x031A` (FIDO2, U2F, PIV, OpenPGP and HSM Auth enabled; OTP
  and OATH disabled, as on the key) and `--engine-setup fido-pin=<any>` (a FIDO PIN set).

### Read-only guard

`tools/measure/guard.py` is an allowlist independent of the probe list, enforced in the
transport layer before any byte is sent: SELECT, GET RESPONSE, a few undefined
instructions, and per applet only reads (READ CONFIG, PIV GET DATA/VERSION/SERIAL/METADATA,
OpenPGP and Security Domain GET DATA of fixed objects), VERIFY with an empty body (a
status query), CTAPHID framing probes, CTAP2 getInfo, clientPIN subcommands 1, 2 and 7,
selection, getAssertion with `up: false` for a random `*.invalid` RP, and U2F VERSION and
check-only AUTHENTICATE. Everything that writes, generates, resets or counts (INITIALIZE
UPDATE included) is refused and never reached the key. The engine runs go through the same
guards, so they prove every probe is admitted.

Before the CCID run the orchestrator checked that an empty VERIFY is a pure status query on
this key: one empty VERIFY on PIV (P2 `80`) and on OpenPGP (P2 `81`), with the retry
counters read before and after (PIV GET METADATA `80`, OpenPGP GET DATA `C4`); the counters
were unchanged. The measurement itself agrees: the OpenPGP PW status bytes read `03 00 03`
before the three empty VERIFY probes (`openpgp-get-00c4`) and still afterwards
(`cla-variants-openpgp`, `lc-le-openpgp`); for PIV the PIN metadata reports 3 of 3 retries
before the empty VERIFY and the VERIFY itself answers `63C3`. Both targets agree.

### Runs

| Run | Target | Sets | Notes |
| --- | --- | --- | --- |
| `physical-ccid` (14:50 UTC) | key | ccid-basic, ccid-errors | made before the harness learned to resynchronise FIDO channels; CCID probes are unaffected |
| `physical-presence` (14:51 UTC) | key | fido-presence-timeout | hit the stuck channel below; not used for results |
| `physical-fido` (14:56 UTC) | key | fido-hid, fido-cbor, fido-timing, fido-presence-timeout | |
| `engine-mirror` (14:58 UTC) | engine | all six | mirrored state as above |
| `engine-aligned` (16:12 UTC) | engine | all six | the same mirrored state, after the engine changes below (working tree of branch `engine`, not yet committed when it ran) |

`compare.py` compared the engine runs with the two physical runs merged into one file (the
76 CCID probes of `physical-ccid` and the 40 FIDO probes of `physical-fido`, unchanged).
Before the changes it found 37 of 116 probes different and 79 identical. The identical
probes were also compared packet by packet (all non-timing fields); nothing differs inside
them except the timings listed under "Timings". After the changes (`engine-aligned`) 13
probes differ and 103 are identical; no probe that was identical before differs now (see
"Comparison after the changes"). After the revision by principle of 2026-10-12
(`engine-reference`) 27 differ and 89 are identical, the 14 new differences each by design
(see "Comparison after the revision").

### The stuck-channel incident

An early physical FIDO run sent `CTAPHID_CBOR` with BCNT 0 (probe `empty-cbor`) without
resynchronising afterwards. The key never answers that request and stays busy with it: in
the next run (`physical-presence`) a broadcast INIT still allocated a channel, but the
selection command on it was answered `ERR_CHANNEL_BUSY` (`06`) within 4 ms, with no
KEEPALIVE. The device stayed busy across separate host sessions until a `CTAPHID_INIT` was
sent on the stuck channel itself, which freed it. Since then every probe that may leave a
transaction open ends with an INIT on its own channel (`probes.py` `resync`), and the
`empty-cbor` probe shows the whole sequence (see the FIDO table).

## State of the key

- Reference form factor USB-C Nano (DeviceInfo `04` = `04`), USB product ID `0406`
  ("YubiKey FIDO+CCID": the OTP HID interface is disabled).
- DeviceInfo capabilities, supported and enabled over USB: `031E` (U2F, FIDO2, PIV,
  OpenPGP, HSM Auth, and bit `0004`, which yubikit does not name). OTP and OATH are neither
  supported nor enabled, so their SELECT answers `6A82`. The engine cannot express this
  mask (its supported mask is the profile's `033B` and it has no bit `0004`); it was
  mirrored as enabled `031A`.
- Challenge-response timeout byte (DeviceInfo `07`): `0F` (15 s).
- FIDO: PIN set, 8 PIN retries, one discoverable credential stored
  (`remainingDiscoverableCredentials` 99).
- PIV: no keys in 9A, 9C, 9D, 9E; PIN and PUK retry counters full (3 of 3).
- OpenPGP: no user keys; PW1 and PW3 have 3 tries left.
- Security Domain: factory SCP03 key set and SCP11b key (key information `E0` is the same
  on both targets).

## Results

Classification, as recorded on 2026-10-11: **behavioural** (the firmware behaves
differently from the engine; every such difference was adopted then, and the review of
2026-10-12 kept some of them different by design, see "Engine changes"), **state-dependent** (caused by the key's stored state or configuration),
**host-artifact** (caused by macOS PC/SC), **unclear**. Probe ids are those of
`tools/measure/probes.py`.

### Management

| Probes | Physical | Engine | Class |
| --- | --- | --- | --- |
| `select-mgmt` (and every probe that selects Management) | `9000`, 30 bytes: ASCII `Virtual mgr - FW version <major>.<minor>.<patch>` | `9000`, 5-byte bare version string | behavioural |
| `mgmt-read-config` | page 0: 52 bytes, length `33`, tags in the order `01 03 02 04 05 06 07 08 0A 0F 20 21 10`, ending with `10 01 01` (more data); page 1: 42 bytes, length `29`, tags `11 12 13 14 15 16 17 18` | page 0: 51 bytes, tags `01 02 03 04 05 06 07 08 0A 14 15 16 18`, no `10`; page 1: `6A86` | behavioural |
| (same) values | `0F 01 00`, `20 03 000000`, `21 03 000000`; page 1: `11 04 00000000`, `12 01 00`, `13` a 12-byte ASCII part number, `14 02 0000`, `15 02 0000`, `16 01 00`, `17 01 00`, `18 02 0000` | tags `0F`, `11`, `12`, `13`, `17`, `20`, `21` absent | behavioural |
| (same) `07` | `0F` | `00` | behavioural (factory value; medium confidence) |
| (same) `01`, `03` | `031E`, `031E` | `033B`, `031A` | state-dependent |
| `lc-le-mgmt` | Le `01`: one byte and `6133`; Le `00`, extended Le, and Lc 1 with one data byte: page 0 | the same with `6132` (one byte shorter page) | follows from the layout |
| `bad-p1p2-mgmt` | P2 `01`: page 0 (`9000`, P2 ignored); P1 `FF` and P1 `02`: `9000` with no data at all | `6A86` for all three | behavioural |
| `cla-variants-mgmt` | CLA `80`: page 0, `9000`; CLA `0C`: `none`; CLA `10`: `9000` (chain open); then GET RESPONSE: `6D00` | CLA `80`: `6E00`; CLA `0C`: `6882`; CLA `10`: `9000`; GET RESPONSE: `6883` | behavioural (CLA 80, GET RESPONSE); CLA 0C unclear |
| `get-response-idle-mgmt` | `6D00` | `6985` | behavioural |
| `undefined-ins-mgmt` | `6D00` ×3 | `6D00` ×3 | differs only in the SELECT text |

### Security Domain and HSM Auth

| Probes | Physical | Engine | Class |
| --- | --- | --- | --- |
| `undefined-ins-sd` | `5E`, `6E`, `93`: `6982` | `6D00` | behavioural |
| `get-response-idle-sd` | `6982` | `6985` | behavioural |
| `cla-variants-sd` | CLA `80` GET DATA `0066`: 65 bytes `66 3F 73 3D …` (card data wrapped in tag `66`); CLA `00`: 63 bytes `73 3D …`; CLA `0C`: `none`; CLA `10`: `9000`; then GET RESPONSE: `6982` | CLA `80`: the bare 63 bytes; CLA `0C`: `6982`; CLA `10`: `9000`; GET RESPONSE: `6883` | behavioural (CLA 80, GET RESPONSE); CLA 0C unclear |
| `cla-variants-hsmauth` | CLA `80`, INS `5E`: `6D00`; CLA `0C`: `none` | `6E00`; `6882` | behavioural (CLA 80); CLA 0C unclear |
| `get-response-idle-hsmauth` | `6D00` | `6985` | behavioural |

### PIV

| Probes | Physical | Engine | Class |
| --- | --- | --- | --- |
| `piv-verify-status-81` | VERIFY P2 `81`, empty body: `6A80` | `6A88` | behavioural |
| `bad-p1p2-piv` | GET DATA P1P2 `3FFE` and `0000`: `6A82`; GET METADATA P1 `01` P2 `9A` (empty slot): `6A88`; GET VERSION P1 `01`, GET SERIAL P2 `01`: `9000` | `6A86`, `6A86`; `6A86`; `9000` | behavioural |
| `lc-le-piv-get-data` | `00CB3FFF 02 5C01 7E` (tag list cut short): `6A82`; `00CB3FFF 05 5C017E` (Lc longer than the data): `none` | `6A80`; `6700` | behavioural; host-artifact |
| `get-response-idle-piv` | `6A80` | `6985` | behavioural |
| `cla-variants-piv` | CLA `80` GET DATA `7E`: `9000` and the discovery object; CLA `0C`: `none`; CLA `10`: `9000`; GET VERSION while the chain is open: `6883` | CLA `80`: `6E00`; CLA `0C`: `6882`; CLA `10`: `9000`; `6883` | behavioural (CLA 80); CLA 0C unclear |

### OpenPGP

| Probes | Physical | Engine | Class |
| --- | --- | --- | --- |
| `openpgp-get-006e`, `chain-61xx`, `chain-extended-le` | key information `DE`: `01 00 02 00 03 00 81 02` (attestation key "imported") | `… 81 01` ("generated") | behavioural |
| `chain-61xx` | `613B` (256 bytes), GET RESPONSE Le `10`: 16 bytes `612B`, GET RESPONSE Le `2B`: 43 bytes `9000`; one more GET RESPONSE: `6D00` | identical up to the last step, which is `6985` | behavioural (last step) |
| `get-response-idle-openpgp` | `6D00` | `6985` | behavioural |
| `cla-variants-openpgp` | CLA `80` GET DATA `C4`: `9000` and the 7 bytes; CLA `0C`: `none`; CLA `10` GET DATA `C4`: `9000` (no data); then GET RESPONSE: `6D00` | CLA `80`: `6E00`; CLA `0C`: `6882`; CLA `10`: `6E00`; GET RESPONSE: `6985` | behavioural (CLA 80, CLA 10, GET RESPONSE); CLA 0C unclear |

### Card session (device level)

| Probes | Physical | Engine | Class |
| --- | --- | --- | --- |
| `select-partial-aid` | `A0000005`: `9000`, 30 bytes; `A000000527`: `9000`, 30 bytes; `A0000003`: `9000`, 19 bytes; `D276000124`: `9000`, no data; `A0000005272107`: `9000`, `79 03 050704` | `6A82` for all five | behavioural |
| `select-odd-p2` | SELECT PIV with P2 `04`, `0C`, `02`, `01`: `6982` each; Management with Le `00`: `9000` | `9000` and the PIV template for all four | unclear (see below) |

The partial-AID responses are redacted (`normalize.py` hides the data of any SELECT whose
AID is not an applet's own), so the selected applet is inferred from the length: 30 bytes is
Management's SELECT text, 19 bytes PIV's application property template, an empty `9000`
OpenPGP, and `79 03 05 07 04` HSM Auth. A DF name that is a prefix of an applet's AID
therefore selects that applet. Two caveats: Management was already selected when the probe
started (the previous probe ended with a Management SELECT), so the tie between
Management and HSM Auth for `A0000005` and `A000000527` (both AIDs start with these bytes;
OTP and OATH are disabled on this key) may be table order or a preference for the current
applet; and the engine's HSM Auth AID is the 8-byte `A000000527210701`, so the 7-byte
`A0000005272107` is itself a partial name.

`select-odd-p2` is confounded: the Security Domain was the selected application when it
ran (the previous probe, `get-response-idle-sd`, selected it), and `6982` is what the
Security Domain answers to every command it does not know. A device-level rule ("SELECT
with P2 other than `00` is `6982`") and the Security Domain answering a SELECT it was
handed cannot be told apart. `select-unknown` (P2 `00`, an unassigned AID, also run with
the Security Domain selected) answered `6A82`, so a P2 `00` SELECT is handled by the
device whatever is selected. Common to both readings: PIV was not selected. Hosts that
select with P2 `0C` are worth checking before choosing a rule.

### Host artifacts

Every CLA `0C` command (Management, PIV, OpenPGP, HSM Auth, Security Domain) and the PIV
GET DATA whose Lc (5) is longer than its data (3 bytes) came back as `none`: either
`SCardTransmit` failed or the reply had no status word. The redacted files do not keep the
PC/SC return code, and raw CCID messages cannot be seen behind macOS PC/SC, so whether the
key answered without a status word or macOS refused the command is not known. The
malformed-Lc case is most likely the host (the APDU is inconsistent before it reaches the
card); CLA `0C` is left unclear. The engine answers `6882` (`6982` in the Security Domain)
and `6700`. The answers at 0.4 to 0.6 ms are about one APDU round trip, so they do not
settle it either.

### FIDO

| Probes | Physical | Engine | Class |
| --- | --- | --- | --- |
| `ping-max`, `ping-7609` | longest echoed PING 1536 bytes; 1537 and every longer length tried (up to 7609): `ERR_INVALID_LEN` (`03`) about 3.9 ms after the first report was written, while the remaining fragments were still being written (so at the initialization packet); the late fragments are ignored and the next request works | 7609 bytes echoed | behavioural |
| `lock`, `lock-expiry` | `CTAPHID_LOCK` with 0, 1 or 2 s: `ERR_INVALID_CMD` (`01`); other channels and broadcast INIT are never locked out | LOCK acknowledged; other channels `ERR_CHANNEL_BUSY` until it lapses (1010 ms, 2015 ms) | behavioural |
| `empty-cbor` | `CTAPHID_CBOR` with BCNT 0: no answer and no KEEPALIVE within 2 s; another channel's PING: `ERR_CHANNEL_BUSY`; CANCEL on the channel: no answer, still busy 3 s after the request; INIT on the channel: INIT answer (same CID), after which the other channel works | `ERR_INVALID_LEN` at once; nothing held | behavioural |
| `client-pin-retries` | getPINRetries: `{3: 8}` (4 bytes) | `{3: 8, 4: false}` (6 bytes) | behavioural |
| `client-pin-uv-retries` | getUVRetries: status `33` (`CTAP2_ERR_PIN_AUTH_INVALID`) | `3E` (`CTAP2_ERR_INVALID_SUBCOMMAND`) | behavioural |
| `get-info`, `get-info-trailing-map`, `get-info-trailing-zero` | identical except `remainingDiscoverableCredentials` (`0x14`) 99; `maxMsgSize` 1536 on both | 100 | state-dependent |
| `selection-keepalive-cancel`, `selection-no-touch`, `message-timeout` | see "Timings" | | behavioural |
| `cancel-idle` | CANCEL on an idle channel: no answer within 0.5 s, the next PING works | the same | identical |

getInfo latency: in `physical-fido` getInfo (375 bytes, 7 reports) took 15.8 ms with no
KEEPALIVE; the first report came 3.75 ms after the request, a plain one-report round trip,
and the rest is report transfer. A getInfo of about 210 ms with two
`KEEPALIVE(PROCESSING)` reports, noted during an earlier physical run, is not in the
measurement files and could not be verified. Either way it is not adopted: the engine
models what the device answers, not how long it computes, and it adds no processing
latency anywhere.

The CTAP status names printed by the measuring tool were partly wrong (corrected on
2026-10-12, see the end of this file): `tools/measure/common.py` labelled `3E`
"UNAUTHORIZED_PERMISSION" and had no name for `33`. In CTAP 2.1 §8.2, `33` is
`CTAP2_ERR_PIN_AUTH_INVALID`, `3E` is `CTAP2_ERR_INVALID_SUBCOMMAND` and `40` is
`CTAP2_ERR_UNAUTHORIZED_PERMISSION`. lk-fido uses the CTAP 2.1 values.

## Timings

| Quantity | Physical | Engine before | Recommended | Engine after (`engine-aligned`) |
| --- | --- | --- | --- | --- |
| KEEPALIVE interval while waiting for a touch | 94.86 ms mean in both runs (14 intervals: min 93.9, max 96.0, σ 0.99; 299 intervals: min 91.5, max 98.1, σ 1.03), status `02` (UPNEEDED) | 100.0 ms | 95 ms | 94.77 ms mean (15 KEEPALIVEs, as on the key) and 95.01 ms (300 KEEPALIVEs) |
| First KEEPALIVE after the request | 93.8 ms and 85.9 ms (two runs; both below one interval although they include 1 to 2 ms of delivery to the host) | at once (0.03 ms) | one interval after the request (95 ms), the upper edge of what was seen; a longer series can decide whether the first tick is anchored to the request | 104.9 ms and 98.3 ms (due at 95 ms; the rest is most likely the daemon's scheduling and the wire socket, which would also explain the engine's wider interval spread) |
| User-presence timeout (selection, no touch) | `CTAP2_ERR_USER_ACTION_TIMEOUT` 28 451.8 ms after the request, 2 ms after the 300th KEEPALIVE | 30 004.5 ms, 301 KEEPALIVEs | 28 500 ms = 300 × 95 ms, the KEEPALIVE due at that instant sent first | 28 506.6 ms, after 300 KEEPALIVEs |
| CANCEL during selection | `CTAP2_ERR_KEEPALIVE_CANCEL` (`2D`) one round trip later (3.7 ms), no KEEPALIVE after it | the same (0.14 ms) | no change | the same (0.07 ms) |
| CTAPHID message timeout (PING initialization packet with BCNT 100, continuation withheld) | `ERR_MSG_TIMEOUT` (`05`) 469.8 ms after the packet was written | 3002.8 ms | 470 ms | 473.0 ms |
| One-report round trip (INIT, PING ≤ 57 bytes, short CTAP2 errors) | 3.0 to 4.2 ms | 0.02 to 0.12 ms | not modelled (host polling) | unchanged |
| CCID APDU round trip | 0.5 to 1.6 ms; READ CONFIG page 1 5.6 ms; OpenPGP `6E` 3.6 ms | about 0.03 ms | not modelled | unchanged |

Both long timers fit a device whose clock runs about 5.4 % fast: 94.86 / 100 = 0.9486 and
28 451.8 / 30 000 = 0.9484, so the firmware most likely counts 100 ms KEEPALIVE ticks and a
30 s (300-tick) timeout on that clock. The message timeout (469.8 / 500 = 0.940, and the
figure still contains 2 to 4 ms of host latency) fits less tightly, perhaps because it is
checked on a coarser tick.

Recommendation: adopt the measured wall-clock values. The engine's clock is the host's
monotonic clock and the engine models what a host observes; a host sees 94.86 ms, not
100 ms. Round to whole milliseconds and keep the structure the key shows: a 95 ms grid
whose first point is one interval after the request, and a presence timeout of exactly 300
intervals (28 500 ms, 0.17 % above the measurement), which reproduces "300 KEEPALIVEs, then
the timeout answer" with the existing rule that a KEEPALIVE due at the timeout instant goes
out first. The message timeout becomes 470 ms (measured 469.8 ms; whether every packet
restarts it was not measured, so the engine's restart rule stays). Unmeasured timers (CCID
time extension 500 ms, card touch timeouts 15 s, U2F window and latch 3 s, OTP reboot delay)
stay model policy; if they are nominal values on the same clock they would measure about
5.4 % shorter, which a later measurement can check. The recommended values were adopted
(see "Engine changes").

Revised on 2026-10-12 by the decision order (rule 4, no clock-drift artefacts): the
presence timeout is the 30 s design value, not 28 500 ms; on the 95 ms grid a host now sees
315 KEEPALIVEs and then the answer alone (see "Revised by principle"). The 95 ms interval
and the first KEEPALIVE one interval after the request stay, because they are within CTAP
2.1 §11.2.9.1.7 ("at least every 100ms"; exactly 100 ms on the host's clock would overrun it
with scheduling jitter). The 470 ms message timeout stays too: it does not fit the clock
ratio of the other two timers closely enough to make 500 ms evident (see "Engine changes").

## What could not be measured

- OTP and OATH: both are disabled on this key (SELECT `6A82`), so no OTP or OATH status
  word, response layout or timing was observed; the OTP HID interface is never opened by the
  harness by design.
- Card touch: timeouts of PIV, OpenPGP and OATH touch policies, the touch-cancel status
  words, and the CCID time-extension cadence need a card command that waits for a touch,
  which is a key operation the read-only guard refuses.
- U2F request window and latch: they need U2F REGISTER or AUTHENTICATE with presence; only
  VERSION and check-only AUTHENTICATE (`6A80` on both) were sent.
- Raw CCID: macOS PC/SC hides the CCID messages (`RDR_to_PC_DataBlock`, time extensions,
  CCID-level chaining, the slot status), the PC/SC return code of failed transmits is not
  kept in the redacted files, and the answers to CLA `0C` are unexplained.
- CTAPHID details not covered by a probe: whether each packet restarts the message timeout;
  the precedence of `INVALID_CMD` for LOCK against a busy device; whether an empty
  `CTAPHID_MSG` behaves like an empty `CTAPHID_CBOR`; whether the stall after an empty CBOR
  ever ends by itself (it lasted at least 3 s in the probe and across host sessions in the
  incident); whether CBOR and MSG messages longer than 1536 bytes are refused like PING
  (getInfo `maxMsgSize` 1536 suggests so).
- clientPIN: getPINRetries was seen only while no power cycle was required (the key is not
  soft-blocked), so whether `powerCycleState: true` is ever sent is unknown;
  getPinUvAuthTokenUsingUvWithPermissions (`06`) and other unsupported subcommands were not
  sent.
- PIV and OpenPGP: VERIFY P2 `81` with a PIN in the body (refused by the guard); GET
  METADATA P1 `01` for an existing object (the empty slot cannot tell "P1 ignored" from "P1
  not `00` is `6A88`"); malformed GET DATA tag lists other than a cut-short one; CLA `90`
  and other proprietary classes.
- Security Domain: CLA `80` GET DATA of objects other than `0066`.
- Card session: SELECT with P2 other than `00` while another applet than the Security Domain
  is selected; the partial-AID tie between Management, OTP, OATH and HSM Auth with OTP and
  OATH enabled or with HSM Auth selected first.
- DeviceInfo over CTAPHID (`0x42`) and OTP HID: only READ CONFIG over CCID was measured.

## Engine changes

Every behavioural difference found above was changed in the crate that owns it, on
2026-10-11 (the tables below merge differences that share one change). Not adopted: `select-odd-p2` and CLA `0C` (unclear), the malformed-Lc PIV GET
DATA (host artifact), the getInfo latency (unclear, and the engine models no processing
time), and the state-dependent DeviceInfo capability masks and
`remainingDiscoverableCredentials`.

On 2026-10-12 every change below was reviewed under the decision order of `docs/CONTRACTS.md`
"Reference, not replica" (`docs/DESIGN.md` §12 decision 8): rule 1 specification (with the
host compatibility exception), rule 2 the reference where the specification is open, rule
3 Yubico's documentation and yubikit for Yubico's own protocols, rule 4 no reference
defects, rule 5 own identity. Five changes were reverted; the rest were kept:

| Change | Probe | 2026-10-12 | Rule and reason |
| --- | --- | --- | --- |
| Management SELECT text `Virtual mgr - FW version …` | `select-mgmt` | kept | rule 3: Yubico-proprietary, yubikit reads the version from the text; rule 5 keeps a message format hosts parse |
| DeviceInfo as two fixed pages, tags `20`/`21`, part number from the profile | `mgmt-read-config`, `lc-le-mgmt` | kept | rule 3: yubikit `DeviceInfo.parse_tlvs` and `read_device_info`; rule 5: the own profile's part number is empty |
| Factory challenge-response timeout `0F` | `mgmt-read-config` | kept | rule 3: Yubico documents 15 s as the default |
| READ CONFIG over CCID ignores P2; past the last page a bare `9000` | `bad-p1p2-mgmt` | kept | rule 3; yubikit never asks for a page that the previous one did not announce |
| CLA `80` served like `00` | `cla-variants-mgmt`, `-hsmauth`, `-piv`, `-openpgp` | kept | rule 2: ISO/IEC 7816-4 leaves the proprietary class to the application, and neither SP 800-73-4 nor OpenPGP card 3.4 defines an answer |
| GET RESPONSE with nothing pending, and during an open chain | `get-response-idle-*`, `chain-61xx`, `cla-variants-*` | kept | rule 2: ISO/IEC 7816-4 defines no status for "nothing pending". OpenPGP's `6D00` during an open chain is kept at medium confidence: if ISO/IEC 7816-4 makes `6883` mandatory there, that case goes back to `6883` |
| Security Domain unknown instruction `6982` outside a channel | `undefined-ins-sd` | kept | rule 2: GP 2.3.1 Table 11-10 lists both `6982` and `6D00` for any command |
| Security Domain `80 CA 00 66` inside tag `66` | `cla-variants-sd` | kept, extended | rule 1: GP 2.3.1 §11.3.3.1, now applied to every GlobalPlatform-class GET DATA |
| SELECT by a partial DF name | `select-partial-aid` | kept | rule 1: ISO/IEC 7816-4 §6.11 allows a right-truncated DF name, and the ATR announces it; the tie order stays model policy |
| PIV VERIFY with P2 `81` answers `6A80` | `piv-verify-status-81` | **reverted** to `6A88` | rule 1: SP 800-73-4 Part 2 §3.2.1 |
| PIV GET DATA with P1P2 other than `3FFF` answers `6A82` | `bad-p1p2-piv` | kept | rule 2: SP 800-73-4 Part 2 §3.1.2 lists `6A82` and defines no status for a wrong P1-P2 |
| PIV GET METADATA ignores P1 | `bad-p1p2-piv` | kept | rule 3: a Yubico extension |
| PIV GET DATA with a cut-short tag list answers `6A82` | `lc-le-piv-get-data` | kept | rule 2: within the §3.1.2 status list |
| OpenPGP GET DATA accepts chaining CLA `10` | `cla-variants-openpgp` | kept | rule 2: chaining is not defined for GET DATA (OpenPGP card 3.4.1 §7.2.6, §7.7) |
| OpenPGP `DE` reports the factory attestation key as imported (`02`) | `openpgp-get-006e` | **reverted** to `01` | rule 1: OpenPGP card 3.4.1 §4.4.3.8; the engine generates that key on the device |
| Requests over 1536 bytes are `ERR_INVALID_LEN` | `ping-max`, `ping-7609` | kept | rule 2: CTAP 2.1 §8 leaves the maximum to the device (at least 1024, announced as `maxMsgSize`) |
| `CTAPHID_LOCK` not implemented | `lock`, `lock-expiry` | kept | rule 2: LOCK is optional (CTAP 2.1 §11.2.6, §11.2.9.2) |
| An empty `CTAPHID_CBOR` stalls the device | `empty-cbor` | **reverted** to `ERR_INVALID_LEN` | rule 4: a reference defect (CTAP 2.1 §11.2.4, §11.2.5.2); rule 1: the request is "BCNT 1..(n + 1)" (§11.2.9.1.2) |
| CTAPHID message timeout 470 ms | `message-timeout` | kept | rule 2: CTAP 2.1 §11.2.5.2 gives no value. Rule 4 does not apply yet: the single sample, after removing the host latency, is about 7 ms short of the 474 ms a 500 ms timer would give on the key's clock, so 500 ms is not evident; a repeated series can decide it |
| No KEEPALIVE at once | `selection-keepalive-cancel` | kept | rule 2: within CTAP 2.1 §11.2.9.1.7 |
| KEEPALIVE every 95 ms | `selection-no-touch` | kept | rule 2: within §11.2.9.1.7 "at least every 100ms" |
| Presence timeout 28 500 ms (300 × 95 ms) | `selection-no-touch` | **reverted** to 30 000 ms | rule 4: a 30 s timer on a fast clock (28 451.8 / 30 000 = 0.9484); CTAP 2.1 §5 "Thirty seconds is a reasonable value" |
| getPINRetries without `powerCycleState` | `client-pin-retries` | kept | rule 2: the field is optional (CTAP 2.1 §6.5.5) |
| getUVRetries answers `33` | `client-pin-uv-retries` | **reverted** to `3E` | rule 1: CTAP 2.1 §8.1 |

Each change has a regression test in the owning crate (or in lk-device) that cites this
file and the probe. Tests that encoded the old model policy were updated to the measured
value with a comment naming the probe; none was removed without a replacement. The catalog
lines concerned (`docs/catalog/{mgmt,sd,hsmauth,piv,openpgp,fido,device}.md`) now say
"measured on the reference key (docs/MEASUREMENT.md, probe …)". Four lines that were
`tested` against the legacy reference catalog became `intentional difference`, because the
key contradicts them: the 7609-byte PING (in `fido.md` and `device.md`), OpenPGP GET
RESPONSE during a chain answering `6883`, and OpenPGP GET DATA refusing CLA `10` with
`6E00`. Catalog totals: 451 lines, 374 tested, 35 intentional differences, 42 deferred
(before: 378, 31, 42).

### Card applications (CCID)

| Change | Crate, file | Regression tests | Probe |
| --- | --- | --- | --- |
| Management SELECT answers `Virtual mgr - FW version <major>.<minor>.<patch>` (30 bytes in the observation) instead of the bare version | lk-mgmt `applet.rs` (`MgmtApplet::select_text`) | `select_returns_version_string`, `select_serves_at_most_ne`, `yubikit_version_search_reads_both_select_texts` (`tests/mgmt.rs`); lk-device `ccid`, `scenario_ccid`, `scenario_mgmt` | `select-mgmt` |
| DeviceInfo is two fixed pages in the measured order (page 0 `01 03 02 04 05 06 07 08 0A 0F 20 21 10`, page 1 `11 12 13 14 15 16 17 18`) instead of greedy paging. New tag constants `FPS_VERSION` (`20`) and `STM_VERSION` (`21`). The part number (`13`) comes from the new `DeviceProfile::part_number` (lk-core): empty in the own profile, twelve `0` characters in the YubiKey profile | lk-mgmt `info.rs`, `config.rs`; lk-core `profile.rs` | `info::tests::pages_match_the_measured_layout`, `merged_is_both_pages_without_more_data`, `empty_part_number_is_an_empty_value`, `config::tests::read_config_serves_the_two_measured_pages`, `read_config_is_length_prefixed_device_info` (Le `01` → `6133`) | `mgmt-read-config`, `lc-le-mgmt` |
| Factory challenge-response timeout byte (`07`) is `0F` (15 s); a written `00` still reads as 15 s | lk-mgmt `config.rs` (`Config::factory`) | `factory_challenge_response_timeout_means_default` | `mgmt-read-config` |
| READ CONFIG over CCID ignores P2; a page past the last answers a bare `9000` without data | lk-mgmt `applet.rs` | `read_config_paging_bounds`; lk-device `ccid::management_reads_as_measured` | `bad-p1p2-mgmt` |
| CLA `80` is served like CLA `00` in Management, HSM Auth, PIV and OpenPGP; other proprietary classes keep `6E00`, and OpenPGP GET ATTESTATION keeps its CLA-`80`-only rule | lk-mgmt `applet.rs`, lk-hsmauth `applet.rs`, lk-piv `lib.rs`, lk-openpgp `lib.rs` | `cla_80_is_served_like_00` (lk-mgmt), `proprietary_class_80_is_served_like_00` (lk-hsmauth), `class_variants` (lk-piv `tests/measured.rs`, lk-openpgp `tests/applet/measured.rs`) | `cla-variants-mgmt`, `-hsmauth`, `-piv`, `-openpgp` |
| GET RESPONSE with nothing pending: Management `6D00`, HSM Auth `6D00`, Security Domain `6982`, PIV `6A80`, OpenPGP `6D00` (was `6985` in all five). GET RESPONSE while a command chain is open: Management and OpenPGP `6D00`, Security Domain `6982`, and the chain is dropped (was `6883`) | lk-mgmt `applet.rs`, lk-hsmauth `applet.rs`, lk-sd `lib.rs`, lk-piv `lib.rs`, lk-openpgp `lib.rs` | `get_response_without_pending_data_is_6d00` (lk-mgmt), `unserved_plaintext_commands_are_6982` (lk-sd), `get_response_with_nothing_pending_answers_6a80` (lk-piv), `get_response_with_nothing_pending_answers_6d00`, `response_chaining_and_the_end_of_it`, `get_response_during_chain_returns_6d00` (lk-openpgp); lk-device `ccid::security_domain_and_hsm_auth_statuses_as_measured` | `get-response-idle-*`, `chain-61xx`, `cla-variants-mgmt`, `-sd`, `-openpgp` |
| Security Domain outside a secure channel answers an unknown instruction `6982` (was `6D00`) | lk-sd `lib.rs` (`dispatch`) | `unserved_plaintext_commands_are_6982`, `unknown_get_data_tag` | `undefined-ins-sd` |
| Security Domain GET DATA `0066` with CLA `80` wraps the card recognition data in tag `66` (65 bytes); CLA `00` unchanged (extended to every GlobalPlatform-class GET DATA on 2026-10-12, see "Revised by principle") | lk-sd `manage.rs` | `proprietary_class_card_data_has_the_66_template`; lk-device `scenario_ccid::select_routes_between_all_seven_applications` | `cla-variants-sd` |
| SELECT by a partial DF name: when no applet AID is a prefix of the name, the first enabled applet in `AppId::ALL` order whose AID starts with the name is selected (was `6A82`) | lk-device `card.rs` (`find_applet`) | `tests::partial_df_names_select_as_measured`, `tests::applet_lookup_by_df_name`, `ccid::select_by_partial_df_name` | `select-partial-aid` |
| PIV VERIFY with P2 `81` answers `6A80`; other unsupported references keep `6A88` (revised 2026-10-12, see "Revised by principle") | lk-piv `pin.rs` | `verify_of_the_puk_reference_answers_6a80` (`tests/measured.rs`), `pin_puk::verify_header_guards_consume_no_retry` | `piv-verify-status-81` |
| PIV GET DATA with P1P2 other than `3FFF` answers `6A82` (was `6A86`; PUT DATA unchanged) | lk-piv `data.rs` | `bad_p1_p2_answers` | `bad-p1p2-piv` |
| PIV GET METADATA ignores P1 (empty slot `9A` with P1 `01`: `6A88`) | lk-piv `admin.rs` | `bad_p1_p2_answers`, `vendor_commands::metadata_for_factory_references` | `bad-p1p2-piv` |
| PIV GET DATA whose `5C` tag list runs past the data field answers `6A82`; other malformed lists keep `6A80` | lk-piv `data.rs` | `get_data_length_forms_and_a_cut_short_tag_list` | `lc-le-piv-get-data` |
| OpenPGP GET DATA accepts chaining CLA `10` (`9000` without data, the chain stays open) | lk-openpgp `lib.rs` (`chainable`) | `framing::get_data_accepts_chaining_cla_10`, `class_variants` | `cla-variants-openpgp` |
| OpenPGP key information `DE` reports the factory attestation key as imported (`02`, was `01`). Attestation checks the attested slot's status, so it keeps working; stored states holding `01` are not migrated (revised 2026-10-12, see "Revised by principle") | lk-openpgp `attest.rs` (`FACTORY_ISSUER_STATUS`), `objects.rs` | `factory_attestation_key_status_is_imported`, `public_objects::application_related_data_layout_matches_observation` | `openpgp-get-006e` |

### FIDO HID

| Change | Crate, file | Regression tests | Probe |
| --- | --- | --- | --- |
| A request longer than 1536 bytes gets `ERR_INVALID_LEN` at its initialization packet, for every command, and its remaining packets are ignored. New public `MAX_MESSAGE_LEN` = 1536; responses may still be up to `MAX_PAYLOAD` (7609 bytes) | lk-ctaphid `protocol.rs`, `framer.rs` | `framing::maximum_ping_is_1536_bytes_and_ends_on_sequence_25`, `bcnt_above_1536_is_invalid_len_at_once_and_the_late_fragments_are_ignored`, `commands::every_request_above_1536_bytes_is_invalid_len`; lk-device `fido::ping_longer_than_1536_bytes_is_invalid_len_and_the_rest_is_ignored`, `scenario_fido::max_message_size_boundary` | `ping-max`, `ping-7609` |
| `CTAPHID_LOCK` is not implemented: `ERR_INVALID_CMD` for any length, and nothing is reserved. The lock state, its timer and `src/lock.rs` are gone; `MAX_LOCK_SECONDS`, `cmd::LOCK` and `err::LOCK_REQUIRED` stay | lk-ctaphid `framer.rs` | `tests/lock.rs` (5 tests, among them `measured_probe_other_channels_are_served_right_after_a_lock`); lk-device `scenario_fido::ctaphid_lock_is_invalid_cmd_and_reserves_nothing` | `lock`, `lock-expiry` |
| `CTAPHID_CBOR` with BCNT 0 is never answered: the device stays busy (other channels `ERR_CHANNEL_BUSY`, CANCEL ignored, no timeout) until INIT on that channel or a USB reset. The application never sees it (new internal `Transaction::Stalled`) (revised 2026-10-12, see "Revised by principle") | lk-ctaphid `framer.rs`, `transaction.rs` | `commands::empty_cbor_request_stalls_the_device_until_init_on_its_channel`, `empty_cbor_stall_ignores_a_late_respond_and_ends_with_a_usb_reset`, `cancel::cancel_of_a_stalled_empty_cbor_request_is_ignored`, `reset::reset_ends_an_empty_cbor_stall`; lk-device `fido::empty_cbor_request_stalls_the_device_until_init_on_its_channel` | `empty-cbor` |
| CTAPHID message timeout `TRANSACTION_TIMEOUT_MS` = 470 (was 3000) | lk-ctaphid `protocol.rs` | `timeout::measured_timeout_is_470_ms`, `measured_probe_ping_with_bcnt_100_and_no_continuation_times_out_at_470_ms`; lk-device `fido::ctaphid_message_timeout_is_a_device_deadline` | `message-timeout` |
| No KEEPALIVE when a command starts waiting for a touch; the first one is due one interval later | lk-device `presence.rs` (`wait_fido`) | `fido::waiting_command_sends_keepalives_and_resolves_on_touch`, the `verify_timing` grid tests | `selection-keepalive-cancel` |
| `KEEPALIVE_INTERVAL_MS` = 95 (was 100) | lk-device `presence.rs` | `fido::late_tick_sends_one_keepalive`, `verify_timing::keepalive_cadence_stays_on_the_grid_with_a_late_host` | `selection-no-touch` |
| CTAP2 user-presence timeout `TOUCH_TIMEOUT_MS` = 28 500 (300 × 95 ms; was 30 000): 300 KEEPALIVEs, then `CTAP2_ERR_USER_ACTION_TIMEOUT` (revised 2026-10-12, see "Revised by principle") | lk-fido `lib.rs` | `persistence::touch_timeout_is_the_measured_28_5_seconds`; lk-device `verify_timing::measured_probe_selection_without_touch_sends_300_keepalives_then_times_out` | `selection-no-touch` |
| clientPIN getPINRetries omits `powerCycleState` (key `4`) unless the PIN is soft-blocked: `{3: 8}` | lk-fido `client_pin.rs` | `get_pin_retries_with_a_pin_set_is_byte_identical_to_the_measured_key`, `get_pin_retries_reports_retries_and_power_cycle_state` | `client-pin-retries` |
| clientPIN getUVRetries (`07`) answers `CTAP2_ERR_PIN_AUTH_INVALID` (`33`); `06` and unknown subcommands keep `CTAP2_ERR_INVALID_SUBCOMMAND` (revised 2026-10-12, see "Revised by principle") | lk-fido `client_pin.rs` | `parameter_types_and_subcommands` | `client-pin-uv-retries` |

### Deliberately not extended

- HSM Auth GET RESPONSE while a chain is open still answers `6883`: the chained case was
  measured only for Management, the Security Domain and OpenPGP.
- READ CONFIG over CTAPHID (`0x42`) and OTP HID serve the same two pages, but a page past
  the last still answers `6A86` / `ERR_INVALID_PAR`: only CCID was measured.
- The Security Domain's GlobalPlatform-class GET DATA was extended beyond the measured
  plaintext `80 CA 00 66` by the specification (GP Card Specification v2.3.1 §11.3.3.1),
  not by this measurement; see "Revised by principle". The physical key's GP-class forms
  other than plaintext `80 CA 00 66` remain unmeasured (see "What could not be measured").
- DeviceInfo tag `13` carries a placeholder of the measured length (12 bytes), not the
  key's part number, which may identify a production batch.
- Unmeasured and unchanged: CLA `90`, `84` and the other proprietary classes (`6E00`); CLA
  `0C` (`6882`, `6982` in the Security Domain); SELECT with P2 other than `00`; an empty
  `CTAPHID_MSG` (`ERR_INVALID_LEN`); LOCK while another channel is busy (`ERR_CHANNEL_BUSY`);
  the restart of the message timeout on every packet; `powerCycleState: true` while
  soft-blocked; clientPIN `06`; data-less OpenPGP commands other than GET DATA with CLA
  `10` (`6E00`).
- Extrapolated from the measurement and marked as such in the tests: PIV GET METADATA with
  P1 `01` on an existing object answers like P1 `00`; CLA `80` on instructions other than
  the measured reads; requests over 1536 bytes on CBOR, MSG and vendor commands are refused
  like PING; OpenPGP drops an open chain on GET RESPONSE (whether the key keeps it was not
  observed). (PIV VERIFY `81` with data or an Le was extrapolated to `6A80` too; since the
  revision by principle every form answers `6A88`.)

Checks after the changes: `cargo test --workspace` 2369 passed, 0 failed, 1 ignored (the
lk-fido long repeat test); `cargo clippy --workspace --all-targets` no warnings;
`tools/license_check.py` and `tools/catalog_status.py --check` clean.

### Revised by principle, 2026-10-12

localkey is its own security key; the reference key is the reference it is compared
against, not a device to clone. Where a public specification defines a behaviour, the engine
follows the specification even where the key differs, and it never copies the key's defects
(hangs, missing answers, clock drift in timings); the full decision order is in
`docs/CONTRACTS.md` "Reference, not replica". The changes below revise earlier ones under
that rule; the card table also holds changes made by the specification, or by the rule that
the own profile carries no Yubico identifiers, where the key was not measured (marked
"unmeasured"). The measured tables above stay as they were; the probes named below now differ
from the key again by design, and each such behaviour of the key is recorded as a known
difference here and as an `intentional difference` in the catalog. "Comparison after the
changes" describes the engine before this revision, "Comparison after the revision" at the
end of this file the engine after it.

#### FIDO HID

| Change | Rule | Known difference (the key) | Crate, file | Regression tests | Probe |
| --- | --- | --- | --- | --- | --- |
| `CTAPHID_CBOR` with BCNT 0 is `ERR_INVALID_LEN` (`03`) at the initialization packet again and holds nothing, like an empty `CTAPHID_MSG`; the internal `Transaction::Stalled` is gone. CTAP 2.1 §11.2.9.1.2: the request is "BCNT 1..(n + 1)", the CTAP command byte first; §11.2.9.1.6: `ERR_INVALID_LEN` is "The length field (BCNT) is invalid for the request" | reference defect not copied: "A request always triggers a response" (§11.2.4); "potentially stalling applications should however, be handled properly" (§11.2.5); the transaction timeout exists "to prevent a stalling application to cause the device to be completely locked out" (§11.2.5.2). The CTAP 2.2 text is the same | no answer and no KEEPALIVE; other channels `ERR_CHANNEL_BUSY`, CANCEL ignored; the device stays busy across host sessions until INIT on the stuck channel ("The stuck-channel incident") | lk-ctaphid `framer.rs`, `transaction.rs` | `commands::empty_cbor_request_is_invalid_len`, `commands::empty_cbor_request_holds_nothing_on_any_channel`, `cancel::cancel_after_a_refused_empty_cbor_request_is_ignored`, `adversarial::rejected_broadcast_init_allocates_no_channel`, the oracle of `fuzz.rs`; lk-device `fido::empty_cbor_request_is_invalid_len_and_holds_nothing` | `empty-cbor` |
| CTAP2 user-presence timeout `TOUCH_TIMEOUT_MS` = 30 000 (was 28 500) for every waiting command. With the measured 95 ms KEEPALIVE grid a host sees 315 KEEPALIVEs, the last at 29 925 ms, then the answer alone at 30 000 ms. CTAP 2.1 §5, "User action timeout": "chosen by the authenticator but MUST be at least 10 seconds. Thirty seconds is a reasonable value." | reference defect not copied (clock drift): 28 451.8 / 30 000 = 0.9484, the same ratio as the KEEPALIVE interval (94.86 / 100 = 0.9486), so the key runs a 30 s timer on a fast oscillator; the engine uses the design value | `CTAP2_ERR_USER_ACTION_TIMEOUT` 28 451.8 ms after the request, after 300 KEEPALIVEs | lk-fido `lib.rs` | `persistence::touch_timeout_is_30_seconds`; lk-device `verify_timing::selection_without_touch_sends_315_keepalives_then_times_out_at_30_s` (was `measured_probe_selection_without_touch_sends_300_keepalives_then_times_out`), `keepalive_cadence_stays_on_the_grid_with_a_late_host`, `keepalive_cadence_survives_jitter`, `touch_exactly_at_the_fido_timeout_is_a_button_press`, `fido::presence_timeout_answers_the_command`, `scenario_fido::make_credential_presence_timeout` | `selection-no-touch` |
| clientPIN getUVRetries (`07`) answers `CTAP2_ERR_INVALID_SUBCOMMAND` (`3E`) again, like getPinUvAuthTokenUsingUvWithPermissions (`06`): the engine has no built-in UV (no `uv` option). CTAP 2.1 §8.1: "If the authenticator implements a command code having subcommands, but does not implement an invoked subcommand, it MUST return CTAP2_ERR_INVALID_SUBCOMMAND"; §6.5.5.3: the UV retries count is "the number of built-in UV attempts" | spec over reference: `33` is `CTAP2_ERR_PIN_AUTH_INVALID`, a pinUvAuthParam failure (§8.2), which does not apply to this request; the note after the §8.1 rule allows for authenticators of earlier versions that do not follow it. No listed host depends on `33`: libfido2 `fido2-token -I` (`tools/token.c`) prints "uv retries: undefined" for any error, ykman `fido info` asks only when the `bioEnroll` option is present, python-fido2 `ClientPin.get_uv_retries` raises `CtapError` for any code | status `33` | lk-fido `client_pin.rs` | `client_pin::parameter_types_and_subcommands` | `client-pin-uv-retries` |

Unchanged by this revision: the KEEPALIVE cadence (95 ms, the first one an interval after
the request) is within CTAP 2.1 §11.2.9.1.7 ("at least every 100ms") and stays as measured.
The open question under "What could not be measured" whether an empty `CTAPHID_MSG` behaves
like an empty `CTAPHID_CBOR` on the key no longer matters for the engine: both are
`ERR_INVALID_LEN` by §11.2.9.1.1 and §11.2.9.1.2.

#### Card applications (CCID)

| Change | Rule | Known difference (the key) | Crate, file | Regression tests | Probe |
| --- | --- | --- | --- | --- | --- |
| PIV VERIFY with P2 `81` answers `6A88` again, like every other reference this card cannot verify, with or without data, Le or P1 `FF`; no retry is spent. SP 800-73-4 Part 2 §3.2.1: "If any key reference value is specified that cannot be verified by the PIV Card Application, then the PIV Card Application shall return the status word 6A 88"; the PUK is compared only inside CHANGE REFERENCE DATA and RESET RETRY COUNTER | specification over reference. No listed host sends VERIFY with P2 `81`: yubico-piv-tool's VERIFY hardcodes P2 `80`, yubikit reads the PUK retries with GET METADATA, OpenSC has no PUK VERIFY | `6A80` | lk-piv `pin.rs` | `measured::verify_of_the_puk_reference_answers_6a88_per_sp800_73_4` (was `verify_of_the_puk_reference_answers_6a80`), `pin_puk::verify_header_guards_consume_no_retry` | `piv-verify-status-81` |
| OpenPGP key information `DE` reports the factory attestation key (ref `81`) as generated, `01` (was `02`): the engine generates it on the device at first start. OpenPGP card 3.4.1 §4.4.3.8: `01` "Key generated by the card", `02` "Key imported into the card". Stored states holding `02` are not migrated (they cannot be told from a key imported into `DA`); attestation is unaffected | specification over reference: on the key `02` is true (Yubico injects its attestation key at manufacture), so copying it would make the engine say something false about its own key. No host depends on it: yubikit maps any of `00`/`01`/`02`, GnuPG `KEY-STATUS` only echoes the pairs | `DE 08 01 00 02 00 03 00 81 02` | lk-openpgp `attest.rs` (`FACTORY_ISSUER_STATUS`), `objects.rs` | `measured::factory_attestation_key_status_is_generated` (was `factory_attestation_key_status_is_imported`), `measured::response_chaining_and_the_end_of_it`, `public_objects::application_related_data_layout_matches_observation` | `openpgp-get-006e`, `chain-61xx`, `chain-extended-le` |
| The Security Domain's SELECT response carries `9F65 01 FF` inside `A5` (29 bytes: `6F 1B 84 08 A000000151000000 A5 0F 73 09 … 9F 65 01 FF`), in both profiles. GP Card Specification v2.3.1 §11.9.3.1 Table 11-82 makes `9F65` "Maximum length of data field in command message" mandatory in a Security Domain's FCI; `FF` is the 255-byte limit of §11.1.5, a device choice since the key sends no value. Extended and chained commands stay accepted | specification over reference. yubikit only selects the Security Domain and does not parse the FCI; no listed host parses it | the observed 25 bytes without `9F65` | lk-sd `data.rs` (`SELECT_FCI`) | `domain::select_response_follows_gp_table_11_82` (keeps the observed 25 bytes as the known difference; was `select_response_matches_reference`); lk-device `scenario_ccid::select_routes_between_all_seven_applications` | `select-sd` and the SELECT that opens `sd-get-00e0`, `sd-get-0066`, `sd-get-9f7f`, `undefined-ins-sd`, `bad-p1p2-sd`, `lc-le-sd`, `get-response-idle-sd`, `cla-variants-sd` |
| Every GlobalPlatform-class GET DATA (CLA `80`, and `84` through SCP03/SCP11) returns the whole data object (`66`, `E0`, `9F7F`, `BF21`, `FF33`/`FF34`); CLA `00`, and `04` under SCP as yubikit sends it, keeps the bare value. GP 2.3.1 §11.3.3.1: with b8 = 1 the response "shall contain the TLV coded data object", with b8 = 0 "only the value". The independent SCP03 and SCP11b known-answer vectors, which wrap `84 CA 00 66`, were recomputed for the 65-byte object | specification; on the key only plaintext `80 CA 00 66` was measured, and it already matches | unmeasured beyond plaintext `80 CA 00 66` | lk-sd `lib.rs` (`dispatch`), `manage.rs` | `domain::gp_class_get_data_returns_whole_data_objects`, `domain::proprietary_class_card_data_has_the_66_template`, `scp03::wrapped_exchange_matches_independent_known_answers`, `scp11::scp11b_matches_independent_known_answers`, `scp11::scp11b_with_the_factory_certificate` | — |
| Key information reports an OCE CA public key as `C0 06 KID KVN B0 40 F0 00` (was `B0 41`). GP 2.3.1 §11.3.3.1.1: for key type `B0` the component length is `40` for ECC 256 "excluding coding identifier '04'". PUT KEY and GENERATE answers keep their TLV length `41` | specification; the key holds no CA key, so this is unmeasured | unmeasured | lk-sd `data.rs` (`key_information`) | `scp11::ec_key_management` (`C0062101B040F000`) | — |
| A SELECT whose (unwrapped) class codes a logical channel other than the basic channel answers `6881` and changes nothing: neither the selection nor a secure channel session; CLA `FF` answers `6E00`. ISO/IEC 7816-4:1995 §5.5: a logical channel is opened by a SELECT carrying its number in the class byte, and the ATR's third software function table byte `C0` says "no logical channel" (Table 87); Table 16 `6881` "Logical channel not supported". Before, such a SELECT changed the basic channel's selection | specification; unmeasured on the key | unmeasured | lk-device `card.rs` (`select_class_refusal`); lk-sd `channel.rs` (only a basic-channel SELECT closes the channel) | `card::tests::select_on_another_logical_channel_is_refused`, `ccid::select_on_another_logical_channel_answers_6881_and_changes_nothing`, `secure_channel::encrypted_select_on_another_logical_channel_keeps_the_session`; lk-sd `scp03::encrypted_select_on_another_logical_channel_keeps_the_session` | — |
| A SELECT by DF name with an empty name (`00 A4 04 00 00`) selects the Security Domain (was `6A82`). GP 2.3.1 §11.9.2.3: "The Lc and data field of the SELECT command may be omitted if the Issuer Security Domain is being selected"; the Security Domain sits at the default ISD AID (§H.1.3) | specification; unmeasured on the key, and no listed host sends this form | unmeasured | lk-device `card.rs` (`find_applet`) | `tests::empty_df_name_selects_the_issuer_security_domain`, `tests::applet_lookup_by_df_name`, `ccid::empty_df_name_selects_the_security_domain` | — |
| `DeviceProfile::own` reports form factor `00`, `FORM_FACTOR.UNKNOWN` (new `form_factor::UNKNOWN`), in DeviceInfo tag `04` and in the PIV (`41482.3.9`) and OpenPGP (`41482.5.9`) attestation extensions; `yubikey_compat` keeps `04` | own identity: a software key has no physical shape, and `04` with firmware 5.7.x makes yubikit and ykman report a physical device model. yubikit gates nothing on the form factor except its Bio checks | `04` (USB-C Nano); every run here uses the compatibility profile, so no probe shows it | lk-core `profile.rs` | lk-core `profile::tests::form_factor_per_profile`; lk-mgmt `device_info_own_profile_matches_expected_bytes`, `device_info_yubikey_profile_matches_expected_bytes`; lk-piv and lk-openpgp `form_factor_extension_follows_the_profile` | — |

## Comparison after the changes

The engine after the changes (`engine-aligned`, same mirrored state) against the merged
physical runs: **13 of 116 probes differ, 103 are identical** (before the changes 37 and
79). These 24 became identical: `select-mgmt`, `undefined-ins-mgmt`,
`get-response-idle-mgmt`, `undefined-ins-sd`, `get-response-idle-sd`,
`get-response-idle-hsmauth`, `select-partial-aid`, `piv-verify-status-81`, `bad-p1p2-piv`,
`get-response-idle-piv`, `openpgp-get-006e`, `chain-61xx`, `chain-extended-le`,
`get-response-idle-openpgp`, `ping-7609`, `ping-max`, `lock`, `lock-expiry`, `empty-cbor`,
`message-timeout`, `client-pin-retries`, `client-pin-uv-retries`,
`selection-keepalive-cancel`, `selection-no-touch`. No probe that was identical before
differs now. The timings are in the "Engine after" column of "Timings"; all are within
`compare.py`'s tolerances, and the KEEPALIVE counts (15 before CANCEL, 300 before the
timeout) are exact.

The remaining CCID differences were checked once more with the three DeviceInfo values
below masked and the SELECT that the harness sends after a `none` answer removed: each
remaining CCID probe then differs in exactly one exchange, the `none` one.

| Probes | What still differs | Class |
| --- | --- | --- |
| `mgmt-read-config`, `bad-p1p2-mgmt`, `lc-le-mgmt` | only DeviceInfo values: tags `01` and `03` (`031E` on the key, `033B` and `031A` on the engine) and the part number in tag `13` (placeholder); page layout, tag order, lengths (52 and 42 bytes) and `6133` are identical | state-dependent (the engine cannot express capability bit `0004`) and the deliberate placeholder |
| `cla-variants-mgmt`, `-piv`, `-openpgp`, `-hsmauth`, `-sd` | the CLA `0C` command: `none` on the key, `6882` (`6982` in the Security Domain) on the engine; the exchanges after it are shifted by the harness's extra SELECT, and are otherwise identical | unclear, not adopted (no status word can be read behind macOS PC/SC) |
| `lc-le-piv-get-data` | Lc 5 with 3 data bytes: `none` on the key, `6700` on the engine; the rest is shifted the same way and otherwise identical (the cut-short tag list answers `6A82` on both) | host artifact |
| `select-odd-p2` | SELECT PIV with P2 `04`, `0C`, `02`, `01`: `6982` on the key, `9000` and the PIV template on the engine | unclear (the Security Domain was selected on the key), not adopted |
| `get-info`, `get-info-trailing-map`, `get-info-trailing-zero` | `remainingDiscoverableCredentials` 99 on the key, 100 on the engine | state-dependent (one discoverable credential on the key) |

At that point no measured behavioural difference remained open (the revision of 2026-10-12
then made some probes differ again by design; see "Comparison after the revision"). What is
left needs another measurement:
CLA `0C` with a reader that shows raw CCID messages, and SELECT with P2 other than `00`
while PIV or Management (not the Security Domain) is selected.

## Comparison after the revision

The engine after the revision by principle (`engine-reference`, the same mirrored state:
`--engine-setup usb-enabled=0x031A --engine-setup fido-pin=…`, profile
`yubikey`, probe sets `ccid-basic`, `ccid-errors`, `fido-hid`, `fido-cbor`,
`fido-timing`, `fido-presence-timeout`) against the merged physical runs: **27 of 116 probes
differ, 89 are identical** (after the changes: 13 and 103). The 13 probes that differed
then differ in exactly the same places now, except `cla-variants-sd`, which also shows the
new SELECT response; the 14 new ones each differ only where this revision decided it. No
probe became identical. Every difference:

| Probes | What differs | Class |
| --- | --- | --- |
| `mgmt-read-config`, `bad-p1p2-mgmt`, `lc-le-mgmt`, `get-info`, `get-info-trailing-map`, `get-info-trailing-zero` | unchanged since "Comparison after the changes": DeviceInfo tags `01`/`03` and the part-number placeholder; `remainingDiscoverableCredentials` 99 against 100 | key state (and the deliberate placeholder) |
| `cla-variants-mgmt`, `-piv`, `-openpgp`, `-hsmauth`, `select-odd-p2` | unchanged: the CLA `0C` command (`none` on the key) and the harness's extra SELECT after it; SELECT with odd P2 while the Security Domain was selected on the key | unclear, not adopted |
| `lc-le-piv-get-data` | unchanged: Lc 5 with 3 data bytes | host artefact |
| `cla-variants-sd` | the CLA `0C` command as before, plus the 29-byte SELECT response in the first exchange and in the harness's extra SELECT | unclear, and intentional: `9F65` (GP 2.3.1 Table 11-82, rule 1) |
| `select-sd`, `sd-get-00e0`, `sd-get-0066`, `sd-get-9f7f`, `undefined-ins-sd`, `bad-p1p2-sd`, `lc-le-sd`, `get-response-idle-sd` | only the opening SELECT: 29 bytes with `9F65 01 FF` against the key's 25; every GET DATA payload and status after it is identical (the harness sends CLA `00`, so the GlobalPlatform-class GET DATA change does not show) | intentional, SD FCI `9F65` (rule 1) |
| `piv-verify-status-81` | `6A88` against `6A80` | intentional, PIV VERIFY `81` (SP 800-73-4 §3.2.1, rule 1) |
| `openpgp-get-006e`, `chain-61xx`, `chain-extended-le` | one byte of `DE`: `81 01` against `81 02`; the chaining itself is identical | intentional, OpenPGP factory attestation key status (§4.4.3.8, rule 1) |
| `client-pin-uv-retries` | `3E` (`CTAP2_ERR_INVALID_SUBCOMMAND`) against `33` | intentional, getUVRetries (CTAP 2.1 §8.1, rule 1) |
| `empty-cbor` | `ERR_INVALID_LEN` at once on the requesting channel, the other channel's PING answered before and after CANCEL, INIT as an ordinary resync; the key: no answer, `ERR_CHANNEL_BUSY` on the other channel until INIT on the stuck one | intentional, reference defect not copied (CTAP 2.1 §11.2.4, §11.2.5.2, rule 4) |

Identical only within `compare.py`'s tolerances, and different by design:
`selection-no-touch` answers `CTAP2_ERR_USER_ACTION_TIMEOUT` 30 004.7 ms after the request,
after 315 KEEPALIVEs, against the key's 28 451.8 ms and 300 (the tolerances are 10 % and
15 %; rule 4, the 30 s design value). The other timings stay as measured: KEEPALIVE mean
interval 94.93 ms (key 94.86), first KEEPALIVE 98.96 ms (key 93.78; the engine's grid
starts when the request is processed, the host stamps add the wire round trip), the
message timeout 470.5 ms (key 469.8).

`tools/measure/common.py` named CTAP2 status `3E` `UNAUTHORIZED_PERMISSION`, which is `40`
in CTAP 2.1 §8.2; it now names `3E` `INVALID_SUBCOMMAND` and `40`
`UNAUTHORIZED_PERMISSION`. `33` stays unnamed (`?`) so that the recorded physical runs
remain comparable.

Checks after the revision: `cargo test --workspace` 2378 passed, 0 failed, 1 ignored on
macOS, 2379 passed, 0 failed, 1 ignored on Linux (Docker, offline); `cargo clippy
--workspace --all-targets` no warnings on both; `tools/license_check.py` clean;
`tools/catalog_status.py --check` clean (451 lines: 372 tested, 13 of them partly deferred
or different, 37 intentional differences, 42 deferred). On the Linux guest's real kernel,
with the compatibility profile: `uhid.sh`, `gadget.sh` and `vpcd.sh` end with rc=0 (libfido2
`fido2-token -I` prints "uv retries: undefined" for `3E` as it did for `33`). The first
`uhid.sh` attempt failed step 4 once: the hidraw node carried all 24 keyboard reports of
`Hello1World` + Enter byte for byte, but the evdev reader received only the last five key
events, consistent with an evdev client queue that overflowed while the reader was not
scheduled (host load 5 to 14 from concurrent builds, under TCG; not provable after the fact,
since `py/evdev_keys.py` does not record `SYN_DROPPED`). No OTP, uhid or daemon
code changed in this revision; the re-run passed. The own profile's form factor `00` is
covered by unit tests only: every host-tool run uses the compatibility profile.
