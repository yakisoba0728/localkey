# Measurement harness

A command-by-command comparison between the engine (`localkeyd`) and a physical YubiKey
5C Nano 5.7.4, to turn the model policies in `docs/STATUS.md` (unmeasured status words,
KEEPALIVE cadence, CTAPHID message timeout, lock answer, cancel code, touch timeouts) into
measured behaviour. The same probe sets run against both targets; `compare.py` lines the
two runs up probe by probe.

The physical side exists only because the user explicitly allowed read-only probes of the
inserted key (`docs/DESIGN.md` §13). Everything below is built so that nothing the
harness sends can change the key's state.

## Files

| File | Role |
| --- | --- |
| `guard.py` | allowlist for every APDU and CTAPHID packet (`CcidGuard`, `FidoGuard`), independent of the probe list |
| `physical.py` | the inserted key through the system PC/SC service (pyscard `smartcard.scard`) and python-fido2's HID backend; creates its own guards |
| `engine.py` | `localkeyd` over its private wire socket (spawns a daemon with a fresh state directory, or attaches to `--wire`); the same guards; `EngineSetup` (unguarded, engine only) |
| `probes.py` | the probe sets |
| `normalize.py` | redaction of a raw run into a shareable one |
| `compare.py` | probe-by-probe verdicts between two runs, Markdown and JSON |
| `measure.py` | the command line |
| `cbor.py`, `common.py` | strict CBOR codec; APDU, BER-TLV and CTAPHID helpers |
| `test_guard.py`, `test_backends.py` | unit tests (no device, no daemon) |

## Safety model

**The guard sits in the transport layer.** `PhysicalCcid` and `PhysicalFido` create their
guard in the constructor and keep it, with the device handle, in name-mangled attributes.
The only methods that send are `transmit`, `send_packet` and `send_message`, and each calls
the guard before a byte leaves; a refusal raises `GuardViolation` and nothing is sent.
There is no raw send method, no IccPowerOn/IccPowerOff, no card reset (the card is always
left with `SCARD_LEAVE_CARD`), and no OTP HID access. The engine backends use the same
guards, so every engine run is also an end-to-end proof that each probe is admitted. Only
`--engine-setup` bypasses the guard, and `measure.py` refuses it for the physical target.

The guard is an allowlist. It tracks the selected applet from the SELECTs it admitted and
their status words: only a first-occurrence SELECT (`P2 & 3 == 0`) whose AID starts with
one of the AIDs below and that answered `9000`/`61xx` selects that applet. Anything else (an
unknown or partial AID, an error, next/last occurrence, a transmit failure, a reconnect,
the start of each PC/SC transaction in shared mode) makes the selection unknown, and then
only SELECT and GET RESPONSE pass.

| Scope | Admitted |
| --- | --- |
| any applet | SELECT by AID (CLA 00, `A4 04 P2`, Lc 1..16, optional Le); GET RESPONSE `C0` without data; the undefined INS `5E`, `6E`, `93` without data; CLA `80`/`0C` on an admitted INS; CLA `10` only on a read INS, after which that INS is refused until a successful SELECT |
| Management `A000000527471117` | READ CONFIG `1D` (any P1/P2; Le/Lc variants) |
| OTP `A0000005272001` | INS `01` with P1 `10` (serial) or `13` (capabilities) only. P1 is the OTP command (`01`/`03` are slot writes), so it is never varied; only P2 and Le are |
| OATH `A0000005272101` | SELECT, GET RESPONSE, undefined INS |
| PIV `A000000308` | GET DATA `CB` with data `5C017E`, `5C035FC102` or `5C035FC107`; GET VERSION `FD`; GET SERIAL `F8`; GET METADATA `F7` with P2 `80 81 9B 9A 9C 9D 9E`; VERIFY `20` with P1 `00`, P2 `80`/`81` and an empty body |
| OpenPGP `D27600012401` | GET DATA `CA` with P1P2 `006E 0065 007A 00C4 5F52 7F74 004F` (and `0000`/`3FFF` as wrong-P1P2 probes); VERIFY `20` with P1 `00`, P2 `81`/`82`/`83` and an empty body |
| HSM Auth `A0000005272107` | SELECT, GET RESPONSE, undefined INS |
| Security Domain `A000000151000000` | GET DATA `CA 00E0`, `CA 0066`, `CA 9F7F` (and `0000`/`3FFF`) |
| CTAPHID | INIT (BCNT 8); PING (any BCNT, any CID including 0 and broadcast: the malformed-framing probes); WINK (BCNT 0); LOCK 0..10 s; CANCEL; the invalid commands `3F`, `3E` (BCNT ≤ 57); raw CBOR/MSG init packets only with BCNT ≤ 57 and admitted content; continuation packets unless they would continue an approved or interrupted CBOR/MSG message |
| CTAP2 (CBOR) | getInfo `04` (up to 16 trailing bytes); clientPIN `06` with keys {1, 2} only and subCommand 1, 2 or 7; selection `0B`; getAssertion `02` with keys {1, 2, 3, 5}, an rpId ending in `.invalid` and options exactly `{up: false}`; the unassigned commands `03`, `05`; an empty payload |
| U2F (MSG) | VERSION (`03`, no data); AUTHENTICATE (`02`) with P1 `07` (check-only) only; the unknown INS `05`, `3F` without data |

Read commands accept Lc/Le variants only in a fixed shape: a length header (1 byte, or
`00` and 2 bytes, whatever value it claims), one *complete* admitted data field, and at
most 2 trailing bytes; reads without data accept only an Le (or `01 00`). A data field is
never admitted in part, so no reading of the bytes can name another object.

**Never sent** (each is a refusal test in `test_guard.py`): PIV `47 DB 87 FE FB FF FA 24 2C
F9 F6` and VERIFY with data or P1 `FF`; OpenPGP `E6 44 DA DB 2A 88 47 84 24 2C F1` and VERIFY
with data or P1 `FF`; Security Domain `50` (INITIALIZE UPDATE bumps a persistent counter),
`82 88 2A D8 E4 E2 F0`; Management `1C 1F 16`; OTP slot writes and every OTP command but
`10`/`13`; every OATH and HSM Auth command but SELECT; CTAP2 makeCredential, reset,
getNextAssertion, bioEnrollment, credentialManagement (and the `40`/`41` previews),
largeBlobs, config, clientPIN subcommands 3, 4, 5, 6, 8, 9; U2F REGISTER and AUTHENTICATE
with P1 other than `07`; CTAPHID commands in the vendor range `40`–`7F` (Yubico's
configuration commands are `40`, `42`, `43`).

Multi-packet CBOR/MSG messages only go through `send_message`: the guard checks the whole
payload, registers the exact fragments, and each fragment must then match byte for byte. A
raw CBOR/MSG init packet that would need continuations is refused, and a CID whose approved
message was interrupted refuses raw continuations for the rest of the session.

### Deviations from the original probe plan

- The invalid-CTAPHID-command probe uses `3F` and `3E`, not `7F`: `40`–`7F` is the vendor
  range, where YubiKeys carry configuration commands.
- The unknown-CTAP2-command probe uses `03` and `05`, not `40`: `40` is the bioEnrollment
  preview and `41` the credentialManagement preview (the alias of the hard-blocked `0A`).
- SELECT probes vary P2 only. `A4` with P1 other than `04` is CALCULATE ALL in OATH.
- The basic SELECT probes send the AIDs yubikit sends (HSM Auth `A000000527210701`); the
  7-byte `A0000005272107` is one of the partial-AID probes.

## Probe sets

`python3 tools/measure/measure.py --list` prints every probe. In short:

- `ccid-basic` (39): ATR; SELECT of each applet and an unassigned AID; READ CONFIG pages
  0/1; OTP serial and capabilities; PIV version, serial, discovery, CHUID, CCC, metadata of
  PIN/PUK/management key/9A/9C/9D/9E, VERIFY status 80/81; OpenPGP GET DATA of the seven
  DOs (61xx followed), VERIFY status 81/82/83; Security Domain key information, card data,
  CPLC.
- `ccid-errors` (37): undefined INS per applet; CLA 80/0C/10 per applet (with the
  interrupted-chain behaviour); wrong P1/P2; Lc/Le variants including extended forms and
  mismatches; GET RESPONSE with nothing pending; SELECT with P2 04/0C/02/01 and with Le;
  partial AIDs; a 61xx chain with a short GET RESPONSE in the middle; extended Le.
- `fido-hid` (20): INIT broadcast and resynchronisation; PING of 0, 1, 57, 58, 7609 bytes;
  PING with BCNT 7610 and 0xFFFF; WINK; idle CANCEL; invalid commands; wrong and skipped
  SEQ; continuation without init; CID 0; PING on the broadcast CID; busy across two
  channels; LOCK (other channel, broadcast INIT, holder, expiry, LOCK 0).
- `fido-cbor` (15): getInfo; clientPIN getPINRetries, getKeyAgreement (protocols 2 and 1),
  getUVRetries; unknown commands; getInfo with trailing bytes; empty CBOR; getAssertion with
  `up:false` and a random `*.invalid` rpId; U2F VERSION, check-only AUTHENTICATE with a
  random key handle, wrong CLA, unknown INS.
- `fido-timing` (3): selection with every KEEPALIVE timestamped for 1.5 s, then CANCEL
  (final answer and delay); the message timeout of a withheld 100-byte PING (up to 5 s);
  LOCK 1 s and 2 s expiry, polled every ~20 ms.
- `fido-presence-timeout` (1, opt-in, not in `all`): selection without a touch until the
  device answers (up to 45 s).

**Do not touch the key during `fido-timing` and `fido-presence-timeout`.** A touch answers
selection with success (harmless, but the measurement is lost).

## Running

Python 3.13 with python-fido2 2.x and pyscard 2.x (physical side) in a virtual
environment. Write runs outside the repository; only redacted files may be committed.

Engine (builds nothing; `localkeyd` from `target/debug` unless `--localkeyd` is given). The
daemon gets a fresh state directory and storage key in a short temporary directory
(`--tmp-base`; Unix socket paths are limited to 104 bytes on macOS) and is stopped by
closing its stdin (`--exit-on-stdin-eof`). `--engine-setup` mirrors the physical key's
observable state; the physical key reports PID `0406` (FIDO+CCID) and `clientPin: true`:

```sh
python3 tools/measure/measure.py --target engine --probes all \
    --engine-setup usb=fido,ccid --engine-setup fido-pin=<any PIN> \
    --out RUNS --label engine-1
```

`usb=IFACES` writes USB_ENABLED (the supported capabilities of the listed interfaces) with
REBOOT through Management WRITE CONFIG and waits for the re-enumeration;
`usb-enabled=0xNNNN` writes an exact capability mask. `fido-pin=PIN` runs clientPIN setPIN
through python-fido2's `ClientPin` over the wire socket.

Physical (needs `--allow-physical`; refuses `--engine-setup`, `--wire`, `--localkeyd`):

```sh
python3 tools/measure/measure.py --target physical --allow-physical --probes all \
    --out RUNS --label physical-1
python3 tools/measure/measure.py --target physical --allow-physical \
    --probes fido-presence-timeout --out RUNS --label physical-presence
```

The CCID backend opens the one reader whose name contains "YubiKey" exclusively, falling
back to shared access with one PC/SC transaction per probe. The FIDO backend opens the one
Yubico FIDO HID interface. On macOS, python-fido2 reads each report through a run loop that
is scheduled per read, so report timestamps are taken in the IOKit callback; the timing
resolution is still that of the host stack.

Compare:

```sh
python3 tools/measure/compare.py RUNS/engine-1-redacted.json RUNS/physical-1-redacted.json \
    --md RUNS/engine-vs-physical.md --json RUNS/engine-vs-physical.json
```

Tests (no device, no daemon):

```sh
python3 -m unittest discover -s tools/measure -p 'test_*.py'
```

## Output and redaction

`LABEL-raw.json` holds every byte and timestamp; keep it out of the repository.
`LABEL-redacted.json` is the shareable form (`normalize.py`). Redacted bytes are written
as `xx`, so lengths and positions survive. The rules are fail-closed: a CCID response whose
command form has no rule is redacted completely.

- Serial: collected from READ CONFIG tag `02`, OTP serial/capabilities, PIV GET SERIAL and
  the OpenPGP AID, then removed from every response in its 4-byte big-endian, 8-digit BCD
  and ASCII-decimal forms.
- OATH SELECT: name/device id `71`, challenge `74`.
- PIV: CHUID `30` (FASC-N), `32`, `33`, `34` (GUID), `36`, `3E`; CCC card identifier `F0`;
  GET SERIAL; GET METADATA public key `04`.
- OpenPGP: AID serial bytes, fingerprints `C5`/`C6`, generation times `CD`, cardholder
  name `5B` and language `5F2D`, signature counter `93`.
- Security Domain CPLC: everything after the first 10 bytes (IC fabricator, type, OS id,
  release date and level stay).
- SELECT of a partial or unknown AID, or with next/last occurrence: all data.
- 61xx/GET RESPONSE chains are reassembled before the rules apply.
- CTAPHID: packets keep only their headers (CID alias, command or SEQ, BCNT). Messages are
  rendered: INIT nonces as lengths and CIDs as aliases (`cid1`, …); PING payloads as a hash
  (they are the harness's own patterns); CBOR byte strings as `xx` except in getInfo (the
  AAGUID is kept) and clientPIN retries; text as `<text:N>` except in getInfo; the
  getKeyAgreement COSE key coordinates as `xx`; the rpId as `<random:N>.invalid`; U2F data
  as `xx` except `U2F_V2`.

`compare.py` verdicts are `identical` (every non-timing feature equal, every timing within
tolerance) or `differs` with the differing features. Tolerances: KEEPALIVE interval mean
±15 ms, stdev ±20 ms, min/max ±50 ms; other `*_ms` values ±max(50 ms, 10 %); counts
±max(2, 15 %).
