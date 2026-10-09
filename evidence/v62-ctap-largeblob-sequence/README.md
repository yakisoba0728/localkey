# v0.62 isolated CTAP large-blob sequencing candidate

CTAP 2.1 §6.10.3 requires sequence validation before PIN/UV verification for a serialized large-blob write. It also sets a new sequence length when `offset=0`, even if subsequent authentication fails. The published v0.61 engine checked PIN first and left an old pending write usable after an unauthenticated restart attempt.

The isolated patch changes this order. A deliberately wrong offset without auth now returns `CTAP1_ERR_INVALID_SEQ` (`0x04`) rather than `CTAP2_ERR_PUAT_REQUIRED` (`0x36`); the correct next fragment still succeeds. Starting a new write without auth still returns `0x36`, and a continuation of the earlier write then returns `0x04`. Committed blob contents remain intact. The same before/after was reproduced with unmodified python-fido2 over private CTAPHID sockets on macOS and a `--network none` ARM64 Linux container. Both candidate C++ suites passed 136 cases and 13,687 assertions. No physical key or host USB/HID/PCSC was opened. The physical 5.7.4 error precedence was not measured.

[Official CTAP 2.1 specification](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorLargeBlobs). Machine-checkable A/B records and hashes are in `summary.json`.
