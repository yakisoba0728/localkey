# CTAPHID WINK length guard

The [FIDO CTAP 2.1 HID command specification](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#ctaphid_wink_0x08) defines `CTAPHID_WINK` with `BCNT=0` in both request and successful response. Published v0.58.0 accepted a one-byte WINK and returned success. The v0.59 source checks the assembled payload before replying and uses the standard `ERR_INVALID_LEN` model response for a nonzero length.

The added C++ regression first failed against the published v0.58 source (`baseline-wink.log`, response command 0x08), then passed with the patch along with 134 tests and 13,622 assertions (`fixed-unit.log`). The independent private Unix CTAPHID socket reproduction confirms that the published macOS daemon returns WINK for the malformed request, while the integrated macOS and Linux daemons return `CTAPHID_ERROR/0x03`. A valid zero-length WINK and a fresh PING succeed after rejection. See `tools/verify_hid_wink.py` and `evidence/v59-integration/hid-wink-{mac,linux}.json`.

This is source-backed protocol behavior, not a physical YubiKey 5C Nano 5.7.4 differential measurement. The exact firmware response and precedence for a malformed WINK remain unmeasured. No physical security key or host USB/HID device was accessed.
