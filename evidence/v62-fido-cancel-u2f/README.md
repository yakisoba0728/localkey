# CTAPHID_CANCEL must leave U2F operations running

The [FIDO CTAP 2.1 specification](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html), §11.2.9.1.5, requires a CTAPHID_CANCEL received while no CBOR request is being processed to be ignored. An INIT on the active CID can still abort any transaction under §11.2.5.3.

Published v0.61 canceled the in-flight token for any command on the same CID. A U2F `REGISTER` APDU waiting in a card-profile RPC therefore returned `6985` after CANCEL, even when software user presence was approved. `source.patch` restricts CANCEL token cancellation to CBOR while preserving INIT resynchronization for U2F. `test.patch` checks both boundaries with a deterministic slow U2F worker.

Private Unix-socket A/B on Mac and no-NIC Linux ARM64, plus actual FIDO endpoints 0x04/0x84 in an owned no-NIC dummy_hcd guest, produced `6985` on the baseline and a valid U2F registration ending `9000` with the candidate. Fresh PING succeeded after each operation. Mac and Linux focused tests passed 2 cases / 19 assertions; both full suites passed 138 cases / 13,706 assertions. `validation.json` records source/binary and raw-evidence hashes.

The Linux guest used a frozen v58 card service and bridge, overlaid with the published v0.61 or candidate v0.62 FIDO daemon. User presence came from a software test approval or owned pseudo-terminal; no physical touch sensor was involved. The physical YubiKey firmware and production USB controllers were not measured.
