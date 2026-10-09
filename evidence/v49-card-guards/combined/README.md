# v0.49 combined card candidate

This isolated candidate copies `emucard/` and `tools/` from the read-only v0.48 staging tree, then applies the YubiHSM Auth RESET APDU-shape patch and OATH PUT minimum-key patch. The pre-existing `work/v49-card-combined-candidate/` root held an older candidate, so this integration is kept under `v48-base-v49-patches/`. The only production card file changed is `emucard/core.py`.

`results/combined-validation.json` records the input core SHA-256 `0e7595b17ea9709fab195fcfbbf43653a8d1af455cbe75d6f0181661424c7f1a`, output core SHA-256 `4d2b50bf7a1a616696c66e1da1171f0b394a1c1a41b7e27323a7ba86eaa0f1d1`, and both patch hashes. Independently reapplying the two patches to a fresh temporary v0.48 core reproduced the combined file byte for byte.

All focused and regression reports passed: HSM Auth RESET 24/24 over private socket and 24/24 over direct IFD; OATH PUT minimum 11/11 over in-memory card/private socket; OATH profile 107/107 over each transport; smartcard SDK 97/97 over each transport; buttons 44/44; prior HSM Auth retry deletion 24/24 over each transport. These are 559 assertion checks, including repeated scenarios across transports, not 559 unique firmware behaviors.

The focused HSM Auth reports verify that malformed RESET leaves encrypted state bytes and stored credentials unchanged while normal YubiKit reset still clears them. The OATH report verifies a raw 13-byte PUT secret is rejected without mutation, a 14-byte secret is accepted, and high-level YubiKit pads shorter source secrets. These are private software tests only; physical firmware 5.7.4 tolerance and exact error statuses remain unmeasured. No physical key or host PC/SC/USB device was accessed.
