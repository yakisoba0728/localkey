# v0.47 combined OpenPGP validation

Read-only validation of `work/security-key-emulator-v47-candidate/security-key-emulator/emucard/core.py`, SHA-256 `4f8fa1def2c7709cc4dfb0250222dcc210c86141e802c9981c2792d71b8fd1d2`.

| Suite | Private CCID socket | Direct IFD ABI |
| --- | ---: | ---: |
| TERMINATE DF / ACTIVATE FILE explicit-Le and normal SDK reset | 28/28 | 28/28 |
| Existing VERIFY / CHANGE REFERENCE DATA APDU headers | 21/21 | 21/21 |
| Existing RESET RETRY COUNTER explicit-Le handling | 36/36 | 36/36 |

All six reports show `passed: true` and zero mismatches. The lifecycle reports independently identify the combined source hash, and include malformed APDU state immutability and normal Yubico SDK reset recovery. The regression adapters were read from `work/v47-openpgp-candidate/tools`; their service fixture executed the combined candidate root. No physical key, host PC/SC, or USB device was accessed. Exact firmware 5.7.4 rejection status and tolerance remain unmeasured.
