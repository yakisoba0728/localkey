# v0.48 YubiHSM Auth credential exhaustion candidate

The published v0.47 software card decrements a credential's password retries to zero after eight failures but leaves the credential stored. It remains visible in `LIST` and prevents the same label from being registered again. [Yubico's YubiHSM Auth credential documentation](https://docs.yubico.com/yesdk/users-manual/application-yubihsm-auth/objects/credential.html) and [Get AES-128 Session Keys command](https://docs.yubico.com/yesdk/users-manual/application-yubihsm-auth/commands/get-aes128-session-keys.html) specify permanent credential deletion after eight failed password attempts. Management-key exhaustion has different semantics and is unchanged.

`source.patch` changes only the YubiHSM Auth password-failure branch of `emucard/core.py`: when retries reach zero, it removes that credential and any corresponding ephemeral challenge before returning the existing `63C0` status. Other credentials and the management-key counter are untouched. The patch applies cleanly to published v0.47. Published base core SHA-256: `4f8fa1def2c7709cc4dfb0250222dcc210c86141e802c9981c2792d71b8fd1d2`; candidate: `de0d8a7626123b16fa53d1acac6e0b0f450c3e26ac98584339e6f0a922ec99da`.

`tools/verify_hsmauth_retry_deletion.py` uses the unmodified YubiKit SDK over a private CCID socket and the direct IFD ABI. It checks symmetric session-key calculation and asymmetric host-challenge paths independently. Both first show retries `7..1`, recovery to eight after a correct password, then retries `7..0` on eight further failures. The v0.47 baseline retains a listed zero-retry credential after restart and rejects registration of the same label. The candidate omits that credential after restart and permits a fresh credential under the label. A peer credential still derives valid keys, and management retries remain eight.

| Evidence in `results/` | Private socket | Direct IFD |
| --- | ---: | ---: |
| Before reproduction, published v0.47 | 24/24 | 24/24 |
| Candidate deletion and recovery | 24/24 | 24/24 |
| Existing smartcard SDK regression | 97/97 | 97/97 |

The reports include source hashes for the focused checks and `physical_key_accessed: false`. The existing regression also covers normal HSM Auth derivation, asymmetric receipt, management-key change, and application reset. No physical YubiKey or host PC/SC/USB device was accessed. The physical firmware 5.7.4 response status on the eighth failure, deletion timing, and power-loss behavior remain unmeasured; `63C0` is retained as this emulator's status contract. Existing zero-retry rows from older software-state files are not migrated by this patch.
