# YubiHSM Auth credential touch-policy syntax

Base: published v0.52.0 `outputs/security-key-emulator`. Only `emucard/core.py` changes. `source.patch` applies with `patch --dry-run -p1`; the published source and package are untouched.

Yubico's [Add credential command reference](https://docs.yubico.com/yesdk/users-manual/application-yubihsm-auth/commands/add-credential.html) defines tag `0x7a` as a **one-byte** Boolean touch policy: `0` means no touch and `1` means touch required. It lists `0x6a80` for wrong syntax. The published emulator converted the first byte to a Python Boolean without checking its value or the tag length, so `02`, `ff`, and `01 00` were all accepted and stored as touch-required credentials.

The patch validates the optional touch-policy value as exactly one byte and either `0` or `1` before storing a credential. The previous absent-tag default remains `0`, and valid YubiKit requests are unchanged. Invalid values return SW=`6a80` without adding a credential.

`verify_hsmauth_touch_policy.py` configures valid no-touch and touch-required credentials through independent YubiKit, checks their listed policies, and compares SDK symmetric session-key derivation with `python-yubihsm`. It sends three malformed tag values through the SDK's raw APDU interface. Published v0.52.0 matches **4/10** expectations and accepts all three invalid values; the candidate matches **10/10**. Candidate regressions: full smartcard SDK/crypto suite **97/97** and OATH profile **107/107**, totaling **204/204**.

This is a documentation-backed protocol acceptance fix. A physical YubiKey 5.7.4 has not been tested, so the exact firmware response to those malformed values is not claimed as measured. Tests use only a private local CCID socket; no host PC/SC, USB/HID device, Keychain, or physical key was accessed.
