# CTAP 2.1 unknown option values

The CTAP 2.1 [message encoding rules](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#message-encoding) require an authenticator to ignore map keys it does not recognize. The shared options parser recognized only `rk`, `up`, and `uv`, yet decoded every value as a boolean before checking its key. A valid unknown key with an integer or nested value was therefore rejected as `CTAP2_ERR_CBOR_UNEXPECTED_TYPE` (`0x11`).

`source.patch` skips only unrecognized option values. Recognized options still require booleans. `verify_unknown_options.py` sends raw CBOR through the unmodified pyfido2 CTAPHID client over a private Unix socket; `baseline.json` and `fixed.json` record before/after status bytes. No physical key or host HID path was used. The candidate Mac C++ suite passed 124 cases and 12,422 assertions (`cpp.log`). Exact physical YubiKey 5.7.4 handling of unknown option values is unmeasured.
