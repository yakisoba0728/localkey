# PIV Printed object: conflicting official descriptions

Yubico's PIV commands page says the YubiKey does not allow `PUT DATA` to `Printed` (0x5FC109):
https://docs.yubico.com/yesdk/users-manual/application-piv/commands.html

Yubico's more detailed GET/PUT DATA page says the low-level `PUT DATA` command accepts `Printed`, warns that overwriting it can make a YubiKey unusable, and distinguishes SDK policy from device behavior:
https://docs.yubico.com/yesdk/users-manual/application-piv/get-and-put-data.html

An isolated candidate rejected this write and passed its own SDK regression, but it was deliberately not promoted. The detailed low-level documentation supports accepting the raw APDU, while the SDK's write restriction is a client policy. The exact response of the reference firmware remains unmeasured. The v0.55 release retains v0.54 behavior for this APDU and tracks physical fidelity as an unresolved question. No physical key was used or modified.
