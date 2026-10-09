# PIV mutating-command Le guards candidate

Yubico documents the PIV GENERATE (`00 47`), IMPORT (`00 FE`) and PUT DATA
(`00 DB`) commands with an absent `Le`:
https://docs.yubico.com/yesdk/users-manual/application-piv/apdu/generate-pair.html
https://docs.yubico.com/yesdk/users-manual/application-piv/apdu/import-asym.html
https://docs.yubico.com/yesdk/users-manual/application-piv/apdu/put-data.html

The published v0.46 software model accepted three explicit `Le` encodings for
each command and changed slot 9A's private key or the target PIV object. The
isolated candidate rejects them before mutation and leaves state unchanged.
The documented commands without `Le` still succeed. `baseline.json` and
`candidate.json` contain the 12-case direct before/after results. The independent
Yubico SDK PIV profile passes 60/60 through a private CCID socket and 60/60
through the direct IFD bridge; its raw logs and reports are kept here.

This is a documented APDU-shape model. The exact status word and handling of
these malformed commands by physical YubiKey 5C Nano firmware 5.7.4 remain
unmeasured. No physical key or host PC/SC reader was used.
