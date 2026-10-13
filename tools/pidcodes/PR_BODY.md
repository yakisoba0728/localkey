Request one PID, `1209:4C4B`, for localkey, an independent Rust software security
key with a Linux USB ConfigFS/FunctionFS composite-device implementation.

Source and USB descriptors: https://github.com/yakisoba0728/localkey
License: https://github.com/yakisoba0728/localkey/blob/main/LICENSE (Apache-2.0)
Transport and desktop verification: https://github.com/yakisoba0728/localkey/blob/main/docs/STATUS.md
Linux CI: https://github.com/yakisoba0728/localkey/actions/runs/38323529249

Both native Linux CI jobs passed for commit
`1a2de8ddf7a8a2734dcee5d86cf7403766351604`: x86_64 and aarch64, 2,390 Rust
tests per architecture, license checks, desktop/installer tests and static-musl
bundle staging. The recorded desktop VMs also verified real Chromium and Firefox
registration/login, PIN and resident keys, installation, upgrade and recovery.

This is software only, with no PCB files. A common project identity lets USB
gadget-capable boards expose the same report/descriptor contract, enables narrow
udev rules, and avoids using the commercial reference device's identity. One PID
will cover its supported interface combinations. UHID also supports same-host
desktop use. The project does not claim hardware key isolation, physical presence
or manufacturer-trusted attestation.

The current default remains the private-test PID `1209:0001`. Public binary
packaging is blocked until allocation, implementation of the assigned identity,
and repeat verification. The candidate has not been treated as reserved or used
in the application. The organization and PID page drafts are included in this
request.

On 2026-10-13 the complete upstream tree at
`39bfde8f3f8520b74c276e6a5c7f0c95c0098d33` and open pull requests had no conflict
for `1209:4C4B` or `org/localkey`. The public source, license and verification
documents were checked without GitHub authentication.
