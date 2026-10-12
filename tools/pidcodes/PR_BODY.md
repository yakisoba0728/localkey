Request one PID, `1209:4c4b`, for localkey, an independent Rust software security
key with a Linux USB ConfigFS/FunctionFS composite-device implementation.

Source and USB descriptors: https://github.com/yakisoba0728/localkey
License: https://github.com/yakisoba0728/localkey/blob/main/LICENSE (Apache-2.0)
Transport and desktop verification: https://github.com/yakisoba0728/localkey/blob/main/docs/STATUS.md

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
