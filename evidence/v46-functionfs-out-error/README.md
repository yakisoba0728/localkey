# FunctionFS OUT negative-completion recovery evidence

The v0.46 Linux bridge applies `source.patch` to the v0.44/v0.45
Linux source. A completed AIO `PREAD` with `res` equal to `-EPIPE`,
`-ESHUTDOWN`, or `-ECONNRESET` now retries the same OUT buffer after a short
wait. A negative IN completion still fails closed because some response bytes
may already be visible to the host.

The private no-NIC ARM64 QEMU fault shim fabricated each negative completion
without submitting that request to the kernel. For all three errors, the
v0.45 bridge exited and the v0.46 bridge passed 28/28 native OTP/HID/CCID
checks after one retry. An injected IN `-EPIPE` still failed closed without a
retry. Without injection, the candidate passed focused long/ZLP cutover 82/82
and six-endpoint halt, three-reset, pending-CCID state 91/91. Raw results and
hashes are in `fault-validation.json`; the corresponding consoles are the
`*-before.log` and `*-after.log` files in this directory. The IN control and
normal-run consoles are `in-epipe-fail-stop.log`, `normal-long.log`, and
`normal-state.log` here.

The final v0.45 card snapshot and this bridge also passed in one private
no-NIC guest boot: native OTP/HID 28/28, stock libccid/PCSC/SDK 122/122,
valid X.509 boundary 8/8, and three separate fault-injected OTP/HID runs at
28/28 each. The combined input hashes, raw console SHA-256 and parsed result
are `combined-inputs.json`, `combined-console.log`, and `combined-result.json`
in this directory. The fault shim does not establish that real
FunctionFS or production hardware returns these errors in the same situation.
No finite run proves elimination of the saved rare kernel panic.
