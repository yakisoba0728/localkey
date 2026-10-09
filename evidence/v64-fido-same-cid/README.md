# v64 isolated CTAPHID same-channel transaction atomicity candidate

Source baseline: locally published v0.62.0. Product change is confined to
`source/src/ctap/hid_device.cpp`; `source.patch` is the reviewable patch. The
new tests are in `tests.patch`. No published output or shared staging was
modified.

The FIDO CTAP 2.1 specification §11.2.2 says a transaction consists of a
request and response, and a second transaction cannot take place until the
first completes or aborts. §11.2.5.3 explicitly permits same-channel INIT
resynchronization and CANCEL. Source:
https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html

Published v0.62 allowed same-channel PING and WINK to reply successfully while
a CBOR worker was still processing that channel. This interleaved an unrelated
request/response pair into an unfinished transaction. A held-card-RPC socket
probe reproduced it on both the published macOS and Linux daemons. The patch
rejects a second initialization packet on the busy CID with CTAPHID_ERROR
CHANNEL_BUSY (0x06), while preserving same-CID INIT and CANCEL. The exact
error byte of physical YubiKey 5C Nano firmware was not measured; 0x06 matches
the implementation's existing busy handling for a second CBOR command.

Validation:

- Baseline with new focused C++ tests: 2 failures/18 assertions, both caused
  by successful PING replies during the original CBOR transaction.
- Fixed focused C++ tests: 42 assertions/2 cases on macOS and Linux.
- Fixed full C++ suites: 13,748 assertions/140 cases on macOS and Linux.
- Fixed independent Yubico python-fido2 private-socket suite: 82/82 checks.
- Mac and Linux private-socket A/B: held CBOR; baseline PING 0x81 and WINK
  0x88; fixed both CTAPHID_ERROR 0x06; original CBOR completes and idle PING
  succeeds in all runs.

The socket and USB probes use disposable emulator state. They do not enumerate
host HID, USB, PC/SC, Keychain, or the physical key. The USB probe uses only an
owned no-NIC QEMU dummy_hcd instance and a frozen private guest image. Its
individual raw consoles, inputs, and result summaries are in
`usb-same-cid-baseline/` and `usb-same-cid-fixed/`.
