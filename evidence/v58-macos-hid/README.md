# v0.58 macOS CTAPHID input candidate

The published v0.57 `IOHIDUserDevice` callback accepted short reports by
zero-padding them, truncated long reports, and silently discarded the oldest
accepted report after 32 pending reports. This could break a multi-report
CTAPHID transaction while reporting success to the host. The [FIDO CTAP 2.1
transport specification](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#usb-transports)
says packets have the fixed length declared by the HID report descriptor, and
the 64-byte configuration allows a maximum 7609-byte message in 129 reports.

The isolated patch accepts exactly 64 bytes, or 65 bytes when the first byte
is a zero Report ID prefix, and rejects other shapes. It gives the inbox room
for 256 reports and returns `kIOReturnNoResources` on overflow instead of
dropping an accepted packet. Apple's
[`IOHIDDeviceSetReport` documentation](https://developer.apple.com/documentation/iokit/1588656-iohiddevicesetreport)
describes the report ID and report length supplied by a host. Only report ID
zero is valid for this descriptor, which declares no Report ID.

`source.patch` applies to the published v0.57 source. On macOS, the isolated
candidate compiled `swpasskeyd`, `ske-usbd`, and the C++ suite, which passed
131 cases and 13,585 assertions. The new tests cover full-length and prefixed
reports, reject truncated/oversized/nonzero-ID reports, and verify that
overflow never changes the order of accepted packets. Unmodified pyfido2
passed 82 CTAP checks through the private Unix socket.

The user has no Apple development signing and provisioning for
`com.apple.developer.hid.virtual.device`. These tests do not register an OS HID
device, exercise the IOKit callback itself, or prove actual macOS browser
recognition. A signed entitled build and independent OS clients are still
needed for that claim.
