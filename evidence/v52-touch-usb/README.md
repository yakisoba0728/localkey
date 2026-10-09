# Linux FunctionFS software-touch keyboard bridge

The private card socket accepts software `touch_down`/`touch_up` events. While a FunctionFS bridge is subscribed, the service queues their OTP keyboard reports for the bridge to send on the USB keyboard IN endpoint. The queue is scoped to the current USB generation and active subscriber; reconnect and profile changes discard stale reports. Existing explicit button requests continue to return reports to their caller.

`result.json`, `inputs.json`, and `console.log` record the isolated no-NIC dummy_hcd candidate guest. It passed 12 touch-to-evdev checks, 28 OTP/keyboard checks, 122 stock libccid checks, 8 X.509 checks, 6 CTAP enterprise checks, and 49 checks across seven USB profiles. `uhid/result.json` and `uhid/console.log` record a separate 25-check regression with the existing `ske-otpd` UHID bridge. The final combined v0.52 source and binaries are tested in `../v52-integration/guest/`.

These tests use a software touch RPC and a private guest. They do not measure a physical sensor, external host, production USB device controller, or YubiKey 5C Nano firmware timing.

`reset/result.json` records a same-generation USB unbind/rebind A/B test. Before the reset guard, a touch sent while disconnected replayed Enter on guest evdev after reconnection. The bridge now tells the card service to discard its queued keyboard reports on USB reset. The same guest procedure then observed no stale keys, while a fresh touch still typed correctly. The reset test also checks subscriber ownership and malformed reset frames; `reset/cpp-tests.log` records 121 C++ cases and 11,631 assertions for the modified bridge build.
