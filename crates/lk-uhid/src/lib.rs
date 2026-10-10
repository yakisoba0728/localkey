//! Linux UHID transport (`docs/PROGRAM.md` "lk-uhid"): the engine's FIDO HID and OTP HID
//! interfaces as two kernel HID devices created through `/dev/uhid`.
//!
//! - [`event`]: `struct uhid_event`, encoded and decoded byte for byte. Pure.
//! - [`report`]: the report-number rule between UHID report data and the engine's reports.
//!   Pure.
//! - [`UhidIo`], [`DevUhid`]: opening the device file; tests hand out socket pairs instead
//!   and play the kernel.
//! - [`UhidTransport`]: the [`lk_run::Transport`] on top, with a reader and a writer thread
//!   per device.
//!
//! Only files are used (no `ioctl`, no `unsafe`), so the crate builds and its tests run on
//! every Unix; it is useful on Linux only (`localkeyd` refuses it elsewhere). The kernel
//! facts come from the UAPI headers, the kernel documentation and the driver sources named
//! below, and the tests play the kernel over `UnixStream::pair()` (`docs/PROGRAM.md`
//! "Linux transports"). It has been **run on a real kernel** only as far as "Settled on a
//! real kernel" below says; the rest is still unverified.
//!
//! # Report numbers
//!
//! The engine's report descriptors declare no Report ID item, so all their reports are
//! report number 0 and `UHID_START` carries no `UHID_DEV_NUMBERED_*` flag (`uhid_hid_start`
//! sets a flag only for a report type the HID core found numbered, `drivers/hid/uhid.c`).
//! What arrives depends on who sends:
//!
//! - `Documentation/hid/uhid.rst` says that without the numbered flag "no prefix is added
//!   by the kernel". That holds for the kernel's own report paths: the HID core builds a
//!   report with the number in front only when the report has an ID (`hid_output_report`),
//!   so the input layer's keyboard LED report arrives as one byte.
//! - hidraw does not add or remove anything: `hidraw_send_report` passes the caller's
//!   buffer, whose first byte is the report number (0 for an unnumbered device,
//!   `Documentation/hid/hidraw.rst`), verbatim to `uhid_hid_output_report` (`write()`) or,
//!   with `buf[0]` as the report number, to `uhid_hid_set_report` (`HIDIOCSFEATURE`), and
//!   uhid copies all `count` bytes into the event (`drivers/hid/hidraw.c`,
//!   `drivers/hid/uhid.c`). The USB driver strips that leading 0 before the wire
//!   (`usbhid_output_report`, `usbhid_set_raw_report` in `drivers/hid/usbhid/hid-core.c`);
//!   uhid does not. A FIDO client writing `00` + 64 bytes to hidraw (as CTAP clients do)
//!   therefore produces a 65-byte `UHID_OUTPUT` starting with `00`, and `HIDIOCSFEATURE`
//!   with `00` + 8 bytes a 9-byte `UHID_SET_REPORT` with `rnum` 0.
//! - `HIDIOCGFEATURE`: `hidraw_get_report` copies the reply data verbatim from offset 0 to
//!   the caller. usbhid keeps the report number in byte 0 and puts the report from byte 1
//!   (`usbhid_get_raw_report`), and hidraw callers written for real keys read it there. The
//!   reply is therefore the report number, then the 8 bytes (9 bytes in all). Note that
//!   `Documentation/hid/hidraw.rst` says the data of an unnumbered report "will begin at
//!   the first byte"; the driver code says otherwise, and this crate follows the code.
//!
//! Conclusion ([`report`] implements it; confirmed on a real kernel, see "Settled on a real
//! kernel"): FIDO output of 64 bytes, or 65 with a leading `00` (stripped), is accepted,
//! any other output is dropped; an OTP feature SET_REPORT with report number 0 of 8 bytes,
//! or 9 with a leading `00`, is accepted; GET_REPORT(feature) is answered with `00` + the
//! 8 bytes. Input reports go out without a prefix (64 bytes FIDO, 8 bytes OTP keyboard),
//! as an unnumbered report is read from hidraw.
//!
//! # As built
//!
//! Choices where `docs/PROGRAM.md` leaves room:
//!
//! - The size of `struct uhid_event` is computed for the target (4380 bytes where a `__u64`
//!   is 8-aligned, 4376 on i386), and every field is host byte order ([`event`]).
//! - Re-enumeration is an unplug and a new plug-in: every device of the previous
//!   enumeration gets `UHID_DESTROY` and its file is closed once its reader has seen the
//!   following `UHID_STOP`; every interface the new identity enables gets a new file and
//!   `UHID_CREATE2`. (`Documentation/hid/uhid.rst` also allows a new CREATE2 on the same
//!   file, but then events the kernel queued for the old device could not be told from the
//!   new device's: `UHID_START` carries no instance, and a late START of the old device
//!   would look like the new one's.) The new device's writer waits for the old device's
//!   writer (at most [`DROP_TIMEOUT`]) so the kernel sees the DESTROY before the CREATE2.
//!   A device whose file ended is replaced the same way.
//! - Retiring a device cannot lose its DESTROY: the writer checks the device's `retiring`
//!   flag before every queued item, and once it is up writes the rest of its queue (all of
//!   it was queued before the retirement: outputs the device produced before it rebooted,
//!   replies to requests it had accepted) except a CREATE2 not yet written, waits at most
//!   [`FEATURE_TIMEOUT`] for replies still owed, writes DESTROY if the kernel accepted the
//!   CREATE2, and ends. A CREATE2 that was never written is not followed by a DESTROY
//!   (`uhid_dev_destroy` would refuse it with `-EINVAL`). The DESTROY comes
//!   [`DESTROY_AFTER_REPLY`] (100 ms) after the last GET_REPORT or SET_REPORT reply, so
//!   the kernel's waiting caller takes the reply (see "Settled on a real kernel").
//! - Replies owed across a re-enumeration: a GET_REPORT or SET_REPORT whose input reached
//!   the runner counts as in flight (taken under the gate, so either before the device
//!   retires or not at all) until its reply is queued. After a re-enumeration that reply
//!   is still queued (a feature read keeps waiting for the runner's marker) and written
//!   before the DESTROY; this is how the SET_REPORT that completes a Management write with
//!   REBOOT, and the status read that `lk_device` answers right before such a reboot,
//!   succeed for the host. When the transport is dropped, owed replies are not written
//!   (no marker is answered any more; the DESTROY fails the requests).
//! - Isolation of a rebooted device, exactly: the old file's reader drops what the kernel
//!   still sends (outputs refused, requests unanswered because the DESTROY failed them).
//!   Inputs the old readers handed to the runner before the re-enumeration are still
//!   handled by the rebooted device, ahead of its plug-in `PowerCycle`, which discards
//!   their volatile effects; a persistent effect (a complete OTP slot write whose
//!   SET_REPORTs were acknowledged before the reboot) stays. Their outputs never reach the
//!   new devices: `enumerate` sends a `Command::Status` marker (the fence) behind them,
//!   and `deliver` drops report outputs (FIDO, OTP keyboard, OTP feature; counted in
//!   [`UhidStats::dropped`]) until the runner has answered it. A reader checks `retiring`
//!   and sends an input under a per-device gate that `retire` takes to raise the flag, so
//!   no old input follows the fence. The first enumeration sets no fence.
//! - Pacing, as lk-wire's reader (`docs/PROGRAM.md` "Program core as built", lk-wire
//!   backpressure): each reader sends a `Command::Status` marker after every
//!   [`INPUT_WINDOW`] (64) inputs and waits for the previous marker's answer before it
//!   sends the next, so at most two windows of a device's inputs wait in the runner's
//!   unbounded channel. Meanwhile the reader does not read `/dev/uhid`; what a host sends
//!   beyond that waits in, and is finally dropped by, the kernel's 32-event queue
//!   (`UHID_BUFSIZE`, `uhid_queue`). An answered feature-read marker starts the window
//!   afresh.
//! - Reports are served from `UHID_CREATE2` on; `UHID_START` is not awaited (the kernel
//!   sends it before hidraw exists, and a HID driver may ask for a report during probe).
//!   The reader starts reading once the writer's CREATE2 was accepted; a device retired
//!   before that (a re-enumeration right after another, while the new writer still waits
//!   for its predecessor) writes nothing, and its reader ends at once, closing the file.
//! - The plug-in `BusEvent::PowerCycle` is sent once per enumeration in which at least one
//!   device was opened and its `UHID_CREATE2` queued; the writer writes the CREATE2 ahead
//!   of any `UHID_INPUT2` the power cycle causes. A CREATE2 the kernel then refuses is
//!   reported, not retried, and the device stays absent until the next enumeration.
//! - `Transport::attached` is whether a `UHID_CREATE2` was accepted, not destroyed, and
//!   the kernel has not refused an input report with `-EINVAL` since. For a whole
//!   `UHID_INPUT2` that error has one cause, a device the kernel does not run
//!   (`uhid_dev_input2`); after an accepted CREATE2 that means `hid_add_device` failed in
//!   `uhid_device_add_worker`, which clears `running` and sends no event
//!   (`drivers/hid/uhid.c`). The transport then reports `UhidNotice::NotRunning` once and
//!   drops the device's input reports until the next enumeration, which still destroys it
//!   (the kernel keeps the device it could not add).
//! - GET_REPORT(feature): the reader drains feature reports left from an earlier request,
//!   sends `OtpGetFeature`, then a `Command::Status` marker, and waits for the marker's
//!   answer (at most [`FEATURE_TIMEOUT`], 1 s; the kernel waits 5 s). The runner handles
//!   commands in order, so the last feature report handed back by then answers this
//!   request; with none, or no answer in time, the reply is `EIO`. The runner must answer
//!   `Command::Status` (`lk_run::Runner` does; pacing and the fence depend on it too).
//! - Every wait for a marker (pacing, feature reads) is done in steps of 20 ms and gives
//!   up once the device is retiring (a feature read only once the transport is dropped):
//!   `lk_run` drops the transport on the runner thread, where no marker can be answered
//!   any more. A retiring device's reader answers no request that arrives after the
//!   retirement.
//! - Every GET_REPORT and SET_REPORT gets a reply at once except that wait: unsupported
//!   ones (any GET_REPORT but the OTP feature report, a report number other than 0) get
//!   `EIO`. SET_REPORT(output) on the OTP keyboard (LEDs) is acknowledged and ignored, as
//!   `UHID_OUTPUT` on it is; SET_REPORT(output) on FIDO is a FIDO report like
//!   `UHID_OUTPUT` (hidraw takes that path only when a device has no output path, which a
//!   UHID device always has; accepted to match the gadget).
//! - `deliver` and `enumerate` only queue: each device's writer has a queue of
//!   [`WRITE_QUEUE_EVENTS`]; a full queue drops the event ([`UhidStats::dropped`]). An
//!   `INPUT2` for a device whose CREATE2 was not accepted is dropped, not written.
//! - A write error from `/dev/uhid` concerns one event and is reported; only the errors of
//!   a peer that is gone (as with a socket pair) end the writer.
//! - Dropping the transport destroys every device and waits at most [`DROP_TIMEOUT`] in
//!   total for the threads. A reader blocked in `read()` wakes only for an event; after
//!   `UHID_DESTROY` that is the `UHID_STOP` the kernel sends for a device that had started
//!   (`uhid_hid_stop`, reached from `hid_destroy_device`). A reader that gets none is left
//!   behind (with its half of the file) and reported.
//! - `UhidNotice`s through an [`Observer`] report enumeration, device lifecycle, refused
//!   reports and failures, and event types with data sizes for `-vv`; never report bytes.
//!   `Debug` of every type shows sizes only.
//!
//! # Settled on a real kernel
//!
//! Guest: Ubuntu's arm64 `7.0.0-38-generic` kernel (upstream 7.0.14) under QEMU, its own
//! `uhid`, `hid`, `hid-generic` and `usbhid` modules, systemd-udevd 259, a static musl
//! `localkeyd` (`tools/linux-guest/`). Two tests:
//!
//! - `tests/smoke.sh`: `localkeyd run --transport uhid -vv`, `ctl status`, a clean shutdown
//!   through stdin EOF. Events: CREATE2 (OTP, FIDO), START (OTP, FIDO), OPEN (OTP); at
//!   shutdown DESTROY and STOP for FIDO, then CLOSE, DESTROY and STOP for OTP.
//! - `tests/uhid.sh`: host software as black-box clients against both profiles: libfido2
//!   1.16.0 (`fido2-token -L/-I/-S`, `fido2-cred -M/-V`, `fido2-assert -G/-V`),
//!   python-fido2 2.0.0 (`CtapHidDevice`, `Ctap2` with PIN tokens, `Fido2Client` with
//!   `Fido2Server`), ykman 5.8.0 (`list`, `info`, `otp info`, `otp chalresp`, `otp
//!   calculate`, `otp static`, `config usb --disable/--enable OTP`), raw hidraw calls,
//!   evdev; `kill -9` and restart; driver unbind and bind; a hidraw flood. Touches through
//!   `localkeyd ctl tap`. Every step passed with the fixes listed below.
//!
//! What the kernel does:
//!
//! - `UHID_CREATE2` as encoded here (4380-byte `struct uhid_event` on aarch64) is accepted
//!   for both devices, and its fields arrive as designed: each hidraw node's uevent shows
//!   `HID_ID=0003:00001209:00000001` (`BUS_USB`, the own profile's vendor and product;
//!   `0003:00001050:00000407` with the YubiKey profile, `0003:00001050:00000406` after
//!   `ykman config usb --disable OTP`), `HID_NAME` the product string (`YubiKey
//!   OTP+FIDO+CCID`, then `YubiKey FIDO+CCID`), `HID_PHYS=localkey`, an empty `HID_UNIQ`;
//!   `HIDIOCGRAWINFO` gives bus 3 and the IDs, `HIDIOCGRAWNAME`/`PHYS`/`UNIQ` the same
//!   strings; `/proc/bus/input/devices` shows `Version=0574`; each node's
//!   `report_descriptor` (and `HIDIOCGRDESC`) is the engine's FIDO (34 bytes) or OTP (77
//!   bytes) descriptor byte for byte, compared with the descriptors the engine sends over
//!   the wire transport. hid-generic binds both (`hidraw` for FIDO; `input,hidraw` for the
//!   OTP keyboard). The devices live under `/devices/virtual/misc/uhid/`, with no USB
//!   ancestor.
//! - `UHID_START` arrives with `dev_flags` 0 for both devices, at every creation (logged
//!   as "started (dev_flags 0x0)").
//! - `UHID_STOP` follows `UHID_DESTROY` promptly for a started device: on shutdown (the
//!   daemon exited about 0.34 s after its stdin closed, both destroys and thread joins
//!   included) and at every re-enumeration (each old device logged "destroyed" and
//!   "stopped", its reader ended and its file was closed; the new device was created
//!   after). The hidraw nodes were gone afterwards.
//! - The kernel itself opens the OTP device: `UHID_OPEN` arrives with no user process
//!   running. The input device has `Handlers=sysrq kbd event0`, and the keyboard and SysRq
//!   handlers open every input device they attach to (`input_open_device` in `kbd_connect`,
//!   `drivers/tty/vt/keyboard.c`, and `sysrq_connect`, `drivers/tty/sysrq.c`), which
//!   hid-input passes on as `UHID_OPEN`; its `UHID_CLOSE` comes only at the DESTROY. On
//!   the FIDO device every hidraw open and close of a client is one `UHID_OPEN` /
//!   `UHID_CLOSE` pair (ykman opens it on every run to enumerate).
//! - Nothing in the kernel asks for reports: with the keyboard and SysRq handlers,
//!   hid-generic, hid-input and systemd-udevd present (no desktop daemons), no
//!   `UHID_GET_REPORT`, `UHID_SET_REPORT` or `UHID_OUTPUT` reached either device except
//!   from hidraw clients (none at all on the OTP device before ykman ran; no keyboard LED
//!   report either).
//! - The report-number rule above holds:
//!   - libfido2, python-fido2 and ykman write `00` + the 64-byte report to the FIDO node,
//!     and each write arrives as a 65-byte `UHID_OUTPUT`. A raw 64-byte write arrives as a
//!     64-byte `UHID_OUTPUT` (hidraw passes the buffer verbatim); both were answered.
//!   - ykman's `HIDIOCSFEATURE(9)` (`00` + the 8-byte report) arrives as a 9-byte
//!     `UHID_SET_REPORT`; a raw `HIDIOCSFEATURE(8)` as an 8-byte one with report number 0
//!     (its first byte, 0); both are acknowledged and returned their size.
//!   - `HIDIOCGFEATURE(9)` returns 9 and the reply data verbatim: `00 00 05 07 04 00 00 00
//!     00`, the report number and then the 8-byte status (firmware 5.7.4). ykman reads the
//!     report from byte 1: challenge-response in slot 2 (HMAC-SHA1, checked against the
//!     generated key, the same answer twice and after a restart) and the slot writes ran
//!     over 510 GET_REPORT and 186 SET_REPORT round trips without an error.
//!     `HIDIOCGFEATURE(8)` returns 8: the report number and the first 7 report bytes (the
//!     kernel cuts the reply to the caller's size). So `hidraw.rst`'s "the data will begin
//!     at the first byte" does not describe uhid; the driver code does.
//!   - hidraw `read()` returns input reports without a prefix: 64 bytes FIDO, 8 bytes OTP
//!     keyboard.
//! - The OTP keyboard: a static password in slot 1 (`ykman otp static 1 Hello1World
//!   --keyboard-layout US`) typed on `ctl tap` came out of evdev as left shift + H, e, l,
//!   l, o, 1, left shift + W, o, r, l, d, Enter (24 eight-byte reports on hidraw: press
//!   and release for each key).
//! - A GET_REPORT or SET_REPORT that is pending when `UHID_DESTROY` is written fails with
//!   `EIO` in the caller (`uhid_dev_destroy`). So does one whose reply was written right
//!   before the DESTROY: the woken caller checks `running` again
//!   (`__uhid_report_queue_and_wait`) and the DESTROY has cleared it. Seen with ykman's
//!   status read after `config usb --disable OTP` (reply written, then DESTROY, `OSError:
//!   [Errno 5]`); with [`DESTROY_AFTER_REPLY`] it succeeds.
//! - `kill -9` of the daemon: the kernel destroys both devices when the process's files
//!   close (`uhid_char_release`): no hidraw node, HID device or input device is left. A
//!   restart on the same state directory presents both again, with the state kept (FIDO
//!   PIN set, a credential made before still asserts and verifies, both OTP slots
//!   programmed, the same HMAC answer).
//! - Driver unbind: unbinding hid-generic (`/sys/bus/hid/drivers/hid-generic/unbind`)
//!   sends `UHID_STOP` and removes the hidraw node (logged, the reader goes on); binding
//!   again sends `UHID_START` (`dev_flags` 0). A DESTROY of a device that no driver has
//!   bound gets no `UHID_STOP`: the reader stays blocked in `read()`. At shutdown that
//!   costs [`DROP_TIMEOUT`] ("fido: the reader thread did not end in time"; the daemon
//!   exited 1.1–1.4 s after its stdin closed); at a re-enumeration the old reader and its
//!   file (holding no device) stay until the process exits. A blocking `read()` cannot be
//!   woken without an event, and std offers `O_NONBLOCK` (`custom_flags`) but no
//!   `poll(2)`, so only a reader that sleeps and retries could notice, at a cost on every
//!   device all the time; not done. The same holds for a device that no driver ever binds.
//! - A hidraw client that writes 5000 reports as fast as it can (0.14–0.74 s) overruns the
//!   kernel's 32-event queue: `uhid_queue` drops the excess and logs "Output queue is
//!   full" once per dropped report with `hid_warn`, not rate-limited (22, 127, 196, 770
//!   and over 4000 lines in five runs); the device answered normally right after. The
//!   bound is the kernel's queue.
//! - Permissions: `/dev/uhid` and both hidraw nodes are `crw-------` root. systemd-udevd's
//!   `fido_id` recognises the FIDO node from its report descriptor (`ID_FIDO_TOKEN=1`,
//!   `ID_SECURITY_TOKEN=1`, tags `security-device`, `seat`, `uaccess`), with either
//!   profile, so a desktop user with a logind seat session gets access without extra
//!   rules; the OTP node is tagged `seat` only. Rules that match the USB device's
//!   attributes (`ATTRS{idVendor}`, as Yubico's) cannot match a uhid device. A rule on the
//!   uhid device path works: `SUBSYSTEM=="hidraw",
//!   DEVPATH=="/devices/virtual/misc/uhid/0003:1209:0001.*", TAG+="uaccess"` tagged the
//!   OTP node `uaccess` (`0003:1050:*` for the YubiKey profile).
//!
//! What the real clients showed in this crate, now fixed (regression tests in
//! `tests/transport.rs`):
//!
//! - The SET_REPORT that completes a Management write with REBOOT (ykman `config usb`
//!   over OTP HID) lost its reply: the device retired before the reader queued it, the
//!   DESTROY failed the request, and `HIDIOCSFEATURE` returned `EIO` for a write that had
//!   taken effect (`a_set_report_whose_input_re_enumerates_is_acknowledged_before_the_destroy`).
//! - Outputs queued before a re-enumeration were discarded once the device retired, so
//!   the CTAPHID response to such a write reached the host only if the writer happened to
//!   be quick (`outputs_delivered_before_a_re_enumeration_reach_the_old_device_before_its_destroy`).
//! - A feature read answered right before a reboot lost its reply in the same way
//!   (`a_feature_read_answered_right_before_a_re_enumeration_gets_its_reply_before_the_destroy`),
//!   and a reply written right before the DESTROY still failed in the kernel
//!   (`the_destroy_after_a_reply_leaves_the_caller_time_to_take_it`).
//! - The engine rebooted right after the last SET_REPORT of such a write, before the host
//!   could read the status it waits for; `lk_device` now reboots after that read (or
//!   `lk_device::OTP_REBOOT_DELAY_MS` later).
//!
//! # Open items for a real kernel
//!
//! - That `-EINVAL` on `UHID_INPUT2` is the only sign of a device whose `hid_add_device`
//!   failed (read from `uhid_dev_input2` and `uhid_device_add_worker`; not provoked: the
//!   kernel accepts the engine's descriptors).
//! - Whether desktop daemons (power or input managers) ask the OTP device for reports;
//!   none ran in the guest. Such a kernel-internal caller would expect the feature report
//!   without the leading `00`.

#![cfg(unix)]

pub mod event;
mod io;
pub mod report;
mod transport;

pub use crate::io::{DEFAULT_UHID_PATH, DevUhid, UhidHalves, UhidIo};
pub use crate::transport::{
    DESTROY_AFTER_REPLY, DROP_TIMEOUT, FEATURE_TIMEOUT, HidInterface, INPUT_WINDOW, Observer, PHYS, UhidNotice,
    UhidStats, UhidTransport, WRITE_QUEUE_EVENTS,
};
