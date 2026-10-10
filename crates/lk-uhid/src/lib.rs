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
//! every Unix; it is useful on Linux only (`localkeyd` refuses it elsewhere). It is
//! **unverified on a real kernel**: every kernel fact comes from the UAPI headers, the
//! kernel documentation and the driver sources named below, and the tests play the kernel
//! over `UnixStream::pair()` (`docs/PROGRAM.md` "Linux transports").
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
//! Conclusion, until a real kernel confirms it ([`report`] implements it): FIDO output of
//! 64 bytes, or 65 with a leading `00` (stripped), is accepted, any other output is
//! dropped; an OTP feature SET_REPORT with report number 0 of 8 bytes, or 9 with a leading
//! `00`, is accepted; GET_REPORT(feature) is answered with `00` + the 8 bytes. Input
//! reports go out without a prefix (64 bytes FIDO, 8 bytes OTP keyboard), as an unnumbered
//! report is read from hidraw.
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
//!   flag before every queued item, and once it is up discards the rest of its queue
//!   (INPUT2s counted in [`UhidStats::dropped`], replies not needed because the DESTROY
//!   fails the kernel's pending requests, `uhid_dev_destroy`), writes DESTROY if the
//!   kernel accepted the CREATE2, and ends. A CREATE2 that was never written is not
//!   followed by a DESTROY (`uhid_dev_destroy` would refuse it with `-EINVAL`).
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
//!   up once the device is retiring: `lk_run` drops the transport on the runner thread,
//!   where no marker can be answered any more, and the reply would be pointless anyway.
//!   A retiring device's reader queues no replies.
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
//! # Open items for a real kernel
//!
//! - Which form hidraw clients actually produce and expect (the report-number rule above),
//!   and that `UHID_START` arrives with `dev_flags` 0.
//! - That `UHID_STOP` follows `UHID_DESTROY` promptly (the old reader's exit on drop and on
//!   re-enumeration depends on it). A device that was created but never started gets
//!   none (one whose `hid_add_device` failed, or that no HID driver bound), and its reader
//!   and file are left behind until the process exits. Waking a blocking `read()` would
//!   need `O_NONBLOCK` or `poll`, which std cannot set on a character device without
//!   `unsafe`. (A device retired before its CREATE2 was written does not leak: its reader
//!   starts reading only after the CREATE2 was accepted, and ends at once otherwise.)
//! - That `-EINVAL` on `UHID_INPUT2` is the only sign of a device whose `hid_add_device`
//!   failed (read from `uhid_dev_input2` and `uhid_device_add_worker`; untested against a
//!   kernel).
//! - How often the kernel logs "Output queue is full" (`uhid_queue`) while pacing holds a
//!   flooding hidraw writer back.
//! - That nothing in the kernel itself (rather than hidraw) asks the OTP device for its
//!   feature report: such a caller would expect the report without the leading `00`.
//! - Permissions: `/dev/uhid` is usually root-only, and the hidraw nodes the kernel creates
//!   need udev rules for a desktop user's FIDO client.

#![cfg(unix)]

pub mod event;
mod io;
pub mod report;
mod transport;

pub use crate::io::{DEFAULT_UHID_PATH, DevUhid, UhidHalves, UhidIo};
pub use crate::transport::{
    DROP_TIMEOUT, FEATURE_TIMEOUT, HidInterface, INPUT_WINDOW, Observer, PHYS, UhidNotice, UhidStats, UhidTransport,
    WRITE_QUEUE_EVENTS,
};
