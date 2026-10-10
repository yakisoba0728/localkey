//! Linux ConfigFS + FunctionFS composite gadget transport (`docs/PROGRAM.md` "lk-gadget").
//!
//! One USB device with the engine's descriptors (OTP keyboard, FIDO HID and CCID
//! interfaces), for a Linux machine with a USB device controller. Byte-level logic tested
//! against fakes, following the kernel's interface definitions; it has been **run on a
//! real kernel** (`dummy_hcd` in a QEMU guest) only as far as "Settled on a real kernel"
//! below says, and the rest is still unverified.
//!
//! - [`descriptor`]: the engine's configuration descriptor parsed into its header and
//!   descriptor sequence, and the [`Layout`] (which interface and endpoint is which).
//! - [`ffs`]: the FunctionFS descriptors and strings blobs and the `ep0` events.
//! - [`control`]: the control-request state machine and the bus-event mapping.
//! - [`ccid`]: CCID bulk-out message reassembly.
//! - [`configfs`]: the ConfigFS gadget tree.
//! - [`io`]: the I/O trait ([`GadgetIo`]) with the real [`KernelIo`], and [`Ep0`], which
//!   maps control-pipe operations to FunctionFS reads and writes.
//! - [`GadgetTransport`]: the [`lk_run::Transport`].
//!
//! All of it compiles and is tested on every Unix; `localkeyd` refuses to start the
//! transport elsewhere than on Linux. Nothing here opens `/sys` or mounts anything in
//! tests: ConfigFS writes go to a root given as a parameter, and FunctionFS goes through
//! [`GadgetIo`].
//!
//! # Kernel sources and what they settled
//!
//! - `include/uapi/linux/usb/functionfs.h`: the magics (`DESCRIPTORS_MAGIC_V2` 3,
//!   `STRINGS_MAGIC` 2), `FUNCTIONFS_HAS_FS_DESC` 1, the V2 descriptors layout (magic,
//!   length, flags, then one LE32 count per flagged speed) and the strings layout, the
//!   event types 0–6 and the packed 12-byte `usb_functionfs_event` (8-byte
//!   `usb_ctrlrequest`, type, 3 padding bytes).
//! - `include/uapi/linux/usb/ch9.h`, `include/uapi/linux/hid.h`: request, descriptor and
//!   class constants and the descriptor layouts.
//! - `drivers/usb/gadget/function/f_fs.c`:
//!   - `__ffs_data_got_descs`: the length field must equal the write, unknown flags are
//!     refused, no trailing bytes. `ffs_do_single_desc` accepts the HID class descriptor
//!     at 9 bytes and the CCID one at 54, refuses device, configuration and string
//!     descriptors, and counts `iInterface` 0 as no string.
//!   - `__ffs_data_got_strings`: `str_count` and `lang_count` must both be 0 or both
//!     nonzero, so with no strings needed the strings blob is the bare 16-byte header
//!     (no language table, so no `0x0409` either).
//!   - `__ffs_func_bind_do_nums`: interface numbers are allocated by the composite
//!     framework in order of appearance; with one function in the configuration they are
//!     the engine's 0, 1, 2. `ffs_func_setup` forwards interface-directed requests with
//!     `wIndex` rewritten to the function's own interface number
//!     (`ffs_func_revmap_intf`), and endpoint-directed ones with `wIndex` rewritten to
//!     the endpoint's 1-based index in the function (`ffs_func_revmap_ep`, the `epN`
//!     number), not an address; [`Control`] stalls every request not directed to an
//!     interface.
//!   - `__ffs_func_bind_do_descs`: `usb_ep_autoconfig` overwrites `bEndpointAddress` with
//!     the endpoint the UDC picks (`drivers/usb/gadget/epautoconf.c` keeps only the
//!     direction bit of the requested address); only `FUNCTIONFS_VIRTUAL_ADDR` restores
//!     the requested address in the descriptor, but then `config_ep_by_speed`
//!     (`composite.c`) matches descriptors to endpoints by that address and fails unless
//!     the two agree (and `ffs_epfiles_create` names the files `ep<address>`). This crate
//!     does not set the flag; tried on a real kernel, see "Settled on a real kernel".
//!   - `ffs_epfiles_create`: endpoint files are `ep1`..`epN` in descriptor order.
//!   - `ffs_ep0_read`/`ffs_ep0_write`/`__ffs_ep0_stall`/`__ffs_ep0_queue_wait`: the `ep0`
//!     semantics described in [`io`]. `__ffs_ep0_queue_wait` returns `EINTR` (after
//!     dequeuing the transfer) before it clears `setup_state`, so an interrupted data
//!     stage leaves its SETUP pending and the next read of an OUT request is that data
//!     stage; `__ffs_ep0_read_events` zeroes the event array and fills in the request for
//!     SETUP only, and returns whole events.
//!   - `__ffs_event_add`: a new event cancels a pending SETUP; `BIND`, `UNBIND`, `ENABLE`
//!     and `DISABLE` discard every queued event except `SUSPEND`/`RESUME`; `RESUME`
//!     discards a queued `SUSPEND`.
//!   - `ffs_func_set_alt`: every call disables and re-enables all endpoints and reports
//!     `ENABLE`; `composite.c` `set_config` calls it once per interface.
//!   - `ffs_epfile_io`: `O_NONBLOCK` only decides whether a transfer on a disabled
//!     endpoint fails with `EAGAIN` or sleeps; `req->zero` comes only from an ioctl;
//!     reading an IN endpoint halts it.
//!   - `ffs_func_unbind` disables the endpoints, then reports `UNBIND`, then
//!     (`functionfs_unbind`) clears `FFS_FL_BOUND`; `ffs_data_closed` resets the
//!     instance (back to "read descriptors") when the last file closes, and `ffs_closed`
//!     then clears `desc_ready` and unregisters a gadget that is still bound;
//!     `ffs_do_functionfs_bind` refuses a bind with `ENODEV` while `desc_ready` is clear.
//! - `drivers/usb/gadget/configfs.c`, `composite.c`, `Documentation/usb/gadget_configfs.rst`:
//!   the attribute formats and the creation and cleanup order (see [`configfs`]);
//!   `MaxPower` is in mA; `UDC` needs `"\n"` to unbind; the composite framework assigns
//!   string indices 1–3 to manufacturer, product and serial number. `composite_setup`
//!   overwrites `bcdUSB` on every GET_DESCRIPTOR(device), so the `bcdUSB` written to
//!   ConfigFS never reaches the host (see the open items).
//! - `drivers/usb/gadget/udc/dummy_hcd.c`: the dummy UDC is high-speed by default
//!   (`is_high_speed` true, `is_super_speed` false) and never sets `lpm_capable`.
//! - What a killed process leaves (see "Leftover" below): `f_fs.c` `ffs_data_closed`
//!   (with the default `no_disconnect` off, the last close resets the instance) and
//!   `ffs_closed` (unregisters the gadget item while `FFS_FL_BOUND`); `ffs_acquire_dev`
//!   refuses a second mount of a mounted instance with `EBUSY`; `configfs.c`
//!   `gadgets_make` (default groups `functions`, `configs`, `strings`, `os_desc`,
//!   `webusb`; a configuration has `strings`), `gadget_dev_desc_UDC_show` (an unbound
//!   gadget reads as an empty line); `fs/proc_namespace.c` `show_vfsmnt` and
//!   `include/linux/seq_file.h` `seq_escape` (the mount table format, octal escapes).
//!
//! # As built
//!
//! Choices where `docs/PROGRAM.md` leaves room or where the kernel forced a refinement:
//!
//! - **Bus events**: only a not-enabled → enabled transition counts. The first after a
//!   bind is `PowerCycle`, later ones `Reset`; an `ENABLE` while enabled (the per-interface
//!   `set_alt` calls of one SET_CONFIGURATION, or a SET_INTERFACE) is none. `SUSPEND` is
//!   passed once until resumed; `RESUME` is always passed (its `SUSPEND` may have been
//!   discarded unread). `DISABLE` and `UNBIND` produce no bus event. Control-pipe HID
//!   state (idle, protocol) returns to its defaults on `PowerCycle` and `Reset`. Once the
//!   transport ends a session (its stop flag), that session passes no bus event:
//!   `dummy_hcd` reports `SUSPEND` before `UNBIND` on every unbind, and the runner would
//!   hand it to the rebooted device after the re-enumeration.
//! - **`ep0` thread**: started after a successful bind and ended by `UNBIND` (whoever
//!   unbound), the stop flag, or 20 failed event reads in a row (about 1 s; the instance
//!   is no longer active). Control requests are answered on it in order; each SETUP gets
//!   exactly one data-stage call, repeated only after `EINTR` (at most 16 times; f_fs
//!   leaves the request pending then); another failed data stage (`EIDRM`: cancelled) is
//!   dropped and events are read again. An event read that is not whole, well-formed
//!   events is discarded whole (the data stage of a request still pending), never
//!   joined with the next read.
//! - **An `UNBIND` the transport did not cause** (or that error limit) ends the whole
//!   session: the `ep0` thread raises the session's stop flag and closes the IN queues,
//!   so every thread ends and closes its file, and f_fs resets. A bind from outside then
//!   fails with `ENODEV` instead of presenting a function whose control requests nobody
//!   answers; the gadget stays unbound until the next enumeration (`Output::Reenumerate`)
//!   or a restart. Keeping `ep0` open across the unbind to serve such a bind would need
//!   `O_NONBLOCK` polling: a blocked read ends only on an event and an unbound gadget has
//!   none, so the transport's next stop could not end that thread, its file would stay
//!   open and f_fs would never return to "read descriptors" for the next session.
//! - **`attached`**: the host has the current session's function configured. The flag
//!   belongs to the session, so a thread of a session being ended (or left behind after
//!   [`STOP_TIMEOUT`]) cannot make a later session look configured.
//! - **Backpressure**: each OUT reader and the `ep0` thread send a `Command::Status`
//!   marker after every [`INPUT_WINDOW_FRAMES`] (64) inputs or [`INPUT_WINDOW_BYTES`]
//!   (256 KiB) and first wait for the previous marker's answer, as lk-wire's reader
//!   does; at most two windows per producer wait in the runner's channel, the rest in
//!   the endpoint (the UDC NAKs). The wait gives up when the session stops, because the
//!   runner thread ends sessions and cannot answer markers meanwhile.
//! - **OTP GET_REPORT**: `Input::OtpGetFeature` followed by a `Command::Status` marker;
//!   the answer is the `Output::OtpFeature` delivered before the marker's reply (the
//!   runner delivers outputs before it takes the next command); [`OTP_REPORT_TIMEOUT`]
//!   (1 s) then stall. A late answer is never given to a later request. Pacing (see
//!   Backpressure) can hold the `ep0` thread before it reads the next SETUP while the
//!   runner works through a backlog; the 1 s budget starts when the request is read.
//! - **UDC binding goes through [`GadgetIo`]** (`bind`/`unbind`), not straight to the
//!   ConfigFS file, because binding and unbinding are what make the kernel report
//!   `BIND`/`UNBIND` and end transfers in flight; a test kernel must see them. The real
//!   implementation writes the gadget's `UDC` file.
//! - **Endpoint files** are opened `O_NONBLOCK` on Linux (see [`io`]); a failed transfer
//!   makes the thread wait for a configuration change (at most 50 ms) and try again, so
//!   only the stop flag ends it. A FIDO packet shorter than 64 bytes is zero-padded; a
//!   zero-length one is ignored. The CCID reassembly policy is in [`ccid`]; its cap is
//!   `dwMaxCCIDMessageLength` as the whole message, header included (USB CCID Rev 1.1
//!   §5.1), so the largest `abData` accepted is 3062 with the reference descriptor.
//! - **IN queues**: [`IN_QUEUE_REPORTS`] per interrupt endpoint, [`IN_QUEUE_MESSAGES`]
//!   for CCID bulk IN; a full queue drops the output. A CCID message that fills whole
//!   64-byte packets is followed by a zero-length write (a zero-length packet), so the
//!   host's larger bulk read completes.
//! - **Re-enumeration**: drain, then stop flag, unbind (`ENODEV`, already unbound, is
//!   reported and ignored), close the IN queues, join the threads within
//!   [`STOP_TIMEOUT`] (a thread still running is left behind and reported), rewrite
//!   `idVendor`, `idProduct`, `bcdDevice`, `bcdUSB` and the strings, reopen `ep0`
//!   (retried for 0.5 s while f_fs resets), write the blobs, open the endpoints, bind,
//!   start the threads. FunctionFS stays mounted and the function stays linked.
//! - **Drain** (re-enumeration only; dropping the transport does not drain): the threads
//!   go on until the host has taken what the runner handed the session before the
//!   reboot, at most [`DRAIN_TIMEOUT`] (1 s): the FIDO IN and CCID bulk IN items queued
//!   or being written (the response to the command that caused the reboot: a CCID
//!   WRITE CONFIG response, a CTAPHID response) and an OTP GET_REPORT in progress (the
//!   status read `lk_device` answers right before an OTP HID Management reboot). The
//!   runner is inside [`lk_run::Transport::enumerate`] meanwhile and answers no marker,
//!   but it has delivered every output of the input that rebooted the device and
//!   delivers nothing more, so the GET_REPORT takes the answer it delivered without
//!   waiting for its marker. The interrupt endpoints are not waited for (the host may not
//!   poll them). What is still owed at the deadline is dropped and reported (`Failed`).
//!   Inputs the old session's readers pass meanwhile are handled after the
//!   re-enumeration by the rebooted device (the runner reads its channel in order); a
//!   response to one goes to the new session before the host has configured it, fails
//!   with `EAGAIN` and is logged as dropped (seen once after `ykman config usb` over
//!   CCID: libccid's next message to the old device).
//! - **ConfigFS**: values are written as `echo` writes them (with a newline). No
//!   configuration string (the engine's `iConfiguration` is 0). The function is linked
//!   into `c.1` after the descriptors are written, with an absolute target. A missing
//!   serial number is written as the empty string. Teardown removes
//!   only what was created, in reverse order, after the unbind and the unmount; when the
//!   unmount fails (a file still open), the tree is left in place and reported, since
//!   removing the function directory under a live mount is unsafe.
//! - **Leftover** of a killed process: a gadget directory that exists already is refused
//!   ([`GadgetError::Exists`], left alone) unless it is the leftover of an earlier process
//!   of this transport ([`ConfigFs::leftover`]: `UDC` empty, and no directory or link
//!   this transport does not create). A kill closes the FunctionFS files, so the kernel
//!   unbinds the gadget (`ffs_closed` → `unregister_gadget_item`), but the ConfigFS tree
//!   and the mount stay, and a daemon that runs until killed would otherwise never start
//!   again. [`GadgetConfig::precheck`] (also run by [`GadgetTransport::with_io`]) only
//!   recognises it; the first enumeration unmounts the instance wherever
//!   [`GadgetIo::functionfs_mounts`] finds it mounted (`/proc/self/mounts` for
//!   [`KernelIo`]), takes the tree apart in reverse order of creation, reports
//!   [`GadgetEvent::Reclaimed`] and creates the gadget as usual. An unmount that fails
//!   (a file still open) leaves everything in place, as teardown does; any failure is a
//!   `Failed` event of that enumeration.
//! - Defaults ([`GadgetConfig::new`]): ConfigFS root [`DEFAULT_CONFIGFS_ROOT`], gadget and
//!   instance [`DEFAULT_NAME`], FunctionFS at [`default_mount_point`] (`/dev/ffs-<name>`,
//!   the naming of `Documentation/usb/functionfs.rst`).
//! - Names in [`GadgetConfig`] are 1–32 of `[A-Za-z0-9_-]`.
//! - [`Layout`] refuses a HID interface whose HID descriptor names a report descriptor
//!   length other than the identity's report descriptor (the host sizes its
//!   GET_DESCRIPTOR(report) by it).
//!
//! # Settled on a real kernel
//!
//! Guest: Ubuntu's arm64 `7.0.0-38-generic` kernel (upstream 7.0.14) under QEMU with its
//! own `libcomposite`, `usb_f_fs`, `udc-core` and `usbhid` modules, and `dummy_hcd` built
//! from the same kernel source (Ubuntu does not ship it), with its defaults (high-speed
//! capable) unless said otherwise; a static musl `localkeyd` (`tools/linux-guest/`). The
//! host side is the same kernel's USB core, with libfido2 1.16.0, python-fido2 2.0.0,
//! ykman 5.8.0, pcsc-lite 2.4.1 with libccid, OpenSC 0.27.0rc1 and GnuPG 2.4.8 as
//! black-box clients. Two tests, both `localkeyd run --transport gadget --udc
//! dummy_udc.0 --profile yubikey-5c-nano-5.7.4`:
//!
//! - `tests/smoke.sh`: enumeration, `ctl status`, a clean shutdown through stdin EOF.
//! - `tests/gadget.sh`: enumeration and descriptors; FIDO and OTP HID through usbhid;
//!   CCID through pcscd and libccid; runtime suspend and resume, port reset, `authorized`
//!   0/1; four re-enumerations through `ykman config usb` (over CCID twice, OTP HID and
//!   FIDO HID); `kill -9` and restart; an external unbind and bind; control requests
//!   through usbfs; `FUNCTIONFS_VIRTUAL_ADDR`; dummy_hcd as a full-speed-only and as a
//!   SuperSpeed controller. Every step passed with the fixes listed below.
//!
//! Descriptors and strings:
//!
//! - f_fs accepts the descriptors and strings blobs (`read descriptors`, `read strings` in
//!   the kernel log), the bind succeeds and the host enumerates `1050:0407` at full speed
//!   (`speed` 12; "not running at top speed", since ConfigFS `max_speed` is `full-speed`
//!   on a high-speed UDC). The 168 bytes in `/sys/bus/usb/devices/1-1/descriptors` (device
//!   descriptor, then the configuration) equal the engine's descriptors (read from the
//!   wire transport's IDENTITY frame) except at six offsets: `iSerialNumber` and five
//!   `bEndpointAddress` values (next points). Interface numbers 0–2, the HID and CCID
//!   class descriptors, `wMaxPacketSize`, `bInterval`, `bmAttributes` and `MaxPower`
//!   arrive unchanged.
//! - After `ykman config usb --disable OTP` the host sees `1050:0406` with the device
//!   descriptor `12 01 00 02 00 00 00 40 50 10 06 04 74 05 01 02 03 01` (`bcdUSB` 2.00,
//!   `bMaxPacketSize0` 64, `bcdDevice` 5.74, as the reference key's `device_fields`) and a
//!   125-byte configuration equal to the reference key's FIDO+CCID
//!   `configuration_descriptor_hex` (`reference/yubikey-5c-nano-5.7.4/`) except the five
//!   `bEndpointAddress` values.
//! - Endpoint addresses: `bEndpointAddress` is what the UDC assigns, in descriptor order
//!   from its endpoint list. On `dummy_hcd` the host saw, for OTP+FIDO+CCID, OTP IN `81`
//!   (as the engine), FIDO OUT `02` and IN `85`, CCID bulk OUT `07`, bulk IN `86` and
//!   interrupt IN `8a` (engine `04`/`84`/`02`/`82`/`83`); for FIDO+CCID, `02`/`81`/`07`/
//!   `86`/`85` (reference `04`/`84`/`02`/`82`/`83`). It cannot be fixed from user space:
//!   with `FUNCTIONFS_VIRTUAL_ADDR` (flags `0x11`, tried with the engine's 0407
//!   descriptors) f_fs accepts the blob, names the endpoint files `ep02 ep04 ep81 ep82
//!   ep83 ep84` instead of `ep1`..`ep6`, and the host does see the engine's addresses in
//!   the configuration descriptor, but SET_CONFIGURATION fails: "ffs_func_eps_enable:
//!   config_ep_by_speed(ep5in-int) returned -5", "usb 1-1: can't set config #1, error
//!   -32", the device stays unconfigured. The same descriptors with flags `0x01` (as this
//!   crate writes them) are configured. A UDC whose own numbering happens to give the
//!   engine's addresses would show them without any flag.
//! - `iSerialNumber`: with no serial number the engine's device descriptor has 0, but the
//!   host sees index 3 and an empty string (GET_DESCRIPTOR(STRING 3) returns `02 03`;
//!   lsusb `iSerial 3` with no text; no `serial` attribute in sysfs). It cannot be fixed
//!   from user space: `configfs_composite_bind` gives every language's manufacturer,
//!   product and serial-number slots string IDs, and `copy_gadget_strings` turns an unset
//!   one into "" (`composite.c`, `configfs.c`); only a gadget with no language directory
//!   gets index 0, and then manufacturer and product lose theirs too. Strings 0–2 are
//!   `04 03 09 04`, "Yubico" and the product string, as the engine's. No client minded
//!   the empty string (libfido2, python-fido2 `serial None`, ykman, libccid's reader
//!   name `Yubico YubiKey OTP+FIDO+CCID 00 00`, GnuPG).
//! - `bcdUSB` and the speed descriptors come from the controller, not from ConfigFS
//!   (`composite_setup`; ConfigFS `max_speed = full-speed` limits the connection speed
//!   only, while `gadget_is_dualspeed`/`gadget_is_superspeed` test the UDC's own
//!   `max_speed`). Seen on three `dummy_hcd` configurations, each enumerated at full
//!   speed:
//!   - defaults (high-speed capable): `bcdUSB` 0x0200, the engine's value;
//!     GET_DESCRIPTOR(DEVICE_QUALIFIER) answered `0a 06 00 02 00 00 00 40 00 00`
//!     (`bNumConfigurations` 0), OTHER_SPEED_CONFIGURATION and BOS stalled. A
//!     full-speed-only device such as the reference key answers DEVICE_QUALIFIER with a
//!     request error (USB 2.0 §9.6.2); no client minded the answer;
//!   - `is_high_speed=0` (full-speed only): `bcdUSB` 0x0200, DEVICE_QUALIFIER and BOS
//!     stalled, as the reference key;
//!   - `is_super_speed=1`: `bcdUSB` 0x0210 (`12 01 10 02 ...`) and a BOS descriptor `05 0f
//!     0f 00 01 0a 10 03 00 0f 00 01 01 f4 01` (a SuperSpeed USB Device Capability,
//!     speeds low to SuperSpeed), DEVICE_QUALIFIER answered with `bcdUSB` 0x0210.
//!
//!   So a high-speed or SuperSpeed controller differs from the reference key in these
//!   descriptors whatever the transport writes; only a full-speed-only controller matches.
//!
//! Control requests:
//!
//! - At enumeration the Linux host sends SET_IDLE (`21 0a`) to interfaces 0 and 1
//!   (acknowledged), GET_DESCRIPTOR(report) (`81 06`, `wValue` `0x2200`) to interface 0
//!   with length 77 and to interface 1 with length 34 (answered; hid-generic's
//!   `report_descriptor` in sysfs is the engine's byte for byte), and SET_REPORT(output)
//!   (`21 09`, `wValue` `0x0200`) to interface 0 with 1 byte (the keyboard LEDs, received
//!   and ignored); the same after a port reset and after `authorized` 0/1. No
//!   GET_STATUS, SET_PROTOCOL or GET_REPORT came from the kernel. usbhid binds interfaces
//!   0 and 1; interface 2 gets no kernel driver, and libccid claims it through usbfs.
//!   libccid sends no CCID class request (`bNumClockSupported` and
//!   `bNumDataRatesSupported` are 0).
//! - ykman's OTP traffic over `ep0` (`ykman otp info`, `chalresp`, `calculate`, `static`)
//!   ran as GET_REPORT(feature) (`a1 01`, `wValue` `0x0300`, length 8) and
//!   SET_REPORT(feature) (`21 09`, `wValue` `0x0300`, length 8), 260 and 99 of them in
//!   one run, without a failure; the HMAC-SHA1 answer matched the generated key.
//! - Stalls and acknowledgements with 1-byte calls keep `ep0` in step: CCID
//!   GET_CLOCK_FREQUENCIES (`a1 02`) and GET_DATA_RATES (`a1 03`) sent through usbfs were
//!   stalled (the host got `EPIPE`) and a CCID ABORT (`21 01`, `wValue` `0x0700`) right
//!   between them was acknowledged (the host got success, the engine the abort).
//! - GET_STATUS to an interface never reaches the function on `dummy_hcd`: the UDC
//!   answers it itself (`00 00`, `handle_control_request` in `dummy_hcd.c`; no SETUP
//!   event came). GET_STATUS to the device answers `00 00` (bus powered).
//!
//! Data:
//!
//! - FIDO through usbhid: `fido2-token -L` lists the node as `vendor=0x1050,
//!   product=0x0407`; `fido2-token -I`, `fido2-cred -M/-V` (touch through `ctl tap`),
//!   `fido2-assert -G/-V` and the python-fido2 flow (`Ctap2` and `Fido2Client` with
//!   `Fido2Server`) all passed; the reports are 64-byte interrupt transfers both ways.
//! - The OTP keyboard: a static password in slot 1 typed on `ctl tap` came out of evdev
//!   as `Hello1World` + Enter, 24 eight-byte reports on the hidraw node.
//! - CCID through pcscd and libccid: the reader `Yubico YubiKey OTP+FIDO+CCID 00 00`, the
//!   profile's ATR, raw APDUs (`opensc-tool -s`), `ykman info`, OATH with touch (the code
//!   is the RFC 6238 TOTP), PIV key and certificate generation and export, OpenPGP and
//!   `gpg --card-status` (scdaemon with `disable-ccid`, through pcscd) all passed.
//! - CCID messages of whole packets: a 704-byte `PC_to_RDR_XfrBlock` (11 full packets;
//!   libusb sends no zero-length packet after it) was reassembled into one message. A
//!   640-byte `RDR_to_PC_DataBlock` (10 full packets) followed by the zero-length write
//!   completed the host's bulk read: libccid reads with 65556-byte URBs, and usbmon showed
//!   that URB complete with 640 bytes; the PIV object came back intact. So the
//!   zero-length write reaches the host as a zero-length packet, and without it the
//!   read would wait for the next message.
//! - `O_NONBLOCK` endpoint files: before the host configures a new session, writes fail
//!   at once with `EAGAIN` (a CCID response to a message of the old session, logged as
//!   dropped) and the threads carry on; transfers work once configured.
//!
//! Bus events:
//!
//! - One enumeration produces exactly one bus event, `PowerCycle` (the per-interface
//!   `ENABLE`s of one SET_CONFIGURATION add none).
//! - Runtime suspend (`power/control` `auto`, after unbinding usbhid: the kernel's
//!   keyboard handler keeps the OTP interface open, and usbhid then needs remote wakeup,
//!   which `bmAttributes` 0x80 does not offer) reached the engine as `Suspend` (`ctl
//!   status`: `suspended=true`); `power/control` `on` as `Resume`.
//! - A port reset (`USBDEVFS_RESET`) and `authorized` 0 then 1 (a SET_CONFIGURATION to 0,
//!   then to 1) each reached the engine as one `Reset`; after `authorized` 0 `attached`
//!   was false. No `DISABLE` was lost to a following `ENABLE` in these runs.
//! - `dummy_hcd` reports `SUSPEND` before `UNBIND` whenever the gadget is unbound: at
//!   shutdown, at every re-enumeration and at an external unbind.
//!
//! Sessions:
//!
//! - Re-enumeration: unbind, `ep0` reopened at once (strace: one `openat` of `ep0` per
//!   re-enumeration, succeeding about 0.1 s after the `UDC` write began; never `EBUSY`),
//!   blobs, bind; the host saw the new product ID and interfaces each time (0406 and back
//!   to 0407, four times).
//! - An external unbind (`echo > UDC`): `SUSPEND`, `UNBIND`, the session ended ("unbound by
//!   someone else") and closed every file right after the `UNBIND` without trouble; an
//!   external bind then failed ("udc dummy_udc.0: failed to start localkey: -19", the
//!   write got `EBUSY`); a clean shutdown after it took 0.35 s (exit 0; the transport's
//!   unbind got `ENODEV`, reported and ignored; tree removed, unmounted). Closing the last
//!   file right after the transport's own unbind (every re-enumeration and shutdown) was
//!   as harmless.
//! - `kill -9`: the USB device disconnected at once (f_fs unregistered the gadget), the
//!   ConfigFS tree (exactly the default groups of [`configfs::GADGET_GROUPS`] and
//!   [`configfs::CONFIG_GROUPS`] plus this transport's directories and link) and the
//!   mount (`localkey /dev/ffs-localkey functionfs rw,relatime 0 0` in
//!   `/proc/self/mounts`) stayed, and `UDC` read empty. The restart reclaimed it ("removed
//!   the leftover gadget ... (unmounted FunctionFS at /dev/ffs-localkey)") and presented
//!   the device again with the state kept (a FIDO credential made before asserts, OTP
//!   slot 2 gives the same HMAC, the PIV certificate and the OATH account are there).
//! - Teardown: the daemon exited with 0 about 0.3–0.35 s after its stdin closed; the USB
//!   device disconnected, FunctionFS was unmounted and the ConfigFS tree removed.
//!
//! What the real clients showed in this crate, now fixed (regression tests in
//! `tests/transport.rs` and `src/transport/tests.rs`):
//!
//! - `ykman config usb --disable OTP` over OTP HID printed "Failed to configure USB
//!   applications" although the device rebooted with the new configuration. `lk_device`
//!   answers the status read of the write (GET_REPORT(feature)) and reboots right after
//!   it; the runner re-enumerated before it answered the request's marker, and the
//!   transport unbound with the GET_REPORT still waiting for it, so the host's request
//!   failed. Re-enumeration now drains first and the GET_REPORT takes the answer the
//!   runner delivered
//!   (`an_otp_get_report_answered_right_before_a_re_enumeration_gets_its_reply_before_the_unbind`,
//!   `an_otp_feature_request_takes_the_delivered_answer_when_the_session_drains`,
//!   `an_otp_feature_request_behind_a_timed_out_one_gives_up_when_the_session_drains`).
//! - The response to the command that rebooted the device (over CCID or FIDO HID) was
//!   queued right before the re-enumeration, and the writer dropped what was still queued
//!   once the stop flag was up, while the unbind ended a write in progress; the guest's
//!   runs got the response only because the writer happened to be quick. The drain makes
//!   it deterministic
//!   (`responses_queued_before_a_re_enumeration_reach_the_host_before_the_unbind`,
//!   `a_re_enumeration_waits_at_most_the_drain_timeout_for_a_host_that_does_not_read`,
//!   `a_drain_waits_for_owed_responses_and_control_requests_until_its_timeout`).
//! - The `SUSPEND` that `dummy_hcd` reports on the transport's own unbind reached the
//!   runner after the re-enumeration and suspended the rebooted device until the host
//!   configured it (`bus_events_of_a_session_the_transport_is_ending_do_not_reach_the_runner`).
//!
//! # Open items a real kernel must settle
//!
//! - Other controllers (dwc2, dwc3, musb, chipidea): which endpoint addresses they assign,
//!   whether they answer interface GET_STATUS themselves as `dummy_hcd` does (if one
//!   forwards it, the contract stalls it, where USB 2.0 §9.4.5 expects two zero bytes),
//!   and whether a soft disconnect reports `SUSPEND` or `DISABLE` first.
//! - Whether a missed `DISABLE` (discarded by a following `ENABLE` before it was read)
//!   hides a bus reset in practice on another controller or under load; then no `Reset`
//!   reaches the engine. Not seen on `dummy_hcd` (two resets, two `Reset`s).
//! - A data stage that fails other than with `EINTR` or `EIDRM` (a failed `usb_ep_queue`,
//!   `ENOMEM`) also leaves its SETUP pending until a later event cancels it. The next
//!   event read is then that data stage: an IN request is stalled by it, and the host
//!   data of an OUT request is discarded unless it happens to look like whole events
//!   (only a data stage of 12 or more bytes can: the FIDO SET_REPORT(output), up to 48
//!   bytes read, whose chunks would need zero padding and, for non-SETUP types, zero
//!   request bytes). Not provoked; how often a real UDC fails a queued `ep0` transfer is
//!   unknown. `EINTR` itself was not provoked either (strace attached with
//!   `PTRACE_SEIZE` interrupted nothing).
//! - A live process of this transport with the same names whose gadget is unbound at the
//!   moment looks like a leftover; two daemons must not share a gadget name (the state
//!   directory's lock does not cover it), or the second takes the first one's gadget
//!   apart. A kernel that adds a default group to ConfigFS gadgets would make every
//!   leftover look foreign (refused, never wrongly removed).
//! - The mount table read is that of the process's own mount namespace. A mount in
//!   another namespace that outlives the killed process (a container's) is invisible
//!   and is not unmounted, and the function directory is then removed under it. By the
//!   source that is not refused: `ffs_free_inst` has no mount check and detaches the
//!   mounted instance (`ffs_release_dev` clears `mounted` and both back pointers), after
//!   which `ffs_ready` refuses and `ffs_closed` does nothing, so the old mount is left
//!   detached and serves nothing. Whether a private namespace that ends with the
//!   process (systemd `PrivateMounts=`) takes its mount with it, leaving nothing to
//!   unmount, is expected but not read from the source. Run the daemon in the mount
//!   namespace where it mounts FunctionFS. Not tried.

#![cfg(unix)]

pub mod ccid;
pub mod configfs;
pub mod control;
pub mod descriptor;
pub mod ffs;
pub mod io;
mod transport;

#[cfg(test)]
mod test_support;

pub use configfs::{ConfigFs, first_udc};
pub use control::{Action, BusTracker, Control};
pub use descriptor::{ConfigDescriptor, Function, Layout, Role};
pub use io::{Ep0, Ep0File, GadgetIo, KernelIo, PROC_MOUNTS, functionfs_mounts};
pub use transport::{
    DEFAULT_CONFIGFS_ROOT, DEFAULT_NAME, DRAIN_TIMEOUT, GadgetConfig, GadgetError, GadgetEvent, GadgetTransport,
    IN_QUEUE_MESSAGES, IN_QUEUE_REPORTS, INPUT_WINDOW_BYTES, INPUT_WINDOW_FRAMES, OTP_REPORT_TIMEOUT, Observer,
    STOP_TIMEOUT, default_mount_point,
};
