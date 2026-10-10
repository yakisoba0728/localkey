//! Linux ConfigFS + FunctionFS composite gadget transport (`docs/PROGRAM.md` "lk-gadget").
//!
//! One USB device with the engine's descriptors (OTP keyboard, FIDO HID and CCID
//! interfaces), for a Linux machine with a USB device controller. **Unverified on a real
//! kernel**: the environment has no gadget support, so everything is byte-level logic
//! tested against fakes, following the kernel's interface definitions.
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
//!     the two agree. This crate does not set the flag.
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
//!   state (idle, protocol) returns to its defaults on `PowerCycle` and `Reset`.
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
//! - **Re-enumeration**: stop flag, unbind (`ENODEV`, already unbound, is reported and
//!   ignored), close the IN queues, join the threads within [`STOP_TIMEOUT`] (a thread
//!   still running is left behind and reported), rewrite `idVendor`, `idProduct`,
//!   `bcdDevice`, `bcdUSB` and the strings, reopen `ep0` (retried for 0.5 s while f_fs
//!   resets), write the blobs, open the endpoints, bind, start the threads. FunctionFS
//!   stays mounted and the function stays linked.
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
//! # Open items a real kernel must settle
//!
//! - Endpoint addresses: the host sees the engine's interface numbers, class
//!   descriptors and endpoint order, but `bEndpointAddress` is whatever the UDC assigns
//!   (on `dummy_hcd`, counters per direction), not `81`/`04`/`84`/`02`/`82`/`83`.
//! - `iSerialNumber`: with no serial number the engine's device descriptor has 0, but
//!   the composite framework gives the serial-number slot index 3 once a language
//!   directory exists (`copy_gadget_strings` turns an unset string into ""), so the host
//!   may read an empty serial string instead.
//! - `bcdUSB`: the host never sees the engine's value through ConfigFS. `composite_setup`
//!   sets it on every GET_DESCRIPTOR(device) from the controller: `0x0320` on a
//!   SuperSpeed-capable UDC running at SuperSpeed, `0x0210` on one running below it (and
//!   then a BOS descriptor is served, which the host reads), `0x0201` on a UDC that is
//!   not SuperSpeed-capable but `lpm_capable` (or with WebUSB), `0x0200` otherwise. So
//!   `dummy_hcd` with its defaults shows the engine's `0x0200`; a SuperSpeed-capable
//!   controller (dwc3, or `dummy_hcd is_super_speed=1`) shows `0x0210` and a BOS
//!   descriptor, unlike the reference key. Whether ConfigFS `max_speed = full-speed`
//!   changes what `gadget_is_superspeed` sees (it tests the UDC's own `max_speed`, while
//!   ConfigFS limits the connection speed) needs a real controller to confirm.
//! - GET_STATUS for an interface reaches the function below SuperSpeed and is stalled
//!   (the contract stalls everything it does not name); a host checking USB 2.0 §9.4.5
//!   expects two zero bytes.
//! - Whether a missed `DISABLE` (discarded by a following `ENABLE` before it was read)
//!   hides a bus reset in practice; then no `Reset` reaches the engine.
//! - The zero-length write after a 64-multiple CCID message, `O_NONBLOCK` on endpoint
//!   files, and the 1-byte stall/acknowledge reads are read from the source, not tried.
//! - A data stage that fails other than with `EINTR` or `EIDRM` (a failed `usb_ep_queue`,
//!   `ENOMEM`) also leaves its SETUP pending until a later event cancels it. The next
//!   event read is then that data stage: an IN request is stalled by it, and the host
//!   data of an OUT request is discarded unless it happens to look like whole events
//!   (only a data stage of 12 or more bytes can: the FIDO SET_REPORT(output), up to 48
//!   bytes read, whose chunks would need zero padding and, for non-SETUP types, zero
//!   request bytes). How often a real UDC fails a queued `ep0` transfer is unknown.
//! - Ending the session right after an `UNBIND` closes the last file while f_fs may not
//!   yet have cleared `FFS_FL_BOUND` (`functionfs_unbind` runs after the event is
//!   queued); `ffs_closed` then calls `unregister_gadget_item`, which by the source waits
//!   for the gadget lock held by the unbind in progress and finds the gadget unbound.
//!   The same holds for the transport's own unbind; not tried.
//! - Whether `ep0` can be reopened at once after the last file of a session closes
//!   (`ffs_ep0_open` refuses while the instance is closing; retried for 0.5 s).
//! - Reclaiming a leftover is read from the sources (`f_fs.c` `ffs_data_closed`,
//!   `ffs_closed`, `ffs_acquire_dev`; `configfs.c` `gadgets_make`,
//!   `gadget_dev_desc_UDC_show`; `fs/proc_namespace.c` `show_vfsmnt`), not tried: that a
//!   killed process's gadget reads `UDC` empty by the time the next one starts, that a
//!   ConfigFS gadget lists exactly the default groups of [`configfs::GADGET_GROUPS`] and
//!   [`configfs::CONFIG_GROUPS`] as directories (a kernel that adds a group would make
//!   every leftover look foreign: refused, never wrongly removed), and that the mount
//!   table names the instance as the device of a `functionfs` mount. A live process of
//!   this transport with the same names whose gadget is unbound at that moment looks
//!   like a leftover; two daemons must not share a gadget name (the state directory's
//!   lock does not cover it), or the second takes the first one's gadget apart.
//! - The mount table read is that of the process's own mount namespace. A mount in
//!   another namespace that outlives the killed process (a container's) is invisible
//!   and is not unmounted, and the function directory is then removed under it. By the
//!   source that is not refused: `ffs_free_inst` has no mount check and detaches the
//!   mounted instance (`ffs_release_dev` clears `mounted` and both back pointers), after
//!   which `ffs_ready` refuses and `ffs_closed` does nothing, so the old mount is left
//!   detached and serves nothing. Whether a private namespace that ends with the
//!   process (systemd `PrivateMounts=`) takes its mount with it, leaving nothing to
//!   unmount, is expected but not read from the source. Run the daemon in the mount
//!   namespace where it mounts FunctionFS.

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
    DEFAULT_CONFIGFS_ROOT, DEFAULT_NAME, GadgetConfig, GadgetError, GadgetEvent, GadgetTransport, IN_QUEUE_MESSAGES,
    IN_QUEUE_REPORTS, INPUT_WINDOW_BYTES, INPUT_WINDOW_FRAMES, OTP_REPORT_TIMEOUT, Observer, STOP_TIMEOUT,
    default_mount_point,
};
