//! Hand-written argument parsing (`docs/PROGRAM.md` "localkeyd": no third-party crates).
//!
//! ```text
//! localkeyd keygen (--key-file PATH | --print)
//! localkeyd run --state DIR (--key-file PATH | --key-command CMD) [TRANSPORT]
//!               [--profile own|yubikey-5c-nano-5.7.4] [--control PATH]
//!               [--wall-clock] [--allow-unreadable] [--exit-on-stdin-eof] [-v | -vv]
//! localkeyd ctl --control PATH (tap [long] | down | up | power-cycle | status | watch | shutdown)
//!
//! TRANSPORT (default wire):
//!   [--transport wire] [--wire PATH]
//!   --transport uhid [--uhid-path PATH]
//!   --transport gadget --udc NAME [--gadget-name NAME] [--configfs DIR] [--ffs-dir DIR]
//!   --transport vpcd [--vpcd-addr HOST:PORT]
//!   --transport uhid,vpcd [--uhid-path PATH] [--vpcd-addr HOST:PORT]
//! ```
//!
//! The transports are `docs/PROGRAM.md` "lk-wire", "lk-uhid", "lk-gadget" and "lk-vpcd",
//! the sets "Transport combinations"; the run side is in `run`.
//!
//! # As built
//!
//! - An option's value is the next argument, or follows `=` in the same argument
//!   (`--state=DIR`). A next argument that starts with `-` is not taken as a value, so a
//!   forgotten value is reported instead of swallowing the next option; such a path can
//!   still be given as `--state=-dir` or `./-dir`. Values are kept as `OsString`, so paths
//!   need not be UTF-8; a key command must be.
//! - Every option may be given once; `-v` and `-vv` count as one option.
//! - `-h` or `--help` anywhere, `help` as the command, or `help` as a plain word after the
//!   command prints the usage and exits 0. The word is recognised where the parser reaches
//!   it (an error earlier on the line is reported instead), and an option's value stays a
//!   value: `--state help` is a state directory named `help`.
//! - The `ctl` command words and `--control` may come in either order.
//! - `--transport` takes a comma-separated set ([`Transports`]): any one of `wire`,
//!   `uhid`, `gadget` and `vpcd`, or `uhid` and `vpcd` together in either order
//!   (`docs/PROGRAM.md` "Transport combinations": `wire` and `gadget` present the whole
//!   device and combine with nothing). An empty name (`uhid,`), a name given twice
//!   (`vpcd,vpcd`) and any other combination are usage errors. Names are not trimmed: the
//!   set is one argument without spaces. The members are kept in [`TransportKind`] order
//!   (wire, uhid, gadget, vpcd), whatever the order on the line, so `vpcd,uhid` is
//!   `uhid,vpcd` everywhere after parsing, in the log too.
//! - `run` collects every option before it looks at `--transport`, so an option that
//!   belongs to a transport outside the set (`--wire` without the wire transport,
//!   `--uhid-path` without uhid, `--udc`, `--gadget-name`, `--configfs` or `--ffs-dir`
//!   without gadget, `--vpcd-addr` without vpcd) is the same usage error wherever it stands
//!   on the line. `--control` belongs to every transport: the control socket is how a
//!   touch reaches the device.
//! - The transport defaults are resolved here, so [`RunOptions`] holds the paths the
//!   daemon uses: `--uhid-path` [`DEFAULT_UHID_PATH`], `--gadget-name`
//!   [`DEFAULT_GADGET_NAME`], `--configfs` [`DEFAULT_CONFIGFS`], `--ffs-dir`
//!   `lk_gadget::default_mount_point` of the gadget name (`/dev/ffs-NAME`, the naming of
//!   `Documentation/usb/functionfs.rst`), `--vpcd-addr` [`DEFAULT_VPCD_ADDR`]. Each
//!   default is the transport crate's own, so the two cannot drift apart. Only the wire
//!   socket's default stays `None`, because it lives in the state directory (`run`
//!   normalises that path first).
//! - `--gadget-name` must be 1 to 32 of `[A-Za-z0-9_-]`, the rule `lk_gadget` applies to
//!   the names it puts into ConfigFS paths (it names the gadget directory, the FunctionFS
//!   instance and the default `--ffs-dir`); `--udc` must not hold a `/` or a newline (it
//!   is a name in `/sys/class/udc`, written to the gadget's `UDC` attribute followed by a
//!   newline). Both must be UTF-8. Checking them here makes a name that can never work a
//!   usage error; `lk_gadget::GadgetTransport` checks them again.
//! - `--vpcd-addr` must be UTF-8 `HOST:PORT` with a host and a port from 1 to 65535 (an
//!   IPv6 address in brackets, `[::1]:35963`). Only the form is checked here; `run`
//!   resolves the address (`lk_vpcd::resolve`) before the state directory is opened, so a
//!   name that does not resolve is a startup failure (exit 2), not a usage error.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

/// The usage text, printed for `--help` (stdout) and after a usage error (stderr).
pub const USAGE: &str = "\
usage:
  localkeyd keygen (--key-file PATH | --print)
  localkeyd run --state DIR (--key-file PATH | --key-command CMD) [TRANSPORT]
                [--profile own|yubikey-5c-nano-5.7.4] [--control PATH]
                [--wall-clock] [--allow-unreadable] [--exit-on-stdin-eof] [-v | -vv]
  localkeyd ctl --control PATH (tap [long] | down | up | power-cycle | status | watch
                                | shutdown)

TRANSPORT, how the device reaches a USB host (default wire):
  [--transport wire] [--wire PATH]
      a private Unix socket for a bridge or tests
  --transport uhid [--uhid-path PATH]
      the FIDO and OTP HID interfaces as kernel HID devices (Linux, /dev/uhid access)
  --transport gadget --udc NAME [--gadget-name NAME] [--configfs DIR] [--ffs-dir DIR]
      the whole device as a USB gadget on the device controller NAME (Linux, root)
  --transport vpcd [--vpcd-addr HOST:PORT]
      the CCID interface as a card in pcscd's vsmartcard vpcd reader (needs vpcd)
  --transport uhid,vpcd [--uhid-path PATH] [--vpcd-addr HOST:PORT]
      FIDO and OTP through UHID, CCID through vpcd: the whole device (Linux)
The control socket is served with every transport: ctl tap is the touch, ctl
shutdown stops the daemon cleanly (as --exit-on-stdin-eof does at EOF) and returns
once it has: it prints ok, then stopped (exit 0) or the daemon's error (exit 1).

run defaults: --profile own, --wire DIR/wire.sock, --control DIR/control.sock,
--uhid-path /dev/uhid, --gadget-name localkey, --configfs /sys/kernel/config/usb_gadget,
--ffs-dir /dev/ffs-NAME (NAME is the gadget name), --vpcd-addr 127.0.0.1:35963
-v logs connections, enumeration, presence and transport events; -vv adds report,
frame and message types and sizes (never their bytes)
exit codes: 0 clean, 1 runtime failure, 2 startup failure (usage, lock, key,
permissions, uhid or gadget on a system other than Linux), 3 unreadable records
refused (see --allow-unreadable)
";

/// The wire socket's name in the state directory when `--wire` is not given.
pub const WIRE_SOCKET: &str = "wire.sock";
/// The control socket's name in the state directory when `--control` is not given.
pub const CONTROL_SOCKET: &str = "control.sock";
/// `--uhid-path` when not given (`docs/PROGRAM.md` "lk-uhid": the device path defaults to
/// `/dev/uhid`).
pub const DEFAULT_UHID_PATH: &str = lk_uhid::DEFAULT_UHID_PATH;
/// `--gadget-name` when not given (`lk_gadget::GadgetConfig::new`'s gadget name).
pub const DEFAULT_GADGET_NAME: &str = lk_gadget::DEFAULT_NAME;
/// `--configfs` when not given: the ConfigFS gadget root (`docs/PROGRAM.md` "lk-gadget";
/// `Documentation/usb/gadget_configfs.rst`).
pub const DEFAULT_CONFIGFS: &str = lk_gadget::DEFAULT_CONFIGFS_ROOT;
/// The longest `--gadget-name` (`lk_gadget::GadgetConfig`: 1 to 32 of `[A-Za-z0-9_-]`).
pub const MAX_GADGET_NAME: usize = 32;
/// `--vpcd-addr` when not given: vpcd's first slot on this machine (`docs/PROGRAM.md`
/// "lk-vpcd"; `lk_vpcd::protocol::DEFAULT_ADDR`, port `VPCDPORT` 35963 of vsmartcard's
/// `vpcd.h`).
pub const DEFAULT_VPCD_ADDR: &str = lk_vpcd::protocol::DEFAULT_ADDR;

/// What the command line asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invocation {
    /// `-h`, `--help` or `help` (see the module's "As built" notes).
    Help,
    /// `keygen`: where the new storage key goes.
    Keygen(KeyOutput),
    /// `run`: the daemon.
    Run(RunOptions),
    /// `ctl`: one control request.
    Ctl(CtlOptions),
}

/// `keygen --key-file PATH` or `keygen --print`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyOutput {
    File(PathBuf),
    Print,
}

/// `--key-file PATH` or `--key-command CMD`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    File(PathBuf),
    Command(String),
}

/// `--profile`: which `lk_core::DeviceProfile` the device presents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// `own`: `DeviceProfile::own`, this project's own identity.
    Own,
    /// `yubikey-5c-nano-5.7.4`: `DeviceProfile::yubikey_5c_nano_5_7_4`.
    YubiKey5cNano574,
}

impl Profile {
    fn parse(value: &str) -> Option<Profile> {
        match value {
            "own" => Some(Profile::Own),
            "yubikey-5c-nano-5.7.4" => Some(Profile::YubiKey5cNano574),
            _ => None,
        }
    }

    /// The name the command line uses.
    pub fn name(self) -> &'static str {
        match self {
            Profile::Own => "own",
            Profile::YubiKey5cNano574 => "yubikey-5c-nano-5.7.4",
        }
    }
}

/// A transport `--transport` can name. The order of the variants is the order of the
/// members of a set ([`Transports`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TransportKind {
    /// `wire`: `lk_wire::WireTransport`, a private Unix socket.
    Wire,
    /// `uhid`: `lk_uhid::UhidTransport`, Linux only.
    Uhid,
    /// `gadget`: `lk_gadget::GadgetTransport`, Linux only.
    Gadget,
    /// `vpcd`: `lk_vpcd::VpcdTransport`, every Unix.
    Vpcd,
}

impl TransportKind {
    fn parse(value: &str) -> Option<TransportKind> {
        match value {
            "wire" => Some(TransportKind::Wire),
            "uhid" => Some(TransportKind::Uhid),
            "gadget" => Some(TransportKind::Gadget),
            "vpcd" => Some(TransportKind::Vpcd),
            _ => None,
        }
    }

    /// The name the command line uses.
    pub fn name(self) -> &'static str {
        match self {
            TransportKind::Wire => "wire",
            TransportKind::Uhid => "uhid",
            TransportKind::Gadget => "gadget",
            TransportKind::Vpcd => "vpcd",
        }
    }

    /// Whether `localkeyd` runs this transport on Linux only (`docs/PROGRAM.md` "Linux
    /// transports"; vpcd "runs on every Unix", "Transport combinations").
    pub fn linux_only(self) -> bool {
        matches!(self, TransportKind::Uhid | TransportKind::Gadget)
    }
}

/// One transport of the set with its options, defaults resolved (see the module's "As
/// built" notes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportOptions {
    /// `wire` (the default).
    Wire {
        /// `--wire`; `None` is [`WIRE_SOCKET`] in the state directory.
        socket: Option<PathBuf>,
    },
    /// `uhid`.
    Uhid {
        /// `--uhid-path`, [`DEFAULT_UHID_PATH`] when not given.
        path: PathBuf,
    },
    /// `gadget`.
    Gadget(GadgetOptions),
    /// `vpcd`.
    Vpcd {
        /// `--vpcd-addr` as given (`HOST:PORT`, resolved by `run`), [`DEFAULT_VPCD_ADDR`]
        /// when not given.
        addr: String,
    },
}

impl TransportOptions {
    pub fn kind(&self) -> TransportKind {
        match self {
            TransportOptions::Wire { .. } => TransportKind::Wire,
            TransportOptions::Uhid { .. } => TransportKind::Uhid,
            TransportOptions::Gadget(_) => TransportKind::Gadget,
            TransportOptions::Vpcd { .. } => TransportKind::Vpcd,
        }
    }
}

/// `--transport`: the transports the device is presented through, at least one, in
/// [`TransportKind`] order. Only the sets `docs/PROGRAM.md` "Transport combinations" allows
/// are ever made: one transport, or `uhid,vpcd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transports(Vec<TransportOptions>);

impl Transports {
    /// The members, in [`TransportKind`] order.
    pub fn members(&self) -> &[TransportOptions] {
        &self.0
    }

    /// The members' kinds, in order.
    pub fn kinds(&self) -> Vec<TransportKind> {
        self.0.iter().map(TransportOptions::kind).collect()
    }

    /// The set as the command line writes it, members in order: `wire`, `uhid,vpcd`.
    pub fn name(&self) -> String {
        self.kinds().iter().map(|kind| kind.name()).collect::<Vec<_>>().join(",")
    }

    /// A set of these members, for tests: the caller keeps them valid and in order.
    #[cfg(test)]
    pub fn of(members: Vec<TransportOptions>) -> Transports {
        Transports(members)
    }
}

/// The options of `--transport gadget` (`lk_gadget::GadgetConfig`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GadgetOptions {
    /// `--udc`: the USB device controller, a name in `/sys/class/udc`. Required.
    pub udc: String,
    /// `--gadget-name`: the ConfigFS gadget directory and the FunctionFS instance.
    pub name: String,
    /// `--configfs`: the ConfigFS gadget root.
    pub configfs: PathBuf,
    /// `--ffs-dir`: where FunctionFS is mounted.
    pub ffs_dir: PathBuf,
}

/// The options of `run`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOptions {
    pub state: PathBuf,
    pub key: KeySource,
    pub profile: Profile,
    /// `--transport` and the options that belong to its members.
    pub transport: Transports,
    /// `--control`; `None` is [`CONTROL_SOCKET`] in the state directory.
    pub control: Option<PathBuf>,
    pub wall_clock: bool,
    pub allow_unreadable: bool,
    pub exit_on_stdin_eof: bool,
    /// 0 by default, 1 for `-v`, 2 for `-vv`.
    pub verbosity: u8,
}

/// The options of `ctl`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtlOptions {
    pub control: PathBuf,
    pub request: Request,
}

/// A control request (`docs/PROGRAM.md` "Control socket").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    Tap { long: bool },
    Down,
    Up,
    PowerCycle,
    Status,
    Watch,
    /// `shutdown`: the daemon stops cleanly (`docs/PROGRAM.md` "Clean shutdown from the
    /// control socket").
    Shutdown,
}

impl Request {
    fn parse(words: &[&str]) -> Option<Request> {
        let request = match words {
            ["tap"] => Request::Tap { long: false },
            ["tap", "long"] => Request::Tap { long: true },
            ["down"] => Request::Down,
            ["up"] => Request::Up,
            ["power-cycle"] => Request::PowerCycle,
            ["status"] => Request::Status,
            ["watch"] => Request::Watch,
            ["shutdown"] => Request::Shutdown,
            _ => return None,
        };
        Some(request)
    }

    /// The request line, without its newline.
    pub fn line(self) -> &'static str {
        match self {
            Request::Tap { long: false } => "tap",
            Request::Tap { long: true } => "tap long",
            Request::Down => "down",
            Request::Up => "up",
            Request::PowerCycle => "power-cycle",
            Request::Status => "status",
            Request::Watch => "watch",
            Request::Shutdown => "shutdown",
        }
    }
}

/// A command line that does not follow [`USAGE`] (exit code 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageError(pub String);

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UsageError {}

fn usage(message: impl Into<String>) -> UsageError {
    UsageError(message.into())
}

/// Parse the arguments after the program name.
pub fn parse(args: &[OsString]) -> Result<Invocation, UsageError> {
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        return Ok(Invocation::Help);
    }
    let Some((command, rest)) = args.split_first() else {
        return Err(usage("no command given (keygen, run or ctl)"));
    };
    match command.to_str() {
        Some("help") => Ok(Invocation::Help),
        Some("keygen") => parse_keygen(rest),
        Some("run") => parse_run(rest),
        Some("ctl") => parse_ctl(rest),
        _ => Err(usage(format!("unknown command {} (expected keygen, run or ctl)", command.display()))),
    }
}

/// One argument: an option with its name and the value after `=`, or a plain word.
enum Arg<'a> {
    Option { name: String, inline: Option<&'a OsStr> },
    Word(&'a OsStr),
}

impl<'a> Arg<'a> {
    fn split(arg: &'a OsStr) -> Arg<'a> {
        let bytes = arg.as_bytes();
        if bytes.len() < 2 || bytes[0] != b'-' {
            return Arg::Word(arg);
        }
        let (name, inline) = match bytes.iter().position(|&byte| byte == b'=') {
            Some(at) if bytes.starts_with(b"--") => (&bytes[..at], Some(OsStr::from_bytes(&bytes[at + 1..]))),
            _ => (bytes, None),
        };
        Arg::Option { name: String::from_utf8_lossy(name).into_owned(), inline }
    }
}

/// Walks the arguments of one command.
struct Args<'a> {
    rest: std::slice::Iter<'a, OsString>,
}

impl<'a> Args<'a> {
    fn new(args: &'a [OsString]) -> Args<'a> {
        Args { rest: args.iter() }
    }

    fn next(&mut self) -> Option<Arg<'a>> {
        self.rest.next().map(|arg| Arg::split(arg))
    }

    /// The value of option `name`: after its `=`, or the next argument unless that is
    /// another option. An empty value is refused.
    fn value(&mut self, name: &str, inline: Option<&'a OsStr>) -> Result<&'a OsStr, UsageError> {
        let value = match (inline, self.rest.as_slice().first()) {
            (Some(value), _) => Some(value),
            (None, Some(next)) if !matches!(Arg::split(next), Arg::Option { .. }) => {
                self.rest.next();
                Some(next.as_os_str())
            }
            (None, _) => None,
        };
        value.filter(|value| !value.is_empty()).ok_or_else(|| usage(format!("{name} needs a value")))
    }
}

/// Set an option that may be given once.
fn once<T>(slot: &mut Option<T>, name: &str, value: T) -> Result<(), UsageError> {
    if slot.is_some() {
        return Err(usage(format!("{name} given twice")));
    }
    *slot = Some(value);
    Ok(())
}

/// Set a flag, which takes no value and may be given once.
fn flag(slot: &mut bool, name: &str, inline: Option<&OsStr>) -> Result<(), UsageError> {
    if inline.is_some() {
        return Err(usage(format!("{name} takes no value")));
    }
    if *slot {
        return Err(usage(format!("{name} given twice")));
    }
    *slot = true;
    Ok(())
}

fn utf8<'a>(name: &str, value: &'a OsStr) -> Result<&'a str, UsageError> {
    value.to_str().ok_or_else(|| usage(format!("the value of {name} is not UTF-8")))
}

fn unexpected(command: &str, arg: &OsStr) -> UsageError {
    usage(format!("unexpected argument for {command}: {}", arg.display()))
}

fn unknown_option(command: &str, name: &str) -> UsageError {
    usage(format!("unknown option for {command}: {name}"))
}

/// The word `help` after a command.
fn is_help(word: &OsStr) -> bool {
    word == "help"
}

fn parse_keygen(args: &[OsString]) -> Result<Invocation, UsageError> {
    let mut file = None;
    let mut print = false;
    let mut args = Args::new(args);
    while let Some(arg) = args.next() {
        match arg {
            Arg::Option { name, inline } => match name.as_str() {
                "--key-file" => once(&mut file, &name, PathBuf::from(args.value(&name, inline)?))?,
                "--print" => flag(&mut print, &name, inline)?,
                _ => return Err(unknown_option("keygen", &name)),
            },
            Arg::Word(word) if is_help(word) => return Ok(Invocation::Help),
            Arg::Word(word) => return Err(unexpected("keygen", word)),
        }
    }
    match (file, print) {
        (Some(path), false) => Ok(Invocation::Keygen(KeyOutput::File(path))),
        (None, true) => Ok(Invocation::Keygen(KeyOutput::Print)),
        (Some(_), true) => Err(usage("keygen takes --key-file PATH or --print, not both")),
        (None, false) => Err(usage("keygen needs --key-file PATH or --print")),
    }
}

fn parse_run(args: &[OsString]) -> Result<Invocation, UsageError> {
    let mut state = None;
    let mut key_file = None;
    let mut key_command = None;
    let mut profile = None;
    let mut transport = None;
    let mut wire = None;
    let mut uhid_path = None;
    let mut udc = None;
    let mut gadget_name = None;
    let mut configfs = None;
    let mut ffs_dir = None;
    let mut vpcd_addr = None;
    let mut control = None;
    let mut wall_clock = false;
    let mut allow_unreadable = false;
    let mut exit_on_stdin_eof = false;
    let mut verbosity = None;
    let mut args = Args::new(args);
    while let Some(arg) = args.next() {
        let (name, inline) = match arg {
            Arg::Option { name, inline } => (name, inline),
            Arg::Word(word) if is_help(word) => return Ok(Invocation::Help),
            Arg::Word(word) => return Err(unexpected("run", word)),
        };
        match name.as_str() {
            "--state" => once(&mut state, &name, PathBuf::from(args.value(&name, inline)?))?,
            "--key-file" => once(&mut key_file, &name, PathBuf::from(args.value(&name, inline)?))?,
            "--key-command" => {
                let command = utf8(&name, args.value(&name, inline)?)?.to_owned();
                once(&mut key_command, &name, command)?;
            }
            "--profile" => {
                let value = utf8(&name, args.value(&name, inline)?)?;
                let parsed = Profile::parse(value).ok_or_else(|| {
                    usage(format!("unknown profile {value} (expected own or yubikey-5c-nano-5.7.4)"))
                })?;
                once(&mut profile, &name, parsed)?;
            }
            "--transport" => {
                let value = utf8(&name, args.value(&name, inline)?)?;
                once(&mut transport, &name, transport_set(value)?)?;
            }
            "--wire" => once(&mut wire, &name, PathBuf::from(args.value(&name, inline)?))?,
            "--uhid-path" => once(&mut uhid_path, &name, PathBuf::from(args.value(&name, inline)?))?,
            "--udc" => {
                let value = utf8(&name, args.value(&name, inline)?)?;
                if value.contains(['/', '\n']) {
                    return Err(usage(format!("--udc {value:?}: a controller name has no slash or newline")));
                }
                once(&mut udc, &name, value.to_owned())?;
            }
            "--gadget-name" => {
                let value = utf8(&name, args.value(&name, inline)?)?;
                if !valid_gadget_name(value) {
                    return Err(usage(format!(
                        "--gadget-name {value:?}: a gadget name is 1 to {MAX_GADGET_NAME} of A-Z, a-z, 0-9, _ and -"
                    )));
                }
                once(&mut gadget_name, &name, value.to_owned())?;
            }
            "--configfs" => once(&mut configfs, &name, PathBuf::from(args.value(&name, inline)?))?,
            "--ffs-dir" => once(&mut ffs_dir, &name, PathBuf::from(args.value(&name, inline)?))?,
            "--vpcd-addr" => {
                let value = utf8(&name, args.value(&name, inline)?)?;
                if !valid_host_port(value) {
                    return Err(usage(format!(
                        "--vpcd-addr {value:?}: expected HOST:PORT with a port from 1 to 65535, such as {DEFAULT_VPCD_ADDR}"
                    )));
                }
                once(&mut vpcd_addr, &name, value.to_owned())?;
            }
            "--control" => once(&mut control, &name, PathBuf::from(args.value(&name, inline)?))?,
            "--wall-clock" => flag(&mut wall_clock, &name, inline)?,
            "--allow-unreadable" => flag(&mut allow_unreadable, &name, inline)?,
            "--exit-on-stdin-eof" => flag(&mut exit_on_stdin_eof, &name, inline)?,
            "-v" | "-vv" => {
                let level = if name == "-v" { 1 } else { 2 };
                if verbosity.is_some() {
                    return Err(usage("-v or -vv given twice"));
                }
                verbosity = Some(level);
            }
            _ => return Err(unknown_option("run", &name)),
        }
    }
    let state = state.ok_or_else(|| usage("run needs --state DIR"))?;
    let key = match (key_file, key_command) {
        (Some(path), None) => KeySource::File(path),
        (None, Some(command)) => KeySource::Command(command),
        (Some(_), Some(_)) => return Err(usage("run takes --key-file PATH or --key-command CMD, not both")),
        (None, None) => return Err(usage("run needs --key-file PATH or --key-command CMD")),
    };
    let kinds = transport.unwrap_or_else(|| vec![TransportKind::Wire]);
    let set = kinds.iter().map(|kind| kind.name()).collect::<Vec<_>>().join(",");
    // Every option that belongs to one transport only, with a set that has that transport.
    let owned = [
        ("--wire", wire.is_some(), TransportKind::Wire),
        ("--uhid-path", uhid_path.is_some(), TransportKind::Uhid),
        ("--udc", udc.is_some(), TransportKind::Gadget),
        ("--gadget-name", gadget_name.is_some(), TransportKind::Gadget),
        ("--configfs", configfs.is_some(), TransportKind::Gadget),
        ("--ffs-dir", ffs_dir.is_some(), TransportKind::Gadget),
        ("--vpcd-addr", vpcd_addr.is_some(), TransportKind::Vpcd),
    ];
    if let Some((option, _, owner)) = owned.iter().find(|(_, given, owner)| *given && !kinds.contains(owner)) {
        return Err(usage(format!(
            "{option} applies to --transport {} only (the transport is {set})",
            owner.name()
        )));
    }
    let mut members = Vec::with_capacity(kinds.len());
    for kind in kinds {
        let member = match kind {
            TransportKind::Wire => TransportOptions::Wire { socket: wire.take() },
            TransportKind::Uhid => TransportOptions::Uhid {
                path: uhid_path.take().unwrap_or_else(|| PathBuf::from(DEFAULT_UHID_PATH)),
            },
            TransportKind::Gadget => {
                let udc = udc.take().ok_or_else(|| usage("--transport gadget needs --udc NAME"))?;
                let name = gadget_name.take().unwrap_or_else(|| DEFAULT_GADGET_NAME.to_owned());
                let ffs_dir = ffs_dir.take().unwrap_or_else(|| lk_gadget::default_mount_point(&name));
                let configfs = configfs.take().unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIGFS));
                TransportOptions::Gadget(GadgetOptions { udc, name, configfs, ffs_dir })
            }
            TransportKind::Vpcd => {
                TransportOptions::Vpcd { addr: vpcd_addr.take().unwrap_or_else(|| DEFAULT_VPCD_ADDR.to_owned()) }
            }
        };
        members.push(member);
    }
    let transport = Transports(members);
    Ok(Invocation::Run(RunOptions {
        state,
        key,
        profile: profile.unwrap_or(Profile::Own),
        transport,
        control,
        wall_clock,
        allow_unreadable,
        exit_on_stdin_eof,
        verbosity: verbosity.unwrap_or(0),
    }))
}

/// The members of a `--transport` value, in [`TransportKind`] order: one transport, or
/// `uhid` and `vpcd` in either order (`docs/PROGRAM.md` "Transport combinations").
fn transport_set(value: &str) -> Result<Vec<TransportKind>, UsageError> {
    let mut kinds = Vec::new();
    for item in value.split(',') {
        if item.is_empty() {
            return Err(usage(format!("--transport {value}: a transport name is empty")));
        }
        let kind = TransportKind::parse(item)
            .ok_or_else(|| usage(format!("unknown transport {item} (expected wire, uhid, gadget or vpcd)")))?;
        if kinds.contains(&kind) {
            return Err(usage(format!("--transport {value} names {item} twice")));
        }
        kinds.push(kind);
    }
    kinds.sort_unstable();
    match kinds.as_slice() {
        [_] | [TransportKind::Uhid, TransportKind::Vpcd] => Ok(kinds),
        _ => Err(usage(format!(
            "--transport {value} cannot be combined: the only set of several transports is uhid,vpcd \
             (wire and gadget present the whole device and combine with nothing)"
        ))),
    }
}

/// `HOST:PORT`: a non-empty host and a port from 1 to 65535 after the last `:` (an IPv6
/// address is written in brackets, `[::1]:35963`). Resolving is left to `run`.
fn valid_host_port(value: &str) -> bool {
    value.rsplit_once(':').is_some_and(|(host, port)| {
        !host.is_empty() && !host.contains(char::is_whitespace) && port.parse::<u16>().is_ok_and(|port| port != 0)
    })
}

/// 1 to [`MAX_GADGET_NAME`] of `[A-Za-z0-9_-]` (see the module's "As built" notes).
fn valid_gadget_name(name: &str) -> bool {
    (1..=MAX_GADGET_NAME).contains(&name.len())
        && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn parse_ctl(args: &[OsString]) -> Result<Invocation, UsageError> {
    let mut control = None;
    let mut words = Vec::new();
    let mut args = Args::new(args);
    while let Some(arg) = args.next() {
        match arg {
            Arg::Option { name, inline } => match name.as_str() {
                "--control" => once(&mut control, &name, PathBuf::from(args.value(&name, inline)?))?,
                _ => return Err(unknown_option("ctl", &name)),
            },
            Arg::Word(word) if is_help(word) => return Ok(Invocation::Help),
            Arg::Word(word) => words.push(word.to_str().ok_or_else(|| unexpected("ctl", word))?),
        }
    }
    let control = control.ok_or_else(|| usage("ctl needs --control PATH"))?;
    if words.is_empty() {
        return Err(usage("ctl needs a command: tap [long], down, up, power-cycle, status, watch or shutdown"));
    }
    let request = Request::parse(&words).ok_or_else(|| {
        usage(format!(
            "unknown ctl command: {} (expected tap [long], down, up, power-cycle, status, watch or shutdown)",
            words.join(" ")
        ))
    })?;
    Ok(Invocation::Ctl(CtlOptions { control, request }))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::Path;

    fn args(line: &[&str]) -> Vec<OsString> {
        line.iter().map(OsString::from).collect()
    }

    fn parsed(line: &[&str]) -> Result<Invocation, UsageError> {
        parse(&args(line))
    }

    fn error(line: &[&str]) -> String {
        match parsed(line) {
            Err(UsageError(message)) => message,
            Ok(invocation) => panic!("{line:?} parsed as {invocation:?}"),
        }
    }

    fn run(line: &[&str]) -> RunOptions {
        match parsed(line) {
            Ok(Invocation::Run(options)) => options,
            other => panic!("{line:?} gave {other:?}"),
        }
    }

    #[test]
    fn keygen_takes_a_key_file_or_print() {
        assert_eq!(parsed(&["keygen", "--key-file", "k"]), Ok(Invocation::Keygen(KeyOutput::File("k".into()))));
        assert_eq!(parsed(&["keygen", "--key-file=k"]), Ok(Invocation::Keygen(KeyOutput::File("k".into()))));
        assert_eq!(parsed(&["keygen", "--print"]), Ok(Invocation::Keygen(KeyOutput::Print)));
        assert_eq!(error(&["keygen"]), "keygen needs --key-file PATH or --print");
        assert_eq!(error(&["keygen", "--key-file", "k", "--print"]), "keygen takes --key-file PATH or --print, not both");
        assert_eq!(error(&["keygen", "--print=yes"]), "--print takes no value");
        assert_eq!(error(&["keygen", "extra"]), "unexpected argument for keygen: extra");
    }

    #[test]
    fn run_has_the_documented_defaults() {
        let options = run(&["run", "--state", "/s", "--key-file", "/k"]);
        assert_eq!(options.profile, Profile::Own);
        assert_eq!(options.transport.members(), [TransportOptions::Wire { socket: None }], "the wire is the default");
        assert_eq!(options.transport.name(), "wire");
        assert_eq!(options.control, None, "the sockets go into the state directory");
        assert_eq!(options.key, KeySource::File("/k".into()));
        assert!(!options.wall_clock && !options.allow_unreadable && !options.exit_on_stdin_eof);
        assert_eq!(options.verbosity, 0);
    }

    #[test]
    fn run_takes_every_documented_option() {
        let options = run(&[
            "run",
            "--state=/s",
            "--key-command",
            "pass show localkey",
            "--profile",
            "yubikey-5c-nano-5.7.4",
            "--wire",
            "/w",
            "--control",
            "/c",
            "--wall-clock",
            "--allow-unreadable",
            "--exit-on-stdin-eof",
            "-vv",
        ]);
        assert_eq!(options.state, PathBuf::from("/s"));
        assert_eq!(options.key, KeySource::Command("pass show localkey".into()));
        assert_eq!(options.profile, Profile::YubiKey5cNano574);
        assert_eq!(options.transport.members(), [TransportOptions::Wire { socket: Some(PathBuf::from("/w")) }]);
        assert_eq!(options.control, Some(PathBuf::from("/c")));
        assert!(options.wall_clock && options.allow_unreadable && options.exit_on_stdin_eof);
        assert_eq!(options.verbosity, 2);
        assert_eq!(run(&["run", "--state", "/s", "--key-file", "/k", "-v"]).verbosity, 1);
    }

    #[test]
    fn run_reports_missing_and_conflicting_options() {
        assert_eq!(error(&["run", "--key-file", "/k"]), "run needs --state DIR");
        assert_eq!(error(&["run", "--state", "/s"]), "run needs --key-file PATH or --key-command CMD");
        assert_eq!(
            error(&["run", "--state", "/s", "--key-file", "/k", "--key-command", "x"]),
            "run takes --key-file PATH or --key-command CMD, not both"
        );
        assert_eq!(error(&["run", "--state", "/s", "--state", "/t", "--key-file", "/k"]), "--state given twice");
        assert_eq!(error(&["run", "--state", "/s", "--key-file", "/k", "-v", "-vv"]), "-v or -vv given twice");
    }

    /// `run --state /s --key-file /k` followed by `extra`.
    fn run_line<'a>(extra: &[&'a str]) -> Vec<&'a str> {
        let mut line = vec!["run", "--state", "/s", "--key-file", "/k"];
        line.extend_from_slice(extra);
        line
    }

    /// The one transport of a set that has one.
    fn transport(extra: &[&str]) -> TransportOptions {
        match run(&run_line(extra)).transport.members() {
            [member] => member.clone(),
            members => panic!("{extra:?} gave the set {members:?}"),
        }
    }

    fn transports(extra: &[&str]) -> Transports {
        run(&run_line(extra)).transport
    }

    fn run_error(extra: &[&str]) -> String {
        error(&run_line(extra))
    }

    #[test]
    fn the_wire_transport_can_be_named() {
        let wire = transport(&["--transport", "wire", "--wire", "/w"]);
        assert_eq!(wire, TransportOptions::Wire { socket: Some(PathBuf::from("/w")) });
        assert_eq!(wire.kind(), TransportKind::Wire);
        assert_eq!(transport(&["--transport=wire"]), TransportOptions::Wire { socket: None });
    }

    #[test]
    fn the_uhid_transport_defaults_to_dev_uhid_and_takes_a_path() {
        let uhid = transport(&["--transport", "uhid"]);
        assert_eq!(uhid, TransportOptions::Uhid { path: PathBuf::from("/dev/uhid") });
        assert_eq!(uhid.kind(), TransportKind::Uhid);
        let uhid = transport(&["--uhid-path", "/tmp/fake", "--transport", "uhid"]);
        assert_eq!(uhid, TransportOptions::Uhid { path: PathBuf::from("/tmp/fake") });
        // The control socket belongs to every transport.
        assert_eq!(run(&run_line(&["--transport", "uhid", "--control", "/c"])).control, Some(PathBuf::from("/c")));
    }

    #[test]
    fn the_gadget_transport_needs_a_udc_and_has_the_documented_defaults() {
        let gadget = transport(&["--transport", "gadget", "--udc", "dummy_udc.0"]);
        let expected = GadgetOptions {
            udc: "dummy_udc.0".into(),
            name: "localkey".into(),
            configfs: PathBuf::from("/sys/kernel/config/usb_gadget"),
            ffs_dir: PathBuf::from("/dev/ffs-localkey"),
        };
        assert_eq!(gadget, TransportOptions::Gadget(expected));
        assert_eq!(gadget.kind(), TransportKind::Gadget);
        // The transport's own options may also come before --transport.
        let before = transport(&["--udc", "dummy_udc.0", "--gadget-name", "g", "--transport", "gadget"]);
        assert_eq!(before.kind(), TransportKind::Gadget);
        assert_eq!(run_error(&["--transport", "gadget"]), "--transport gadget needs --udc NAME");
        assert_eq!(run_error(&["--transport", "gadget", "--gadget-name", "g"]), "--transport gadget needs --udc NAME");
    }

    #[test]
    fn the_gadget_transport_takes_every_documented_option() {
        let options = run(&run_line(&[
            "--transport",
            "gadget",
            "--udc=fe980000.usb",
            "--gadget-name",
            "lk_2",
            "--configfs",
            "/cfg",
            "--ffs-dir",
            "/mnt/ffs",
            "--control",
            "/c",
        ]));
        let expected = GadgetOptions {
            udc: "fe980000.usb".into(),
            name: "lk_2".into(),
            configfs: PathBuf::from("/cfg"),
            ffs_dir: PathBuf::from("/mnt/ffs"),
        };
        assert_eq!(options.transport.members(), [TransportOptions::Gadget(expected)]);
        assert_eq!(options.control, Some(PathBuf::from("/c")));
    }

    #[test]
    fn the_default_ffs_dir_follows_the_gadget_name() {
        match transport(&["--transport", "gadget", "--udc", "u", "--gadget-name", "g-1"]) {
            TransportOptions::Gadget(gadget) => assert_eq!(gadget.ffs_dir, PathBuf::from("/dev/ffs-g-1")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_defaults_match_the_transport_crates() {
        assert_eq!(lk_uhid::DevUhid::default().path(), Path::new(DEFAULT_UHID_PATH));
        let crate_defaults = lk_gadget::GadgetConfig::new("u");
        let TransportOptions::Gadget(ours) = transport(&["--transport", "gadget", "--udc", "u"]) else {
            panic!("the gadget transport was asked for");
        };
        assert_eq!(ours.configfs, crate_defaults.configfs_root);
        assert_eq!(ours.name, crate_defaults.gadget_name);
        assert_eq!(ours.name, crate_defaults.function_name);
        assert_eq!(ours.ffs_dir, crate_defaults.mount_point);
        assert_eq!(ours.udc, crate_defaults.udc);
    }

    #[test]
    fn an_option_of_another_transport_is_a_usage_error_wherever_it_stands() {
        for (chosen, option, value, owner) in [
            ("wire", "--uhid-path", "/u", "uhid"),
            ("wire", "--udc", "u", "gadget"),
            ("wire", "--gadget-name", "g", "gadget"),
            ("wire", "--configfs", "/cfg", "gadget"),
            ("wire", "--ffs-dir", "/f", "gadget"),
            ("uhid", "--wire", "/w", "wire"),
            ("uhid", "--udc", "u", "gadget"),
            ("uhid", "--gadget-name", "g", "gadget"),
            ("uhid", "--configfs", "/cfg", "gadget"),
            ("uhid", "--ffs-dir", "/f", "gadget"),
            ("gadget", "--wire", "/w", "wire"),
            ("gadget", "--uhid-path", "/u", "uhid"),
            ("gadget", "--vpcd-addr", "127.0.0.1:1", "vpcd"),
            ("wire", "--vpcd-addr", "127.0.0.1:1", "vpcd"),
            ("uhid", "--vpcd-addr", "127.0.0.1:1", "vpcd"),
            ("vpcd", "--wire", "/w", "wire"),
            ("vpcd", "--uhid-path", "/u", "uhid"),
            ("vpcd", "--udc", "u", "gadget"),
            ("vpcd", "--ffs-dir", "/f", "gadget"),
            ("uhid,vpcd", "--wire", "/w", "wire"),
            ("uhid,vpcd", "--udc", "u", "gadget"),
            ("uhid,vpcd", "--configfs", "/cfg", "gadget"),
        ] {
            // The gadget transport's own required option, so only the foreign one is wrong.
            let required: &[&str] = if chosen == "gadget" { &["--udc", "u0"] } else { &[] };
            let expected = format!("{option} applies to --transport {owner} only (the transport is {chosen})");
            let before = [&[option, value, "--transport", chosen][..], required].concat();
            let after = [&["--transport", chosen][..], required, &[option, value]].concat();
            assert_eq!(run_error(&before), expected, "{before:?}");
            assert_eq!(run_error(&after), expected, "{after:?}");
        }
        // Without --transport the transport is the wire.
        assert_eq!(run_error(&["--udc", "u"]), "--udc applies to --transport gadget only (the transport is wire)");
        assert_eq!(
            run_error(&["--uhid-path", "/u"]),
            "--uhid-path applies to --transport uhid only (the transport is wire)"
        );
    }

    #[test]
    fn the_vpcd_transport_defaults_to_vpcds_own_port_on_loopback_and_takes_an_address() {
        let vpcd = transport(&["--transport", "vpcd"]);
        assert_eq!(vpcd, TransportOptions::Vpcd { addr: "127.0.0.1:35963".into() });
        assert_eq!(vpcd.kind(), TransportKind::Vpcd);
        assert_eq!(DEFAULT_VPCD_ADDR, lk_vpcd::protocol::DEFAULT_ADDR, "the crate's own default");
        for addr in ["127.0.0.1:40000", "[::1]:35963", "localhost:35963", "192.0.2.7:1", "vpcd.example:65535"] {
            let given = transport(&["--vpcd-addr", addr, "--transport=vpcd"]);
            assert_eq!(given, TransportOptions::Vpcd { addr: addr.into() }, "{addr}");
        }
    }

    #[test]
    fn a_vpcd_address_must_be_host_and_port() {
        for addr in ["127.0.0.1", "35963", ":35963", "localhost:", "h:0", "h:65536", "h:x", "[::1]", "a b:1"] {
            assert_eq!(
                run_error(&["--transport", "vpcd", "--vpcd-addr", addr]),
                format!("--vpcd-addr {addr:?}: expected HOST:PORT with a port from 1 to 65535, such as 127.0.0.1:35963"),
                "{addr}"
            );
        }
        assert_eq!(run_error(&["--transport", "vpcd", "--vpcd-addr="]), "--vpcd-addr needs a value");
    }

    /// `docs/PROGRAM.md` "Transport combinations": `uhid,vpcd` in either order, each with
    /// its own options and defaults, members in kind order.
    #[test]
    fn uhid_and_vpcd_combine_in_either_order_with_their_own_options() {
        let expected = [
            TransportOptions::Uhid { path: PathBuf::from("/dev/uhid") },
            TransportOptions::Vpcd { addr: "127.0.0.1:35963".into() },
        ];
        for value in ["uhid,vpcd", "vpcd,uhid"] {
            let set = transports(&["--transport", value]);
            assert_eq!(set.members(), expected, "{value}");
            assert_eq!(set.kinds(), [TransportKind::Uhid, TransportKind::Vpcd]);
            assert_eq!(set.name(), "uhid,vpcd", "{value}");
        }
        let set = transports(&["--vpcd-addr", "127.0.0.1:9", "--transport=vpcd,uhid", "--uhid-path", "/u", "--control", "/c"]);
        assert_eq!(
            set.members(),
            [TransportOptions::Uhid { path: PathBuf::from("/u") }, TransportOptions::Vpcd { addr: "127.0.0.1:9".into() }]
        );
    }

    #[test]
    fn other_combinations_duplicates_and_empty_names_are_usage_errors() {
        for value in ["wire,vpcd", "wire,uhid", "uhid,gadget", "gadget,vpcd", "wire,gadget", "uhid,vpcd,wire", "vpcd,uhid,gadget"] {
            assert_eq!(
                run_error(&["--transport", value]),
                format!(
                    "--transport {value} cannot be combined: the only set of several transports is uhid,vpcd \
                     (wire and gadget present the whole device and combine with nothing)"
                ),
                "{value}"
            );
        }
        assert_eq!(run_error(&["--transport", "uhid,uhid"]), "--transport uhid,uhid names uhid twice");
        assert_eq!(run_error(&["--transport", "vpcd,uhid,vpcd"]), "--transport vpcd,uhid,vpcd names vpcd twice");
        for value in ["uhid,", ",vpcd", "uhid,,vpcd", ","] {
            assert_eq!(run_error(&["--transport", value]), format!("--transport {value}: a transport name is empty"));
        }
        assert_eq!(run_error(&["--transport", "uhid, vpcd"]), "unknown transport  vpcd (expected wire, uhid, gadget or vpcd)");
        assert_eq!(run_error(&["--transport", "uhid,usb"]), "unknown transport usb (expected wire, uhid, gadget or vpcd)");
        assert_eq!(run_error(&["--transport", "uhid,vpcd", "--transport", "vpcd"]), "--transport given twice");
    }

    #[test]
    fn transport_values_and_names_are_checked() {
        assert_eq!(run_error(&["--transport", "usb"]), "unknown transport usb (expected wire, uhid, gadget or vpcd)");
        assert_eq!(run_error(&["--transport", "uhid", "--transport", "uhid"]), "--transport given twice");
        assert_eq!(run_error(&["--transport", "uhid", "--uhid-path"]), "--uhid-path needs a value");
        assert_eq!(run_error(&["--transport", "gadget", "--udc="]), "--udc needs a value");
        assert_eq!(
            run_error(&["--transport", "gadget", "--udc", "a/b"]),
            "--udc \"a/b\": a controller name has no slash or newline"
        );
        assert_eq!(
            run_error(&["--transport", "gadget", "--udc", "u", "--gadget-name", "a.b"]),
            "--gadget-name \"a.b\": a gadget name is 1 to 32 of A-Z, a-z, 0-9, _ and -"
        );
        let longest = "g".repeat(MAX_GADGET_NAME);
        let too_long = "g".repeat(MAX_GADGET_NAME + 1);
        let accepted = transport(&["--transport", "gadget", "--udc", "u", "--gadget-name", &longest]);
        assert_eq!(accepted.kind(), TransportKind::Gadget);
        let refused = run_error(&["--transport", "gadget", "--udc", "u", "--gadget-name", &too_long]);
        assert!(refused.starts_with("--gadget-name"), "{refused}");
    }

    #[test]
    fn a_forgotten_value_is_reported_instead_of_taking_the_next_option() {
        assert_eq!(error(&["run", "--state", "--key-file", "/k"]), "--state needs a value");
        assert_eq!(error(&["run", "--key-file", "/k", "--state"]), "--state needs a value");
        assert_eq!(error(&["run", "--state=", "--key-file", "/k"]), "--state needs a value");
        // A path that starts with `-` can still be given after `=`.
        assert_eq!(run(&["run", "--state=-s", "--key-file", "/k"]).state, PathBuf::from("-s"));
    }

    #[test]
    fn run_refuses_unknown_options_values_and_words() {
        assert_eq!(error(&["run", "--state", "/s", "--key-file", "/k", "--verbose"]), "unknown option for run: --verbose");
        assert_eq!(
            error(&["run", "--state", "/s", "--key-file", "/k", "--profile", "yubikey"]),
            "unknown profile yubikey (expected own or yubikey-5c-nano-5.7.4)"
        );
        assert_eq!(error(&["run", "--state", "/s", "--key-file", "/k", "now"]), "unexpected argument for run: now");
        assert_eq!(error(&["run", "--state", "/s", "--key-file", "/k", "--wall-clock=1"]), "--wall-clock takes no value");
    }

    #[test]
    fn paths_need_not_be_utf8() {
        let state = OsStr::from_bytes(b"/s\xff").to_owned();
        let line = vec![OsString::from("run"), OsString::from("--state"), state.clone(), "--key-file".into(), "/k".into()];
        match parse(&line) {
            Ok(Invocation::Run(options)) => assert_eq!(options.state, PathBuf::from(state)),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn ctl_takes_every_documented_command() {
        for (words, request) in [
            (&["tap"][..], Request::Tap { long: false }),
            (&["tap", "long"], Request::Tap { long: true }),
            (&["down"], Request::Down),
            (&["up"], Request::Up),
            (&["power-cycle"], Request::PowerCycle),
            (&["status"], Request::Status),
            (&["watch"], Request::Watch),
            (&["shutdown"], Request::Shutdown),
        ] {
            let mut line = vec!["ctl", "--control", "/c"];
            line.extend_from_slice(words);
            let expected = CtlOptions { control: "/c".into(), request };
            assert_eq!(parsed(&line), Ok(Invocation::Ctl(expected.clone())));
            assert_eq!(request.line(), words.join(" "));
            // The command may also come first.
            let mut line = vec!["ctl"];
            line.extend_from_slice(words);
            line.extend_from_slice(&["--control", "/c"]);
            assert_eq!(parsed(&line), Ok(Invocation::Ctl(expected)));
        }
    }

    #[test]
    fn ctl_reports_missing_and_unknown_commands() {
        assert_eq!(error(&["ctl", "status"]), "ctl needs --control PATH");
        assert_eq!(
            error(&["ctl", "--control", "/c"]),
            "ctl needs a command: tap [long], down, up, power-cycle, status, watch or shutdown"
        );
        assert_eq!(
            error(&["ctl", "--control", "/c", "tap", "short"]),
            "unknown ctl command: tap short (expected tap [long], down, up, power-cycle, status, watch or shutdown)"
        );
        assert_eq!(
            error(&["ctl", "--control", "/c", "shutdown", "now"]),
            "unknown ctl command: shutdown now (expected tap [long], down, up, power-cycle, status, watch or shutdown)"
        );
    }

    #[test]
    fn help_and_unknown_commands() {
        assert_eq!(parsed(&["--help"]), Ok(Invocation::Help));
        assert_eq!(parsed(&["help"]), Ok(Invocation::Help));
        assert_eq!(parsed(&["run", "-h"]), Ok(Invocation::Help));
        assert_eq!(error(&[]), "no command given (keygen, run or ctl)");
        assert_eq!(error(&["serve"]), "unknown command serve (expected keygen, run or ctl)");
    }

    #[test]
    fn the_word_help_after_a_command_asks_for_the_usage() {
        for line in [
            &["run", "--state", "/s", "--key-file", "/k", "help"][..],
            &["run", "help"],
            &["keygen", "help"],
            &["keygen", "--print", "help"],
            &["ctl", "--control", "/c", "help"],
            &["ctl", "tap", "help"],
            &["ctl", "help"],
        ] {
            assert_eq!(parsed(line), Ok(Invocation::Help), "{line:?}");
        }
    }

    #[test]
    fn help_as_an_option_value_stays_a_value() {
        assert_eq!(run(&["run", "--state", "help", "--key-file", "/k"]).state, PathBuf::from("help"));
        assert_eq!(run(&["run", "--state", "/s", "--key-command", "help"]).key, KeySource::Command("help".into()));
        let expected = CtlOptions { control: "help".into(), request: Request::Status };
        assert_eq!(parsed(&["ctl", "--control", "help", "status"]), Ok(Invocation::Ctl(expected)));
    }
}
