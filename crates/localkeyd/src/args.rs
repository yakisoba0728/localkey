//! Hand-written argument parsing (`docs/PROGRAM.md` "localkeyd": no third-party crates).
//!
//! ```text
//! localkeyd keygen (--key-file PATH | --print)
//! localkeyd run --state DIR (--key-file PATH | --key-command CMD)
//!               [--profile own|yubikey-5c-nano-5.7.4] [--wire PATH] [--control PATH]
//!               [--wall-clock] [--allow-unreadable] [--exit-on-stdin-eof] [-v | -vv]
//! localkeyd ctl --control PATH (tap [long] | down | up | power-cycle | status | watch)
//! ```
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

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

/// The usage text, printed for `--help` (stdout) and after a usage error (stderr).
pub const USAGE: &str = "\
usage:
  localkeyd keygen (--key-file PATH | --print)
  localkeyd run --state DIR (--key-file PATH | --key-command CMD)
                [--profile own|yubikey-5c-nano-5.7.4] [--wire PATH] [--control PATH]
                [--wall-clock] [--allow-unreadable] [--exit-on-stdin-eof] [-v | -vv]
  localkeyd ctl --control PATH (tap [long] | down | up | power-cycle | status | watch)

run defaults: --profile own, --wire DIR/wire.sock, --control DIR/control.sock
exit codes: 0 clean, 1 runtime failure, 2 startup failure (usage, lock, key,
permissions), 3 unreadable records refused (see --allow-unreadable)
";

/// The wire socket's name in the state directory when `--wire` is not given.
pub const WIRE_SOCKET: &str = "wire.sock";
/// The control socket's name in the state directory when `--control` is not given.
pub const CONTROL_SOCKET: &str = "control.sock";

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

/// The options of `run`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOptions {
    pub state: PathBuf,
    pub key: KeySource,
    pub profile: Profile,
    /// `--wire`; `None` is [`WIRE_SOCKET`] in the state directory.
    pub wire: Option<PathBuf>,
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
    let mut wire = None;
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
            "--wire" => once(&mut wire, &name, PathBuf::from(args.value(&name, inline)?))?,
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
    Ok(Invocation::Run(RunOptions {
        state,
        key,
        profile: profile.unwrap_or(Profile::Own),
        wire,
        control,
        wall_clock,
        allow_unreadable,
        exit_on_stdin_eof,
        verbosity: verbosity.unwrap_or(0),
    }))
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
        return Err(usage("ctl needs a command: tap [long], down, up, power-cycle, status or watch"));
    }
    let request = Request::parse(&words).ok_or_else(|| {
        usage(format!(
            "unknown ctl command: {} (expected tap [long], down, up, power-cycle, status or watch)",
            words.join(" ")
        ))
    })?;
    Ok(Invocation::Ctl(CtlOptions { control, request }))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!((options.wire, options.control), (None, None), "the sockets go into the state directory");
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
        assert_eq!(options.wire, Some(PathBuf::from("/w")));
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
        assert_eq!(error(&["ctl", "--control", "/c"]), "ctl needs a command: tap [long], down, up, power-cycle, status or watch");
        assert_eq!(
            error(&["ctl", "--control", "/c", "tap", "short"]),
            "unknown ctl command: tap short (expected tap [long], down, up, power-cycle, status or watch)"
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
