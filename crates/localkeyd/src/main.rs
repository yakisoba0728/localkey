//! `localkeyd`: the daemon binary (`docs/PROGRAM.md` "localkeyd").
//!
//! - `keygen` makes a storage key ([`keygen`]);
//! - `run` opens the state directory, starts the device on the runner thread and serves it
//!   on the wire socket, with the control socket for the user side ([`run`]);
//! - `ctl` sends one request to a running daemon's control socket ([`ctl`]).
//!
//! The arguments are parsed by hand ([`args`]); a usage error exits with code 2 and prints
//! the usage to stderr. Unix only, like `lk-wire`.

#![forbid(unsafe_code)]

mod args;
mod ctl;
mod keygen;
mod log;
mod run;

use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

use args::{Invocation, USAGE};

/// Exit code of a runtime failure (`docs/PROGRAM.md` "localkeyd", exit codes).
const EXIT_RUNTIME: u8 = 1;
/// Exit code of a startup failure: usage, lock, key, permissions.
const EXIT_STARTUP: u8 = 2;
/// Exit code of `run` refusing unreadable records.
const EXIT_UNREADABLE: u8 = 3;

fn main() -> ExitCode {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    match args::parse(&arguments) {
        Ok(Invocation::Help) => {
            let _ = io::stdout().write_all(USAGE.as_bytes());
            ExitCode::SUCCESS
        }
        Ok(Invocation::Keygen(output)) => keygen::keygen(&output),
        Ok(Invocation::Run(options)) => run::run(&options),
        Ok(Invocation::Ctl(options)) => ctl::ctl(&options),
        Err(error) => {
            log::line(error);
            let _ = io::stderr().write_all(USAGE.as_bytes());
            ExitCode::from(EXIT_STARTUP)
        }
    }
}
