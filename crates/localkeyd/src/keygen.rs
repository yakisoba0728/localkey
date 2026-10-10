//! `localkeyd keygen (--key-file PATH | --print)`: a fresh storage key from the OS
//! (`docs/PROGRAM.md` "lk-host", Storage key).
//!
//! `--key-file` writes a new file with mode 0600 and never overwrites one (an older key
//! may still seal records). `--print` writes the key's text form to stdout, for a keychain
//! or password manager that a `--key-command` later reads it back from.
//!
//! Exit codes: 0 when the key was written, 1 when it could not be (the file exists, or the
//! OS randomness or the output failed).

use std::io::{self, Write};
use std::process::ExitCode;

use lk_host::{HostError, OsEntropy, generate_key, key_text, write_key_file};

use crate::args::KeyOutput;
use crate::log;

pub fn keygen(output: &KeyOutput) -> ExitCode {
    match write_key(output) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            log::line(message);
            ExitCode::FAILURE
        }
    }
}

fn write_key(output: &KeyOutput) -> Result<(), String> {
    let mut entropy = OsEntropy::open().map_err(|error| format!("randomness: {error}"))?;
    let key = generate_key(&mut entropy);
    match output {
        KeyOutput::File(path) => {
            write_key_file(path, &key).map_err(|error| match error {
                HostError::Io { source, .. } if source.kind() == io::ErrorKind::AlreadyExists => format!(
                    "{} already exists; keygen never overwrites a key file (records may still be sealed with it)",
                    path.display()
                ),
                error => format!("cannot write the key file: {error}"),
            })?;
            log::line(format!("wrote a new storage key to {} (mode 0600)", path.display()));
            Ok(())
        }
        KeyOutput::Print => {
            let text = key_text(&key);
            let mut stdout = io::stdout().lock();
            stdout.write_all(&text).and_then(|()| stdout.flush()).map_err(|error| format!("stdout: {error}"))
        }
    }
}
