//! Runs VeraCrypt's Linux mounts as root for fido2veracrypt, through a sudoers rule that allows
//! only this program. See the README for installing it.

use std::process::ExitCode;

use fido2veracrypt::{cli, helper};

fn main() -> ExitCode {
    let parsed = cli::utf8_args(std::env::args_os().skip(1)).and_then(|args| helper::parse(&args));
    match parsed.and_then(|action| helper::run(&action)) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::from(2)
        }
    }
}
