//! Runs VeraCrypt's Linux mounts as root for fido2veracrypt, through a sudoers rule that allows
//! only this program. See the README for installing it.

use std::process::ExitCode;

use fido2veracrypt::helper;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match helper::parse(&args).and_then(|action| helper::run(&action)) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::from(2)
        }
    }
}
