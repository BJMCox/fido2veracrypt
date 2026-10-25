//! The root helper's checks. It runs VeraCrypt as root for Linux mounts, so it accepts only fixed
//! actions on containers that have a slot file beside them, and passes VeraCrypt fixed options.
//! Root VeraCrypt with free options would be root code execution: `--token-lib` loads any
//! library, and `--create` with `--force` overwrites any file.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{Context, Result, bail, ensure};

use crate::slots;
use crate::veracrypt::mount_args;

/// Where VeraCrypt's Linux packages install it. The helper never searches `PATH`.
const VERACRYPT: &str = "/usr/bin/veracrypt";
/// VeraCrypt's key derivations.
const HASHES: [&str; 6] = [
    "Argon2",
    "SHA-512",
    "SHA-256",
    "BLAKE2s-256",
    "Whirlpool",
    "Streebog",
];

#[derive(Debug)]
pub enum Action {
    /// Mounts the container. The passphrase comes on stdin.
    Open {
        container: PathBuf,
        hash: String,
    },
    /// Attaches the container without a filesystem, to test a passphrase from stdin.
    Check {
        container: PathBuf,
        hash: String,
    },
    Close {
        container: PathBuf,
        force: bool,
    },
}

pub fn parse(args: &[String]) -> Result<Action> {
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let hash = |hash: &str| {
        ensure!(HASHES.contains(&hash), "Unknown key derivation {hash:?}");
        Ok(hash.to_owned())
    };
    Ok(match words.as_slice() {
        ["open", container, h] => Action::Open {
            container: checked(Path::new(container))?,
            hash: hash(h)?,
        },
        ["check", container, h] => Action::Check {
            container: checked(Path::new(container))?,
            hash: hash(h)?,
        },
        ["close", container] => Action::Close {
            container: checked(Path::new(container))?,
            force: false,
        },
        ["close", container, "--force"] => Action::Close {
            container: checked(Path::new(container))?,
            force: true,
        },
        _ => bail!(
            "Usage: fido2veracrypt-helper open|check <container> <hash>, or close <container> [--force]"
        ),
    })
}

/// The container's canonical path, if it is an absolute path to a regular file with a slot file
/// beside it.
pub fn checked(container: &Path) -> Result<PathBuf> {
    ensure!(
        container.is_absolute(),
        "The container path must be absolute"
    );
    let canonical = container
        .canonicalize()
        .with_context(|| format!("No container at {}", container.display()))?;
    ensure!(
        canonical.metadata()?.is_file(),
        "{} is not a regular file",
        canonical.display()
    );
    let slot = slots::path(&canonical);
    ensure!(
        slot.symlink_metadata().is_ok_and(|m| m.is_file()),
        "{} has no slot file beside it",
        canonical.display()
    );
    Ok(canonical)
}

pub fn veracrypt_args(action: &Action) -> Vec<String> {
    match action {
        Action::Open { container, hash } => mount_args(container, Some(hash), true),
        Action::Check { container, hash } => {
            let mut args = mount_args(container, Some(hash), true);
            args.insert(args.len() - 1, "--filesystem=none".to_owned());
            args
        }
        Action::Close { container, force } => {
            let mut args = vec!["--text".to_owned(), "--non-interactive".to_owned()];
            if *force {
                args.push("--force".to_owned());
            }
            args.push("-u".to_owned());
            args.push(container.display().to_string());
            args
        }
    }
}

/// Runs VeraCrypt with a cleared environment and passes on its exit status. Its stdin, stdout,
/// and stderr are the helper's own, so the passphrase flows through and messages flow back.
pub fn run(action: &Action) -> Result<ExitCode> {
    let status = Command::new(VERACRYPT)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .args(veracrypt_args(action))
        .status()
        .with_context(|| format!("Cannot run {VERACRYPT}"))?;
    Ok(match status.code() {
        Some(0) => ExitCode::SUCCESS,
        Some(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        None => ExitCode::FAILURE,
    })
}

#[cfg(test)]
mod tests;
