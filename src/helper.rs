//! The root helper's checks. It runs VeraCrypt as root for Linux mounts, so it accepts only fixed
//! actions on containers that have a slot file beside them, and passes VeraCrypt fixed options.
//! Root VeraCrypt with free options would be root code execution: `--token-lib` loads any
//! library, and `--create` with `--force` overwrites any file.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

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
    /// Mounts the container. The passphrase comes on stdin. Without a hash, VeraCrypt tries each.
    Open {
        container: PathBuf,
        hash: Option<String>,
    },
    /// Attaches the container without a filesystem and detaches it again, to test a passphrase
    /// from stdin.
    Check {
        container: PathBuf,
        hash: Option<String>,
    },
    Close {
        container: PathBuf,
        force: bool,
    },
}

pub fn parse(args: &[String]) -> Result<Action> {
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    // `any` lets VeraCrypt try every key derivation, for a header whose one is not known.
    let hash = |hash: &str| match hash {
        "any" => Ok(None),
        hash if HASHES.contains(&hash) => Ok(Some(hash.to_owned())),
        hash => bail!("Unknown key derivation {hash:?}"),
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
            "Usage: fido2veracrypt-helper open|check <container> <hash|any>, or close <container> [--force]"
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

/// The VeraCrypt runs for `action`, in order. A check detaches in the same call, so a client
/// killed in between cannot leave a root device attached.
pub fn veracrypt_steps(action: &Action) -> Vec<Vec<String>> {
    match action {
        Action::Open { container, hash } => {
            vec![mount_args(container, hash.as_deref(), true, true)]
        }
        Action::Check { container, hash } => vec![
            mount_args(container, hash.as_deref(), true, false),
            close_args(container, false),
        ],
        Action::Close { container, force } => vec![close_args(container, *force)],
    }
}

fn close_args(container: &Path, force: bool) -> Vec<String> {
    let mut args = vec!["--text".to_owned(), "--non-interactive".to_owned()];
    if force {
        args.push("--force".to_owned());
    }
    args.push("-u".to_owned());
    args.push(container.display().to_string());
    args
}

/// The environment VeraCrypt gets: a fixed `PATH`, and sudo's record of the real user, which
/// VeraCrypt needs to mount the volume for that user. sudo sets the `SUDO_` variables itself and,
/// with its default `env_reset`, drops any the user passes, so they cannot name another user.
pub fn environment(from: impl Fn(&str) -> Option<OsString>) -> Vec<(String, OsString)> {
    let mut env = vec![(
        "PATH".to_owned(),
        OsString::from("/usr/sbin:/usr/bin:/sbin:/bin"),
    )];
    for name in ["SUDO_UID", "SUDO_GID", "SUDO_USER"] {
        if let Some(value) = from(name) {
            env.push((name.to_owned(), value));
        }
    }
    env
}

/// Runs each step with only [`environment`], stops at the first failure, and passes on its exit
/// status. The first step reads the helper's stdin, so the passphrase flows through, and messages
/// flow back on stdout and stderr.
pub fn run(action: &Action) -> Result<ExitCode> {
    for (index, args) in veracrypt_steps(action).into_iter().enumerate() {
        let status = Command::new(VERACRYPT)
            .env_clear()
            .envs(environment(|name| std::env::var_os(name)))
            .args(args)
            .stdin(if index == 0 {
                Stdio::inherit()
            } else {
                Stdio::null()
            })
            .status()
            .with_context(|| format!("Cannot run {VERACRYPT}"))?;
        match status.code() {
            Some(0) => {}
            Some(code) => return Ok(ExitCode::from(u8::try_from(code).unwrap_or(1))),
            None => return Ok(ExitCode::FAILURE),
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests;
