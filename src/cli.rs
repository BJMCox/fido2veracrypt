//! The command line: commands, flags, and the help text.

use std::path::PathBuf;

use anyhow::{Result, anyhow, bail, ensure};

pub const HELP: &str = "\
fido2veracrypt opens VeraCrypt containers with a FIDO2 security key.

Usage: fido2veracrypt <command> [options]

Commands:
  create <container> --size <size> --label <label>
      Make a container and enroll the plugged-in key under <label>.
  adopt <container> --label <label>
      Enroll a key for an existing container and give it a new passphrase.
  open <container>
      Unlock and mount a container.
  close [<container>] [--force]
      Unmount a container, or every open one. On macOS, --force closes it even with files
      open, and unsaved changes in them are lost.
  add-key <container> --label <label> [--recovery]
      Enroll another key. --recovery uses the recovery passphrase and rebuilds the slot file.
  remove-key <container> --label <label>...
      Remove lost or stolen keys and change the passphrase.
  rotate <container>
      Change the passphrase and show the new one.
  status [<container>]
      Show the open volumes, or one container's keys and state.
  list-keys <container>
      List the enrolled keys.
  completions zsh|bash
      Print the shell completion script.
  help
      Show this text.

Sizes take a K, M, G, or T suffix, in powers of 1024.
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Create {
        container: PathBuf,
        size: u64,
        label: String,
    },
    Adopt {
        container: PathBuf,
        label: String,
    },
    Open {
        container: PathBuf,
    },
    Close {
        container: Option<PathBuf>,
        force: bool,
    },
    AddKey {
        container: PathBuf,
        label: String,
        recovery: bool,
    },
    RemoveKey {
        container: PathBuf,
        labels: Vec<String>,
    },
    Rotate {
        container: PathBuf,
    },
    Status {
        container: Option<PathBuf>,
    },
    ListKeys {
        container: PathBuf,
    },
    Completions {
        shell: Shell,
    },
    Help,
    Version,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    Zsh,
    Bash,
}

/// The words after a command name, split into positionals and flags.
#[derive(Default)]
struct Words {
    positionals: Vec<String>,
    size: Option<String>,
    labels: Vec<String>,
    force: bool,
    recovery: bool,
}

pub fn parse(args: &[String]) -> Result<Command> {
    let Some((name, rest)) = args.split_first() else {
        return Ok(Command::Help);
    };
    let words = words(rest)?;
    let command = match name.as_str() {
        "help" | "-h" | "--help" => {
            words.only(&[], 0)?;
            Command::Help
        }
        "--version" | "-V" => {
            words.only(&[], 0)?;
            Command::Version
        }
        "create" => {
            words.only(&["--size", "--label"], 1)?;
            Command::Create {
                container: words.container()?,
                size: parse_size(
                    words
                        .size
                        .as_deref()
                        .ok_or_else(|| anyhow!("create needs --size"))?,
                )?,
                label: words.label()?,
            }
        }
        "adopt" => {
            words.only(&["--label"], 1)?;
            Command::Adopt {
                container: words.container()?,
                label: words.label()?,
            }
        }
        "open" => {
            words.only(&[], 1)?;
            Command::Open {
                container: words.container()?,
            }
        }
        "close" => {
            words.only(&["--force"], 1)?;
            Command::Close {
                container: words.positionals.first().map(PathBuf::from),
                force: words.force,
            }
        }
        "add-key" => {
            words.only(&["--label", "--recovery"], 1)?;
            Command::AddKey {
                container: words.container()?,
                label: words.label()?,
                recovery: words.recovery,
            }
        }
        "remove-key" => {
            words.only(&["--label"], 1)?;
            ensure!(
                !words.labels.is_empty(),
                "remove-key needs at least one --label"
            );
            Command::RemoveKey {
                container: words.container()?,
                labels: words.labels.clone(),
            }
        }
        "rotate" => {
            words.only(&[], 1)?;
            Command::Rotate {
                container: words.container()?,
            }
        }
        "status" => {
            words.only(&[], 1)?;
            Command::Status {
                container: words.positionals.first().map(PathBuf::from),
            }
        }
        "list-keys" => {
            words.only(&[], 1)?;
            Command::ListKeys {
                container: words.container()?,
            }
        }
        "completions" => {
            words.only(&[], 1)?;
            Command::Completions {
                shell: match words.positionals.first().map(String::as_str) {
                    Some("zsh") => Shell::Zsh,
                    Some("bash") => Shell::Bash,
                    _ => bail!("completions takes zsh or bash"),
                },
            }
        }
        other => bail!("Unknown command {other:?}. Run `fido2veracrypt help`."),
    };
    Ok(command)
}

fn words(args: &[String]) -> Result<Words> {
    let mut words = Words::default();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let mut value = |flag: &str| {
            args.next()
                .cloned()
                .ok_or_else(|| anyhow!("{flag} needs a value"))
        };
        match arg.as_str() {
            "--size" => words.size = Some(value("--size")?),
            "--label" => words.labels.push(value("--label")?),
            "--force" => words.force = true,
            "--recovery" => words.recovery = true,
            flag if flag.starts_with("--") => bail!("Unknown option {flag}"),
            _ => words.positionals.push(arg.clone()),
        }
    }
    Ok(words)
}

impl Words {
    /// Refuses flags outside `allowed` and more than `max` positionals.
    fn only(&self, allowed: &[&str], max: usize) -> Result<()> {
        for (flag, used) in [
            ("--size", self.size.is_some()),
            ("--label", !self.labels.is_empty()),
            ("--force", self.force),
            ("--recovery", self.recovery),
        ] {
            ensure!(
                !used || allowed.contains(&flag),
                "This command takes no {flag}"
            );
        }
        ensure!(
            self.positionals.len() <= max,
            "Too many arguments: {}",
            self.positionals[max..].join(" ")
        );
        Ok(())
    }

    fn container(&self) -> Result<PathBuf> {
        self.positionals
            .first()
            .map(PathBuf::from)
            .ok_or_else(|| anyhow!("Name the container file"))
    }

    fn label(&self) -> Result<String> {
        match self.labels.as_slice() {
            [label] => Ok(label.clone()),
            [] => bail!("Give the key a --label"),
            _ => bail!("Give one --label"),
        }
    }
}

/// The arguments as text. `std::env::args` panics on bytes that are not UTF-8, which would break
/// the exit codes, so this refuses them with an error.
pub fn utf8_args(args: impl IntoIterator<Item = std::ffi::OsString>) -> Result<Vec<String>> {
    args.into_iter()
        .map(|arg| {
            arg.into_string().map_err(|arg| {
                anyhow!(
                    "The argument {} is not valid UTF-8. Rename the file.",
                    arg.to_string_lossy()
                )
            })
        })
        .collect()
}

/// Bytes, or a number with K, M, G, or T for powers of 1024.
pub fn parse_size(text: &str) -> Result<u64> {
    let (digits, shift) = match text.chars().last().map(|c| c.to_ascii_uppercase()) {
        Some('K') => (&text[..text.len() - 1], 10),
        Some('M') => (&text[..text.len() - 1], 20),
        Some('G') => (&text[..text.len() - 1], 30),
        Some('T') => (&text[..text.len() - 1], 40),
        _ => (text, 0),
    };
    ensure!(
        !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()),
        "The size {text:?} is not a whole number with an optional K, M, G, or T"
    );
    let number: u64 = digits.parse()?;
    number
        .checked_mul(1 << shift)
        .ok_or_else(|| anyhow!("The size {text:?} is too large"))
}

#[cfg(test)]
mod tests;
