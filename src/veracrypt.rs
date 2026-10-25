//! Runs VeraCrypt. Passphrases go to its stdin, never on a command line.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use zeroize::Zeroizing;

/// 1.26.30 fixes CVE-2026-108982, where a FUSE-T dismount could leave the volume readable, and it
/// is the version the tests pin.
const MIN_VERSION: (u32, u32, u32) = (1, 26, 30);
/// The key derivation every container gets.
pub const HASH: &str = "Argon2";
/// How long the passphrase change waits for each prompt.
pub const TIMEOUT: Duration = Duration::from_secs(30);
/// The root-owned helper that runs VeraCrypt's Linux mounts.
pub const HELPER: &str = "/usr/local/libexec/fido2veracrypt-helper";
const MAC_APP: &str = "/Applications/VeraCrypt.app/Contents/MacOS/VeraCrypt";

/// The prompts of `veracrypt --text -C`, in order, and whether each takes the new passphrase.
const PROMPTS: [(&str, bool); 3] = [
    ("Enter password: ", false),
    ("Enter new password: ", true),
    ("Re-enter password: ", true),
];
const CHANGED: &str = "Password, PIM and/or keyfile(s) successfully changed.";

/// A volume VeraCrypt has open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Volume {
    pub container: PathBuf,
    pub device: Option<String>,
    /// None for a volume attached without a filesystem, or left behind by a Finder eject.
    pub mount_point: Option<PathBuf>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Mount {
    Mounted,
    WrongPassphrase,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Close {
    Closed,
    /// A file on the volume is open.
    Busy,
    NotOpen,
}

pub trait VeraCrypt {
    /// Makes an exFAT container. On Linux the label comes from formatting. On macOS a failed
    /// label leaves a working volume, so it comes back as `Ok(Some(error))`.
    fn create(
        &self,
        container: &Path,
        size: u64,
        passphrase: &str,
        label: &str,
    ) -> Result<Option<anyhow::Error>>;
    fn mount(&self, container: &Path, passphrase: &str, hash: Option<&str>) -> Result<Mount>;
    /// Whether `passphrase` opens the header, checked without mounting a filesystem.
    fn opens(&self, container: &Path, passphrase: &str, hash: Option<&str>) -> Result<bool>;
    fn close(&self, container: &Path, force: bool) -> Result<Close>;
    fn list(&self) -> Result<Vec<Volume>>;
    /// Changes the header from `old` to `new`, and its key derivation to Argon2. `old_hash` is the
    /// current key derivation, when known. In `-C` mode VeraCrypt takes it as `--hash`, and the
    /// new one as `--new-hash`.
    fn change(&self, container: &Path, old: &str, old_hash: Option<&str>, new: &str) -> Result<()>;
    /// Sets an exFAT label on macOS.
    fn set_label(&self, mount_point: &Path, label: &str) -> Result<()>;
}

/// The installed VeraCrypt.
pub struct Real {
    binary: PathBuf,
    linux: bool,
}

impl Real {
    /// Finds VeraCrypt (`configured`, then the macOS app, then `PATH`) and refuses versions before
    /// 1.26.30.
    pub fn find(configured: Option<PathBuf>) -> Result<Self> {
        let binary = configured
            .or_else(|| Path::new(MAC_APP).is_file().then(|| PathBuf::from(MAC_APP)))
            .or_else(|| on_path("veracrypt"))
            .context(
                "VeraCrypt is not installed. On macOS: brew install --cask veracrypt-fuse-t",
            )?;
        let output = Command::new(&binary)
            .args(["--text", "--version"])
            .output()
            .with_context(|| format!("Cannot run {}", binary.display()))?;
        check_version(&String::from_utf8_lossy(&output.stdout))?;
        Ok(Self {
            binary,
            linux: cfg!(target_os = "linux"),
        })
    }

    /// The VeraCrypt binary in use.
    pub fn binary(&self) -> &Path {
        &self.binary
    }

    fn veracrypt(&self) -> Command {
        Command::new(&self.binary)
    }

    /// VeraCrypt as root on Linux: through the helper when it is installed and the container has a
    /// slot file, which the helper requires, else through sudo with the same fixed options. A
    /// container has no slot file yet during `adopt`, and has lost it in a recovery.
    fn root(&self, action: &str, container: &Path, extra: &[&str], args: Vec<String>) -> Command {
        if Path::new(HELPER).is_file() && crate::slots::path(container).is_file() {
            let mut command = Command::new("sudo");
            command.arg(HELPER).arg(action).arg(container).args(extra);
            command
        } else {
            let mut command = Command::new("sudo");
            command.arg(&self.binary).args(args);
            command
        }
    }

    fn mount_command(&self, container: &Path, hash: Option<&str>, filesystem: bool) -> Command {
        let args = mount_args(container, hash, self.linux, filesystem);
        if !self.linux {
            let mut command = self.veracrypt();
            command.args(args);
            return command;
        }
        let action = if filesystem { "open" } else { "check" };
        // `any` asks the helper to let VeraCrypt try every key derivation.
        self.root(action, container, &[hash.unwrap_or("any")], args)
    }
}

impl VeraCrypt for Real {
    fn create(
        &self,
        container: &Path,
        size: u64,
        passphrase: &str,
        label: &str,
    ) -> Result<Option<anyhow::Error>> {
        let filesystem = if self.linux { "none" } else { "exfat" };
        let mut args: Vec<String> = ["--text", "--non-interactive", "--stdin", "--create"]
            .map(str::to_owned)
            .to_vec();
        args.push(container.display().to_string());
        args.extend([
            format!("--size={size}"),
            "--volume-type=normal".into(),
            "--encryption=AES".into(),
            format!("--hash={HASH}"),
            format!("--filesystem={filesystem}"),
            "--pim=0".into(),
            "-k".into(),
            String::new(),
            "--random-source=/dev/urandom".into(),
        ]);
        // On Linux too the container file is made as the user, so it stays theirs. Only attaching
        // and formatting need root.
        let mut command = self.veracrypt();
        command.args(&args);
        succeed(run(&mut command, Some(passphrase))?, "create the container")?;
        if self.linux {
            return self
                .format_on_linux(container, passphrase, label)
                .map(|()| None);
        }
        Ok(self.label_new(container, passphrase, label).err())
    }

    fn mount(&self, container: &Path, passphrase: &str, hash: Option<&str>) -> Result<Mount> {
        let output = run(
            &mut self.mount_command(container, hash, true),
            Some(passphrase),
        )?;
        if output.status.success() {
            return Ok(Mount::Mounted);
        }
        if text(&output).contains("Incorrect password") {
            return Ok(Mount::WrongPassphrase);
        }
        bail!(
            "VeraCrypt could not open the container: {}",
            text(&output).trim()
        )
    }

    fn opens(&self, container: &Path, passphrase: &str, hash: Option<&str>) -> Result<bool> {
        let output = run(
            &mut self.mount_command(container, hash, false),
            Some(passphrase),
        )?;
        if !output.status.success() {
            ensure!(
                text(&output).contains("Incorrect password"),
                "VeraCrypt could not check the passphrase: {}",
                text(&output).trim()
            );
            return Ok(false);
        }
        match self.close(container, false)? {
            Close::Closed | Close::NotOpen => Ok(true),
            Close::Busy => {
                bail!("VeraCrypt attached the container to check it and could not detach it")
            }
        }
    }

    fn close(&self, container: &Path, force: bool) -> Result<Close> {
        let mut args = vec!["--text".to_owned(), "--non-interactive".to_owned()];
        if force {
            args.push("--force".to_owned());
        }
        args.push("-u".to_owned());
        args.push(container.display().to_string());
        let mut command = if self.linux {
            self.root(
                "close",
                container,
                if force { &["--force"] } else { &[] },
                args,
            )
        } else {
            let mut command = self.veracrypt();
            command.args(args);
            command
        };
        let output = run(&mut command, None)?;
        close_outcome(output.status.success(), &text(&output))
    }

    fn list(&self) -> Result<Vec<Volume>> {
        let output = run(self.veracrypt().args(["--text", "-l", "-v"]), None)?;
        let said = text(&output);
        ensure!(
            output.status.success() || said.contains("No volumes mounted"),
            "VeraCrypt could not list its volumes: {}",
            said.trim()
        );
        Ok(parse_list(&said))
    }

    fn change(&self, container: &Path, old: &str, old_hash: Option<&str>, new: &str) -> Result<()> {
        let mut command = self.veracrypt();
        command.args(change_args(container, old_hash));
        drive_change(&mut command, old, new, TIMEOUT)
    }

    fn set_label(&self, mount_point: &Path, label: &str) -> Result<()> {
        let output = run(
            Command::new("diskutil")
                .arg("rename")
                .arg(mount_point)
                .arg(label),
            None,
        )?;
        succeed(output, "set the volume label")
    }
}

impl Real {
    /// VeraCrypt cannot label a filesystem, so this attaches the bare volume as root and
    /// mkfs.exfat formats it with the label. The volume is detached again whatever fails.
    fn format_on_linux(&self, container: &Path, passphrase: &str, label: &str) -> Result<()> {
        let mut attach = Command::new("sudo");
        attach
            .arg(&self.binary)
            .args(mount_args(container, Some(HASH), true, false));
        succeed(
            run(&mut attach, Some(passphrase))?,
            "attach the new container",
        )?;
        let formatted = (|| {
            // sudo keeps SUDO_UID, so root's VeraCrypt lists the volume it attached.
            let listed = run(
                Command::new("sudo")
                    .arg(&self.binary)
                    .args(["--text", "-l", "-v"]),
                None,
            )?;
            let device = parse_list(&text(&listed))
                .into_iter()
                .find(|v| v.container == container)
                .and_then(|v| v.device)
                .context("VeraCrypt attached the container but reported no device")?;
            succeed(
                run(
                    Command::new("sudo").args(["mkfs.exfat", "-L", label, &device]),
                    None,
                )?,
                "format the container with mkfs.exfat",
            )
        })();
        let detached = self.close(container, false);
        formatted?;
        match detached? {
            Close::Closed | Close::NotOpen => Ok(()),
            Close::Busy => bail!("The new container is formatted but could not be detached"),
        }
    }

    /// Opens a new macOS container once to label it, then closes it.
    fn label_new(&self, container: &Path, passphrase: &str, label: &str) -> Result<()> {
        ensure!(
            self.mount(container, passphrase, Some(HASH))? == Mount::Mounted,
            "The new container did not open with its passphrase"
        );
        let labeled = self
            .list()?
            .into_iter()
            .find(|v| v.container == container)
            .and_then(|v| v.mount_point)
            .context("VeraCrypt reported no mount point for the new container")
            .and_then(|mount_point| self.set_label(&mount_point, label));
        self.close(container, false)?;
        labeled
    }
}

/// The arguments of `veracrypt -C`. Without `old_hash`, VeraCrypt tries every key derivation.
pub fn change_args(container: &Path, old_hash: Option<&str>) -> Vec<String> {
    let mut args: Vec<String> = [
        "--text",
        "-C",
        "--pim=0",
        "--new-pim=0",
        "-k",
        "",
        "--new-keyfiles=",
        "--random-source=/dev/urandom",
    ]
    .map(str::to_owned)
    .to_vec();
    if let Some(hash) = old_hash {
        args.push(format!("--hash={hash}"));
    }
    args.push(format!("--new-hash={HASH}"));
    args.push(container.display().to_string());
    args
}

/// Mount options. With `mount` false, VeraCrypt attaches the volume without a filesystem. A Linux
/// mount runs as root, so it accepts only exFAT: any other type would have the kernel parse a
/// filesystem image the user wrote.
pub fn mount_args(container: &Path, hash: Option<&str>, linux: bool, mount: bool) -> Vec<String> {
    let mut args: Vec<String> = ["--text", "--non-interactive", "--stdin"]
        .map(str::to_owned)
        .to_vec();
    if let Some(hash) = hash {
        args.push(format!("--hash={hash}"));
    }
    args.extend(["--pim=0", "-k", "", "--protect-hidden=no"].map(str::to_owned));
    if !mount {
        args.push("--filesystem=none".to_owned());
    } else if linux {
        args.push("--filesystem=exfat".to_owned());
        args.push("--fs-options=nosuid,nodev".to_owned());
    }
    args.push(container.display().to_string());
    args
}

/// What a `veracrypt -u` run reports. A busy volume reads "in use" from VeraCrypt on macOS and
/// "target is busy" from umount on Linux.
pub fn close_outcome(success: bool, said: &str) -> Result<Close> {
    Ok(if success {
        Close::Closed
    } else if said.contains("in use") || said.contains("target is busy") {
        Close::Busy
    } else if said.contains("No such volume") {
        Close::NotOpen
    } else {
        bail!("VeraCrypt could not close the container: {}", said.trim())
    })
}

/// Parses `veracrypt --text -l -v`, whose labeled lines keep paths with spaces intact.
pub fn parse_list(text: &str) -> Vec<Volume> {
    let mut volumes = Vec::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        let present = (!value.is_empty() && value != "-").then(|| value.to_owned());
        match key {
            "Slot" => volumes.push(Volume {
                container: PathBuf::new(),
                device: None,
                mount_point: None,
            }),
            "Volume" => {
                if let Some(volume) = volumes.last_mut() {
                    volume.container = PathBuf::from(value);
                }
            }
            "Virtual Device" => {
                if let Some(volume) = volumes.last_mut() {
                    volume.device = present;
                }
            }
            "Mount Directory" => {
                if let Some(volume) = volumes.last_mut() {
                    volume.mount_point = present.map(PathBuf::from);
                }
            }
            _ => {}
        }
    }
    volumes
}

pub fn parse_version(text: &str) -> Result<(u32, u32, u32)> {
    let version = text
        .split_whitespace()
        .find_map(|word| {
            let parts: Vec<u32> = word
                .split('.')
                .map(str::parse)
                .collect::<Result<_, _>>()
                .ok()?;
            match parts.as_slice() {
                [major, minor, patch] => Some((*major, *minor, *patch)),
                _ => None,
            }
        })
        .with_context(|| format!("Cannot read VeraCrypt's version from {:?}", text.trim()))?;
    Ok(version)
}

pub fn check_version(text: &str) -> Result<()> {
    let version = parse_version(text)?;
    ensure!(
        version >= MIN_VERSION,
        "VeraCrypt {}.{}.{} is too old. Install 1.26.30 or later, which fixes a dismount that could leave a volume readable.",
        version.0,
        version.1,
        version.2
    );
    Ok(())
}

/// Answers the prompts of `veracrypt --text -C`. Any prompt other than the next expected one, or
/// a silence longer than `timeout`, stops VeraCrypt before it gets an answer, so it changes
/// nothing.
pub fn drive_change(command: &mut Command, old: &str, new: &str, timeout: Duration) -> Result<()> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Cannot run VeraCrypt")?;
    let output = merged(&mut child);
    let mut stdin = child.stdin.take();
    let mut said = String::new();
    for (prompt, takes_new) in PROMPTS {
        if let Err(error) = wait_for(&output, &mut said, prompt, timeout) {
            drop(stdin);
            let _ = child.kill();
            let _ = child.wait();
            return Err(
                error.context("VeraCrypt's password change stopped. The container is unchanged.")
            );
        }
        said.clear();
        let answer = Zeroizing::new(format!("{}\n", if takes_new { new } else { old }));
        stdin
            .as_mut()
            .context("VeraCrypt's input closed")?
            .write_all(answer.as_bytes())
            .context("VeraCrypt stopped reading")?;
    }
    drop(stdin.take());
    let deadline = Instant::now() + timeout;
    loop {
        match output.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(chunk) => said.push_str(&String::from_utf8_lossy(&chunk)),
            Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => {
                let _ = child.kill();
                let _ = child.wait();
                bail!("VeraCrypt did not finish the password change");
            }
        }
    }
    let status = child.wait()?;
    ensure!(
        status.success() && said.contains(CHANGED),
        "VeraCrypt did not change the passphrase: {}",
        said.trim()
    );
    Ok(())
}

/// The child's stdout and stderr as one stream of chunks, read on their own threads.
fn merged(child: &mut Child) -> Receiver<Vec<u8>> {
    let (sender, receiver) = mpsc::channel();
    let streams: [Option<Box<dyn Read + Send>>; 2] = [
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    ];
    for mut stream in streams.into_iter().flatten() {
        let sender = sender.clone();
        std::thread::spawn(move || {
            let mut buffer = [0u8; 512];
            while let Ok(n @ 1..) = stream.read(&mut buffer) {
                if sender.send(buffer[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
    }
    receiver
}

/// Waits until the last line of `said` is `prompt`. Fails on any other prompt, on silence, or when
/// VeraCrypt ends.
fn wait_for(
    output: &Receiver<Vec<u8>>,
    said: &mut String,
    prompt: &str,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let last = said.rsplit('\n').next().unwrap_or_default().trim_start();
        if last == prompt {
            return Ok(());
        }
        if last.ends_with(": ") {
            bail!("VeraCrypt asked {last:?}, not {prompt:?}");
        }
        match output.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(chunk) => said.push_str(&String::from_utf8_lossy(&chunk)),
            Err(RecvTimeoutError::Timeout) => bail!("VeraCrypt did not ask {prompt:?} in time"),
            Err(RecvTimeoutError::Disconnected) => {
                bail!(
                    "VeraCrypt ended before it asked {prompt:?}: {}",
                    said.trim()
                )
            }
        }
    }
}

/// Runs `command`, writing `stdin` and a newline to it when given.
fn run(command: &mut Command, stdin: Option<&str>) -> Result<Output> {
    command
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .with_context(|| format!("Cannot run {:?}", command.get_program()))?;
    if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
        let line = Zeroizing::new(format!("{input}\n"));
        pipe.write_all(line.as_bytes())?;
    }
    Ok(child.wait_with_output()?)
}

fn succeed(output: Output, what: &str) -> Result<()> {
    ensure!(
        output.status.success(),
        "Could not {what}: {}",
        text(&output).trim()
    );
    Ok(())
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn on_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(name))
            .find(|path| path.is_file())
    })
}

#[cfg(test)]
mod tests;
