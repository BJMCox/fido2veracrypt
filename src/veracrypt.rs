//! Runs VeraCrypt. Passphrases go to its stdin, never on a command line.

use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use zeroize::Zeroizing;

/// 1.26.30 fixes CVE-2026-108982, where a FUSE-T dismount could leave the volume readable, and it
/// is the version the tests pin.
const MIN_VERSION: (u32, u32, u32) = (1, 26, 30);
/// The key derivation every container gets.
pub const HASH: &str = "Argon2";
/// How long a read-only query or each passphrase-change step may take.
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
    /// The same optional binary configuration for the CLI and native app.
    pub fn configured() -> Result<Self> {
        Self::find(configured_binary()?)
    }

    /// Finds VeraCrypt (`configured`, then the macOS app, then `PATH`) and refuses versions before
    /// 1.26.30.
    pub fn find(configured: Option<PathBuf>) -> Result<Self> {
        let binary = configured
            .or_else(|| Path::new(MAC_APP).is_file().then(|| PathBuf::from(MAC_APP)))
            .or_else(|| on_path("veracrypt"))
            .context(
                "VeraCrypt is not installed. On macOS: brew install --cask veracrypt-fuse-t",
            )?;
        check_binary_version(&mut Command::new(&binary))?;
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
        self.root_with_helper(
            action,
            container,
            extra,
            args,
            (Path::new(HELPER), Path::new(crate::helper::VERACRYPT)),
        )
    }

    fn root_with_helper(
        &self,
        action: &str,
        container: &Path,
        extra: &[&str],
        args: Vec<String>,
        (helper, helper_binary): (&Path, &Path),
    ) -> Command {
        let same_binary = self
            .binary
            .canonicalize()
            .ok()
            .zip(helper_binary.canonicalize().ok())
            .is_some_and(|(selected, fixed)| selected == fixed);
        if same_binary && helper.is_file() && crate::slots::path(container).is_file() {
            let mut command = Command::new("sudo");
            command.arg(helper).arg(action).arg(container).args(extra);
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

fn configured_binary() -> Result<Option<PathBuf>> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let base = if cfg!(target_os = "macos") {
        home.map(|h| h.join("Library/Application Support"))
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| home.map(|h| h.join(".config")))
    };
    let Some(base) = base else { return Ok(None) };
    let path = base.join("fido2veracrypt/config.toml");
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("Cannot read {}", path.display())),
    };
    let table: toml::Table = text
        .parse()
        .with_context(|| format!("Invalid config {}", path.display()))?;
    Ok(table
        .get("veracrypt")
        .and_then(toml::Value::as_str)
        .map(PathBuf::from))
}

impl VeraCrypt for Real {
    fn create(
        &self,
        container: &Path,
        size: u64,
        passphrase: &str,
        label: &str,
    ) -> Result<Option<anyhow::Error>> {
        crate::slots::validate_path(container)?;
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
        crate::slots::validate_path(container)?;
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
        crate::slots::validate_path(container)?;
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
        crate::slots::validate_path(container)?;
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
        self.list_snapshot(false, Instant::now() + TIMEOUT)
    }

    fn change(&self, container: &Path, old: &str, old_hash: Option<&str>, new: &str) -> Result<()> {
        crate::slots::validate_path(container)?;
        let mut command = self.veracrypt();
        command.args(change_args(container, old_hash));
        drive_change(&mut command, old, new, TIMEOUT)
    }

    fn set_label(&self, mount_point: &Path, label: &str) -> Result<()> {
        crate::slots::validate_path(mount_point)?;
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
    fn list_snapshot(&self, as_root: bool, deadline: Instant) -> Result<Vec<Volume>> {
        let query = |slot: Option<u32>| {
            let mut command = if as_root {
                let mut command = Command::new("sudo");
                command.arg(&self.binary);
                command
            } else {
                self.veracrypt()
            };
            command.args(["--text", "--non-interactive", "--list", "--verbose"]);
            if let Some(slot) = slot {
                command.arg("--slot").arg(slot.to_string());
            }
            checked_list_output(run_captured(&mut command, None, Some(deadline))?)
        };
        let records = query(None)?;
        // A path can contain an entire forged record. The numeric slot lookup selects one
        // native VolumeInfo, so its output must contain exactly that same single record.
        for record in &records {
            let selected = query(Some(record.slot))?;
            ensure!(
                selected.as_slice() == std::slice::from_ref(record),
                "VeraCrypt's volume list changed or is ambiguous. Container status is unknown."
            );
        }
        time_left(deadline)?;
        Ok(records.into_iter().map(|record| record.volume).collect())
    }

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
            let device = self
                .list_snapshot(true, Instant::now() + TIMEOUT)?
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
        let labeled = (|| {
            self.list()?
                .into_iter()
                .find(|v| v.container == container)
                .and_then(|v| v.mount_point)
                .context("VeraCrypt reported no mount point for the new container")
                .and_then(|mount_point| self.set_label(&mount_point, label))
        })();
        match self.close(container, false)? {
            Close::Closed | Close::NotOpen => {}
            Close::Busy => {
                bail!("The new container is still open. Close its files and close the container.")
            }
        }
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

#[derive(Debug, PartialEq, Eq)]
struct ListedVolume {
    slot: u32,
    volume: Volume,
}

/// An unknown response cannot establish that a volume is closed.
fn checked_list_output(output: Output) -> Result<Vec<ListedVolume>> {
    let mut said = String::from_utf8(output.stdout)
        .context("VeraCrypt returned non-UTF-8 volume paths. Container status is unknown.")?;
    said.push_str(
        &String::from_utf8(output.stderr)
            .context("VeraCrypt returned non-UTF-8 output. Container status is unknown.")?,
    );
    ensure!(
        output.status.success()
            || matches!(
                said.trim_end_matches('\n'),
                "Error: No volumes mounted." | "No volumes mounted."
            ),
        "VeraCrypt could not list its volumes: {}",
        said.trim()
    );
    checked_list(&said)
}

fn checked_list(text: &str) -> Result<Vec<ListedVolume>> {
    if matches!(
        text.trim_end_matches('\n'),
        "Error: No volumes mounted." | "No volumes mounted."
    ) {
        return Ok(Vec::new());
    }
    // DisplayVolumeProperties in VeraCrypt 1.26.30 emits this fixed order and one blank
    // separator. Skipping blank or unknown lines would hide a newline inside a path.
    let mut lines = text.split_terminator('\n').peekable();
    let mut slots = HashSet::new();
    let mut records = Vec::new();
    while lines.peek().is_some() {
        let slot: u32 = list_field(&mut lines, "Slot")?
            .parse()
            .context("Invalid volume slot")?;
        ensure!(
            slots.insert(slot),
            "VeraCrypt repeated a volume slot. Container status is unknown."
        );
        let container = list_field(&mut lines, "Volume")?;
        crate::slots::validate_path(Path::new(container))?;
        let device = list_field(&mut lines, "Virtual Device")?;
        let mount = list_field(&mut lines, "Mount Directory")?;
        crate::slots::validate_path(Path::new(mount))?;
        for field in [
            "Size",
            "Type",
            "Read-Only",
            "Hidden Volume Protected",
            "Encryption Algorithm",
            "Primary Key Size",
        ] {
            list_field(&mut lines, field)?;
        }
        let secondary = lines
            .peek()
            .is_some_and(|line| line.starts_with("Secondary Key Size (XTS Mode): "));
        if secondary {
            list_field(&mut lines, "Secondary Key Size (XTS Mode)")?;
        }
        list_field(&mut lines, "Block Size")?;
        let mode = list_field(&mut lines, "Mode of Operation")?;
        ensure!(
            secondary == (mode == "XTS"),
            "VeraCrypt returned inconsistent volume properties"
        );
        for field in ["KDF", "Volume Format Version", "Embedded Backup Header"] {
            list_field(&mut lines, field)?;
        }
        if !device.starts_with("/dev/mapper/veracrypt") {
            list_field(&mut lines, "Data Read since Mount")?;
            list_field(&mut lines, "Data Written since Mount")?;
        }
        ensure!(
            lines.next() == Some(""),
            "VeraCrypt returned an incomplete volume list. Container status is unknown."
        );
        let volume = Volume {
            container: PathBuf::from(container),
            device: (!device.is_empty() && device != "-").then(|| device.to_owned()),
            mount_point: (!mount.is_empty() && mount != "-").then(|| PathBuf::from(mount)),
        };
        ensure!(
            volume.container.is_absolute()
                && volume.mount_point.as_ref().is_none_or(|p| p.is_absolute()),
            "VeraCrypt returned an invalid volume path. Container status is unknown."
        );
        records.push(ListedVolume { slot, volume });
    }
    ensure!(
        !records.is_empty(),
        "VeraCrypt returned an empty volume list. Container status is unknown."
    );
    Ok(records)
}

fn list_field<'a>(lines: &mut impl Iterator<Item = &'a str>, name: &str) -> Result<&'a str> {
    let (field, value) = lines
        .next()
        .and_then(|line| line.split_once(": "))
        .context("VeraCrypt returned an incomplete volume list. Container status is unknown.")?;
    ensure!(
        field == name && !value.contains(['\r', '\0']),
        "VeraCrypt returned unexpected volume properties. Container status is unknown."
    );
    Ok(value)
}

/// Parses `veracrypt --text -l -v`, whose labeled lines keep paths with spaces intact.
pub fn parse_list(text: &str) -> Vec<Volume> {
    let mut volumes = Vec::new();
    for line in text.split_terminator('\n') {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        // Paths can end in spaces. Strip only the formatting before an absolute path.
        let value = value.strip_prefix(' ').unwrap_or(value);
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

pub(crate) fn check_binary_version(command: &mut Command) -> Result<()> {
    let output = run_read_only(command.args(["--text", "--version"]), TIMEOUT)?;
    ensure!(
        output.status.success(),
        "VeraCrypt could not report its version: {}",
        text(&output).trim()
    );
    check_version(&String::from_utf8_lossy(&output.stdout))
}

/// Answers `veracrypt --text -C` in order, bounding each prompt and final completion.
/// Failure after the last answer can leave a changed header; the pending secret must be retained.
pub fn drive_change(command: &mut Command, old: &str, new: &str, timeout: Duration) -> Result<()> {
    let (mut child, output) = capture(command.stdin(Stdio::piped()))?;
    let mut stdin = child.child.stdin.take();
    let mut said = String::new();
    for (prompt, takes_new) in PROMPTS {
        wait_for(&output, &mut said, prompt, timeout)
            .context("VeraCrypt's password change stopped before confirmation")?;
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
    while let Some((_, chunk)) = output.read(Some(deadline))? {
        said.push_str(&String::from_utf8_lossy(&chunk));
    }
    let status = child.wait(Some(deadline))?;
    ensure!(
        status.success() && said.contains(CHANGED),
        "VeraCrypt did not confirm the passphrase change: {}",
        said.trim()
    );
    Ok(())
}

struct ChildGuard {
    child: Child,
    reaped: bool,
}

impl ChildGuard {
    fn spawn(command: &mut Command) -> Result<Self> {
        Ok(Self {
            child: command
                .spawn()
                .with_context(|| format!("Cannot run {:?}", command.get_program()))?,
            reaped: false,
        })
    }

    fn wait(&mut self, deadline: Option<Instant>) -> Result<ExitStatus> {
        let status = if let Some(deadline) = deadline {
            loop {
                let remaining = time_left(deadline)?;
                if let Some(status) = self.child.try_wait()? {
                    break status;
                }
                thread::sleep(remaining.min(Duration::from_millis(10)));
            }
        } else {
            self.child.wait()?
        };
        self.reaped = true;
        Ok(status)
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

type OutputChunk = io::Result<(bool, Vec<u8>)>;

struct OutputReader {
    receiver: Receiver<OutputChunk>,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl OutputReader {
    fn start(streams: [UnixStream; 2]) -> Result<Self> {
        let (sender, receiver) = mpsc::channel();
        let mut output = Self {
            receiver,
            stop: Arc::new(AtomicBool::new(false)),
            threads: Vec::new(),
        };
        for (index, mut stream) in streams.into_iter().enumerate() {
            stream.set_read_timeout(Some(Duration::from_millis(20)))?;
            let (sender, stop) = (sender.clone(), Arc::clone(&output.stop));
            output.threads.push(
                thread::Builder::new()
                    .name("veracrypt-output".into())
                    .spawn(move || {
                        let mut buffer = [0u8; 512];
                        while !stop.load(Ordering::Relaxed) {
                            let chunk = match stream.read(&mut buffer) {
                                Ok(0) => break,
                                Ok(count) => Ok((index == 1, buffer[..count].to_vec())),
                                Err(error)
                                    if matches!(
                                        error.kind(),
                                        io::ErrorKind::Interrupted
                                            | io::ErrorKind::WouldBlock
                                            | io::ErrorKind::TimedOut
                                    ) =>
                                {
                                    continue;
                                }
                                Err(error) => Err(error),
                            };
                            let failed = chunk.is_err();
                            if sender.send(chunk).is_err() || failed {
                                break;
                            }
                        }
                    })?,
            );
        }
        Ok(output)
    }

    fn read(&self, deadline: Option<Instant>) -> Result<Option<(bool, Vec<u8>)>> {
        let received = if let Some(deadline) = deadline {
            self.receiver.recv_timeout(time_left(deadline)?)
        } else {
            self.receiver
                .recv()
                .map_err(|_| RecvTimeoutError::Disconnected)
        };
        match received {
            Ok(chunk) => chunk.map(Some).context("Could not read VeraCrypt's output"),
            Err(RecvTimeoutError::Disconnected) => Ok(None),
            Err(RecvTimeoutError::Timeout) => bail!("VeraCrypt did not finish before its deadline"),
        }
    }
}

impl Drop for OutputReader {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

fn time_left(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .context("VeraCrypt did not finish before its deadline")
}

fn capture(command: &mut Command) -> Result<(ChildGuard, OutputReader)> {
    // Timed socket reads let the reader threads end even if a descendant retains stdout.
    let (stdout, child_stdout) = UnixStream::pair()?;
    let (stderr, child_stderr) = UnixStream::pair()?;
    command
        .stdout(Stdio::from(OwnedFd::from(child_stdout)))
        .stderr(Stdio::from(OwnedFd::from(child_stderr)));
    let child = ChildGuard::spawn(command);
    // Command retains its configured descriptors after spawn; release those parent copies.
    command.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    let child = child?;
    Ok((child, OutputReader::start([stdout, stderr])?))
}

pub(crate) fn run_inherited(command: &mut Command) -> Result<ExitStatus> {
    ChildGuard::spawn(command)?.wait(None)
}

/// Waits until the last line of `said` is `prompt`. Fails on any other prompt, on silence, or when
/// VeraCrypt ends.
fn wait_for(
    output: &OutputReader,
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
        match output.read(Some(deadline))? {
            Some((_, chunk)) => said.push_str(&String::from_utf8_lossy(&chunk)),
            None => {
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
    run_captured(command, stdin, None)
}

fn run_read_only(command: &mut Command, timeout: Duration) -> Result<Output> {
    run_captured(command, None, Some(Instant::now() + timeout))
}

fn run_captured(
    command: &mut Command,
    stdin: Option<&str>,
    deadline: Option<Instant>,
) -> Result<Output> {
    if let Some(deadline) = deadline {
        time_left(deadline)?;
    }
    command.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let (mut child, output) = capture(command)?;
    if let (Some(input), Some(mut pipe)) = (stdin, child.child.stdin.take()) {
        let line = Zeroizing::new(format!("{input}\n"));
        pipe.write_all(line.as_bytes())?;
    }
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    while let Some((is_stderr, chunk)) = output.read(deadline)? {
        if is_stderr {
            stderr.extend(chunk);
        } else {
            stdout.extend(chunk);
        }
    }
    Ok(Output {
        status: child.wait(deadline)?,
        stdout,
        stderr,
    })
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
