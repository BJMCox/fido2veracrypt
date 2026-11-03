//! What each command does.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use fido2kit::fido::Unlock;
use fido2kit::vault::{KeyKind, Vault};
use zeroize::Zeroizing;

use crate::cli::{Command, HELP, Shell};
use crate::keys::Keys;
use crate::passphrase::Passphrase;
use crate::slots::{self, APP, HASH_META, SECRET};
use crate::ui::{Step, Ui, field};
use crate::veracrypt::{Close, HASH, HELPER, Mount, VeraCrypt};

pub const ZSH: &str = include_str!("../completions/_fido2veracrypt");
pub const BASH: &str = include_str!("../completions/fido2veracrypt.bash");

const ANOTHER_CONTAINER: &str = "The passphrase in this slot file does not open this container. Is the slot file from another container?";

// O_NONBLOCK keeps an untrusted FIFO from blocking before descriptor type validation.
#[cfg(target_os = "macos")]
const NONBLOCK: i32 = 0x4;
#[cfg(target_os = "linux")]
const NONBLOCK: i32 = if cfg!(any(
    target_arch = "mips",
    target_arch = "mips64",
    target_arch = "mips32r6",
    target_arch = "mips64r6"
)) {
    0x80
} else if cfg!(any(target_arch = "sparc", target_arch = "sparc64")) {
    0x4000
} else {
    0x800
};

fn open_regular(path: impl AsRef<Path>) -> std::io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Not a regular file",
        ));
    }
    Ok(file)
}

pub struct Tools<'a> {
    pub vc: &'a dyn VeraCrypt,
    pub keys: &'a mut dyn Keys,
    pub ui: &'a mut dyn Ui,
}

impl Tools<'_> {
    fn begin_change(&mut self, container: &Path, message: &str) -> Result<()> {
        require_closed(self.vc, container)?;
        self.ui.begin_work(message)
    }
}

/// A slot file unlocked with keys whose outputs the vault's tag check accepted.
struct Unlocked {
    slot: PathBuf,
    vault: Vault,
    unlocks: Vec<Unlock>,
}

pub fn run(command: Command, t: &mut Tools) -> Result<()> {
    match &command {
        Command::Create { label, .. }
        | Command::Adopt { label, .. }
        | Command::AddKey { label, .. } => {
            ensure!(
                !label.trim().is_empty() && label.len() <= 256,
                "Give the key a name of at most 256 UTF-8 bytes"
            );
        }
        _ => {}
    }
    match command {
        Command::Create {
            container,
            size,
            label,
        } => transaction(&container, |container| create(t, container, size, &label)),
        Command::Adopt { container, label } => {
            change_transaction(t, &container, |t, container| adopt(t, container, &label))
        }
        Command::Open { container } => transaction(&container, |container| open(t, container)),
        Command::Close { container, force } => close(t, container, force),
        Command::AddKey {
            container,
            label,
            recovery: false,
        } => change_transaction(t, &container, |t, container| add_key(t, container, &label)),
        Command::AddKey {
            container,
            label,
            recovery: true,
        } => change_transaction(t, &container, |t, container| {
            add_key_with_recovery(t, container, &label)
        }),
        Command::RemoveKey { container, labels } => {
            change_transaction(t, &container, |t, container| {
                remove_key(t, container, &labels)
            })
        }
        Command::Rotate { container } => change_transaction(t, &container, rotate),
        Command::Status { container } => status(t, container.as_deref().map(resolve).transpose()?),
        Command::ListKeys { container } => list_keys(t, &resolve(&container)?),
        Command::Completions { shell } => {
            t.ui.say(match shell {
                Shell::Zsh => ZSH,
                Shell::Bash => BASH,
            });
            Ok(())
        }
        Command::Help => {
            t.ui.say(HELP);
            Ok(())
        }
        Command::Version => {
            t.ui.say(concat!("fido2veracrypt ", env!("CARGO_PKG_VERSION")));
            Ok(())
        }
    }
}

/// The lock file stays in place: unlinking it would let another client lock a different inode.
/// The container lock also serializes hard-link aliases. VeraCrypt itself does not lock files.
struct Transaction {
    _path: Option<LockedFile>,
    _container: Option<LockedFile>,
}

struct LockedFile(File);

impl LockedFile {
    fn acquire(file: File) -> Result<Self> {
        file.try_lock().context("Another command is using this container, or its filesystem cannot lock it. Try again after that command finishes.")?;
        Ok(Self(file))
    }
}

impl Drop for LockedFile {
    fn drop(&mut self) {
        // A concurrent fork may briefly inherit this open-file description before exec. Closing
        // only our descriptor would leave its lock held until that child closes its copy.
        let _ = self.0.unlock();
    }
}

impl Transaction {
    fn acquire(container: &Path) -> Result<Self> {
        let file = match open_regular(container) {
            Ok(file) => Some(LockedFile::acquire(file)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        let identity = match container.canonicalize() {
            Ok(path) => path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => container.to_owned(),
            Err(error) => return Err(error.into()),
        };
        let mut name = identity.into_os_string();
        name.push(".fido2veracrypt_lock");
        let lock = match open_regular(&name) {
            Ok(lock) => Some(lock),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&name)
                {
                    Ok(lock) => Some(lock),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        Some(open_regular(&name)?)
                    }
                    // A read-only source needs no new sidecar. Its inode lock still excludes all
                    // header transactions; a new Create cannot use an existing container.
                    Err(error)
                        if file.is_some()
                            && matches!(
                                error.kind(),
                                std::io::ErrorKind::PermissionDenied
                                    | std::io::ErrorKind::ReadOnlyFilesystem
                            ) =>
                    {
                        None
                    }
                    Err(error) => {
                        return Err(error)
                            .context("Cannot create the container's transaction lock");
                    }
                }
            }
            Err(error) => return Err(error.into()),
        };
        let lock = if let Some(lock) = lock {
            ensure!(
                std::fs::symlink_metadata(&name)?.is_file(),
                "The container's transaction lock is not a regular file"
            );
            Some(LockedFile::acquire(lock)?)
        } else {
            None
        };
        Ok(Self {
            _path: lock,
            _container: file,
        })
    }
}

fn transaction(container: &Path, action: impl FnOnce(&Path) -> Result<()>) -> Result<()> {
    let container = resolve(container)?;
    let _lock = Transaction::acquire(&container)?;
    action(&container)
}

fn change_transaction(
    t: &mut Tools,
    container: &Path,
    action: impl FnOnce(&mut Tools, &Path) -> Result<()>,
) -> Result<()> {
    transaction(container, |container| {
        require_closed(t.vc, container)?;
        action(t, container)
    })
}

fn require_closed(vc: &dyn VeraCrypt, container: &Path) -> Result<()> {
    let source = container.metadata().context("Cannot find the container")?;
    for volume in vc.list()? {
        let attached = volume
            .container
            .metadata()
            .context("An attached container is unavailable. Close it before changing keys or the recovery phrase.")?;
        ensure!(
            (source.dev(), source.ino()) != (attached.dev(), attached.ino()),
            "Close the container before changing its keys or recovery phrase."
        );
    }
    Ok(())
}

fn create(t: &mut Tools, container: &Path, size: u64, label: &str) -> Result<()> {
    let slot = slots::path(container);
    ensure!(
        !container.exists(),
        "{} exists. Use adopt to bring an existing container under fido2veracrypt.",
        container.display()
    );
    ensure!(
        !slot.exists(),
        "{} is left over from an interrupted create, with no container beside it. Delete it, then run create again.",
        slot.display()
    );
    let salt = Vault::new_salt()?;
    t.ui.step(Step::Enroll)?;
    let enrollment = t.keys.enroll(&salt, &[])?;
    let passphrase = Passphrase::generate()?;
    show_recovery(t.ui, &passphrase)?;
    t.ui.step(Step::Write)?;
    t.ui.begin_work("Creating container…")?;
    let mut vault = Vault::create(
        APP,
        salt,
        label,
        &enrollment,
        SECRET,
        passphrase.as_str().as_bytes(),
    )?;
    vault.set_secret_meta(
        std::slice::from_ref(&enrollment.unlock),
        SECRET,
        HASH_META,
        HASH,
    )?;
    vault.save(&slot, true)?;
    match t
        .vc
        .create(container, size, passphrase.as_str(), &slots::label(container))
    {
        // A container file left behind is not usable, and only the owner should delete files.
        Err(error) if container.exists() => {
            return Err(error.context(format!(
                "The container {} was made but not finished. Delete it and {}, then run create again",
                container.display(),
                slot.display()
            )));
        }
        Err(error) => {
            let _ = std::fs::remove_file(&slot);
            return Err(error.context("The container was not created, and its slot file was removed"));
        }
        Ok(Some(setup_error)) => t.ui.warn(&format!(
            "The container was created, but final setup failed: {setup_error:#}. Check whether it is still open before removing the drive."
        )),
        Ok(None) => {}
    }
    t.ui.say(&format!("Created {}.", container.display()));
    Ok(())
}

fn adopt(t: &mut Tools, container: &Path, label: &str) -> Result<()> {
    let slot = slots::path(container);
    ensure!(
        container.is_file(),
        "No container at {}",
        container.display()
    );
    ensure!(
        !slot.exists(),
        "{} already has a slot file. Use add-key to enroll another key.",
        container.display()
    );
    t.ui.step(Step::Authenticate)?;
    let old = t.ui.secret("The container's current password: ")?;
    t.begin_change(container, "Checking the current password…")?;
    ensure!(
        t.vc.opens(container, &old, None)?,
        "That password does not open the container. Nothing was changed."
    );
    t.ui.end_work()?;
    t.ui.say(
        "The old password still opens any copy of this container made before now, such as a backup. Only a new container with the files copied over removes that.",
    );
    let salt = Vault::new_salt()?;
    t.ui.step(Step::Enroll)?;
    let enrollment = t.keys.enroll(&salt, &[])?;
    let new = Passphrase::generate()?;
    show_recovery(t.ui, &new)?;
    t.ui.step(Step::Write)?;
    t.begin_change(container, "Adding key access…")?;
    let unlocks = vec![enrollment.unlock.clone()];
    let mut vault = Vault::create(APP, salt, label, &enrollment, SECRET, old.as_bytes())?;
    vault.set_pending(&unlocks, SECRET, new.as_str().as_bytes())?;
    vault.save(&slot, true)?;
    apply_pending(
        t.vc,
        container,
        &mut Unlocked {
            slot,
            vault,
            unlocks,
        },
    )?;
    t.ui.say(&format!("Adopted {}.", container.display()));
    Ok(())
}

fn open(t: &mut Tools, container: &Path) -> Result<()> {
    let unlocked = unlock(t, container)?;
    let passphrase = current(&unlocked)?;
    let hash = hash_of(&unlocked.vault);
    t.ui.begin_work("Opening container…")?;
    if t.vc.mount(container, &passphrase, hash.as_deref())? == Mount::WrongPassphrase {
        bail!(ANOTHER_CONTAINER);
    }
    let mut mount_point = mount_point(t.vc, container)?;
    if cfg!(target_os = "macos")
        && let Some(untitled) = mount_point.as_deref().filter(|m| {
            m.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("Untitled"))
        })
    {
        match t.vc.set_label(untitled, &slots::label(container)) {
            Ok(()) => mount_point = mount_point_after_label(t.vc, container, untitled)?,
            Err(error) => t.ui.warn(&format!(
                "The volume has no label, and setting one failed: {error:#}"
            )),
        }
    }
    t.ui.say(&match mount_point {
        Some(mount_point) => format!("Opened at {}", mount_point.display()),
        None => format!("Opened {}", container.display()),
    });
    Ok(())
}

fn close(t: &mut Tools, container: Option<PathBuf>, force: bool) -> Result<()> {
    let targets = match container {
        Some(container) => {
            slots::validate_path(&container)?;
            let absolute = std::path::absolute(&container)?;
            let volumes = t.vc.list()?;
            // An attachment keeps its original name even after its source moves or disappears.
            let attached = volumes
                .iter()
                .find(|v| v.container == absolute)
                .or_else(|| {
                    let resolved = resolve(&container).ok()?;
                    volumes.iter().find(|v| v.container == resolved)
                });
            match attached {
                Some(volume) => vec![volume.container.clone()],
                None => {
                    t.ui.say(&format!("{} is not open", container.display()));
                    return Ok(());
                }
            }
        }
        None => {
            let volumes = t.vc.list()?;
            require_sources(&volumes)?;
            volumes
                .into_iter()
                .map(|v| v.container)
                .filter(|c| slots::path(c).exists())
                .collect()
        }
    };
    if targets.is_empty() {
        t.ui.say("No fido2veracrypt volume is open.");
        return Ok(());
    }
    let mut busy = Vec::new();
    for container in targets {
        let _lock = container
            .is_file()
            .then(|| Transaction::acquire(&container))
            .transpose()?;
        match t.vc.close(&container, force)? {
            Close::Closed => t.ui.say(&format!("Closed {}", container.display())),
            Close::NotOpen => t.ui.say(&format!("{} is not open", container.display())),
            Close::Busy => busy.push(container.display().to_string()),
        }
    }
    if busy.is_empty() {
        return Ok(());
    }
    // Linux cannot unmount a local filesystem with open files, so there even --force fails.
    if force {
        bail!(
            "Even --force could not close {}: a program still has a file open on it. Close that program, then run close again. `fuser -vm <mount point>` names it.",
            busy.join(", ")
        );
    }
    bail!(
        "A file on {} is still open. Close it and try again, or run close --force, which loses unsaved changes in it.",
        busy.join(", ")
    )
}

fn add_key(t: &mut Tools, container: &Path, label: &str) -> Result<()> {
    let mut unlocked = unlock(t, container)?;
    require_finished(&unlocked)?;
    t.ui.step(Step::Connect)?;
    t.ui.connect_key("Connect the new key.")?;
    t.ui.step(Step::Enroll)?;
    let enrollment = t
        .keys
        .enroll(&unlocked.vault.salt(), &unlocked.vault.cred_ids())?;
    t.ui.step(Step::Write)?;
    t.begin_change(container, "Adding key…")?;
    unlocked
        .vault
        .add_key(&unlocked.unlocks, label, &enrollment)?;
    unlocked.vault.save(&unlocked.slot, false)?;
    t.ui.say(&format!(
        "Added {}. The recovery phrase stays the same.",
        field(label)
    ));
    Ok(())
}

fn add_key_with_recovery(t: &mut Tools, container: &Path, label: &str) -> Result<()> {
    ensure!(
        container.is_file(),
        "No container at {}",
        container.display()
    );
    let slot = slots::path(container);
    let original = read_slot(&slot)?;
    t.ui.step(Step::Authenticate)?;
    let typed = t.ui.secret("Recovery phrase: ")?;
    let passphrase = Passphrase::parse(&typed)?;
    t.begin_change(container, "Checking the recovery phrase…")?;
    let argon2 = t.vc.opens(container, passphrase.as_str(), Some(HASH))?;
    ensure!(
        argon2 || t.vc.opens(container, passphrase.as_str(), None)?,
        "That recovery phrase does not open the container. Nothing was changed."
    );
    t.ui.end_work()?;
    let salt = Vault::new_salt()?;
    t.ui.step(Step::Connect)?;
    t.ui.connect_key("Connect the new key.")?;
    t.ui.step(Step::Enroll)?;
    let enrollment = t.keys.enroll(&salt, &[])?;
    let mut vault = Vault::create(
        APP,
        salt,
        label,
        &enrollment,
        SECRET,
        passphrase.as_str().as_bytes(),
    )?;
    if argon2 {
        vault.set_secret_meta(
            std::slice::from_ref(&enrollment.unlock),
            SECRET,
            HASH_META,
            HASH,
        )?;
    }
    // Enrollment can take minutes. Check the actual header again before replacing metadata.
    t.ui.step(Step::Write)?;
    t.begin_change(container, "Restoring key access…")?;
    ensure!(
        t.vc.opens(container, passphrase.as_str(), argon2.then_some(HASH))?,
        "The container changed during enrollment. Its slot file was not replaced. Try recovery again."
    );
    let replaced = replace_slot(&mut vault, &slot, original.as_deref())?;
    t.ui.say(&format!(
        "Added {} as the only key. The recovery phrase stays the same.",
        field(label)
    ));
    if let Some(old) = replaced {
        t.ui.say(&format!(
            "The old slot file is now {}. Enroll the other keys again with add-key.",
            old.display()
        ));
    }
    Ok(())
}

fn remove_key(t: &mut Tools, container: &Path, labels: &[String]) -> Result<()> {
    let (slot, vault) = load(container)?;
    let labels: Vec<&str> = labels.iter().map(String::as_str).collect();
    let mut kept: Vec<(String, Vec<u8>)> = vault
        .kept_keys(&labels)?
        .into_iter()
        .map(|(label, id)| (label.to_owned(), id.to_vec()))
        .collect();
    kept.sort();
    let salt = vault.salt();
    let ids: Vec<&[u8]> = kept.iter().map(|(_, id)| id.as_slice()).collect();
    t.ui.step(Step::Authenticate)?;
    let first = t.keys.unlock(&salt, &ids)?;
    // The tag check comes before anything acts on the labels.
    vault.verify(std::slice::from_ref(&first))?;
    let mut unlocked = Unlocked {
        slot,
        vault,
        unlocks: vec![first],
    };
    finish_pending(t, container, &mut unlocked)?;
    require_finished(&unlocked)?;
    for (label, id) in &kept {
        if unlocked.unlocks.iter().any(|u| &u.cred_id == id) {
            continue;
        }
        t.ui.connect_key(&format!("Connect “{}”.", field(label)))?;
        let unlock = t.keys.unlock_key(label, &salt, id)?;
        unlocked.unlocks.push(unlock);
    }
    let new = Passphrase::generate()?;
    show_recovery(t.ui, &new)?;
    t.ui.step(Step::Write)?;
    t.begin_change(container, "Removing keys…")?;
    unlocked.vault.remove_keys(&labels, &unlocked.unlocks)?;
    unlocked
        .vault
        .set_pending(&unlocked.unlocks, SECRET, new.as_str().as_bytes())?;
    unlocked.vault.save(&unlocked.slot, false)?;
    apply_pending(t.vc, container, &mut unlocked)?;
    t.ui.say(&format!(
        "Removed {}. Use a remaining key or the new recovery phrase.",
        labels
            .iter()
            .map(|label| field(label))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    Ok(())
}

fn rotate(t: &mut Tools, container: &Path) -> Result<()> {
    let mut unlocked = unlock(t, container)?;
    require_finished(&unlocked)?;
    let new = Passphrase::generate()?;
    show_recovery(t.ui, &new)?;
    t.ui.step(Step::Write)?;
    t.begin_change(container, "Changing recovery phrase…")?;
    unlocked
        .vault
        .set_pending(&unlocked.unlocks, SECRET, new.as_str().as_bytes())?;
    unlocked.vault.save(&unlocked.slot, false)?;
    apply_pending(t.vc, container, &mut unlocked)?;
    t.ui.say("Recovery phrase changed. Your keys still work. The old phrase no longer opens this container.");
    Ok(())
}

fn status(t: &mut Tools, container: Option<PathBuf>) -> Result<()> {
    let volumes = t.vc.list()?;
    let Some(container) = container else {
        require_sources(&volumes)?;
        let ours: Vec<_> = volumes
            .iter()
            .filter(|v| slots::path(&v.container).exists())
            .collect();
        if ours.is_empty() {
            t.ui.say("No fido2veracrypt volume is open.");
        }
        for volume in ours {
            t.ui.say(&match &volume.mount_point {
                Some(mount_point) => format!(
                    "{}: open at {}",
                    volume.container.display(),
                    mount_point.display()
                ),
                None => format!(
                    "{}: half closed, still unlocked. Run `fido2veracrypt close {}`.",
                    volume.container.display(),
                    volume.container.display()
                ),
            });
        }
        if cfg!(target_os = "linux") {
            t.ui.say(if Path::new(HELPER).is_file() {
                "The helper is installed, so open and close need no password."
            } else {
                "The helper is not installed, so open and close ask for your sudo password."
            });
        }
        return Ok(());
    };
    let (_, vault) = load(&container)?;
    let open = volumes.iter().find(|v| v.container == container);
    t.ui.say(&format!(
        "{}: {}",
        container.display(),
        match open.map(|v| &v.mount_point) {
            Some(Some(mount_point)) => format!("open at {}", mount_point.display()),
            Some(None) => "half closed, still unlocked".to_owned(),
            None => "closed".to_owned(),
        }
    ));
    let labels: Vec<String> = vault.keys().iter().map(|k| field(k.label)).collect();
    t.ui.say(&format!("Keys: {}", labels.join(", ")));
    t.ui.say(&format!(
        "Key derivation: {}",
        field(&hash_of(&vault).unwrap_or_else(|| "unknown".to_owned()))
    ));
    if vault.has_pending(SECRET) {
        t.ui.say("A passphrase change is unfinished. The next open finishes it.");
    }
    t.ui.say("(Read without a key, so these details are unverified.)");
    Ok(())
}

/// Without its sidecar, an unavailable attachment cannot safely be classified as foreign.
fn require_sources(volumes: &[crate::veracrypt::Volume]) -> Result<()> {
    for volume in volumes {
        ensure!(
            volume.container.exists(),
            "An attached volume's source is unavailable: {}. Its ownership is unknown. Close it by naming that exact path.",
            field(&volume.container.display().to_string())
        );
    }
    Ok(())
}

fn list_keys(t: &mut Tools, container: &Path) -> Result<()> {
    let (_, vault) = load(container)?;
    for key in vault.keys() {
        t.ui.key_label(key.label)?;
        let aaguid = key
            .aaguid
            .map(|a| a.iter().map(|b| format!("{b:02x}")).collect::<String>())
            .unwrap_or_else(|| "-".to_owned());
        let created = key.created.map(date).unwrap_or_else(|| "-".to_owned());
        let migrated = if key.kind == KeyKind::Fido2HmacV2 {
            "  migrated"
        } else {
            ""
        };
        t.ui.say(&format!(
            "{}  {aaguid}  {created}{migrated}",
            field(key.label)
        ));
    }
    t.ui.say("(Read without a key, so these entries are unverified.)");
    Ok(())
}

/// Shows the passphrase and has the owner type its last group back before anything is written.
fn show_recovery(ui: &mut dyn Ui, passphrase: &Passphrase) -> Result<()> {
    ui.step(Step::Recovery)?;
    ui.say(
        "Save this recovery phrase away from the drive. VeraCrypt accepts it exactly as shown, including dashes:",
    );
    ui.show_secret(passphrase.as_str())?;
    let typed = Zeroizing::new(ui.ask("Enter its last group to confirm you saved it: ")?);
    let typed = Zeroizing::new(
        typed
            .trim()
            .to_ascii_uppercase()
            .chars()
            .map(|c| match c {
                'I' | 'L' => '1',
                'O' => '0',
                c => c,
            })
            .collect::<String>(),
    );
    ensure!(
        typed.as_str() == passphrase.last_group(),
        "That is not the last group. The new passphrase was not written. Run the command again."
    );
    Ok(())
}

fn load(container: &Path) -> Result<(PathBuf, Vault)> {
    ensure!(
        container.is_file(),
        "No container at {}",
        container.display()
    );
    let slot = slots::path(container);
    ensure!(
        slot.is_file(),
        "{} has no slot file. Use adopt, or add-key --recovery with the recovery passphrase.",
        container.display()
    );
    let vault = Vault::load(APP, &slot)?;
    Ok((slot, vault))
}

/// Unlocks with the key the owner uses, checks the tag, and finishes an interrupted change.
fn unlock(t: &mut Tools, container: &Path) -> Result<Unlocked> {
    let (slot, vault) = load(container)?;
    t.ui.step(Step::Authenticate)?;
    let unlock = t.keys.unlock(&vault.salt(), &vault.cred_ids())?;
    vault.verify(std::slice::from_ref(&unlock))?;
    let mut unlocked = Unlocked {
        slot,
        vault,
        unlocks: vec![unlock],
    };
    finish_pending(t, container, &mut unlocked)?;
    Ok(unlocked)
}

/// A pending passphrase means a change stopped part way. The header holds either value, so the
/// one that opens it decides what is left. A removed key may know the old passphrase, so this
/// runs before anything else uses the volume.
///
/// After a failed write, probe both values again. Opening may use a verified old value, but
/// another slot mutation must not discard an unfinished pending value.
fn finish_pending(t: &mut Tools, container: &Path, unlocked: &mut Unlocked) -> Result<()> {
    if !unlocked.vault.has_pending(SECRET) {
        return Ok(());
    }
    // Even opens() attaches a volume temporarily, so cancellation must stop before probing.
    t.begin_change(container, "Finishing an earlier change…")?;
    repair_pending(t, container, unlocked)?;
    t.ui.end_work()
}

fn repair_pending(t: &mut Tools, container: &Path, unlocked: &mut Unlocked) -> Result<()> {
    let current = current(unlocked)?;
    let pending = pending(unlocked)?;
    let hash = hash_of(&unlocked.vault);
    if t.vc.opens(container, &current, hash.as_deref())? {
        if let Err(error) = t.vc.change(container, &current, hash.as_deref(), &pending) {
            if t.vc.opens(container, &pending, Some(HASH))? {
                commit(unlocked)?;
                t.ui.warn(&format!(
                    "The earlier change reported an error ({error:#}), but its new passphrase opens the header. The slot file now records it."
                ));
                return Ok(());
            }
            ensure!(
                t.vc.opens(container, &current, hash.as_deref())?,
                "The failed change left an unknown header state. Both stored passphrases were preserved. Use the recovery printout."
            );
            t.ui.warn(&format!(
                "Warning: an earlier passphrase change could not finish: {error:#}. The old passphrase still opens this container, so any key removed since may still open it with an old copy of the slot file. The change stays pending, and the next unlock tries it again."
            ));
            return Ok(());
        }
    } else {
        ensure!(
            t.vc.opens(container, &pending, Some(HASH))?,
            "Neither the current nor the new passphrase in the slot file opens this container. Use add-key --recovery with the newest printout."
        );
    }
    commit(unlocked)?;
    t.ui.say("Finished an interrupted passphrase change.");
    Ok(())
}

fn require_finished(unlocked: &Unlocked) -> Result<()> {
    ensure!(
        !unlocked.vault.has_pending(SECRET),
        "The earlier passphrase change is still unfinished. Its stored values were preserved. Run open to retry it before changing keys or rotating again."
    );
    Ok(())
}

/// Changes the header to the pending passphrase, then makes it current.
fn apply_pending(vc: &dyn VeraCrypt, container: &Path, unlocked: &mut Unlocked) -> Result<()> {
    let current = current(unlocked)?;
    let pending = pending(unlocked)?;
    vc.change(
        container,
        &current,
        hash_of(&unlocked.vault).as_deref(),
        &pending,
    )?;
    commit(unlocked)
}

fn commit(unlocked: &mut Unlocked) -> Result<()> {
    unlocked.vault.commit_pending(&unlocked.unlocks, SECRET)?;
    unlocked
        .vault
        .set_secret_meta(&unlocked.unlocks, SECRET, HASH_META, HASH)?;
    unlocked.vault.save(&unlocked.slot, false)
}

fn current(unlocked: &Unlocked) -> Result<Zeroizing<String>> {
    text(unlocked.vault.open(&unlocked.unlocks, Some(SECRET))?)
}

fn pending(unlocked: &Unlocked) -> Result<Zeroizing<String>> {
    text(
        unlocked
            .vault
            .open_pending(&unlocked.unlocks, SECRET)?
            .context("No pending passphrase is stored")?,
    )
}

fn text(mut bytes: Zeroizing<Vec<u8>>) -> Result<Zeroizing<String>> {
    String::from_utf8(std::mem::take(&mut *bytes))
        .map(Zeroizing::new)
        .map_err(|e| {
            let mut bytes = e.into_bytes();
            zeroize::Zeroize::zeroize(&mut bytes);
            anyhow::anyhow!("The stored passphrase is not text")
        })
}

fn hash_of(vault: &Vault) -> Option<String> {
    vault
        .secret_meta(SECRET)
        .and_then(|meta| meta.get(HASH_META))
        .cloned()
}

fn mount_point(vc: &dyn VeraCrypt, container: &Path) -> Result<Option<PathBuf>> {
    Ok(vc
        .list()?
        .into_iter()
        .find(|v| v.container == container)
        .and_then(|v| v.mount_point))
}

/// After a rename, macOS moves the mount point. Falls back to the old one if VeraCrypt has not
/// caught up.
fn mount_point_after_label(
    vc: &dyn VeraCrypt,
    container: &Path,
    old: &Path,
) -> Result<Option<PathBuf>> {
    Ok(mount_point(vc, container)?.or_else(|| Some(old.to_owned())))
}

/// An absolute path with its folder's symlinks resolved, as VeraCrypt reports it in its list.
fn resolve(path: &Path) -> Result<PathBuf> {
    slots::validate_path(path)?;
    let name = path
        .file_name()
        .with_context(|| format!("{} names no file", path.display()))?;
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let resolved = parent
        .canonicalize()
        .with_context(|| format!("Cannot find the folder {}", parent.display()))?
        .join(name);
    slots::validate_path(&resolved)?;
    Ok(resolved)
}

fn read_slot(path: &Path) -> Result<Option<Vec<u8>>> {
    let file = match open_regular(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut bytes = Vec::new();
    file.take((1 << 20) + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 1 << 20,
        "The slot file exceeds 1 MiB. Move it aside before recovery."
    );
    Ok(Some(bytes))
}

fn unique_slot_path(slot: &Path, suffix: &str) -> Result<PathBuf> {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random)?;
    let random: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let mut name = slot.as_os_str().to_owned();
    name.push(format!(".{suffix}-{random}"));
    Ok(PathBuf::from(name))
}

/// Stage first, then replace under the vault writer's directory lock. The original file stays
/// in place until the atomic rename, so a failed save never needs a destructive rollback.
fn replace_slot(
    vault: &mut Vault,
    slot: &Path,
    original: Option<&[u8]>,
) -> Result<Option<PathBuf>> {
    if original.is_none() {
        vault.save(slot, true)?;
        return Ok(None);
    }
    let stage = unique_slot_path(slot, "recovering")?;
    vault.save(&stage, true)?;
    let result = (|| {
        let dir = File::open(slot.parent().context("The slot file has no directory")?)?;
        // The operation lock still serializes our clients on exFAT, which cannot lock folders.
        if let Err(error) = dir.lock()
            && error.kind() != std::io::ErrorKind::Unsupported
            && !(cfg!(target_os = "macos") && matches!(error.raw_os_error(), Some(45 | 102)))
        {
            return Err(error.into());
        }
        ensure!(
            read_slot(slot)?.as_deref() == original,
            "The slot file changed during enrollment. Nothing was replaced. Try again."
        );
        let backup = unique_slot_path(slot, "replaced")?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&backup)?;
        file.write_all(original.expect("checked above"))?;
        file.sync_all()?;
        std::fs::rename(&stage, slot).with_context(|| {
            format!(
                "Cannot replace {}. The old slot remains at {}",
                slot.display(),
                backup.display()
            )
        })?;
        Ok(Some(backup))
    })();
    let _ = std::fs::remove_file(&stage);
    result
}

/// A UTC date from UNIX seconds, by Howard Hinnant's days-to-civil algorithm.
fn date(seconds: u64) -> String {
    let days = i64::try_from(seconds / 86_400).unwrap_or(0) + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests;
