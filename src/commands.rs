//! What each command does.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use fido2kit::fido::Unlock;
use fido2kit::vault::{KeyKind, Vault};
use zeroize::Zeroizing;

use crate::cli::{Command, HELP, Shell};
use crate::keys::Keys;
use crate::passphrase::Passphrase;
use crate::slots::{self, APP, HASH_META, SECRET};
use crate::ui::Ui;
use crate::veracrypt::{Close, HASH, HELPER, Mount, VeraCrypt};

pub const ZSH: &str = include_str!("../completions/_fido2veracrypt");
pub const BASH: &str = include_str!("../completions/fido2veracrypt.bash");

const ANOTHER_CONTAINER: &str = "The passphrase in this slot file does not open this container. Is the slot file from another container?";

pub struct Tools<'a> {
    pub vc: &'a dyn VeraCrypt,
    pub keys: &'a mut dyn Keys,
    pub ui: &'a mut dyn Ui,
}

/// A slot file unlocked with keys whose outputs the vault's tag check accepted.
struct Unlocked {
    slot: PathBuf,
    vault: Vault,
    unlocks: Vec<Unlock>,
}

pub fn run(command: Command, t: &mut Tools) -> Result<()> {
    match command {
        Command::Create {
            container,
            size,
            label,
        } => create(t, &resolve(&container)?, size, &label),
        Command::Adopt { container, label } => adopt(t, &resolve(&container)?, &label),
        Command::Open { container } => open(t, &resolve(&container)?),
        Command::Close { container, force } => {
            close(t, container.as_deref().map(resolve).transpose()?, force)
        }
        Command::AddKey {
            container,
            label,
            recovery: false,
        } => add_key(t, &resolve(&container)?, &label),
        Command::AddKey {
            container,
            label,
            recovery: true,
        } => add_key_with_recovery(t, &resolve(&container)?, &label),
        Command::RemoveKey { container, labels } => remove_key(t, &resolve(&container)?, &labels),
        Command::Rotate { container } => rotate(t, &resolve(&container)?),
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
    t.ui.say("Enroll the key that will open this container.");
    let enrollment = t.keys.enroll(&salt, &[])?;
    let passphrase = Passphrase::generate()?;
    show_recovery(t.ui, &passphrase)?;
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
        Err(error) => {
            let _ = std::fs::remove_file(&slot);
            return Err(error.context("The container was not created, and its slot file was removed"));
        }
        Ok(Some(label_error)) => t.ui.say(&format!(
            "The container works, but its label could not be set: {label_error:#}. The next open on macOS tries again."
        )),
        Ok(None) => {}
    }
    t.ui.say(&format!(
        "Created {}. Open it with: fido2veracrypt open {}",
        container.display(),
        container.display()
    ));
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
    let old = t.ui.secret("The container's current password: ")?;
    ensure!(
        t.vc.opens(container, &old, None)?,
        "That password does not open the container. Nothing was changed."
    );
    t.ui.say(
        "The old password still opens any copy of this container made before now, such as a backup. Only a new container with the files copied over removes that.",
    );
    let salt = Vault::new_salt()?;
    t.ui.say("Enroll the key that will open this container.");
    let enrollment = t.keys.enroll(&salt, &[])?;
    let new = Passphrase::generate()?;
    show_recovery(t.ui, &new)?;
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
            Err(error) => t.ui.say(&format!(
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
        Some(container) => vec![container],
        None => {
            t.vc.list()?
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
        match t.vc.close(&container, force)? {
            Close::Closed => t.ui.say(&format!("Closed {}", container.display())),
            Close::NotOpen => t.ui.say(&format!("{} is not open", container.display())),
            Close::Busy => busy.push(container.display().to_string()),
        }
    }
    ensure!(
        busy.is_empty(),
        "A file on {} is still open. Close it and try again, or run close --force, which loses unsaved changes in it.",
        busy.join(", ")
    );
    Ok(())
}

fn add_key(t: &mut Tools, container: &Path, label: &str) -> Result<()> {
    let mut unlocked = unlock(t, container)?;
    t.ui.say("Now enroll the new key. If both keys blink, touch the new one.");
    let enrollment = t
        .keys
        .enroll(&unlocked.vault.salt(), &unlocked.vault.cred_ids())?;
    unlocked
        .vault
        .add_key(&unlocked.unlocks, label, &enrollment)?;
    unlocked.vault.save(&unlocked.slot, false)?;
    t.ui.say(&format!("Enrolled {label}. The passphrase did not change."));
    Ok(())
}

fn add_key_with_recovery(t: &mut Tools, container: &Path, label: &str) -> Result<()> {
    ensure!(
        container.is_file(),
        "No container at {}",
        container.display()
    );
    let typed = t.ui.secret("Recovery passphrase: ")?;
    let passphrase = Passphrase::parse(&typed)?;
    let argon2 = t.vc.opens(container, passphrase.as_str(), Some(HASH))?;
    ensure!(
        argon2 || t.vc.opens(container, passphrase.as_str(), None)?,
        "That recovery passphrase does not open the container. Nothing was changed."
    );
    let salt = Vault::new_salt()?;
    t.ui.say("Enroll the key that will open this container.");
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
    let slot = slots::path(container);
    let mut replaced = None;
    if slot.exists() {
        let mut name = slot.clone().into_os_string();
        name.push(format!(".replaced-{}", unix_seconds()));
        std::fs::rename(&slot, &name)
            .with_context(|| format!("Cannot rename {}", slot.display()))?;
        replaced = Some(PathBuf::from(name));
    }
    if let Err(error) = vault.save(&slot, true) {
        if let Some(old) = &replaced {
            let _ = std::fs::rename(old, &slot);
        }
        return Err(error);
    }
    t.ui.say(&format!(
        "Enrolled {label} as the only key of a new slot file. The passphrase did not change."
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
    t.ui.say("Unlock with a key you keep.");
    let first = t.keys.unlock(&salt, &ids)?;
    // The tag check comes before anything acts on the labels.
    vault.verify(std::slice::from_ref(&first))?;
    let mut unlocked = Unlocked {
        slot,
        vault,
        unlocks: vec![first],
    };
    finish_pending(t, container, &mut unlocked)?;
    for (label, id) in &kept {
        if unlocked.unlocks.iter().any(|u| &u.cred_id == id) {
            continue;
        }
        t.ui.say(&format!("Plug in the key labeled {label}."));
        let unlock = t.keys.unlock_key(label, &salt, id)?;
        unlocked.unlocks.push(unlock);
    }
    let new = Passphrase::generate()?;
    show_recovery(t.ui, &new)?;
    unlocked.vault.remove_keys(&labels, &unlocked.unlocks)?;
    unlocked
        .vault
        .set_pending(&unlocked.unlocks, SECRET, new.as_str().as_bytes())?;
    unlocked.vault.save(&unlocked.slot, false)?;
    apply_pending(t.vc, container, &mut unlocked)?;
    t.ui.say(&format!(
        "Removed {}. The passphrase changed, so the old printout no longer works.",
        labels.join(", ")
    ));
    Ok(())
}

fn rotate(t: &mut Tools, container: &Path) -> Result<()> {
    let mut unlocked = unlock(t, container)?;
    let new = Passphrase::generate()?;
    show_recovery(t.ui, &new)?;
    unlocked
        .vault
        .set_pending(&unlocked.unlocks, SECRET, new.as_str().as_bytes())?;
    unlocked.vault.save(&unlocked.slot, false)?;
    apply_pending(t.vc, container, &mut unlocked)?;
    t.ui.say("The passphrase changed, so the old printout no longer works.");
    Ok(())
}

fn status(t: &mut Tools, container: Option<PathBuf>) -> Result<()> {
    let volumes = t.vc.list()?;
    let Some(container) = container else {
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
    let labels: Vec<&str> = vault.keys().iter().map(|k| k.label).collect();
    t.ui.say(&format!("Keys: {}", labels.join(", ")));
    t.ui.say(&format!(
        "Key derivation: {}",
        hash_of(&vault).unwrap_or_else(|| "unknown".to_owned())
    ));
    if vault.has_pending(SECRET) {
        t.ui.say("A passphrase change is unfinished. The next open finishes it.");
    }
    t.ui.say("(Read without a key, so these details are unverified.)");
    Ok(())
}

fn list_keys(t: &mut Tools, container: &Path) -> Result<()> {
    let (_, vault) = load(container)?;
    for key in vault.keys() {
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
        t.ui.say(&format!("{}  {aaguid}  {created}{migrated}", key.label));
    }
    t.ui.say("(Read without a key, so these entries are unverified.)");
    Ok(())
}

/// Shows the passphrase and has the owner type its last group back before anything is written.
fn show_recovery(ui: &mut dyn Ui, passphrase: &Passphrase) -> Result<()> {
    ui.say(
        "Your recovery passphrase. Write it down and keep it away from the drive. VeraCrypt alone opens the container with it, typed exactly as shown, dashes included:",
    );
    ui.say("");
    ui.say(passphrase.as_str());
    ui.say("");
    let typed = ui.ask("Type its last group to confirm you wrote it down: ")?;
    let typed: String = typed
        .trim()
        .to_ascii_uppercase()
        .chars()
        .map(|c| match c {
            'I' | 'L' => '1',
            'O' => '0',
            c => c,
        })
        .collect();
    ensure!(
        typed == passphrase.last_group(),
        "That is not the last group. Nothing was written. Run the command again."
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
fn finish_pending(t: &mut Tools, container: &Path, unlocked: &mut Unlocked) -> Result<()> {
    if !unlocked.vault.has_pending(SECRET) {
        return Ok(());
    }
    let current = current(unlocked)?;
    let pending = pending(unlocked)?;
    if t.vc
        .opens(container, &current, hash_of(&unlocked.vault).as_deref())?
    {
        t.vc.change(container, &current, &pending)?;
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

/// Changes the header to the pending passphrase, then makes it current.
fn apply_pending(vc: &dyn VeraCrypt, container: &Path, unlocked: &mut Unlocked) -> Result<()> {
    let current = current(unlocked)?;
    let pending = pending(unlocked)?;
    vc.change(container, &current, &pending)?;
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
    let name = path
        .file_name()
        .with_context(|| format!("{} names no file", path.display()))?;
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    Ok(parent
        .canonicalize()
        .with_context(|| format!("Cannot find the folder {}", parent.display()))?
        .join(name))
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
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
