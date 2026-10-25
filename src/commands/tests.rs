use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use fido2kit::fido::{Enrollment, Unlock};
use fido2kit::vault::Vault;
use zeroize::Zeroizing;

use super::*;
use crate::slots;
use crate::veracrypt::{Close, HASH, Mount, VeraCrypt, Volume};

#[derive(Clone, Default)]
struct Container {
    passphrase: String,
    hash: Option<String>,
    label: Option<String>,
    mounted: bool,
    /// Mounted with no mount point, as a Finder eject leaves it.
    half_closed: bool,
    busy: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum Crash {
    /// The change fails before VeraCrypt writes the header.
    BeforeHeader,
    /// VeraCrypt writes the header, then the process dies.
    AfterHeader,
}

#[derive(Default)]
struct FakeVeraCrypt {
    containers: RefCell<BTreeMap<PathBuf, Container>>,
    crash: RefCell<Option<Crash>>,
    fail_create: bool,
    /// Fails after writing the container file, as a failed format on Linux does.
    fail_after_file: bool,
    /// --force cannot close a busy volume, as on Linux.
    force_fails: bool,
}

impl FakeVeraCrypt {
    fn get(&self, container: &Path) -> Container {
        self.containers.borrow()[container].clone()
    }

    fn insert(&self, container: &Path, value: Container) {
        std::fs::write(container, b"ciphertext").unwrap();
        self.containers
            .borrow_mut()
            .insert(container.to_owned(), value);
    }

    fn matches(stored: &Container, passphrase: &str, hash: Option<&str>) -> bool {
        stored.passphrase == passphrase && hash.is_none_or(|h| stored.hash.as_deref() == Some(h))
    }
}

impl VeraCrypt for FakeVeraCrypt {
    fn create(
        &self,
        container: &Path,
        _: u64,
        passphrase: &str,
        label: &str,
    ) -> Result<Option<anyhow::Error>> {
        if self.fail_create {
            bail!("VeraCrypt failed");
        }
        if self.fail_after_file {
            std::fs::write(container, b"unformatted").unwrap();
            bail!("mkfs.exfat failed");
        }
        self.insert(
            container,
            Container {
                passphrase: passphrase.to_owned(),
                hash: Some(HASH.to_owned()),
                label: Some(label.to_owned()),
                ..Container::default()
            },
        );
        Ok(None)
    }

    fn mount(&self, container: &Path, passphrase: &str, hash: Option<&str>) -> Result<Mount> {
        let mut containers = self.containers.borrow_mut();
        let stored = containers.get_mut(container).unwrap();
        if !Self::matches(stored, passphrase, hash) {
            return Ok(Mount::WrongPassphrase);
        }
        stored.mounted = true;
        Ok(Mount::Mounted)
    }

    fn opens(&self, container: &Path, passphrase: &str, hash: Option<&str>) -> Result<bool> {
        Ok(Self::matches(&self.get(container), passphrase, hash))
    }

    fn close(&self, container: &Path, force: bool) -> Result<Close> {
        let mut containers = self.containers.borrow_mut();
        let stored = containers.get_mut(container).unwrap();
        Ok(if !stored.mounted {
            Close::NotOpen
        } else if stored.busy && (!force || self.force_fails) {
            Close::Busy
        } else {
            stored.mounted = false;
            stored.half_closed = false;
            Close::Closed
        })
    }

    fn list(&self) -> Result<Vec<Volume>> {
        Ok(self
            .containers
            .borrow()
            .iter()
            .filter(|(_, c)| c.mounted)
            .map(|(path, c)| Volume {
                container: path.clone(),
                device: Some("/dev/disk9".into()),
                mount_point: (!c.half_closed).then(|| {
                    PathBuf::from("/Volumes").join(c.label.clone().unwrap_or("Untitled".into()))
                }),
            })
            .collect())
    }

    fn change(&self, container: &Path, old: &str, old_hash: Option<&str>, new: &str) -> Result<()> {
        let crash = *self.crash.borrow();
        if crash == Some(Crash::BeforeHeader) {
            bail!("crashed before the header");
        }
        let mut containers = self.containers.borrow_mut();
        let stored = containers.get_mut(container).unwrap();
        // VeraCrypt's -C tries the old password only with the named key derivation.
        if old_hash.is_some_and(|h| stored.hash.as_deref() != Some(h)) {
            bail!("Incorrect PRF (hash)");
        }
        if stored.passphrase != old {
            bail!("Incorrect password");
        }
        stored.passphrase = new.to_owned();
        stored.hash = Some(HASH.to_owned());
        if crash == Some(Crash::AfterHeader) {
            bail!("crashed after the header");
        }
        Ok(())
    }

    fn set_label(&self, mount_point: &Path, label: &str) -> Result<()> {
        let mut containers = self.containers.borrow_mut();
        let untitled = mount_point.file_name().unwrap() == "Untitled";
        let stored = containers
            .values_mut()
            .find(|c| c.mounted && c.label.is_none() && untitled)
            .unwrap();
        stored.label = Some(label.to_owned());
        Ok(())
    }
}

/// Keys by number: key `n` has credential ID `[n; 16]`, and its output depends on the salt.
#[derive(Default)]
struct FakeKeys {
    plugged: Vec<u8>,
}

fn output(id: u8, salt: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(salt.map(|b| b ^ id))
}

impl Keys for FakeKeys {
    fn unlock(&mut self, salt: &[u8; 32], cred_ids: &[&[u8]]) -> Result<Unlock> {
        for &id in &self.plugged {
            if cred_ids.contains(&[id; 16].as_slice()) {
                return Ok(Unlock {
                    cred_id: vec![id; 16],
                    output: output(id, salt),
                });
            }
        }
        bail!("This security key is not enrolled.")
    }

    fn unlock_key(&mut self, label: &str, salt: &[u8; 32], cred_id: &[u8]) -> Result<Unlock> {
        match self.plugged.iter().find(|&&id| [id; 16] == cred_id) {
            Some(&id) => Ok(Unlock {
                cred_id: vec![id; 16],
                output: output(id, salt),
            }),
            None => bail!("Key {label} is not plugged in"),
        }
    }

    fn enroll(&mut self, salt: &[u8; 32], exclude: &[&[u8]]) -> Result<Enrollment> {
        let id = *self
            .plugged
            .iter()
            .find(|&&id| !exclude.contains(&[id; 16].as_slice()))
            .expect("a new key is plugged in");
        Ok(Enrollment {
            unlock: Unlock {
                cred_id: vec![id; 16],
                output: output(id, salt),
            },
            aaguid: [id; 16],
            uv: true,
        })
    }
}

/// Answers hidden prompts from `secrets` and the printout check with the shown passphrase's last
/// group, or `wrong` when `confirm` is false.
struct FakeUi {
    said: Vec<String>,
    /// What went to the terminal only.
    shown: Vec<String>,
    secrets: VecDeque<String>,
    confirm: bool,
}

impl Default for FakeUi {
    fn default() -> Self {
        Self {
            said: Vec::new(),
            shown: Vec::new(),
            secrets: VecDeque::new(),
            confirm: true,
        }
    }
}

impl FakeUi {
    fn shown_passphrase(&self) -> String {
        self.shown
            .last()
            .cloned()
            .expect("a recovery passphrase was shown")
    }

    fn output(&self) -> String {
        self.said.join("\n")
    }
}

impl Ui for FakeUi {
    fn say(&mut self, text: &str) {
        self.said.push(text.to_owned());
    }

    fn show_secret(&mut self, text: &str) -> Result<()> {
        self.shown.push(text.to_owned());
        Ok(())
    }

    fn secret(&mut self, _: &str) -> Result<Zeroizing<String>> {
        Ok(Zeroizing::new(
            self.secrets.pop_front().expect("a scripted secret"),
        ))
    }

    fn ask(&mut self, prompt: &str) -> Result<String> {
        assert!(prompt.contains("last group"), "{prompt}");
        Ok(if self.confirm {
            self.shown_passphrase()[60..].to_owned()
        } else {
            "WRNG".into()
        })
    }
}

struct World {
    dir: tempfile::TempDir,
    vc: FakeVeraCrypt,
    keys: FakeKeys,
    ui: FakeUi,
}

impl World {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            vc: FakeVeraCrypt::default(),
            keys: FakeKeys { plugged: vec![1] },
            ui: FakeUi::default(),
        }
    }

    /// A path inside the world's folder, with its symlinks resolved as the commands resolve them.
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().canonicalize().unwrap().join(name)
    }

    fn run(&mut self, line: &str) -> Result<()> {
        let dir = self.path("");
        let args: Vec<String> = line
            .split_whitespace()
            .map(|word| word.replace("DIR/", &dir.display().to_string()))
            .collect();
        let command = crate::cli::parse(&args)?;
        run(
            command,
            &mut Tools {
                vc: &self.vc,
                keys: &mut self.keys,
                ui: &mut self.ui,
            },
        )
    }

    fn slot(&self, name: &str) -> Vault {
        Vault::load(slots::APP, &slots::path(&self.path(name))).unwrap()
    }

    fn stored(&self, name: &str, key: u8) -> String {
        let vault = self.slot(name);
        let unlock = Unlock {
            cred_id: vec![key; 16],
            output: output(key, &vault.salt()),
        };
        String::from_utf8(vault.open(&[unlock], Some(slots::SECRET)).unwrap().to_vec()).unwrap()
    }
}

fn error_of(result: Result<()>) -> String {
    format!("{:#}", result.expect_err("an error"))
}

#[test]
fn create_makes_a_container_and_a_slot_file_that_opens_it() {
    let mut world = World::new();
    world
        .run("create DIR/secure.hc --size 1G --label yubikey")
        .unwrap();
    let shown = world.ui.shown_passphrase();
    let container = world.vc.get(&world.path("secure.hc"));
    assert_eq!(container.passphrase, shown);
    assert_eq!(container.label.as_deref(), Some("secure"));
    assert_eq!(world.stored("secure.hc", 1), shown);
    let vault = world.slot("secure.hc");
    assert_eq!(
        vault.secret_meta(slots::SECRET).unwrap()[slots::HASH_META],
        HASH
    );
    assert_eq!(vault.keys()[0].label, "yubikey");
}

#[test]
fn create_refuses_an_existing_container_or_a_leftover_slot_file() {
    let mut world = World::new();
    world.run("create DIR/a.hc --size 1G --label k").unwrap();
    assert!(world.run("create DIR/a.hc --size 1G --label k").is_err());
    std::fs::write(slots::path(&world.path("b.hc")), b"left over").unwrap();
    let error = error_of(world.run("create DIR/b.hc --size 1G --label k"));
    assert!(error.contains("interrupted"), "{error}");
}

#[test]
fn a_wrong_printout_check_writes_nothing() {
    let mut world = World::new();
    world.ui.confirm = false;
    assert!(world.run("create DIR/a.hc --size 1G --label k").is_err());
    assert!(!world.path("a.hc").exists());
    assert!(!slots::path(&world.path("a.hc")).exists());
}

#[test]
fn a_failed_create_removes_its_slot_file() {
    let mut world = World::new();
    world.vc.fail_create = true;
    assert!(world.run("create DIR/a.hc --size 1G --label k").is_err());
    assert!(!slots::path(&world.path("a.hc")).exists());
}

#[test]
fn open_mounts_and_names_a_slot_file_from_another_container() {
    let mut world = World::new();
    world.run("create DIR/a.hc --size 1G --label k").unwrap();
    world.run("create DIR/b.hc --size 1G --label k").unwrap();
    world.run("open DIR/a.hc").unwrap();
    assert!(world.vc.get(&world.path("a.hc")).mounted);
    assert!(world.ui.output().contains("/Volumes/a"));
    std::fs::copy(
        slots::path(&world.path("a.hc")),
        slots::path(&world.path("b.hc")),
    )
    .unwrap();
    let error = error_of(world.run("open DIR/b.hc"));
    assert!(error.contains("another container"), "{error}");
}

#[cfg(target_os = "macos")]
#[test]
fn open_labels_an_untitled_volume_on_macos() {
    let mut world = World::new();
    world
        .run("create DIR/linux.hc --size 1G --label k")
        .unwrap();
    world
        .vc
        .containers
        .borrow_mut()
        .get_mut(&world.path("linux.hc"))
        .unwrap()
        .label = None;
    world.run("open DIR/linux.hc").unwrap();
    assert_eq!(
        world.vc.get(&world.path("linux.hc")).label.as_deref(),
        Some("linux")
    );
}

fn existing(world: &World, name: &str) {
    world.vc.insert(
        &world.path(name),
        Container {
            passphrase: "old password".into(),
            hash: Some("SHA-512".into()),
            ..Container::default()
        },
    );
}

#[test]
fn adopt_switches_a_container_to_a_new_passphrase_and_argon2() {
    let mut world = World::new();
    existing(&world, "old.hc");
    world.ui.secrets.push_back("old password".into());
    world.run("adopt DIR/old.hc --label k").unwrap();
    let shown = world.ui.shown_passphrase();
    let container = world.vc.get(&world.path("old.hc"));
    assert_eq!(container.passphrase, shown);
    assert_eq!(container.hash.as_deref(), Some(HASH));
    assert_eq!(world.stored("old.hc", 1), shown);
    assert!(!world.slot("old.hc").has_pending(slots::SECRET));
    assert!(world.ui.output().contains("old password still opens"));
}

#[test]
fn adopt_refuses_a_wrong_password() {
    let mut world = World::new();
    existing(&world, "old.hc");
    world.ui.secrets.push_back("guess".into());
    assert!(world.run("adopt DIR/old.hc --label k").is_err());
    assert!(!slots::path(&world.path("old.hc")).exists());
}

#[test]
fn an_adopt_interrupted_before_the_header_finishes_on_the_next_open() {
    let mut world = World::new();
    existing(&world, "old.hc");
    world.ui.secrets.push_back("old password".into());
    *world.vc.crash.borrow_mut() = Some(Crash::BeforeHeader);
    assert!(world.run("adopt DIR/old.hc --label k").is_err());
    let shown = world.ui.shown_passphrase();
    *world.vc.crash.borrow_mut() = None;
    world.run("open DIR/old.hc").unwrap();
    assert_eq!(world.vc.get(&world.path("old.hc")).passphrase, shown);
    assert_eq!(world.stored("old.hc", 1), shown);
    assert!(!world.slot("old.hc").has_pending(slots::SECRET));
}

#[test]
fn a_rotation_interrupted_at_either_step_finishes_on_the_next_open() {
    for crash in [Crash::BeforeHeader, Crash::AfterHeader] {
        let mut world = World::new();
        world.run("create DIR/a.hc --size 1G --label k").unwrap();
        *world.vc.crash.borrow_mut() = Some(crash);
        assert!(world.run("rotate DIR/a.hc").is_err());
        let new = world.ui.shown_passphrase();
        assert!(world.slot("a.hc").has_pending(slots::SECRET));
        *world.vc.crash.borrow_mut() = None;
        world.run("open DIR/a.hc").unwrap();
        let container = world.vc.get(&world.path("a.hc"));
        assert_eq!(container.passphrase, new);
        assert!(container.mounted);
        assert_eq!(world.stored("a.hc", 1), new);
        assert!(!world.slot("a.hc").has_pending(slots::SECRET));
    }
}

#[test]
fn rotate_changes_the_passphrase() {
    let mut world = World::new();
    world.run("create DIR/a.hc --size 1G --label k").unwrap();
    let old = world.ui.shown_passphrase();
    world.run("rotate DIR/a.hc").unwrap();
    let new = world.ui.shown_passphrase();
    assert_ne!(old, new);
    assert_eq!(world.vc.get(&world.path("a.hc")).passphrase, new);
    assert_eq!(world.stored("a.hc", 1), new);
}

fn two_keys(world: &mut World) {
    world.run("create DIR/a.hc --size 1G --label one").unwrap();
    world.keys.plugged = vec![1, 2];
    world.run("add-key DIR/a.hc --label two").unwrap();
}

#[test]
fn add_key_enrolls_a_second_key_without_changing_the_passphrase() {
    let mut world = World::new();
    two_keys(&mut world);
    let shown = world.ui.shown_passphrase();
    assert_eq!(world.stored("a.hc", 2), shown);
    assert_eq!(world.vc.get(&world.path("a.hc")).passphrase, shown);
}

#[test]
fn remove_key_drops_a_lost_key_and_changes_the_passphrase() {
    let mut world = World::new();
    two_keys(&mut world);
    let old = world.ui.shown_passphrase();
    world.keys.plugged = vec![1];
    world.run("remove-key DIR/a.hc --label two").unwrap();
    let new = world.ui.shown_passphrase();
    assert_ne!(old, new);
    assert_eq!(world.vc.get(&world.path("a.hc")).passphrase, new);
    let labels: Vec<String> = world
        .slot("a.hc")
        .keys()
        .iter()
        .map(|k| k.label.to_owned())
        .collect();
    assert_eq!(labels, ["one"]);
}

#[test]
fn an_interrupted_remove_key_never_gives_the_removed_key_the_new_passphrase() {
    let mut world = World::new();
    two_keys(&mut world);
    world.keys.plugged = vec![1];
    *world.vc.crash.borrow_mut() = Some(Crash::BeforeHeader);
    assert!(world.run("remove-key DIR/a.hc --label two").is_err());
    let new = world.ui.shown_passphrase();
    let vault = world.slot("a.hc");
    assert!(vault.has_pending(slots::SECRET));
    assert!(!vault.cred_ids().contains(&[2u8; 16].as_slice()));
    *world.vc.crash.borrow_mut() = None;
    world.run("open DIR/a.hc").unwrap();
    assert_eq!(world.vc.get(&world.path("a.hc")).passphrase, new);
}

#[test]
fn add_key_with_the_recovery_passphrase_rebuilds_the_slot_file() {
    let mut world = World::new();
    two_keys(&mut world);
    let shown = world.ui.shown_passphrase();
    let typed = shown.replace('-', "").to_lowercase();
    world.keys.plugged = vec![3];
    world.ui.secrets.push_back(typed);
    world
        .run("add-key DIR/a.hc --label three --recovery")
        .unwrap();
    assert_eq!(world.stored("a.hc", 3), shown);
    assert_eq!(world.slot("a.hc").keys().len(), 1);
    let replaced = std::fs::read_dir(world.path(""))
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_string_lossy().contains(".replaced-"));
    assert!(replaced);
}

#[test]
fn add_key_with_a_wrong_recovery_passphrase_changes_nothing() {
    let mut world = World::new();
    world.run("create DIR/a.hc --size 1G --label k").unwrap();
    let before = std::fs::read(slots::path(&world.path("a.hc"))).unwrap();
    world.ui.secrets.push_back("0".repeat(52));
    assert!(world.run("add-key DIR/a.hc --label k2 --recovery").is_err());
    assert_eq!(
        std::fs::read(slots::path(&world.path("a.hc"))).unwrap(),
        before
    );
}

#[test]
fn close_names_a_busy_volume_and_force_closes_it() {
    let mut world = World::new();
    world.run("create DIR/a.hc --size 1G --label k").unwrap();
    world.run("open DIR/a.hc").unwrap();
    world
        .vc
        .containers
        .borrow_mut()
        .get_mut(&world.path("a.hc"))
        .unwrap()
        .busy = true;
    let error = error_of(world.run("close DIR/a.hc"));
    assert!(error.contains("--force"), "{error}");
    world.run("close DIR/a.hc --force").unwrap();
    assert!(!world.vc.get(&world.path("a.hc")).mounted);
}

#[test]
fn close_without_a_container_closes_only_volumes_with_slot_files() {
    let mut world = World::new();
    world.run("create DIR/a.hc --size 1G --label k").unwrap();
    world.run("open DIR/a.hc").unwrap();
    existing(&world, "foreign.hc");
    world
        .vc
        .containers
        .borrow_mut()
        .get_mut(&world.path("foreign.hc"))
        .unwrap()
        .mounted = true;
    world.run("close").unwrap();
    assert!(!world.vc.get(&world.path("a.hc")).mounted);
    assert!(world.vc.get(&world.path("foreign.hc")).mounted);
}

#[test]
fn status_names_a_half_closed_volume() {
    let mut world = World::new();
    world.run("create DIR/a.hc --size 1G --label k").unwrap();
    world.run("open DIR/a.hc").unwrap();
    world
        .vc
        .containers
        .borrow_mut()
        .get_mut(&world.path("a.hc"))
        .unwrap()
        .half_closed = true;
    world.run("status").unwrap();
    assert!(
        world.ui.output().contains("half closed"),
        "{}",
        world.ui.output()
    );
}

#[test]
fn a_change_that_keeps_failing_still_opens_with_the_current_passphrase() {
    let mut world = World::new();
    existing(&world, "old.hc");
    world.ui.secrets.push_back("old password".into());
    *world.vc.crash.borrow_mut() = Some(Crash::BeforeHeader);
    assert!(world.run("adopt DIR/old.hc --label k").is_err());
    // The change keeps failing, for example after a VeraCrypt update changed its prompts.
    world.run("open DIR/old.hc").unwrap();
    assert!(world.vc.get(&world.path("old.hc")).mounted);
    assert!(
        world.ui.output().contains("could not finish"),
        "{}",
        world.ui.output()
    );
    assert!(world.slot("old.hc").has_pending(slots::SECRET));
}

#[test]
fn a_create_that_fails_after_writing_the_container_keeps_both_files_and_names_them() {
    let mut world = World::new();
    world.vc.fail_after_file = true;
    let error = error_of(world.run("create DIR/a.hc --size 1G --label k"));
    assert!(world.path("a.hc").exists());
    assert!(slots::path(&world.path("a.hc")).exists());
    assert!(error.contains("Delete"), "{error}");
}

#[test]
fn the_recovery_passphrase_goes_to_the_terminal_and_never_to_stdout() {
    // A redirect such as `| tee log` would otherwise write it to disk.
    let mut world = World::new();
    world.run("create DIR/a.hc --size 1G --label k").unwrap();
    let shown = world.ui.shown_passphrase();
    assert!(!world.ui.output().contains(&shown));
}

#[test]
fn a_volume_that_even_force_cannot_close_says_to_close_the_program() {
    let mut world = World::new();
    world.run("create DIR/a.hc --size 1G --label k").unwrap();
    world.run("open DIR/a.hc").unwrap();
    world.vc.force_fails = true;
    world
        .vc
        .containers
        .borrow_mut()
        .get_mut(&world.path("a.hc"))
        .unwrap()
        .busy = true;
    let error = error_of(world.run("close DIR/a.hc --force"));
    assert!(!error.contains("run close --force"), "{error}");
    assert!(error.contains("fuser"), "{error}");
}
