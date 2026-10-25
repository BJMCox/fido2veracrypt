use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use fido2veracrypt::cli;
use fido2veracrypt::commands::{self, Tools};
use fido2veracrypt::keys::Fido;
use fido2veracrypt::ui::Terminal;
use fido2veracrypt::veracrypt::{Close, Mount, Real, VeraCrypt, Volume};

fn main() -> ExitCode {
    let command =
        match cli::utf8_args(std::env::args_os().skip(1)).and_then(|args| cli::parse(&args)) {
            Ok(command) => command,
            Err(error) => {
                eprintln!("{error:#}");
                return ExitCode::from(2);
            }
        };
    let vc = Lazy::default();
    let result = commands::run(
        command,
        &mut Tools {
            vc: &vc,
            keys: &mut Fido,
            ui: &mut Terminal,
        },
    );
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::FAILURE
        }
    }
}

/// Finds VeraCrypt on first use, so commands that never run it, such as help, work without it.
#[derive(Default)]
struct Lazy(RefCell<Option<Real>>);

impl Lazy {
    fn with<T>(&self, use_it: impl FnOnce(&Real) -> Result<T>) -> Result<T> {
        if self.0.borrow().is_none() {
            let real = Real::find(configured()?)?;
            *self.0.borrow_mut() = Some(real);
        }
        use_it(self.0.borrow().as_ref().expect("just found"))
    }
}

impl VeraCrypt for Lazy {
    fn create(
        &self,
        container: &Path,
        size: u64,
        passphrase: &str,
        label: &str,
    ) -> Result<Option<anyhow::Error>> {
        self.with(|vc| vc.create(container, size, passphrase, label))
    }

    fn mount(&self, container: &Path, passphrase: &str, hash: Option<&str>) -> Result<Mount> {
        self.with(|vc| vc.mount(container, passphrase, hash))
    }

    fn opens(&self, container: &Path, passphrase: &str, hash: Option<&str>) -> Result<bool> {
        self.with(|vc| vc.opens(container, passphrase, hash))
    }

    fn close(&self, container: &Path, force: bool) -> Result<Close> {
        self.with(|vc| vc.close(container, force))
    }

    fn list(&self) -> Result<Vec<Volume>> {
        self.with(|vc| vc.list())
    }

    fn change(&self, container: &Path, old: &str, old_hash: Option<&str>, new: &str) -> Result<()> {
        self.with(|vc| vc.change(container, old, old_hash, new))
    }

    fn set_label(&self, mount_point: &Path, label: &str) -> Result<()> {
        self.with(|vc| vc.set_label(mount_point, label))
    }
}

/// The `veracrypt` path from the optional config file.
fn configured() -> Result<Option<PathBuf>> {
    let Some(path) = config_path() else {
        return Ok(None);
    };
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

fn config_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let base = if cfg!(target_os = "macos") {
        home?.join("Library/Application Support")
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| home.map(|h| h.join(".config")))?
    };
    Some(base.join("fido2veracrypt/config.toml"))
}
