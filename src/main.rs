use std::cell::RefCell;
use std::path::Path;
use std::process::ExitCode;

use anyhow::Result;
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
                eprintln!("{}", format!("{error:#}").escape_debug());
                return ExitCode::from(2);
            }
        };
    let vc = Lazy::default();
    let mut terminal = Terminal::new(&command);
    let result = commands::run(
        command,
        &mut Tools {
            vc: &vc,
            keys: &mut Fido,
            ui: &mut terminal,
        },
    );
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", format!("{error:#}").escape_debug());
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
            let real = Real::configured()?;
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
