//! The security keys.

use std::io::BufRead;

use anyhow::{Context, Result, ensure};
use fido2kit::fido::{self, Enrollment, FidoError, Key, Unlock};
use zeroize::Zeroizing;

use crate::slots::APP;

pub trait Keys {
    /// The output of whichever enrolled key the owner uses: a choosing touch when several are
    /// plugged in, then its PIN and a touch.
    fn unlock(&mut self, salt: &[u8; 32], cred_ids: &[&[u8]]) -> Result<Unlock>;
    /// The output of the key labeled `label`, after asking the owner to plug it in.
    fn unlock_key(&mut self, label: &str, salt: &[u8; 32], cred_id: &[u8]) -> Result<Unlock>;
    /// A new credential on the key the owner uses. Its PIN and two touches.
    fn enroll(&mut self, salt: &[u8; 32], exclude: &[&[u8]]) -> Result<Enrollment>;
}

/// The plugged-in FIDO2 keys, with prompts on the terminal.
pub struct Fido;

impl Keys for Fido {
    fn unlock(&mut self, salt: &[u8; 32], cred_ids: &[&[u8]]) -> Result<Unlock> {
        let key = choose()?;
        with_pin(|pin| {
            eprintln!("Touch the key.");
            fido::derive(APP, &key, pin, salt, cred_ids)
        })
    }

    fn unlock_key(&mut self, label: &str, salt: &[u8; 32], cred_id: &[u8]) -> Result<Unlock> {
        eprintln!("Plug in the key labeled {label}, then press Enter.");
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .context("Cannot read from the terminal")?;
        self.unlock(salt, &[cred_id])
    }

    fn enroll(&mut self, salt: &[u8; 32], exclude: &[&[u8]]) -> Result<Enrollment> {
        let key = choose()?;
        with_pin(|pin| {
            eprintln!("Touch the key, then touch it again when it blinks.");
            fido::enroll(APP, &key, pin, salt, exclude)
        })
    }
}

/// The only plugged-in key, or the one the owner touches when several blink.
fn choose() -> Result<Key> {
    let devices = fido::devices();
    if devices.len() > 1 {
        eprintln!("Several keys are plugged in. Touch the one to use.");
    }
    Ok(fido::select(devices)?)
}

/// Asks for the PIN until the key accepts it or refuses for another reason.
fn with_pin<T>(mut attempt: impl FnMut(&str) -> Result<T, FidoError>) -> Result<T> {
    loop {
        let pin =
            Zeroizing::new(rpassword::prompt_password("PIN: ").context("Cannot read the PIN")?);
        ensure!(
            !pin.is_empty(),
            "Enter the key's PIN. A key without a PIN cannot open containers. Set one with the vendor's tool."
        );
        match attempt(&pin) {
            Ok(value) => return Ok(value),
            Err(error) => {
                let error = anyhow::Error::new(error);
                if !fido::retry_pin(&error) {
                    return Err(error);
                }
                eprintln!("{error}");
            }
        }
    }
}
