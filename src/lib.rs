//! Opens VeraCrypt containers with a FIDO2 security key.

pub mod cli;
pub mod commands;
#[cfg(target_os = "macos")]
mod desktop;
pub mod helper;
pub mod keys;
pub mod passphrase;
pub mod slots;
pub mod ui;
pub mod veracrypt;

#[cfg(test)]
mod test_support;
