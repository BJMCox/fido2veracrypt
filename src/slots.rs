//! The slot file beside each container: a fido2kit vault that holds the container's passphrase.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use fido2kit::App;

/// The relying-party ID and vault domain. It must never change after the first enrollment.
pub const APP: App = App::new("fido2veracrypt");
/// The vault's only secret.
pub const SECRET: &str = "passphrase";
/// The secret's metadata key for VeraCrypt's key derivation, so each mount names it.
pub const HASH_META: &str = "fido2veracrypt.hash";
const EXTENSION: &str = ".fido2veracrypt_meta";

/// `<container>.fido2veracrypt_meta`.
pub fn path(container: &Path) -> PathBuf {
    let mut name = OsString::from(container.as_os_str());
    name.push(EXTENSION);
    PathBuf::from(name)
}

/// The container's name without its extension, cut to the 11 UTF-16 units exFAT allows.
pub fn label(container: &Path) -> String {
    let stem = container
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut label = String::new();
    for c in stem.chars() {
        if label.encode_utf16().count() + c.len_utf16() > 11 {
            break;
        }
        label.push(c);
    }
    label
}
