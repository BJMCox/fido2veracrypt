use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

pub(crate) fn write_script(path: &Path, text: &str) {
    // Write in a child so parallel spawns cannot inherit a writable executable descriptor.
    // On Linux that inherited descriptor can make execution fail with ETXTBSY.
    let mut writer = Command::new("/bin/sh")
        .args([
            "-c",
            "umask 077; cat > \"$1\" && chmod 700 \"$1\"",
            "write-script",
        ])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    writer
        .stdin
        .take()
        .unwrap()
        .write_all(text.as_bytes())
        .unwrap();
    assert!(writer.wait().unwrap().success());
}
