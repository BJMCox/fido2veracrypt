use super::*;

fn words(line: &str) -> Vec<String> {
    line.split_whitespace().map(str::to_owned).collect()
}

/// A container with a slot file beside it, in a fresh folder.
fn container() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.hc");
    std::fs::write(&path, b"x").unwrap();
    std::fs::write(crate::slots::path(&path), b"x").unwrap();
    (dir, path)
}

#[test]
fn only_the_three_fixed_actions_parse() {
    let (_dir, path) = container();
    let p = path.display();
    assert!(matches!(
        parse(&words(&format!("open {p} Argon2"))).unwrap(),
        Action::Open { .. }
    ));
    assert!(matches!(
        parse(&words(&format!("check {p} SHA-512"))).unwrap(),
        Action::Check { .. }
    ));
    assert!(matches!(
        parse(&words(&format!("close {p} --force"))).unwrap(),
        Action::Close { force: true, .. }
    ));
    for line in [
        format!("create {p} Argon2"),
        format!("open {p}"),
        format!("open {p} --token-lib=/tmp/evil.so"),
        format!("open {p} Argon2 extra"),
        format!("close {p} --forced"),
        format!("close {p} --force --force"),
        "open".to_owned(),
        String::new(),
    ] {
        assert!(parse(&words(&line)).is_err(), "{line:?} was accepted");
    }
}

#[test]
fn a_container_needs_a_slot_file_and_must_be_a_regular_file() {
    let (dir, path) = container();
    assert_eq!(checked(&path).unwrap(), path.canonicalize().unwrap());
    let bare = dir.path().join("bare.hc");
    std::fs::write(&bare, b"x").unwrap();
    assert!(checked(&bare).is_err());
    let folder = dir.path().join("folder.hc");
    std::fs::create_dir(&folder).unwrap();
    std::fs::write(crate::slots::path(&folder), b"x").unwrap();
    assert!(checked(&folder).is_err());
    assert!(checked(Path::new("relative.hc")).is_err());
}

#[test]
fn veracrypt_runs_with_fixed_options_only() {
    let (_dir, path) = container();
    let open = veracrypt_args(&Action::Open {
        container: path.clone(),
        hash: "Argon2".into(),
    });
    assert!(open.contains(&"--fs-options=nosuid,nodev".to_owned()));
    assert!(open.contains(&"--hash=Argon2".to_owned()));
    assert_eq!(open.last().unwrap(), &path.display().to_string());
    let check = veracrypt_args(&Action::Check {
        container: path.clone(),
        hash: "Argon2".into(),
    });
    assert!(check.contains(&"--filesystem=none".to_owned()));
    let close = veracrypt_args(&Action::Close {
        container: path,
        force: true,
    });
    assert!(close.contains(&"--force".to_owned()) && close.contains(&"-u".to_owned()));
    for args in [&open, &check, &close] {
        assert!(
            !args
                .iter()
                .any(|a| a.contains("token") || a.contains("create") || a.contains("keyfiles=")),
            "{args:?}"
        );
    }
}
