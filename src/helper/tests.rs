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
    let open = veracrypt_steps(&Action::Open {
        container: path.clone(),
        hash: Some("Argon2".into()),
    })
    .concat();
    assert!(open.contains(&"--fs-options=nosuid,nodev".to_owned()));
    assert!(open.contains(&"--hash=Argon2".to_owned()));
    assert_eq!(open.last().unwrap(), &path.display().to_string());
    let check = veracrypt_steps(&Action::Check {
        container: path.clone(),
        hash: Some("Argon2".into()),
    })
    .concat();
    assert!(check.contains(&"--filesystem=none".to_owned()));
    let close = veracrypt_steps(&Action::Close {
        container: path,
        force: true,
    })
    .concat();
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

#[test]
fn open_mounts_only_exfat_and_check_mounts_nothing() {
    // A user who builds the container could otherwise have the kernel parse any filesystem type
    // as root, and kernel filesystem bugs are a known way to root.
    let (_dir, path) = container();
    let open = veracrypt_steps(&Action::Open {
        container: path.clone(),
        hash: Some("Argon2".into()),
    })
    .concat();
    let filesystems = |args: &[String]| {
        args.iter()
            .filter(|a| a.starts_with("--filesystem="))
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(filesystems(&open), ["--filesystem=exfat"]);
    let check = veracrypt_steps(&Action::Check {
        container: path,
        hash: Some("Argon2".into()),
    })
    .concat();
    assert_eq!(filesystems(&check), ["--filesystem=none"]);
}

#[test]
fn veracrypt_keeps_only_sudos_record_of_the_real_user() {
    // VeraCrypt mounts the volume for SUDO_UID and SUDO_GID. Without them it belongs to root.
    let from = |name: &str| match name {
        "SUDO_UID" => Some("1000".into()),
        "SUDO_GID" => Some("1000".into()),
        "SUDO_USER" => Some("owner".into()),
        "LD_PRELOAD" => Some("/tmp/evil.so".into()),
        _ => None,
    };
    let env = environment(from);
    let names: Vec<&str> = env.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["PATH", "SUDO_UID", "SUDO_GID", "SUDO_USER"]);
}

#[test]
fn any_lets_veracrypt_try_every_key_derivation() {
    let (_dir, path) = container();
    let action = parse(&words(&format!("check {} any", path.display()))).unwrap();
    assert!(matches!(&action, Action::Check { hash: None, .. }));
    assert!(
        veracrypt_steps(&action)[0]
            .iter()
            .all(|a| !a.starts_with("--hash"))
    );
}

#[test]
fn check_attaches_and_detaches_in_one_call() {
    // A client killed between two calls would leave a root dm device attached.
    let (_dir, path) = container();
    let steps = veracrypt_steps(&Action::Check {
        container: path.clone(),
        hash: Some("Argon2".into()),
    });
    assert_eq!(steps.len(), 2);
    assert!(steps[0].contains(&"--filesystem=none".to_owned()));
    assert!(steps[1].contains(&"-u".to_owned()));
    assert_eq!(steps[1].last().unwrap(), &path.display().to_string());
}
