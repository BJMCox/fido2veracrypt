use super::*;
use std::os::unix::fs::PermissionsExt;

const LIST: &str = "\
Slot: 1
Volume: /Volumes/stick/my secure.hc
Virtual Device: /dev/disk4
Mount Directory: /Volumes/My Drive
Size: 63.8 MiB
Type: Normal

Slot: 2
Volume: /tmp/other.hc
Virtual Device:\x20
Mount Directory:\x20
Size: 2 MiB
";

#[test]
fn the_verbose_list_keeps_paths_with_spaces_and_marks_half_closed_volumes() {
    let volumes = parse_list(LIST);
    assert_eq!(volumes.len(), 2);
    assert_eq!(
        volumes[0].container,
        Path::new("/Volumes/stick/my secure.hc")
    );
    assert_eq!(
        volumes[0].mount_point.as_deref(),
        Some(Path::new("/Volumes/My Drive"))
    );
    assert_eq!(volumes[1].mount_point, None);
    assert_eq!(volumes[1].device, None);
    assert!(parse_list("Error: No volumes mounted.\n").is_empty());
}

#[test]
fn versions_below_the_minimum_are_refused() {
    assert_eq!(parse_version("VeraCrypt 1.26.30\n").unwrap(), (1, 26, 30));
    assert!(check_version("VeraCrypt 1.26.30").is_ok());
    assert!(check_version("VeraCrypt 1.27.0").is_ok());
    assert!(check_version("VeraCrypt 1.26.29").is_err());
    assert!(check_version("VeraCrypt 1.26").is_err());
    assert!(check_version("Nothing").is_err());
}

#[test]
fn mount_arguments_name_the_hash_and_never_take_the_passphrase() {
    let args = mount_args(Path::new("/s.hc"), Some("Argon2"), true, true);
    assert!(args.contains(&"--hash=Argon2".to_owned()));
    assert!(args.contains(&"--stdin".to_owned()));
    assert!(args.contains(&"--fs-options=nosuid,nodev".to_owned()));
    assert_eq!(args.last().unwrap(), "/s.hc");
    assert!(
        !args
            .iter()
            .any(|a| a.starts_with("-p") || a.starts_with("--password"))
    );
    assert!(
        !mount_args(Path::new("/s.hc"), None, false, true)
            .iter()
            .any(|a| a.starts_with("--hash"))
    );
}

/// A stand-in for `veracrypt -C` that prints `prompts`, records the answers, and prints `tail`.
fn fake(dir: &Path, prompts: &[&str], tail: &str) -> PathBuf {
    let script = dir.join("veracrypt");
    let mut body = String::from("#!/bin/sh\n");
    for prompt in prompts {
        body.push_str(&format!(
            "printf '%s' '{prompt}'\nread -r line\necho \"$line\" >> '{}'\n",
            dir.join("answers").display()
        ));
    }
    body.push_str(tail);
    std::fs::write(&script, body).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    script
}

fn answers(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("answers")).unwrap_or_default()
}

const PROMPTS: [&str; 3] = [
    "Enter password: ",
    "Enter new password: ",
    "Re-enter password: ",
];
const SUCCESS: &str = "echo\necho 'Password, PIM and/or keyfile(s) successfully changed.'\n";

#[test]
fn the_change_answers_each_prompt_in_order() {
    let dir = tempfile::tempdir().unwrap();
    let mut command = std::process::Command::new(fake(dir.path(), &PROMPTS, SUCCESS));
    drive_change(&mut command, "old", "new", TIMEOUT).unwrap();
    assert_eq!(answers(dir.path()), "old\nnew\nnew\n");
}

#[test]
fn an_unexpected_prompt_stops_the_change_without_an_answer() {
    let dir = tempfile::tempdir().unwrap();
    let prompts = ["Enter password: ", "Enter PIM: ", "Enter new password: "];
    let mut command = std::process::Command::new(fake(dir.path(), &prompts, SUCCESS));
    assert!(drive_change(&mut command, "old", "new", TIMEOUT).is_err());
    assert_eq!(
        answers(dir.path())
            .lines()
            .filter(|l| !l.is_empty())
            .count(),
        1
    );
}

#[test]
fn prompts_out_of_order_stop_the_change() {
    let dir = tempfile::tempdir().unwrap();
    let prompts = ["Enter new password: ", "Enter password: "];
    let mut command = std::process::Command::new(fake(dir.path(), &prompts, SUCCESS));
    assert!(drive_change(&mut command, "old", "new", TIMEOUT).is_err());
    assert!(!answers(dir.path()).contains("old"));
}

#[test]
fn a_silent_veracrypt_times_out() {
    let dir = tempfile::tempdir().unwrap();
    let mut command = std::process::Command::new(fake(dir.path(), &[], "sleep 5\n"));
    let started = std::time::Instant::now();
    assert!(drive_change(&mut command, "old", "new", Duration::from_millis(300)).is_err());
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn a_change_without_the_success_line_fails() {
    let dir = tempfile::tempdir().unwrap();
    let mut command = std::process::Command::new(fake(
        dir.path(),
        &PROMPTS,
        "echo 'Error: Incorrect password.'\nexit 1\n",
    ));
    assert!(drive_change(&mut command, "old", "new", TIMEOUT).is_err());
}

#[test]
fn a_change_names_the_new_hash_and_the_current_one_only_when_known() {
    let unknown = change_args(Path::new("/s.hc"), None);
    assert!(unknown.contains(&"--new-hash=Argon2".to_owned()));
    assert!(!unknown.iter().any(|a| a.starts_with("--hash")));
    let known = change_args(Path::new("/s.hc"), Some("SHA-512"));
    assert!(known.contains(&"--hash=SHA-512".to_owned()));
    assert!(known.contains(&"--new-hash=Argon2".to_owned()));
    assert_eq!(known.last().unwrap(), "/s.hc");
}
