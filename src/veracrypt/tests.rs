use super::*;
use std::os::unix::fs::PermissionsExt;

const PROPERTIES: &str = "\
Size: 63.8 MiB
Type: Normal
Read-Only: No
Hidden Volume Protected: No
Encryption Algorithm: AES
Primary Key Size: 256 bits
Secondary Key Size (XTS Mode): 256 bits
Block Size: 128 bits
Mode of Operation: XTS
KDF: Argon2
Volume Format Version: 2
Embedded Backup Header: Yes
Data Read since Mount: 0 B
Data Written since Mount: 0 B

";

fn list(container: &str, mount: &str) -> String {
    format!(
        "Slot: 1\nVolume: {container}\nVirtual Device: /dev/disk4\nMount Directory: {mount}\n{PROPERTIES}"
    )
}

fn fake_list(dir: &Path, snapshot: &str, slots: &[(u32, &str)]) -> Real {
    std::fs::write(dir.join("snapshot"), snapshot).unwrap();
    std::fs::write(dir.join("queries"), "").unwrap();
    for (slot, record) in slots {
        std::fs::write(dir.join(format!("slot-{slot}")), record).unwrap();
    }
    let body = r#"fixture=$(dirname "$0")
case "$*" in
    '--text --version') printf 'VeraCrypt 1.26.30\n' ;;
    '--text --non-interactive --list --verbose') cat "$fixture/snapshot" ;;
    '--text --non-interactive --list --verbose --slot '*)
        [ "$#" -eq 6 ] || exit 2
        printf '%s\n' "$6" >> "$fixture/queries"
        cat "$fixture/slot-$6"
        ;;
    *) exit 2 ;;
esac
"#;
    Real::find(Some(fake(dir, &[], body))).unwrap()
}

#[test]
fn the_verbose_list_keeps_paths_with_spaces_and_marks_half_closed_volumes() {
    let text = list("/Volumes/stick/my secure.hc", "/Volumes/My Drive")
        + &list("/tmp/other.hc", "")
            .replace("Slot: 1", "Slot: 2")
            .replace("Virtual Device: /dev/disk4", "Virtual Device: ");
    let volumes = checked_list(&text).unwrap();
    assert_eq!(volumes.len(), 2);
    assert_eq!(
        volumes[0].volume.container,
        Path::new("/Volumes/stick/my secure.hc")
    );
    assert_eq!(
        volumes[0].volume.mount_point.as_deref(),
        Some(Path::new("/Volumes/My Drive"))
    );
    assert_eq!(volumes[1].volume.mount_point, None);
    assert_eq!(volumes[1].volume.device, None);
    assert!(parse_list("Error: No volumes mounted.\n").is_empty());
}

#[test]
fn only_a_complete_snapshot_can_establish_closed_volumes() {
    let text = list("/tmp/Example.hc", "/Volumes/Example");
    assert_eq!(
        checked_list(&text)
            .unwrap()
            .into_iter()
            .map(|record| record.volume)
            .collect::<Vec<_>>(),
        parse_list(&text)
    );
    assert!(
        checked_list("Error: No volumes mounted.\n")
            .unwrap()
            .is_empty()
    );
    for unknown in [
        "",
        "Unexpected output",
        "Slot: 1\nMount Directory: /Volumes/Test\n",
        "Slot: 1\nVolume: /test.hc\n",
        "Slot: 1\nVolume: /test.hc\nMount Directory: -\nSlot: 2\n",
    ] {
        assert!(checked_list(unknown).is_err());
    }
}

#[test]
fn mounted_paths_keep_trailing_spaces() {
    let volumes = checked_list(&list("/tmp/Example.hc ", "/Volumes/Example ")).unwrap();
    assert_eq!(volumes[0].volume.container, Path::new("/tmp/Example.hc "));
    assert_eq!(
        volumes[0].volume.mount_point.as_deref(),
        Some(Path::new("/Volumes/Example "))
    );
}

#[test]
fn line_breaks_cannot_shorten_an_attached_container_path() {
    let cr = list("/tmp/Example.hc\r", "/Volumes/Example");
    assert_eq!(parse_list(&cr)[0].container, Path::new("/tmp/Example.hc\r"));
    for container in [
        "/tmp/Example.hc\r",
        "/tmp/Example.hc\n",
        "/tmp/Example\nAnnotation: suffix.hc",
        "/tmp/Example\nVirtual Device: /dev/other",
    ] {
        assert!(checked_list(&list(container, "/Volumes/Example")).is_err());
    }
}

#[test]
fn a_snapshot_confirms_each_numeric_slot_without_comparing_io_counters() {
    let dir = tempfile::tempdir().unwrap();
    let first = list("/tmp/First.hc", "/Volumes/First");
    let first_read = first.replace("Data Read since Mount: 0 B", "Data Read since Mount: 512 B");
    let second = list("/tmp/Second.hc", "").replace("Slot: 1", "Slot: 3");
    for (snapshot, slots, queries) in [
        ("Error: No volumes mounted.\n".to_owned(), vec![], ""),
        (first.clone(), vec![(1, first_read.as_str())], "1\n"),
        (
            format!("{first}{second}"),
            vec![(1, first_read.as_str()), (3, second.as_str())],
            "1\n3\n",
        ),
    ] {
        let vc = fake_list(dir.path(), &snapshot, &slots);
        assert_eq!(vc.list().unwrap(), parse_list(&snapshot));
        assert_eq!(
            std::fs::read_to_string(dir.path().join("queries")).unwrap(),
            queries
        );
    }
}

#[test]
fn a_full_record_inside_a_real_path_cannot_forge_a_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    // Slashes in ignored properties keep every actual filename component below NAME_MAX.
    let prefix = list("first.hc", "/Volumes/Injected")
        .replace("Encryption Algorithm: AES", "Encryption Algorithm: /AES")
        .replace("KDF: Argon2", "KDF: /Argon2");
    let container = dir.path().join(format!(
        "{}Slot: 2\nVolume: /second.hc",
        prefix.strip_prefix("Slot: 1\nVolume: ").unwrap()
    ));
    std::fs::create_dir_all(container.parent().unwrap()).unwrap();
    std::fs::write(&container, "public dummy container").unwrap();
    let snapshot = list(container.to_str().unwrap(), "/Volumes/Actual");
    assert_eq!(checked_list(&snapshot).unwrap().len(), 2);
    let vc = fake_list(dir.path(), &snapshot, &[(1, &snapshot)]);
    assert!(vc.list().is_err());
    assert_eq!(
        std::fs::read_to_string(dir.path().join("queries")).unwrap(),
        "1\n"
    );
}

#[test]
fn a_slot_that_changes_during_confirmation_invalidates_the_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let snapshot = list("/tmp/Example.hc", "/Volumes/Example");
    for changed in [
        snapshot.replace("Slot: 1", "Slot: 2"),
        snapshot.replace("/tmp/Example.hc", "/tmp/Other.hc"),
        snapshot.replace("/dev/disk4", "/dev/disk5"),
        snapshot.replace("/Volumes/Example", "/Volumes/Other"),
        "Error: No volumes mounted.\n".to_owned(),
    ] {
        let vc = fake_list(dir.path(), &snapshot, &[(1, &changed)]);
        assert!(vc.list().is_err());
    }
}

#[test]
fn slot_confirmation_shares_the_snapshot_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let snapshot = list("/tmp/Example.hc", "/Volumes/Example");
    let body = format!("sleep 0.2\nprintf '%s' '{snapshot}'\n");
    let vc = Real {
        binary: fake(dir.path(), &[], &body),
        linux: false,
    };
    let started = Instant::now();
    assert!(
        vc.list_snapshot(false, started + Duration::from_millis(300))
            .is_err()
    );
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn an_invalid_utf8_volume_path_cannot_be_replaced_in_a_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let listed = list("/tmp/Example\\377.hc", "/Volumes/Example");
    let body = format!(
        "if [ \"$2\" = '--version' ]; then\n  printf 'VeraCrypt 1.26.30\\n'\nelse\n  printf '{listed}'\nfi\n"
    );
    let vc = Real::find(Some(fake(dir.path(), &[], &body))).unwrap();
    assert!(vc.list().is_err());
}

#[test]
fn a_failed_list_cannot_be_excused_by_words_in_a_container_path() {
    let dir = tempfile::tempdir().unwrap();
    let listed = list("/tmp/No volumes mounted.hc", "/Volumes/Example");
    let body = format!(
        "if [ \"$2\" = '--version' ]; then\n  printf 'VeraCrypt 1.26.30\\n'\nelse\n  printf '%s' '{listed}'\n  exit 1\nfi\n"
    );
    let vc = Real::find(Some(fake(dir.path(), &[], &body))).unwrap();
    assert!(vc.list().is_err());
}

#[test]
fn ordered_properties_accept_kernel_mounts_but_reject_continuations() {
    let text = list("/tmp/Example.hc", "/Volumes/Example");
    let kernel = text
        .replace("/dev/disk4", "/dev/mapper/veracrypt1")
        .replace(
            "Data Read since Mount: 0 B\nData Written since Mount: 0 B\n",
            "",
        );
    assert_eq!(
        checked_list(&kernel).unwrap()[0].volume.device.as_deref(),
        Some("/dev/mapper/veracrypt1")
    );
    let legacy = text
        .replace("Secondary Key Size (XTS Mode): 256 bits\n", "")
        .replace("Mode of Operation: XTS", "Mode of Operation: LRW");
    assert!(checked_list(&legacy).is_ok());
    for malformed in [
        text.replace("Virtual Device:", "Unexpected Field:"),
        text.replace("Virtual Device:", "\nVirtual Device:"),
        text.replace("Type: Normal\n", "Type: Normal\nType: Normal\n"),
        text.replace(
            "Size: 63.8 MiB\nType: Normal",
            "Type: Normal\nSize: 63.8 MiB",
        ),
        text.replace("Data Written since Mount: 0 B\n\n", ""),
    ] {
        assert!(checked_list(&malformed).is_err());
    }
}

#[test]
fn creation_detaches_even_when_the_label_lookup_fails() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("veracrypt");
    std::fs::write(
        &script,
        r#"#!/bin/sh
for arg in "$@"; do
    case "$arg" in
        -u) : > "$(dirname "$0")/closed"; exit 0 ;;
        --list) printf 'unrecognized mount list\n'; exit 0 ;;
    esac
done
exit 0
"#,
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    let vc = Real {
        binary: script,
        linux: false,
    };
    assert!(
        vc.create(
            &dir.path().join("Example.hc"),
            64 * 1024 * 1024,
            "public test passphrase",
            "Example"
        )
        .unwrap()
        .is_some()
    );
    assert!(dir.path().join("closed").is_file());
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
fn a_failed_version_command_cannot_pass_the_version_gate() {
    let dir = tempfile::tempdir().unwrap();
    let binary = fake(dir.path(), &[], "printf 'VeraCrypt 1.26.30\\n'\nexit 1\n");
    assert!(Real::find(Some(binary)).is_err());
}

#[test]
fn a_custom_binary_cannot_silently_switch_to_the_helper_binary() {
    let dir = tempfile::tempdir().unwrap();
    let fixed = dir.path().join("system-veracrypt");
    let custom = dir.path().join("custom-veracrypt");
    let helper = dir.path().join("helper");
    let container = dir.path().join("container.hc");
    for file in [&fixed, &custom, &helper, &crate::slots::path(&container)] {
        std::fs::write(file, "dummy").unwrap();
    }
    let alias = dir.path().join("system-alias");
    std::os::unix::fs::symlink(&fixed, &alias).unwrap();
    let args = mount_args(&container, Some(HASH), true, true);
    for binary in [&fixed, &alias, &custom] {
        let vc = Real {
            binary: binary.clone(),
            linux: true,
        };
        let command =
            vc.root_with_helper("open", &container, &[HASH], args.clone(), (&helper, &fixed));
        let words: Vec<_> = command.get_args().map(|arg| arg.to_owned()).collect();
        if binary == &custom {
            assert_eq!(words[0], custom.as_os_str());
            assert_eq!(
                words[1..],
                args.iter()
                    .map(std::ffi::OsString::from)
                    .collect::<Vec<_>>()
            );
        } else {
            assert_eq!(
                words,
                [
                    helper.as_os_str(),
                    std::ffi::OsStr::new("open"),
                    container.as_os_str(),
                    std::ffi::OsStr::new(HASH)
                ]
            );
        }
    }
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
fn read_only_queries_bound_exit_and_descendant_output_lifetimes() {
    let dir = tempfile::tempdir().unwrap();
    for body in [
        "sleep 2\n",
        "exec 1>&- 2>&-\nsleep 2\n",
        "sleep 2 &\nexit 0\n",
    ] {
        let mut command = Command::new(fake(dir.path(), &[], body));
        let started = Instant::now();
        assert!(run_read_only(&mut command, Duration::from_millis(50)).is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
    }
    // The fixtures' harmless descendant sleepers are finite; leave none after this test.
    thread::sleep(Duration::from_millis(2100));
}

#[test]
fn change_completion_requires_exit_before_the_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let tail = format!("{SUCCESS}exec 1>&- 2>&-\nsleep 2\n");
    let mut command = Command::new(fake(dir.path(), &PROMPTS, &tail));
    let started = Instant::now();
    assert!(drive_change(&mut command, "old", "new", Duration::from_millis(50)).is_err());
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn failed_input_stops_child_work_before_returning() {
    let dir = tempfile::tempdir().unwrap();
    let body =
        "exec 0<&-\nprintf 'Enter password: '\nsleep 0.3\n: > \"$(dirname \"$0\")/late-write\"\n";
    let mut change = Command::new(fake(dir.path(), &[], body));
    assert!(drive_change(&mut change, "old", "new", TIMEOUT).is_err());
    let mut ordinary = Command::new(fake(dir.path(), &[], body));
    // Larger than a pipe buffer so a close before reading cannot be hidden by buffering.
    assert!(run(&mut ordinary, Some(&"public dummy input".repeat(65536))).is_err());
    thread::sleep(Duration::from_millis(500));
    assert!(!dir.path().join("late-write").exists());
}

#[test]
fn normal_capture_preserves_both_output_streams() {
    let dir = tempfile::tempdir().unwrap();
    let mut command = Command::new(fake(dir.path(), &[], "printf 'out'\nprintf 'err' >&2\n"));
    let output = run_read_only(&mut command, TIMEOUT).unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"out");
    assert_eq!(output.stderr, b"err");
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

#[test]
fn a_busy_volume_is_recognized_on_both_systems() {
    let mac = "Error: The volume is in use. Close files and applications using it, then retry unmounting.";
    let linux = "Error: umount: /media/veracrypt1: target is busy.";
    assert_eq!(close_outcome(false, mac).unwrap(), Close::Busy);
    assert_eq!(close_outcome(false, linux).unwrap(), Close::Busy);
    assert_eq!(
        close_outcome(false, "Error: No such volume is mounted.").unwrap(),
        Close::NotOpen
    );
    assert_eq!(close_outcome(true, "").unwrap(), Close::Closed);
    assert!(close_outcome(false, "Error: something else").is_err());
}
