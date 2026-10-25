//! Runs the real VeraCrypt on throwaway containers. Opt-in with FIDO2VERACRYPT_IT=1, because it
//! needs VeraCrypt (and FUSE-T on macOS, or root on Linux) and mounts volumes.

use std::path::Path;

use fido2veracrypt::veracrypt::{Close, HASH, Mount, Real, VeraCrypt};

const FIRST: &str = "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH-JJJJ-KKKK-MMMM-NNNN-PPPP";
const SECOND: &str = "QQQQ-RRRR-SSSS-TTTT-VVVV-WWWW-XXXX-YYYY-ZZZZ-0000-1111-2222-3333";

fn enabled() -> bool {
    std::env::var_os("FIDO2VERACRYPT_IT").is_some_and(|v| v == "1")
}

fn mount_point(vc: &Real, container: &Path) -> Option<std::path::PathBuf> {
    vc.list()
        .unwrap()
        .into_iter()
        .find(|v| v.container == container)
        .and_then(|v| v.mount_point)
}

#[test]
fn real_veracrypt_creates_opens_changes_and_closes_a_container() {
    if !enabled() {
        eprintln!("skipped: set FIDO2VERACRYPT_IT=1 to run");
        return;
    }
    let vc = Real::find(None).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let label = format!("f2vc{}", std::process::id() % 100_000);
    let container = dir
        .path()
        .canonicalize()
        .unwrap()
        .join(format!("{label}.hc"));

    assert!(
        vc.create(&container, 8 << 20, FIRST, &label)
            .unwrap()
            .is_none()
    );
    assert!(vc.opens(&container, FIRST, Some(HASH)).unwrap());
    assert!(!vc.opens(&container, SECOND, Some(HASH)).unwrap());
    assert_eq!(
        vc.mount(&container, SECOND, Some(HASH)).unwrap(),
        Mount::WrongPassphrase
    );

    // The prompts of a real `veracrypt -C` must match the driver.
    vc.change(&container, FIRST, Some(HASH), SECOND).unwrap();
    assert!(!vc.opens(&container, FIRST, Some(HASH)).unwrap());

    assert_eq!(
        vc.mount(&container, SECOND, Some(HASH)).unwrap(),
        Mount::Mounted
    );
    let mounted = mount_point(&vc, &container).expect("a mount point");
    if cfg!(target_os = "macos") {
        assert_eq!(mounted, Path::new("/Volumes").join(&label));
    }
    std::fs::write(mounted.join("note.txt"), b"kept").unwrap();

    let held = std::fs::File::open(mounted.join("note.txt")).unwrap();
    assert_eq!(vc.close(&container, false).unwrap(), Close::Busy);
    assert_eq!(vc.close(&container, true).unwrap(), Close::Closed);
    drop(held);
    assert_eq!(vc.close(&container, false).unwrap(), Close::NotOpen);

    assert_eq!(
        vc.mount(&container, SECOND, Some(HASH)).unwrap(),
        Mount::Mounted
    );
    let mounted = mount_point(&vc, &container).unwrap();
    assert_eq!(std::fs::read(mounted.join("note.txt")).unwrap(), b"kept");
    if cfg!(target_os = "macos") {
        // A Finder eject unmounts the filesystem but leaves the volume unlocked.
        let device = vc
            .list()
            .unwrap()
            .into_iter()
            .find(|v| v.container == container)
            .and_then(|v| v.device)
            .unwrap();
        assert!(
            std::process::Command::new("diskutil")
                .args(["eject", &device])
                .status()
                .unwrap()
                .success()
        );
        let volume = vc
            .list()
            .unwrap()
            .into_iter()
            .find(|v| v.container == container)
            .unwrap();
        assert_eq!(volume.mount_point, None);
    }
    assert_eq!(vc.close(&container, false).unwrap(), Close::Closed);
    assert!(vc.list().unwrap().iter().all(|v| v.container != container));
}

#[test]
fn real_veracrypt_changes_a_sha512_container_to_argon2() {
    if !enabled() {
        eprintln!("skipped: set FIDO2VERACRYPT_IT=1 to run");
        return;
    }
    let vc = Real::find(None).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let container = dir.path().canonicalize().unwrap().join("old.hc");
    // A container as plain VeraCrypt makes it by default, with SHA-512 key derivation.
    let mut create = std::process::Command::new(vc.binary());
    create
        .args(["--text", "--non-interactive", "--stdin", "--create"])
        .arg(&container)
        .args([
            "--size=2097152",
            "--volume-type=normal",
            "--encryption=AES",
            "--hash=SHA-512",
            "--filesystem=none",
            "--pim=0",
            "-k",
            "",
            "--random-source=/dev/urandom",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null());
    let mut child = create.spawn().unwrap();
    use std::io::Write;
    writeln!(child.stdin.take().unwrap(), "{FIRST}").unwrap();
    assert!(child.wait().unwrap().success());

    vc.change(&container, FIRST, None, SECOND).unwrap();
    assert!(vc.opens(&container, SECOND, Some(HASH)).unwrap());
    assert!(!vc.opens(&container, FIRST, None).unwrap());
}
