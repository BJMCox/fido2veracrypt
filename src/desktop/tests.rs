use super::*;
use std::ptr;

#[derive(Default)]
struct Replies {
    events: Vec<u32>,
    answer: String,
    cancel_at: Option<u32>,
}

unsafe extern "C" fn reply(
    context: *mut c_void,
    kind: u32,
    _: *const u8,
    _: usize,
    _: *const u8,
    _: usize,
    response: *mut u8,
    capacity: usize,
) -> isize {
    let replies = unsafe { &mut *context.cast::<Replies>() };
    replies.events.push(kind);
    if replies.cancel_at == Some(kind) {
        return -1;
    }
    if capacity == 0 {
        return 0;
    }
    let bytes = replies.answer.as_bytes();
    assert!(bytes.len() <= capacity);
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), response, bytes.len());
    }
    bytes.len() as isize
}

fn host(replies: &mut Replies) -> Host {
    Host {
        callback: reply,
        context: ptr::from_mut(replies).cast(),
    }
}

#[test]
fn recovery_answer_leaves_validation_and_the_write_barrier_to_the_command() {
    let mut replies = Replies {
        answer: "ABCD".into(),
        ..Replies::default()
    };
    let mut ui = AppUi {
        host: host(&mut replies),
        closed: None,
    };
    assert_eq!(ui.ask("Last group").unwrap(), "ABCD");
    assert_eq!(replies.events, [CONFIRM]);
}

#[test]
fn cancelling_a_key_connection_stops_before_device_access() {
    let mut replies = Replies {
        cancel_at: Some(CONNECT),
        ..Replies::default()
    };
    let mut keys = AppKeys {
        host: host(&mut replies),
        adding: true,
    };
    assert!(keys.enroll(&[0; 32], &[]).err().unwrap().is::<Cancelled>());
    assert!(
        keys.unlock_key("Backup", &[0; 32], &[1])
            .err()
            .unwrap()
            .is::<Cancelled>()
    );
    assert_eq!(replies.events, [STEP, CONNECT, STEP, CONNECT]);
}

#[test]
fn success_messages_do_not_replace_the_warning_event() {
    let mut replies = Replies::default();
    let mut ui = AppUi {
        host: host(&mut replies),
        closed: None,
    };
    ui.warn("The new container is still open.");
    ui.say("Created container.");
    assert_eq!(replies.events, [WARNING, INFO]);
}

#[test]
fn a_late_hid_answer_is_discarded_after_cancel() {
    let mut replies = Replies {
        answer: "public-test-pin".into(),
        cancel_at: Some(CHECK),
        ..Replies::default()
    };
    let mut calls = 0;
    let result = AppKeys {
        host: host(&mut replies),
        adding: false,
    }
    .with_pin("PIN", "Touch", |_| {
        calls += 1;
        Ok(Zeroizing::new([7u8; 32]))
    });
    assert!(result.unwrap_err().is::<Cancelled>());
    assert_eq!(calls, 1);
    assert_eq!(replies.events, [PIN, TOUCH, CHECK]);
}

#[test]
fn key_changes_recheck_attachments_after_prompts_including_hard_links() {
    let dir = tempfile::tempdir().unwrap();
    let container = dir.path().join("container.hc");
    let alias = dir.path().join("alias.hc");
    let snapshot = dir.path().join("snapshot");
    let binary = dir.path().join("veracrypt");
    std::fs::write(&container, b"public fixture").unwrap();
    std::fs::hard_link(&container, &alias).unwrap();
    std::fs::write(&snapshot, "Error: No volumes mounted.\n").unwrap();
    crate::test_support::write_script(
        &binary,
        r#"#!/bin/sh
case "$*" in
  '--text --version') printf 'VeraCrypt 1.26.30\n' ;;
  '--text --non-interactive --list --verbose'|'--text --non-interactive --list --verbose --slot 1') cat "$(dirname "$0")/snapshot" ;;
  *) exit 2 ;;
esac
"#,
    );
    let vc = Real::find(Some(binary)).unwrap();
    let mut replies = Replies::default();
    let mut ui = AppUi {
        host: host(&mut replies),
        closed: Some((&vc, &container)),
    };
    ui.begin_work("Change keys").unwrap();
    ui.end_work().unwrap();
    std::fs::write(&snapshot, format!(
        "Slot: 1\nVolume: {}\nVirtual Device: /dev/disk9\nMount Directory: /Volumes/Example\nSize: 64 MiB\nType: Normal\nRead-Only: No\nHidden Volume Protected: No\nEncryption Algorithm: AES\nPrimary Key Size: 256 bits\nSecondary Key Size (XTS Mode): 256 bits\nBlock Size: 128 bits\nMode of Operation: XTS\nKDF: Argon2\nVolume Format Version: 2\nEmbedded Backup Header: Yes\nData Read since Mount: 0 B\nData Written since Mount: 0 B\n\n",
        alias.display()
    )).unwrap();
    assert!(ui.begin_work("Change keys").is_err());
    assert_eq!(replies.events, [WORKING, READY]);
    std::fs::remove_file(&alias).unwrap();
    assert!(ui.begin_work("Change keys").is_err());
    std::fs::write(&alias, b"different container").unwrap();
    ui.begin_work("Change keys").unwrap();
    assert_eq!(replies.events, [WORKING, READY, WORKING]);
}
