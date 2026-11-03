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
    let mut ui = AppUi {
        host: host(&mut replies),
    };
    assert!(
        ui.connect_key("Connect the new key.")
            .unwrap_err()
            .is::<Cancelled>()
    );
    assert_eq!(replies.events, [CONNECT]);
}

#[test]
fn success_messages_do_not_replace_the_warning_event() {
    let mut replies = Replies::default();
    let mut ui = AppUi {
        host: host(&mut replies),
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
