//! Native app callbacks. HID work stays on one thread for hidapi's run-loop lifetime.

use std::ffi::{CStr, c_char, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{OnceLock, mpsc};

use anyhow::{Context, Result, ensure};
use fido2kit::fido::{self, Enrollment, FidoError, Key, Unlock};
use zeroize::Zeroizing;

use crate::cli::{self, Command};
use crate::commands::{self, Tools};
use crate::keys::Keys;
use crate::slots::APP;
use crate::ui::{Step, Ui};
use crate::veracrypt::{Real, VeraCrypt};

const INFO: u32 = 1;
const PIN: u32 = 2;
const CONFIRM: u32 = 3;
const RECOVERY: u32 = 4;
const TOUCH: u32 = 5;
const WORKING: u32 = 6;
const VOLUME: u32 = 7;
const ERROR: u32 = 8;
const CHECK: u32 = 9;
const WARNING: u32 = 10;
const KEY_LABEL: u32 = 11;
const CONNECT: u32 = 12;
const READY: u32 = 13;
const STEP: u32 = 14;
const RESPONSE_CAPACITY: usize = 4096;

type Callback = unsafe extern "C" fn(
    *mut c_void,
    u32,
    *const u8,
    usize,
    *const u8,
    usize,
    *mut u8,
    usize,
) -> isize;

#[derive(Clone, Copy)]
struct Host {
    callback: Callback,
    context: *mut c_void,
}

// The caller promises a thread-safe callback and retains its context until fvc_run returns.
unsafe impl Send for Host {}

#[derive(Debug)]
struct Cancelled;

impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Cancelled")
    }
}
impl std::error::Error for Cancelled {}

impl Host {
    fn call(&self, kind: u32, text: &str, detail: &str, response: &mut [u8]) -> Result<usize> {
        // The spans live for this synchronous callback. No allocation crosses the ABI.
        let count = unsafe {
            (self.callback)(
                self.context,
                kind,
                text.as_ptr(),
                text.len(),
                detail.as_ptr(),
                detail.len(),
                response.as_mut_ptr(),
                response.len(),
            )
        };
        if count < 0 {
            return Err(Cancelled.into());
        }
        let count = count as usize;
        ensure!(
            count <= response.len(),
            "The app returned an oversized answer"
        );
        Ok(count)
    }

    fn emit(&self, kind: u32, text: &str, detail: &str) -> Result<()> {
        self.call(kind, text, detail, &mut []).map(|_| ())
    }

    fn answer(&self, kind: u32, prompt: &str) -> Result<Zeroizing<String>> {
        let mut response = Zeroizing::new(vec![0u8; RESPONSE_CAPACITY]);
        let count = self.call(kind, prompt, "", &mut response)?;
        let text =
            std::str::from_utf8(&response[..count]).context("The app returned invalid text")?;
        Ok(Zeroizing::new(text.to_owned()))
    }

    fn working(&self, text: &str) -> Result<()> {
        // The host checks Cancel and enters non-cancellable work in one serialized step.
        self.emit(WORKING, text, "")
    }

    fn step(&self, step: Step) -> Result<()> {
        let name = match step {
            Step::Authenticate => "authenticate",
            Step::Connect => "connect",
            Step::Enroll => "enroll",
            Step::Recovery => "recovery",
            Step::Write => "write",
        };
        self.emit(STEP, name, "")
    }
}

struct AppUi {
    host: Host,
}

impl Ui for AppUi {
    fn step(&mut self, step: Step) -> Result<()> {
        self.host.step(step)
    }
    fn key_label(&mut self, label: &str) -> Result<()> {
        self.host.emit(KEY_LABEL, label, "")
    }
    fn connect_key(&mut self, prompt: &str) -> Result<()> {
        self.host.answer(CONNECT, prompt).map(|_| ())
    }
    fn begin_work(&mut self, message: &str) -> Result<()> {
        self.host.working(message)
    }
    fn end_work(&mut self) -> Result<()> {
        self.host.emit(READY, "", "")
    }
    fn say(&mut self, text: &str) {
        let _ = self.host.emit(INFO, text, "");
    }
    fn warn(&mut self, text: &str) {
        let _ = self.host.emit(WARNING, text, "");
    }
    fn show_secret(&mut self, text: &str) -> Result<()> {
        self.host.emit(RECOVERY, text, "")
    }
    fn secret(&mut self, prompt: &str) -> Result<Zeroizing<String>> {
        self.host.answer(PIN, prompt)
    }
    fn ask(&mut self, prompt: &str) -> Result<String> {
        let answer = self.host.answer(CONFIRM, prompt)?;
        Ok(answer.to_string())
    }
}

struct AppKeys {
    host: Host,
    adding: bool,
}

impl AppKeys {
    fn choose(&self, prompt: &str) -> Result<Key> {
        self.host.emit(CHECK, "", "")?;
        let devices = fido::devices();
        if devices.len() > 1 {
            self.host
                .emit(TOUCH, prompt, "Several keys are connected.")?;
        }
        let key = fido::select(devices)?;
        self.host.emit(CHECK, "", "")?;
        Ok(key)
    }

    fn with_pin<T>(
        &self,
        prompt: &str,
        touch: &str,
        mut attempt: impl FnMut(&str) -> Result<T, FidoError>,
    ) -> Result<T> {
        loop {
            let pin = self.host.answer(PIN, prompt)?;
            ensure!(!pin.is_empty(), "Enter the key's PIN.");
            self.host.emit(TOUCH, touch, "Keep the key connected.")?;
            let result = attempt(&pin);
            self.host.emit(CHECK, "", "")?;
            match result {
                Ok(value) => return Ok(value),
                Err(error) => {
                    let error = anyhow::Error::new(error);
                    if !fido::retry_pin(&error) {
                        return Err(error);
                    }
                    self.host.emit(INFO, &error.to_string(), "")?;
                }
            }
        }
    }
}

impl Keys for AppKeys {
    fn unlock(&mut self, salt: &[u8; 32], ids: &[&[u8]]) -> Result<Unlock> {
        let touch = if self.adding {
            "Touch a key that already opens this container."
        } else {
            "Touch your security key."
        };
        let key = self.choose(touch)?;
        let prompt = if self.adding {
            "Enter the PIN of an existing key."
        } else {
            "Enter your security key's PIN."
        };
        self.with_pin(prompt, touch, |pin| fido::derive(APP, &key, pin, salt, ids))
    }
    fn unlock_key(&mut self, label: &str, salt: &[u8; 32], id: &[u8]) -> Result<Unlock> {
        let label = crate::ui::field(label);
        let touch = format!("Touch “{label}”.");
        let key = self.choose(&touch)?;
        self.with_pin(&format!("Enter the PIN for “{label}”."), &touch, |pin| {
            fido::derive(APP, &key, pin, salt, &[id])
        })
    }
    fn enroll(&mut self, salt: &[u8; 32], exclude: &[&[u8]]) -> Result<Enrollment> {
        let key = self.choose(if self.adding {
            "Touch the new key."
        } else {
            "Touch the key you want to use."
        })?;
        self.with_pin(
            if self.adding {
                "Enter the new key's PIN."
            } else {
                "Enter your security key's PIN."
            },
            if self.adding {
                "Touch the new key, then touch it again when it blinks."
            } else {
                "Touch your key, then touch it again when it blinks."
            },
            |pin| fido::enroll(APP, &key, pin, salt, exclude),
        )
    }
}

fn run(args: Vec<String>, host: Host) -> Result<()> {
    host.emit(CHECK, "", "")?;
    let vc = Real::configured()?;
    if args == ["volumes"] {
        for volume in vc.list()? {
            host.emit(
                VOLUME,
                &volume.container.to_string_lossy(),
                &volume
                    .mount_point
                    .as_ref()
                    .map(|p| p.to_string_lossy())
                    .unwrap_or_default(),
            )?;
        }
        return Ok(());
    }
    let command = cli::parse(&args)?;
    ensure!(
        matches!(
            &command,
            Command::Create { .. }
                | Command::Open { .. }
                | Command::ListKeys { .. }
                | Command::AddKey {
                    recovery: false,
                    ..
                }
                | Command::RemoveKey { .. }
                | Command::Rotate { .. }
                | Command::Close {
                    container: Some(_),
                    force: false
                }
        ),
        "This command is not available in the app"
    );
    if matches!(&command, Command::Close { .. }) {
        host.working("Closing container…")?;
    }
    let adding = matches!(&command, Command::AddKey { .. });
    commands::run(
        command,
        &mut Tools {
            vc: &vc,
            keys: &mut AppKeys { host, adding },
            ui: &mut AppUi { host },
        },
    )
}

struct Job {
    args: Vec<String>,
    host: Host,
    done: mpsc::Sender<i32>,
}

fn worker() -> &'static mpsc::Sender<Job> {
    static WORKER: OnceLock<mpsc::Sender<Job>> = OnceLock::new();
    WORKER.get_or_init(|| {
        let (sender, jobs) = mpsc::channel::<Job>();
        std::thread::Builder::new().name("fido2vc-key".into()).spawn(move || {
            for job in jobs {
                let result = catch_unwind(AssertUnwindSafe(|| run(job.args, job.host)))
                    .unwrap_or_else(|_| Err(anyhow::anyhow!("An internal error stopped the operation. Check the container's status.")));
                let code = match result {
                    Ok(()) => 0,
                    Err(error) if error.is::<Cancelled>() => 2,
                    Err(error) => { let _ = job.host.emit(ERROR, &format!("{error:#}"), ""); 1 }
                };
                let _ = job.done.send(code);
            }
        }).expect("start security-key worker");
        sender
    })
}

/// Runs an app operation: 0 success, 1 error, 2 cancellation.
///
/// # Safety
/// `argv` contains `argc` valid NUL-terminated UTF-8 strings for this call's duration.
/// `callback` and `context` stay live until this returns. The callback runs on the dedicated
/// worker, must not unwind, and must obey the buffer contract in Fido2VC.h.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fvc_run(
    argc: usize,
    argv: *const *const c_char,
    callback: Callback,
    context: *mut c_void,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // A vault can hold 255 keys, and Remove takes one --label pair per removed key.
        if argv.is_null() || argc == 0 || argc > 512 {
            return 1;
        }
        // The caller supplies the pointer and string lifetimes documented above.
        let pointers = unsafe { std::slice::from_raw_parts(argv, argc) };
        let mut args = Vec::with_capacity(argc);
        for &pointer in pointers {
            if pointer.is_null() {
                return 1;
            }
            let Ok(text) = (unsafe { CStr::from_ptr(pointer) }).to_str() else {
                return 1;
            };
            args.push(text.to_owned());
        }
        let (done, result) = mpsc::channel();
        if worker()
            .send(Job {
                args,
                host: Host { callback, context },
                done,
            })
            .is_err()
        {
            return 1;
        }
        result.recv().unwrap_or(1)
    }))
    .unwrap_or(1)
}

#[cfg(test)]
mod tests;
