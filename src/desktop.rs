//! Native app callbacks. HID work stays on one thread for hidapi's run-loop lifetime.

use std::ffi::{CStr, c_char, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{OnceLock, mpsc};

use anyhow::{Context, Result, bail, ensure};
use fido2kit::fido::{self, Enrollment, FidoError, Key, Unlock};
use zeroize::Zeroizing;

use crate::cli::{self, Command};
use crate::commands::{self, Tools};
use crate::keys::Keys;
use crate::slots::APP;
use crate::ui::Ui;
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
}

struct AppUi(Host);

impl Ui for AppUi {
    fn say(&mut self, text: &str) {
        let _ = self.0.emit(INFO, text, "");
    }
    fn warn(&mut self, text: &str) {
        let _ = self.0.emit(WARNING, text, "");
    }
    fn show_secret(&mut self, text: &str) -> Result<()> {
        self.0.emit(RECOVERY, text, "")
    }
    fn secret(&mut self, prompt: &str) -> Result<Zeroizing<String>> {
        self.0.answer(PIN, prompt)
    }
    fn ask(&mut self, prompt: &str) -> Result<String> {
        let answer = self.0.answer(CONFIRM, prompt)?;
        // Create's recovery check is the only visible question in this scoped bridge.
        // It writes its slot before calling VeraCrypt, so start the barrier before returning.
        self.0.working("Creating container…")?;
        Ok(answer.to_string())
    }
}

struct AppKeys(Host);

impl AppKeys {
    fn choose(&self) -> Result<Key> {
        self.0.emit(CHECK, "", "")?;
        let devices = fido::devices();
        if devices.len() > 1 {
            self.0.emit(
                TOUCH,
                "Touch the key you want to use.",
                "Several keys are connected.",
            )?;
        }
        let key = fido::select(devices)?;
        self.0.emit(CHECK, "", "")?;
        Ok(key)
    }

    fn with_pin<T>(
        &self,
        touch: &str,
        mut attempt: impl FnMut(&str) -> Result<T, FidoError>,
    ) -> Result<T> {
        loop {
            let pin = self.0.answer(PIN, "Enter your security key's PIN.")?;
            ensure!(!pin.is_empty(), "Enter the key's PIN.");
            self.0.emit(TOUCH, touch, "Keep the key connected.")?;
            let result = attempt(&pin);
            self.0.emit(CHECK, "", "")?;
            match result {
                Ok(value) => return Ok(value),
                Err(error) => {
                    let error = anyhow::Error::new(error);
                    if !fido::retry_pin(&error) {
                        return Err(error);
                    }
                    self.0.emit(INFO, &error.to_string(), "")?;
                }
            }
        }
    }
}

impl Keys for AppKeys {
    fn unlock(&mut self, salt: &[u8; 32], ids: &[&[u8]]) -> Result<Unlock> {
        let key = self.choose()?;
        let unlock = self.with_pin("Touch your security key.", |pin| {
            fido::derive(APP, &key, pin, salt, ids)
        })?;
        // Unlock may repair a pending passphrase change before mount. Cover that whole path.
        self.0.working("Opening container…")?;
        Ok(unlock)
    }
    fn unlock_key(&mut self, _: &str, _: &[u8; 32], _: &[u8]) -> Result<Unlock> {
        bail!("This version of the app does not remove keys")
    }
    fn enroll(&mut self, salt: &[u8; 32], exclude: &[&[u8]]) -> Result<Enrollment> {
        let key = self.choose()?;
        self.with_pin(
            "Touch your key, then touch it again when it blinks.",
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
                | Command::Close {
                    container: Some(_),
                    force: false
                }
        ),
        "The app supports creating, opening, and closing containers"
    );
    if matches!(&command, Command::Close { .. }) {
        host.working("Closing container…")?;
    }
    commands::run(
        command,
        &mut Tools {
            vc: &vc,
            keys: &mut AppKeys(host),
            ui: &mut AppUi(host),
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
        if argv.is_null() || argc == 0 || argc > 16 {
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
