//! The terminal.

use std::io::{BufRead, Write};

use anyhow::{Context, Result, ensure};
use zeroize::Zeroizing;

use crate::cli::Command;

/// A visible step in a multi-stage operation. This does not change cancellation policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Authenticate,
    Connect,
    Enroll,
    Recovery,
    Write,
}

pub trait Ui {
    fn say(&mut self, text: &str);
    fn step(&mut self, _step: Step) -> Result<()> {
        Ok(())
    }
    /// Wait for the owner to connect the requested key before accessing devices.
    fn connect_key(&mut self, prompt: &str) -> Result<()> {
        self.ask(&format!("{prompt} Press Enter to continue: "))?;
        Ok(())
    }
    /// A key label, separate from its human-readable listing.
    fn key_label(&mut self, _label: &str) -> Result<()> {
        Ok(())
    }
    /// Check cancellation before persistent changes or temporary volume attachments.
    fn begin_work(&mut self, _message: &str) -> Result<()> {
        Ok(())
    }
    /// A completed repair reached a stable state; later prompts may be cancelled again.
    fn end_work(&mut self) -> Result<()> {
        Ok(())
    }
    /// A warning that remains visible after a successful operation.
    fn warn(&mut self, text: &str) {
        self.say(text);
    }
    /// Shows a secret privately, never on stdout, so a redirect cannot save it.
    fn show_secret(&mut self, text: &str) -> Result<()>;
    /// A hidden answer, such as a password.
    fn secret(&mut self, prompt: &str) -> Result<Zeroizing<String>>;
    /// A visible answer.
    fn ask(&mut self, prompt: &str) -> Result<String>;
}

pub struct Terminal {
    steps: &'static [(Step, &'static str)],
}

impl Terminal {
    pub fn new(command: &Command) -> Self {
        use Step::*;
        let steps: &[_] = match command {
            Command::Create { .. } => &[
                (Enroll, "Enroll your key"),
                (Recovery, "Save the recovery phrase"),
                (Write, "Create the container"),
            ],
            Command::Adopt { .. } => &[
                (Authenticate, "Enter the container's current password"),
                (Enroll, "Enroll your key"),
                (Recovery, "Save the new recovery phrase"),
                (Write, "Add key access to the container"),
            ],
            Command::AddKey {
                recovery: false, ..
            } => &[
                (Authenticate, "Use an existing key"),
                (Connect, "Connect the new key"),
                (Enroll, "Enroll the new key"),
                (Write, "Save the new key"),
            ],
            Command::AddKey { recovery: true, .. } => &[
                (Authenticate, "Enter the recovery phrase"),
                (Connect, "Connect the new key"),
                (Enroll, "Enroll the new key"),
                (Write, "Restore key access"),
            ],
            Command::RemoveKey { .. } => &[
                (Authenticate, "Use the keys you're keeping"),
                (Recovery, "Save the new recovery phrase"),
                (Write, "Remove the selected keys"),
            ],
            Command::Rotate { .. } => &[
                (Authenticate, "Use an existing key"),
                (Recovery, "Save the new recovery phrase"),
                (Write, "Change the recovery phrase"),
            ],
            _ => &[],
        };
        Self { steps }
    }
}

/// Escape data fields before interpolating them into messages with trusted line breaks.
pub(crate) fn field(text: &str) -> String {
    escape(text, false)
}

fn escape(text: &str, keep_layout: bool) -> String {
    let mut safe = String::with_capacity(text.len());
    for c in text.chars() {
        if (c.is_control() && !(keep_layout && matches!(c, '\n' | '\t')))
            || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            safe.extend(c.escape_debug());
        } else {
            safe.push(c);
        }
    }
    safe
}

impl Ui for Terminal {
    fn step(&mut self, step: Step) -> Result<()> {
        if let Some(index) = self.steps.iter().position(|(value, _)| *value == step) {
            eprintln!(
                "\n[{}/{}] {}",
                index + 1,
                self.steps.len(),
                self.steps[index].1
            );
        }
        Ok(())
    }

    fn begin_work(&mut self, message: &str) -> Result<()> {
        eprintln!("{}", escape(message, true));
        Ok(())
    }

    fn say(&mut self, text: &str) {
        // Keep application paragraphs, but never send terminal control sequences to the tty.
        println!("{}", escape(text, true));
    }

    fn show_secret(&mut self, text: &str) -> Result<()> {
        std::io::stdout().flush()?;
        let mut tty = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/tty")
            .context("The recovery phrase is shown only on a terminal. Run this from one.")?;
        writeln!(tty, "\n{text}\n")?;
        Ok(())
    }

    fn secret(&mut self, prompt: &str) -> Result<Zeroizing<String>> {
        Ok(Zeroizing::new(
            rpassword::prompt_password(prompt).context("Cannot read from the terminal")?,
        ))
    }

    fn ask(&mut self, prompt: &str) -> Result<String> {
        print!("{prompt}");
        std::io::stdout().flush()?;
        let mut line = String::new();
        ensure!(
            std::io::stdin().lock().read_line(&mut line)? > 0,
            "Input ended before confirmation."
        );
        Ok(line.trim().to_owned())
    }
}
