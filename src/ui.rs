//! The terminal.

use std::io::{BufRead, Write};

use anyhow::{Context, Result};
use zeroize::Zeroizing;

pub trait Ui {
    fn say(&mut self, text: &str);
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

pub struct Terminal;

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
    fn say(&mut self, text: &str) {
        // Keep application paragraphs, but never send terminal control sequences to the tty.
        println!("{}", escape(text, true));
    }

    fn show_secret(&mut self, text: &str) -> Result<()> {
        let mut tty = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/tty")
            .context("The recovery passphrase is shown only on a terminal. Run this from one.")?;
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
        std::io::stdin().lock().read_line(&mut line)?;
        Ok(line.trim().to_owned())
    }
}
