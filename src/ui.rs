//! The terminal.

use std::io::{BufRead, Write};

use anyhow::{Context, Result};
use zeroize::Zeroizing;

pub trait Ui {
    fn say(&mut self, text: &str);
    /// Shows a secret on the terminal only, never on stdout, so a redirect cannot save it.
    fn show_secret(&mut self, text: &str) -> Result<()>;
    /// A hidden answer, such as a password.
    fn secret(&mut self, prompt: &str) -> Result<Zeroizing<String>>;
    /// A visible answer.
    fn ask(&mut self, prompt: &str) -> Result<String>;
}

pub struct Terminal;

impl Ui for Terminal {
    fn say(&mut self, text: &str) {
        println!("{text}");
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
