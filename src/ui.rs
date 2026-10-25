//! The terminal.

use std::io::{BufRead, Write};

use anyhow::{Context, Result};
use zeroize::Zeroizing;

pub trait Ui {
    fn say(&mut self, text: &str);
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
