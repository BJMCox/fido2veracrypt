//! The container passphrase, which is also the recovery passphrase the owner keeps on paper.

use anyhow::{Result, anyhow, ensure};
use zeroize::Zeroizing;

/// Crockford base32: no I, L, O, or U, so a printout cannot be misread.
pub const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// 52 characters of 5 bits each, 260 bits.
const SYMBOLS: usize = 52;
const GROUP: usize = 4;

/// A container passphrase in its canonical form: 13 groups of 4 characters joined by dashes, 64
/// characters in all, within VeraCrypt's 128-byte limit.
pub struct Passphrase(Zeroizing<String>);

impl Passphrase {
    pub fn generate() -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; SYMBOLS]);
        getrandom::fill(bytes.as_mut()).map_err(|e| anyhow!("The random source failed: {e}"))?;
        Ok(Self::from_symbols(bytes.iter().map(|&b| symbol(b))))
    }

    /// Accepts what a person types from the printout: any case, with or without dashes or
    /// spaces, and I, L, and O for 1, 1, and 0, as Crockford base32 allows.
    pub fn parse(input: &str) -> Result<Self> {
        let symbols = Zeroizing::new(
            input
                .chars()
                .filter(|c| !matches!(c, '-' | ' '))
                .map(|c| match c.to_ascii_uppercase() {
                    'I' | 'L' => Ok(b'1'),
                    'O' => Ok(b'0'),
                    c if c.is_ascii() && ALPHABET.contains(&(c as u8)) => Ok(c as u8),
                    _ => Err(anyhow!(
                        "The recovery passphrase holds a character that is not on the printout"
                    )),
                })
                .collect::<Result<Vec<u8>>>()?,
        );
        ensure!(
            symbols.len() == SYMBOLS,
            "The recovery passphrase has {SYMBOLS} characters besides the dashes, and {} were typed",
            symbols.len()
        );
        Ok(Self::from_symbols(symbols.iter().copied()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// What the owner types back to show the printout was written down.
    pub fn last_group(&self) -> &str {
        &self.0[self.0.len() - GROUP..]
    }

    fn from_symbols(symbols: impl Iterator<Item = u8>) -> Self {
        let mut text = Zeroizing::new(String::with_capacity(SYMBOLS + SYMBOLS / GROUP));
        for (index, symbol) in symbols.enumerate() {
            if index > 0 && index % GROUP == 0 {
                text.push('-');
            }
            text.push(char::from(symbol));
        }
        Self(text)
    }
}

/// 256 is a multiple of 32, so a uniform byte gives a uniform character.
fn symbol(byte: u8) -> u8 {
    ALPHABET[usize::from(byte % 32)]
}

#[cfg(test)]
mod tests;
