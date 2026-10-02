use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

pub const TOKEN_LEN: usize = 16;

/// Keyed hash over search tokens. The on-disk index therefore stores no
/// plaintext terms: an attacker with the database file cannot enumerate the
/// vocabulary of the mailbox without the index subkey.
///
/// The trade-off is that only whole-token equality can be answered from the
/// index; prefix and substring queries fall back to decrypt-and-scan.
#[derive(Clone)]
pub struct BlindIndex {
    key: [u8; 32],
}

impl Drop for BlindIndex {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl std::fmt::Debug for BlindIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BlindIndex(<redacted>)")
    }
}

impl BlindIndex {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn token(&self, field: &str, term: &str) -> [u8; TOKEN_LEN] {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.key)
            .expect("HMAC accepts a key of any length");
        mac.update(field.as_bytes());
        mac.update(b"\x1f");
        mac.update(term.as_bytes());
        let tag = mac.finalize().into_bytes();
        let mut out = [0u8; TOKEN_LEN];
        out.copy_from_slice(&tag[..TOKEN_LEN]);
        out
    }
}

pub fn tokenize(text: &str) -> impl Iterator<Item = String> + '_ {
    text.split(|c: char| !c.is_alphanumeric() && c != '\'' && c != '_')
        .filter(|w| !w.is_empty() && w.len() <= 64)
        .map(|w| w.to_lowercase())
}
