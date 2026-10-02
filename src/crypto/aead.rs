use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use rand_core::TryRngCore;
use zeroize::Zeroize;

pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("ciphertext is too short to contain a nonce")]
    Truncated,
    #[error("decryption failed: wrong key, or the record was tampered with")]
    Decrypt,
    #[error("encryption failed")]
    Encrypt,
    #[error("could not read from the operating system RNG: {0}")]
    Rng(String),
}

pub fn random_bytes(out: &mut [u8]) -> Result<(), CryptoError> {
    rand_core::OsRng
        .try_fill_bytes(out)
        .map_err(|e| CryptoError::Rng(e.to_string()))
}

#[derive(Clone)]
pub struct Cipher {
    inner: XChaCha20Poly1305,
}

impl std::fmt::Debug for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Cipher(<redacted>)")
    }
}

impl Cipher {
    pub fn new(key: &[u8; 32]) -> Self {
        Self { inner: XChaCha20Poly1305::new(&Key::from(*key)) }
    }

    /// `aad` binds the ciphertext to its location, so a record cannot be moved
    /// to a different table or key without detection.
    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut nonce = [0u8; NONCE_LEN];
        random_bytes(&mut nonce)?;
        let ct = self
            .inner
            .encrypt(&XNonce::from(nonce), Payload { msg: plaintext, aad })
            .map_err(|_| CryptoError::Encrypt)?;

        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if sealed.len() < NONCE_LEN + TAG_LEN {
            return Err(CryptoError::Truncated);
        }
        let (nonce, ct) = sealed.split_at(NONCE_LEN);
        let mut n = [0u8; NONCE_LEN];
        n.copy_from_slice(nonce);
        self.inner
            .decrypt(&XNonce::from(n), Payload { msg: ct, aad })
            .map_err(|_| CryptoError::Decrypt)
    }

    pub fn seal_with_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.inner
            .encrypt(&XNonce::from(*nonce), Payload { msg: plaintext, aad })
            .map_err(|_| CryptoError::Encrypt)
    }

    pub fn open_with_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.inner
            .decrypt(&XNonce::from(*nonce), Payload { msg: ct, aad })
            .map_err(|_| CryptoError::Decrypt)
    }
}

pub struct Scrubbed<T: Zeroize>(pub T);

impl<T: Zeroize> Drop for Scrubbed<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
