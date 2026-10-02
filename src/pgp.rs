use std::path::{Path, PathBuf};

use pgp::composed::{
    ArmorOptions, DetachedSignature, Deserializable, Message, MessageBuilder, SignedPublicKey,
    SignedSecretKey,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::{KeyDetails, Password};
use secrecy::{ExposeSecret, SecretString};

use crate::store::model::CryptoState;

#[derive(Debug, thiserror::Error)]
pub enum PgpError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("OpenPGP error: {0}")]
    Pgp(#[from] pgp::errors::Error),
    #[error("no public key on file for {0}")]
    NoPublicKey(String),
    #[error("no secret key on file for {0}")]
    NoSecretKey(String),
    #[error("this key cannot encrypt; it has no usable encryption subkey")]
    NoEncryptionSubkey,
    #[error("the message is not OpenPGP-encrypted")]
    NotEncrypted,
    #[error("the signature does not match the signed content")]
    BadSignature,
}

type Result<T> = std::result::Result<T, PgpError>;

#[derive(Default)]
pub struct Keyring {
    pub public: Vec<SignedPublicKey>,
    pub secret: Vec<SignedSecretKey>,
}

impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keyring")
            .field("public", &self.public.len())
            .field("secret", &self.secret.len())
            .finish()
    }
}

impl Keyring {
    pub fn load_public(&mut self, path: &Path) -> Result<usize> {
        let data = read(path)?;
        let before = self.public.len();
        for key in SignedPublicKey::from_reader_many(std::io::Cursor::new(data))?.0.flatten() {
            self.public.push(key);
        }
        Ok(self.public.len() - before)
    }

    pub fn load_secret(&mut self, path: &Path) -> Result<usize> {
        let data = read(path)?;
        let before = self.secret.len();
        for key in SignedSecretKey::from_reader_many(std::io::Cursor::new(data))?.0.flatten() {
            self.secret.push(key);
        }
        Ok(self.secret.len() - before)
    }

    pub fn import_public_bytes(&mut self, data: &[u8]) -> Result<usize> {
        let before = self.public.len();
        for key in SignedPublicKey::from_reader_many(std::io::Cursor::new(data.to_vec()))?.0.flatten()
        {
            self.public.push(key);
        }
        Ok(self.public.len() - before)
    }

    pub fn public_for(&self, email: &str) -> Option<&SignedPublicKey> {
        self.public.iter().find(|k| key_matches(user_ids(k), email))
    }

    pub fn secret_for(&self, email: &str) -> Option<&SignedSecretKey> {
        self.secret.iter().find(|k| key_matches(secret_user_ids(k), email))
    }

    pub fn can_encrypt_to(&self, email: &str) -> bool {
        self.public_for(email).is_some()
    }

    pub fn export_public(&self, email: &str) -> Result<String> {
        let key = self
            .public_for(email)
            .ok_or_else(|| PgpError::NoPublicKey(email.to_string()))?;
        Ok(key.to_armored_string(ArmorOptions::default())?)
    }

    pub fn fingerprints(&self) -> Vec<(String, Vec<String>)> {
        self.public
            .iter()
            .map(|k| {
                (
                    format!("{:X}", k.fingerprint()),
                    user_ids(k).into_iter().collect(),
                )
            })
            .collect()
    }
}

fn read(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|source| PgpError::Io { path: path.to_path_buf(), source })
}

fn user_ids(k: &SignedPublicKey) -> Vec<String> {
    k.details
        .users
        .iter()
        .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
        .collect()
}

fn secret_user_ids(k: &SignedSecretKey) -> Vec<String> {
    k.details
        .users
        .iter()
        .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
        .collect()
}

fn key_matches(ids: Vec<String>, email: &str) -> bool {
    let needle = email.to_ascii_lowercase();
    ids.iter().any(|id| {
        let id = id.to_ascii_lowercase();
        id.contains(&format!("<{needle}>")) || id == needle
    })
}

/// Encrypts to every recipient, optionally signing with the sender's key.
/// Encrypting to the sender as well is deliberate: otherwise the copy filed in
/// Sent is unreadable to the person who wrote it.
pub fn encrypt(
    keyring: &Keyring,
    recipients: &[String],
    signer: Option<(&str, &SecretString)>,
    plaintext: &[u8],
) -> Result<String> {
    let keys: Vec<&SignedPublicKey> = recipients
        .iter()
        .map(|r| {
            keyring
                .public_for(r)
                .ok_or_else(|| PgpError::NoPublicKey(r.clone()))
        })
        .collect::<Result<_>>()?;

    let mut builder = MessageBuilder::from_bytes("", plaintext.to_vec())
        .seipd_v1(rand08::thread_rng(), SymmetricKeyAlgorithm::AES256);

    for key in &keys {
        let subkey = encryption_subkey(key).ok_or(PgpError::NoEncryptionSubkey)?;
        builder.encrypt_to_key(rand08::thread_rng(), subkey)?;
    }

    if let Some((email, pw)) = signer {
        let secret = keyring
            .secret_for(email)
            .ok_or_else(|| PgpError::NoSecretKey(email.to_string()))?;
        builder.sign(
            &secret.primary_key,
            Password::from(pw.expose_secret().to_string()),
            HashAlgorithm::Sha256,
        );
    }

    Ok(builder.to_armored_string(rand08::thread_rng(), ArmorOptions::default())?)
}

fn encryption_subkey(key: &SignedPublicKey) -> Option<&pgp::composed::SignedPublicSubKey> {
    key.public_subkeys
        .iter()
        .find(|sk| sk.algorithm().can_encrypt())
}

pub fn sign_detached(
    keyring: &Keyring,
    email: &str,
    password: &SecretString,
    data: &[u8],
) -> Result<String> {
    let key = keyring
        .secret_for(email)
        .ok_or_else(|| PgpError::NoSecretKey(email.to_string()))?;

    let sig = DetachedSignature::sign_binary_data(
        rand08::thread_rng(),
        &key.primary_key,
        &Password::from(password.expose_secret().to_string()),
        HashAlgorithm::Sha256,
        std::io::Cursor::new(data),
    )?;

    Ok(sig.to_armored_string(ArmorOptions::default())?)
}

pub fn verify_detached(keyring: &Keyring, armored_sig: &str, data: &[u8]) -> CryptoState {
    let Ok((sig, _)) = DetachedSignature::from_armor_single(std::io::Cursor::new(armored_sig))
    else {
        return CryptoState::SignedInvalid;
    };

    let mut saw_key = false;
    for key in &keyring.public {
        if sig.verify(key, data).is_ok() {
            return CryptoState::SignedValid;
        }
        saw_key = true;
        for sub in &key.public_subkeys {
            if sig.verify(sub, data).is_ok() {
                return CryptoState::SignedValid;
            }
        }
    }

    if saw_key { CryptoState::SignedInvalid } else { CryptoState::SignedUnknownKey }
}

pub fn decrypt(
    keyring: &Keyring,
    armored: &[u8],
    password: &SecretString,
) -> Result<(Vec<u8>, CryptoState)> {
    let pw = Password::from(password.expose_secret().to_string());

    for key in &keyring.secret {
        let Ok((msg, _)) = Message::from_armor(std::io::Cursor::new(armored)) else {
            continue;
        };
        let Ok(mut decrypted) = msg.decrypt(&pw, key) else {
            continue;
        };
        if decrypted.is_compressed() {
            decrypted = decrypted.decompress()?;
        }
        let signed = decrypted.is_signed();
        let data = decrypted.as_data_vec().map_err(|source| PgpError::Io {
            path: PathBuf::from("<message>"),
            source,
        })?;
        let state = if signed {
            CryptoState::EncryptedAndSigned
        } else {
            CryptoState::Encrypted
        };
        return Ok((data, state));
    }

    Err(PgpError::NotEncrypted)
}

pub const MIME_ENCRYPTED_PREAMBLE: &str = "Version: 1\r\n";

/// Builds the two-part body of an RFC 3156 `multipart/encrypted` message.
pub fn encrypted_parts(armored: &str) -> (Vec<u8>, Vec<u8>) {
    (
        MIME_ENCRYPTED_PREAMBLE.as_bytes().to_vec(),
        armored.as_bytes().to_vec(),
    )
}

/// RFC 3156 §5: the signed part must be canonicalised to CRLF line endings
/// before hashing, and the signature covers the part's headers as well as its
/// body.
pub fn canonicalize_for_signing(part: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(part.len() + 32);
    let mut prev = 0u8;
    for &b in part {
        if b == b'\n' && prev != b'\r' {
            out.push(b'\r');
        }
        out.push(b);
        prev = b;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalises_bare_newlines() {
        assert_eq!(canonicalize_for_signing(b"a\nb"), b"a\r\nb");
        assert_eq!(canonicalize_for_signing(b"a\r\nb"), b"a\r\nb");
    }

    #[test]
    fn matches_user_id_by_bracketed_email() {
        assert!(key_matches(vec!["Ada <ada@example.org>".into()], "ada@example.org"));
        assert!(!key_matches(vec!["Ada <ada@example.org>".into()], "bob@example.org"));
    }
}
