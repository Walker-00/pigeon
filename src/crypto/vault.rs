use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::aead::{Cipher, CryptoError, random_bytes};

const MAGIC: &[u8; 8] = b"PIGEONv1";
const KDF_ARGON2ID: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const WRAPPED_LEN: usize = 32 + 16;

/// Argon2id parameters. 256 MiB / 3 passes is deliberately expensive: the vault
/// is unlocked once per session, so the cost is paid once but must be paid by an
/// offline attacker for every guess.
const M_COST: u32 = 262_144;
const T_COST: u32 = 3;
const P_COST: u32 = 4;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("vault file {0} is not a pigeon vault")]
    BadMagic(PathBuf),
    #[error("vault file {0} is truncated or corrupt")]
    Corrupt(PathBuf),
    #[error("unsupported key-derivation function id {0}")]
    UnknownKdf(u8),
    #[error("incorrect passphrase")]
    WrongPassphrase,
    #[error("key derivation failed: {0}")]
    Kdf(String),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; 32]);

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}

impl MasterKey {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut k = [0u8; 32];
        random_bytes(&mut k)?;
        Ok(Self(k))
    }

    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    /// Every subsystem gets its own key so that compromise of one (say, the
    /// blind-index key handed to a search process) does not yield the others.
    pub fn subkey(&self, label: &str) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut out = [0u8; 32];
        hk.expand(label.as_bytes(), &mut out)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        out
    }

    pub fn cipher_for(&self, label: &str) -> Cipher {
        let mut sk = self.subkey(label);
        let c = Cipher::new(&sk);
        sk.zeroize();
        c
    }
}

#[derive(Debug, Clone)]
pub struct VaultHeader {
    pub kdf: u8,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub wrapped: [u8; WRAPPED_LEN],
}

impl VaultHeader {
    fn aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(8 + 1 + 12 + SALT_LEN);
        aad.extend_from_slice(MAGIC);
        aad.push(self.kdf);
        aad.extend_from_slice(&self.m_cost.to_le_bytes());
        aad.extend_from_slice(&self.t_cost.to_le_bytes());
        aad.extend_from_slice(&self.p_cost.to_le_bytes());
        aad.extend_from_slice(&self.salt);
        aad
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = self.aad();
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.wrapped);
        out
    }

    fn decode(path: &Path, raw: &[u8]) -> Result<Self, VaultError> {
        const HEAD: usize = 8 + 1 + 12 + SALT_LEN;
        if raw.len() < HEAD + NONCE_LEN + WRAPPED_LEN {
            return Err(VaultError::Corrupt(path.to_path_buf()));
        }
        if &raw[..8] != MAGIC {
            return Err(VaultError::BadMagic(path.to_path_buf()));
        }
        let kdf = raw[8];
        if kdf != KDF_ARGON2ID {
            return Err(VaultError::UnknownKdf(kdf));
        }
        let u32_at = |o: usize| u32::from_le_bytes(raw[o..o + 4].try_into().unwrap());
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&raw[21..21 + SALT_LEN]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&raw[HEAD..HEAD + NONCE_LEN]);
        let mut wrapped = [0u8; WRAPPED_LEN];
        wrapped.copy_from_slice(&raw[HEAD + NONCE_LEN..HEAD + NONCE_LEN + WRAPPED_LEN]);

        Ok(Self {
            kdf,
            m_cost: u32_at(9),
            t_cost: u32_at(13),
            p_cost: u32_at(17),
            salt,
            nonce,
            wrapped,
        })
    }

    fn derive_kek(&self, passphrase: &[u8]) -> Result<[u8; 32], VaultError> {
        let params = Params::new(self.m_cost, self.t_cost, self.p_cost, Some(32))
            .map_err(|e| VaultError::Kdf(e.to_string()))?;
        let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut kek = [0u8; 32];
        a2.hash_password_into(passphrase, &self.salt, &mut kek)
            .map_err(|e| VaultError::Kdf(e.to_string()))?;
        Ok(kek)
    }
}

pub struct Vault {
    pub path: PathBuf,
    pub header: VaultHeader,
    key: MasterKey,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault").field("path", &self.path).finish_non_exhaustive()
    }
}

impl Vault {
    pub fn exists(path: &Path) -> bool {
        path.is_file()
    }

    pub fn create(path: &Path, passphrase: &[u8]) -> Result<Self, VaultError> {
        let mut salt = [0u8; SALT_LEN];
        random_bytes(&mut salt)?;
        let mut nonce = [0u8; NONCE_LEN];
        random_bytes(&mut nonce)?;

        let mut header = VaultHeader {
            kdf: KDF_ARGON2ID,
            m_cost: M_COST,
            t_cost: T_COST,
            p_cost: P_COST,
            salt,
            nonce,
            wrapped: [0u8; WRAPPED_LEN],
        };

        let key = MasterKey::generate()?;
        let mut kek = header.derive_kek(passphrase)?;
        let sealed = Cipher::new(&kek).seal_with_nonce(&nonce, &header.aad(), key.expose())?;
        kek.zeroize();

        if sealed.len() != WRAPPED_LEN {
            return Err(VaultError::Corrupt(path.to_path_buf()));
        }
        header.wrapped.copy_from_slice(&sealed);

        write_private(path, &header.encode())?;
        Ok(Self { path: path.to_path_buf(), header, key })
    }

    pub fn unlock(path: &Path, passphrase: &[u8]) -> Result<Self, VaultError> {
        let raw = std::fs::read(path).map_err(|source| VaultError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let header = VaultHeader::decode(path, &raw)?;
        let mut kek = header.derive_kek(passphrase)?;
        let opened = Cipher::new(&kek).open_with_nonce(&header.nonce, &header.aad(), &header.wrapped);
        kek.zeroize();

        let mut bytes = opened.map_err(|_| VaultError::WrongPassphrase)?;
        let mut k = [0u8; 32];
        k.copy_from_slice(&bytes);
        bytes.zeroize();

        Ok(Self {
            path: path.to_path_buf(),
            header,
            key: MasterKey::from_bytes(k),
        })
    }

    pub fn change_passphrase(&mut self, new_passphrase: &[u8]) -> Result<(), VaultError> {
        let mut salt = [0u8; SALT_LEN];
        random_bytes(&mut salt)?;
        let mut nonce = [0u8; NONCE_LEN];
        random_bytes(&mut nonce)?;
        self.header.salt = salt;
        self.header.nonce = nonce;

        let mut kek = self.header.derive_kek(new_passphrase)?;
        let sealed =
            Cipher::new(&kek).seal_with_nonce(&nonce, &self.header.aad(), self.key.expose())?;
        kek.zeroize();
        self.header.wrapped.copy_from_slice(&sealed);
        write_private(&self.path, &self.header.encode())
    }

    pub fn key(&self) -> &MasterKey {
        &self.key
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let io = |source: std::io::Error| VaultError::Io { path: path.to_path_buf(), source };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(io)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes).map_err(io)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).map_err(io)?;
    }

    std::fs::rename(&tmp, path).map_err(io)?;
    Ok(())
}
