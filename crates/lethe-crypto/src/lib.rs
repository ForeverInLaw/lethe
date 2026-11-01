//! Archive encryption + signed receipts.
//!
//! Container layout (FR-BAK-2, open & documented): a header (magic + version +
//! secretstream init header) followed by encrypted chunks. What the chunks hold is
//! documented in `lethe_core::archive`.
//!
//! Keys (envelope): a random data-key encrypts the stream; the data-key is
//! wrapped by Argon2id(passphrase) for portability AND by the OS keychain for
//! convenience (wrapping is done at the app layer; this crate handles the
//! passphrase path + the stream).

pub mod container;
pub mod receipt;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("key derivation failed: {0}")]
    Kdf(String),
    #[error("encryption failed: {0}")]
    Seal(String),
    #[error("decryption/authentication failed")]
    Open,
    #[error("signature verification failed")]
    BadSignature,
    #[error("io: {0}")]
    Io(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;

/// 32-byte symmetric data-key (the secretstream key).
pub type DataKey = [u8; 32];

/// A fresh random data-key from the OS CSPRNG. The app wraps it (Argon2
/// passphrase for portable legal handoff and/or the OS keychain for
/// convenience); the engine only ever handles the raw key.
pub fn random_data_key() -> DataKey {
    let mut key: DataKey = [0u8; 32];
    dryoc::rng::copy_randombytes(&mut key);
    key
}

/// Lowercase hex. Used for the receipt's public-key / signature fields so a
/// receipt is a plain, diffable JSON document.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

pub(crate) fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}
