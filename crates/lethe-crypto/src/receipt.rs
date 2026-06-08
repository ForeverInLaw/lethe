//! Tamper-evident run receipts (FR-REP-2). Ed25519 detached signature over a
//! canonical-JSON run summary. Verifiable offline; contains counts only — no
//! tokens, no content, no per-item identifiers (NFR-PRIV-1 / US-5.1 AC2).
//!
//! Signing key = per-install Ed25519 keypair held in the OS keychain; the
//! public key is surfaced in the (M2) trust panel.

use dryoc::classic::crypto_sign::{
    crypto_sign_detached, crypto_sign_keypair, crypto_sign_verify_detached,
};
use serde::{Deserialize, Serialize};

use crate::{from_hex, to_hex, CryptoError, Result};

// ed25519 sizes (classic API uses plain arrays).
const PUBLIC_KEY_LEN: usize = 32;
const SECRET_KEY_LEN: usize = 64;
const SIGNATURE_LEN: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSummary {
    pub run_id: String,
    pub platform: String,
    pub account_label: String,
    pub started_epoch_secs: u64,
    pub finished_epoch_secs: u64,
    pub deleted: u64,
    pub skipped: u64,
    pub failed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedReceipt {
    pub summary: RunSummary,
    pub public_key_hex: String,
    pub signature_hex: String,
}

/// Canonical bytes signed/verified. `RunSummary` is a flat struct of scalars,
/// so serde_json emits fields in declaration order deterministically — no map
/// key reordering to worry about.
fn canonical(summary: &RunSummary) -> Result<Vec<u8>> {
    serde_json::to_vec(summary).map_err(|e| CryptoError::Seal(e.to_string()))
}

pub struct ReceiptSigner {
    public_key: [u8; PUBLIC_KEY_LEN],
    secret_key: [u8; SECRET_KEY_LEN],
}

impl ReceiptSigner {
    /// New per-install keypair.
    pub fn generate() -> Self {
        let (public_key, secret_key) = crypto_sign_keypair();
        Self { public_key, secret_key }
    }

    /// Reconstruct from keychain-stored secret key bytes. An ed25519 secret key
    /// is `seed || public_key`, so the public half is recovered from its tail.
    pub fn from_secret_bytes(secret: &[u8]) -> Result<Self> {
        if secret.len() != SECRET_KEY_LEN {
            return Err(CryptoError::Kdf(format!(
                "secret key must be {SECRET_KEY_LEN} bytes, got {}",
                secret.len()
            )));
        }
        let mut secret_key = [0u8; SECRET_KEY_LEN];
        secret_key.copy_from_slice(secret);
        let mut public_key = [0u8; PUBLIC_KEY_LEN];
        public_key.copy_from_slice(&secret_key[SECRET_KEY_LEN - PUBLIC_KEY_LEN..]);
        Ok(Self { public_key, secret_key })
    }

    /// Raw secret key bytes, for the app to persist in the OS keychain.
    pub fn secret_bytes(&self) -> &[u8] {
        &self.secret_key
    }

    pub fn public_key_hex(&self) -> String {
        to_hex(&self.public_key)
    }

    /// Sign canonical JSON of `summary` (detached Ed25519).
    pub fn sign(&self, summary: &RunSummary) -> Result<SignedReceipt> {
        let bytes = canonical(summary)?;
        let mut sig = [0u8; SIGNATURE_LEN];
        crypto_sign_detached(&mut sig, &bytes, &self.secret_key)
            .map_err(|e| CryptoError::Seal(e.to_string()))?;
        Ok(SignedReceipt {
            summary: summary.clone(),
            public_key_hex: to_hex(&self.public_key),
            signature_hex: to_hex(&sig),
        })
    }
}

/// Offline verification. `Err(BadSignature)` if tampered or malformed.
pub fn verify(receipt: &SignedReceipt) -> Result<()> {
    let pk_bytes = from_hex(&receipt.public_key_hex).ok_or(CryptoError::BadSignature)?;
    let sig_bytes = from_hex(&receipt.signature_hex).ok_or(CryptoError::BadSignature)?;
    let public_key: [u8; PUBLIC_KEY_LEN] =
        pk_bytes.try_into().map_err(|_| CryptoError::BadSignature)?;
    let signature: [u8; SIGNATURE_LEN] =
        sig_bytes.try_into().map_err(|_| CryptoError::BadSignature)?;

    let bytes = canonical(&receipt.summary)?;
    crypto_sign_verify_detached(&signature, &bytes, &public_key)
        .map_err(|_| CryptoError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary() -> RunSummary {
        RunSummary {
            run_id: "run-1".into(),
            platform: "bluesky".into(),
            account_label: "alice".into(),
            started_epoch_secs: 1_000,
            finished_epoch_secs: 1_042,
            deleted: 37,
            skipped: 2,
            failed: 1,
        }
    }

    #[test]
    fn sign_then_verify_ok() {
        let signer = ReceiptSigner::generate();
        let receipt = signer.sign(&summary()).unwrap();
        assert!(verify(&receipt).is_ok());
    }

    #[test]
    fn tampered_summary_fails() {
        let signer = ReceiptSigner::generate();
        let mut receipt = signer.sign(&summary()).unwrap();
        receipt.summary.deleted += 1; // lie about the count
        assert!(matches!(verify(&receipt), Err(CryptoError::BadSignature)));
    }

    #[test]
    fn reconstructed_signer_matches() {
        let signer = ReceiptSigner::generate();
        let restored = ReceiptSigner::from_secret_bytes(signer.secret_bytes()).unwrap();
        assert_eq!(signer.public_key_hex(), restored.public_key_hex());
        // A receipt signed by the restored signer still verifies.
        assert!(verify(&restored.sign(&summary()).unwrap()).is_ok());
    }
}
