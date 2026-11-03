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
    /// How many of `deleted` other people can still see. Left out when none, so
    /// receipts signed before this field existed keep their exact signed bytes.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub deleted_only_for_self: u64,
    pub skipped: u64,
    pub failed: u64,
    /// Items that only this account would have stopped seeing, left because the
    /// person did not agree to that. Left out when none, like the field below.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub kept_only_for_self: u64,
    /// Items in the set the platform did not let this account delete.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub undeletable: u64,
}

fn is_zero(count: &u64) -> bool {
    *count == 0
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
    let bytes = canonical(&receipt.summary)?;
    verify_detached(&bytes, &receipt.public_key_hex, &receipt.signature_hex)
}

fn verify_detached(message: &[u8], public_key_hex: &str, signature_hex: &str) -> Result<()> {
    let pk_bytes = from_hex(public_key_hex).ok_or(CryptoError::BadSignature)?;
    let sig_bytes = from_hex(signature_hex).ok_or(CryptoError::BadSignature)?;
    let public_key: [u8; PUBLIC_KEY_LEN] =
        pk_bytes.try_into().map_err(|_| CryptoError::BadSignature)?;
    let signature: [u8; SIGNATURE_LEN] =
        sig_bytes.try_into().map_err(|_| CryptoError::BadSignature)?;

    crypto_sign_verify_detached(&signature, message, &public_key)
        .map_err(|_| CryptoError::BadSignature)
}

/// Names the layout of a `ReceiptFile`, so a later layout can be told apart.
const RECEIPT_FILE_FORMAT: &str = "lethe-receipt/1";
const RECEIPT_FILE_ALGORITHM: &str = "ed25519";
/// Where someone handed a receipt file finds how to check it.
const RECEIPT_FILE_ABOUT: &str = "https://github.com/ForeverInLaw/lethe/blob/master/docs/receipt-file.md";

/// A receipt as a JSON file a person can hand over, checked without the app or its
/// store: an Ed25519 signature by `public_key_hex` over the UTF-8 bytes of
/// `summary`. `docs/receipt-file.md` shows how.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptFile {
    format: String,
    /// A link to the layout and to how to check it; the check does not read it.
    about: String,
    algorithm: String,
    /// The summary exactly as it was signed. It stays text, because encoding it
    /// again could change the bytes the signature covers.
    summary: String,
    public_key_hex: String,
    signature_hex: String,
}

impl ReceiptFile {
    /// `summary_json` must be the signed text as stored, not a summary encoded again.
    pub fn new(summary_json: String, public_key_hex: String, signature_hex: String) -> Self {
        Self {
            format: RECEIPT_FILE_FORMAT.into(),
            about: RECEIPT_FILE_ABOUT.into(),
            algorithm: RECEIPT_FILE_ALGORITHM.into(),
            summary: summary_json,
            public_key_hex,
            signature_hex,
        }
    }

    /// The summary, once its signature holds. `Err(BadSignature)` for an edited
    /// file or one in a layout this version does not know.
    pub fn verify(&self) -> Result<RunSummary> {
        if self.format != RECEIPT_FILE_FORMAT || self.algorithm != RECEIPT_FILE_ALGORITHM {
            return Err(CryptoError::BadSignature);
        }
        verify_detached(self.summary.as_bytes(), &self.public_key_hex, &self.signature_hex)?;
        serde_json::from_str(&self.summary).map_err(|_| CryptoError::BadSignature)
    }
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
            deleted_only_for_self: 0,
            skipped: 2,
            failed: 1,
            kept_only_for_self: 0,
            undeletable: 0,
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
    fn a_receipt_signed_before_the_field_existed_still_verifies() {
        let signer = ReceiptSigner::generate();
        let signed = r#"{"run_id":"run-1","platform":"bluesky","account_label":"alice","started_epoch_secs":1000,"finished_epoch_secs":1042,"deleted":37,"skipped":2,"failed":1}"#;
        let mut signature = [0u8; SIGNATURE_LEN];
        crypto_sign_detached(&mut signature, signed.as_bytes(), &signer.secret_key).unwrap();
        let receipt = SignedReceipt {
            summary: serde_json::from_str(signed).unwrap(),
            public_key_hex: signer.public_key_hex(),
            signature_hex: to_hex(&signature),
        };

        assert!(verify(&receipt).is_ok());
    }

    #[test]
    fn what_stayed_visible_to_others_cannot_be_edited_out_of_a_receipt() {
        let signer = ReceiptSigner::generate();
        let mut receipt = signer
            .sign(&RunSummary { deleted_only_for_self: 5, ..summary() })
            .unwrap();
        assert!(verify(&receipt).is_ok());

        receipt.summary.deleted_only_for_self = 0;

        assert!(matches!(verify(&receipt), Err(CryptoError::BadSignature)));
    }

    #[test]
    fn a_receipt_file_proves_its_summary_without_the_store() {
        let signer = ReceiptSigner::generate();
        let receipt = signer.sign(&summary()).unwrap();
        let signed_text = serde_json::to_string(&receipt.summary).unwrap();
        let file = ReceiptFile::new(signed_text, receipt.public_key_hex, receipt.signature_hex);
        let handed_over = serde_json::to_string_pretty(&file).unwrap();

        let proven = serde_json::from_str::<ReceiptFile>(&handed_over).unwrap().verify().unwrap();

        assert_eq!((proven.run_id.as_str(), proven.deleted), ("run-1", 37));
    }

    #[test]
    fn a_receipt_file_with_an_edited_summary_or_another_key_fails() {
        let signer = ReceiptSigner::generate();
        let receipt = signer.sign(&summary()).unwrap();
        let signed_text = serde_json::to_string(&receipt.summary).unwrap();
        let edited = ReceiptFile::new(
            signed_text.replace("\"deleted\":37", "\"deleted\":38"),
            receipt.public_key_hex.clone(),
            receipt.signature_hex.clone(),
        );
        let other_key = ReceiptFile::new(
            signed_text,
            ReceiptSigner::generate().public_key_hex(),
            receipt.signature_hex,
        );

        assert!(matches!(edited.verify(), Err(CryptoError::BadSignature)));
        assert!(matches!(other_key.verify(), Err(CryptoError::BadSignature)));
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
