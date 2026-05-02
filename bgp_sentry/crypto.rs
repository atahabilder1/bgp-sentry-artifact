//! Ed25519 cryptographic utilities for BGP-Sentry blockchain.
//!
//! Port of Python's `SignatureUtils` — uses `ed25519-dalek` for fast
//! signing/verification.  Follows the same pattern: SHA-256 hash the payload
//! first, then sign the 32-byte digest with Ed25519.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use tracing::error;

// ---------------------------------------------------------------------------
// KeyPair
// ---------------------------------------------------------------------------

/// Wrapper around an Ed25519 signing key.
#[derive(Debug)]
pub struct KeyPair {
    signing_key: SigningKey,
}

impl KeyPair {
    /// Generate a fresh random Ed25519 key pair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Construct from an existing signing key (e.g. loaded from storage).
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    /// Return the public (verifying) key.
    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Sign an arbitrary payload.
    ///
    /// The payload is SHA-256 hashed first (matching the Python implementation)
    /// and the 32-byte digest is then signed with Ed25519.
    ///
    /// Returns the hex-encoded 64-byte signature.
    pub fn sign(&self, payload: &[u8]) -> String {
        let digest = Sha256::digest(payload);
        let sig: Signature = self.signing_key.sign(&digest);
        hex::encode(sig.to_bytes())
    }

    /// Verify a hex-encoded signature against a payload and public key.
    ///
    /// Returns `true` if valid, `false` on any error (bad hex, wrong key, etc.).
    pub fn verify(payload: &[u8], signature_hex: &str, public_key: &VerifyingKey) -> bool {
        let sig_bytes = match hex::decode(signature_hex) {
            Ok(b) => b,
            Err(e) => {
                error!("verify: bad hex signature: {e}");
                return false;
            }
        };
        let sig = match Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(e) => {
                error!("verify: invalid signature bytes: {e}");
                return false;
            }
        };
        let digest = Sha256::digest(payload);
        public_key.verify(&digest, &sig).is_ok()
    }
}

// ---------------------------------------------------------------------------
// Convenience signing helpers
// ---------------------------------------------------------------------------

/// Create a canonical JSON payload for a transaction and sign it.
///
/// The canonical form has sorted keys and no extra whitespace, matching the
/// Python `json.dumps(sort_keys=True, separators=(',', ':'))` convention.
pub fn sign_transaction(
    tx_id: &str,
    observer_as: u32,
    ip_prefix: &str,
    sender_asn: u32,
    key: &KeyPair,
) -> String {
    // Canonical JSON with sorted keys (fields in alphabetical order).
    let canonical = format!(
        r#"{{"ip_prefix":"{ip_prefix}","observer_as":{observer_as},"sender_asn":{sender_asn},"tx_id":"{tx_id}"}}"#,
    );
    key.sign(canonical.as_bytes())
}

/// Create a canonical JSON payload for a vote and sign it.
pub fn sign_vote(tx_id: &str, voter_as: u32, vote: &str, key: &KeyPair) -> String {
    let canonical = format!(
        r#"{{"tx_id":"{tx_id}","vote":"{vote}","voter_as":{voter_as}}}"#,
    );
    key.sign(canonical.as_bytes())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = KeyPair::generate();
        let payload = b"hello world";
        let sig = kp.sign(payload);
        assert!(KeyPair::verify(payload, &sig, &kp.public_key()));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let sig = kp1.sign(b"data");
        assert!(!KeyPair::verify(b"data", &sig, &kp2.public_key()));
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let kp = KeyPair::generate();
        let sig = kp.sign(b"original");
        assert!(!KeyPair::verify(b"tampered", &sig, &kp.public_key()));
    }

    #[test]
    fn verify_rejects_bad_hex() {
        let kp = KeyPair::generate();
        assert!(!KeyPair::verify(b"x", "not-hex!", &kp.public_key()));
    }

    #[test]
    fn sign_transaction_deterministic() {
        let kp = KeyPair::generate();
        let s1 = sign_transaction("tx-1", 100, "10.0.0.0/8", 200, &kp);
        let s2 = sign_transaction("tx-1", 100, "10.0.0.0/8", 200, &kp);
        // Ed25519 is deterministic — same input, same signature.
        assert_eq!(s1, s2);
    }

    #[test]
    fn sign_vote_verifies() {
        let kp = KeyPair::generate();
        let sig = sign_vote("tx-1", 42, "APPROVE", &kp);
        let canonical = r#"{"tx_id":"tx-1","vote":"APPROVE","voter_as":42}"#;
        assert!(KeyPair::verify(canonical.as_bytes(), &sig, &kp.public_key()));
    }
}
