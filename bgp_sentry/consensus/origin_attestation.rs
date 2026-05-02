//! Blockchain Origin Attestation (BOA) — consensus-derived origin registry.
//!
//! Unlike the ephemeral `KnowledgeBase` (which stores time-windowed local
//! observations for voting), the BOA is a **persistent, consensus-backed**
//! registry of (prefix, origin_asn) pairs that have been committed to the
//! blockchain with CONFIRMED consensus status.
//!
//! The BOA serves as an alternative to RPKI ROAs for prefixes that lack ROA
//! coverage. When a new BGP announcement arrives and the ROA-based detectors
//! find no matching ROA, the BOA is consulted:
//!
//! - **PREFIX_HIJACK**: the exact prefix exists in BOA with a different origin.
//! - **SUBPREFIX_HIJACK**: a covering (less-specific) prefix exists in BOA
//!   with a different origin.
//!
//! Design principles:
//! - **No expiry**: entries accumulate over the lifetime of the blockchain.
//! - **Consensus-gated**: only CONFIRMED legitimate transactions are recorded.
//! - **Thread-safe**: uses `DashMap` for lock-free concurrent access.

use dashmap::DashMap;
use ipnet::IpNet;

use crate::types::AttackDetection;

/// A confirmed origin attestation from the blockchain.
#[derive(Debug, Clone)]
pub struct BoaEntry {
    /// The AS that legitimately originates this prefix (confirmed by consensus).
    pub origin_asn: u32,
    /// Number of distinct CONFIRMED transactions attesting this mapping.
    pub attestation_count: u32,
}

/// Thread-safe, persistent origin attestation registry.
///
/// Populated from CONFIRMED blockchain transactions. Queried by the attack
/// detector as a fallback when no ROA exists for a given prefix.
pub struct OriginAttestation {
    /// Primary index: exact `ip_prefix` string → list of attested origins.
    entries: DashMap<String, Vec<BoaEntry>>,
}

impl OriginAttestation {
    /// Create an empty BOA store.
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    /// Record a confirmed (prefix, origin) attestation.
    ///
    /// If the same (prefix, origin) pair already exists, its attestation count
    /// is incremented. Otherwise a new entry is created.
    ///
    /// Only call this for **legitimate, CONFIRMED** transactions.
    pub fn attest(&self, prefix: &str, origin_asn: u32) {
        let mut bucket = self.entries.entry(prefix.to_owned()).or_default();
        if let Some(entry) = bucket.iter_mut().find(|e| e.origin_asn == origin_asn) {
            entry.attestation_count += 1;
        } else {
            bucket.push(BoaEntry {
                origin_asn,
                attestation_count: 1,
            });
        }
    }

    /// Check for PREFIX_HIJACK: exact prefix in BOA with a different origin.
    ///
    /// Returns `Some(AttackDetection)` if the prefix is attested to a different
    /// AS than `announced_origin`.
    pub fn check_prefix_hijack(
        &self,
        announced_origin: u32,
        ip_prefix: &str,
    ) -> Option<AttackDetection> {
        let bucket = self.entries.get(ip_prefix)?;

        // Find a confirmed origin that differs from the announced one.
        let legitimate = bucket.iter().find(|e| e.origin_asn != announced_origin)?;

        Some(AttackDetection {
            attack_type: "PREFIX_HIJACK".into(),
            severity: "HIGH".into(),
            description: format!(
                "AS{} announces {} but BOA attests AS{} ({} confirmations)",
                announced_origin, ip_prefix, legitimate.origin_asn,
                legitimate.attestation_count,
            ),
            as_path: vec![],
            evidence: serde_json::json!({
                "announced_prefix": ip_prefix,
                "announcing_as": announced_origin,
                "boa_attested_as": legitimate.origin_asn,
                "boa_attestation_count": legitimate.attestation_count,
                "source": "blockchain_origin_attestation",
            }),
        })
    }

    /// Check for SUBPREFIX_HIJACK: a covering (less-specific) prefix in BOA
    /// with a different origin than `announced_origin`.
    ///
    /// Returns `Some(AttackDetection)` if a covering prefix is found.
    pub fn check_subprefix_hijack(
        &self,
        announced_origin: u32,
        ip_prefix: &str,
    ) -> Option<AttackDetection> {
        let announced: IpNet = ip_prefix.parse().ok()?;

        for entry in self.entries.iter() {
            let boa_prefix_str = entry.key();
            let boa_net: IpNet = match boa_prefix_str.parse() {
                Ok(n) => n,
                Err(_) => continue,
            };

            // Skip exact match (handled by check_prefix_hijack).
            if announced == boa_net {
                continue;
            }

            // Check if announced is a more-specific (subnet) of the BOA prefix.
            if is_subnet_of(announced, boa_net) {
                // Find a confirmed origin that differs from the announced one.
                if let Some(legitimate) = entry.value().iter().find(|e| e.origin_asn != announced_origin) {
                    return Some(AttackDetection {
                        attack_type: "SUBPREFIX_HIJACK".into(),
                        severity: "HIGH".into(),
                        description: format!(
                            "AS{} announces {} (sub-prefix of {} attested to AS{} by BOA, {} confirmations)",
                            announced_origin, ip_prefix, boa_prefix_str,
                            legitimate.origin_asn, legitimate.attestation_count,
                        ),
                        as_path: vec![],
                        evidence: serde_json::json!({
                            "boa_prefix": boa_prefix_str.clone(),
                            "boa_attested_as": legitimate.origin_asn,
                            "boa_attestation_count": legitimate.attestation_count,
                            "announced_prefix": ip_prefix,
                            "announcing_as": announced_origin,
                            "source": "blockchain_origin_attestation",
                        }),
                    });
                }
            }
        }

        None
    }

    /// Total number of unique prefixes in the BOA.
    pub fn prefix_count(&self) -> usize {
        self.entries.len()
    }

    /// Total number of (prefix, origin) attestations.
    pub fn attestation_count(&self) -> usize {
        self.entries.iter().map(|e| e.value().len()).sum()
    }
}

/// Check if `inner` is a subnet of `outer`.
fn is_subnet_of(inner: IpNet, outer: IpNet) -> bool {
    match (inner, outer) {
        (IpNet::V4(i), IpNet::V4(o)) => {
            o.contains(&i.addr()) && i.prefix_len() >= o.prefix_len()
        }
        (IpNet::V6(i), IpNet::V6(o)) => {
            o.contains(&i.addr()) && i.prefix_len() >= o.prefix_len()
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attest_and_prefix_hijack() {
        let boa = OriginAttestation::new();
        boa.attest("10.0.0.0/24", 65001);
        boa.attest("10.0.0.0/24", 65001); // duplicate — increment count

        // Same origin: no hijack.
        assert!(boa.check_prefix_hijack(65001, "10.0.0.0/24").is_none());

        // Different origin: hijack detected.
        let det = boa.check_prefix_hijack(65099, "10.0.0.0/24");
        assert!(det.is_some());
        let d = det.unwrap();
        assert_eq!(d.attack_type, "PREFIX_HIJACK");
        assert!(d.description.contains("BOA"));
    }

    #[test]
    fn test_subprefix_hijack() {
        let boa = OriginAttestation::new();
        boa.attest("10.0.0.0/16", 65001);

        // Sub-prefix by different origin.
        let det = boa.check_subprefix_hijack(65099, "10.0.1.0/24");
        assert!(det.is_some());
        assert_eq!(det.unwrap().attack_type, "SUBPREFIX_HIJACK");

        // Sub-prefix by same origin: no hijack.
        assert!(boa.check_subprefix_hijack(65001, "10.0.1.0/24").is_none());
    }

    #[test]
    fn test_exact_prefix_not_subprefix() {
        let boa = OriginAttestation::new();
        boa.attest("10.0.0.0/24", 65001);

        // Exact match should NOT trigger subprefix (handled by prefix_hijack).
        assert!(boa.check_subprefix_hijack(65099, "10.0.0.0/24").is_none());
    }

    #[test]
    fn test_unknown_prefix() {
        let boa = OriginAttestation::new();
        assert!(boa.check_prefix_hijack(65001, "192.168.0.0/16").is_none());
        assert!(boa.check_subprefix_hijack(65001, "192.168.1.0/24").is_none());
    }

    #[test]
    fn test_attestation_counts() {
        let boa = OriginAttestation::new();
        assert_eq!(boa.prefix_count(), 0);
        assert_eq!(boa.attestation_count(), 0);

        boa.attest("10.0.0.0/24", 65001);
        boa.attest("10.0.0.0/24", 65002);
        boa.attest("192.168.0.0/16", 65003);

        assert_eq!(boa.prefix_count(), 2);
        assert_eq!(boa.attestation_count(), 3);
    }
}
