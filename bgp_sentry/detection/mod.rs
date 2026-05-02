//! BGP Attack Detection Module
//!
//! 6 enabled detectors (one per control-plane attack category):
//! 1. PREFIX_HIJACK     — Prefix Hijacking: exact prefix, different origin (ROA mismatch)
//! 2. SUBPREFIX_HIJACK  — Prefix Hijacking: more-specific prefix, different origin
//! 3. BOGON_INJECTION   — Invalid Injection: reserved/private prefix ranges
//! 4. ROUTE_FLAPPING    — Control-Plane Instability: rapid oscillation
//! 5. ROUTE_LEAK        — Policy Violation: valley-free violation
//! 6. PATH_POISONING    — Path Manipulation: consecutive AS pair with no CAIDA relationship

use std::collections::HashMap;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use ipnet::IpNet;
use serde_json::Value;
use tracing::warn;

use crate::types::AttackDetection;

// ---------------------------------------------------------------------------
// Bogon ranges (RFC 1918 / 5737 / 6598 / 2544 etc.)
// ---------------------------------------------------------------------------

fn bogon_ranges() -> Vec<IpNet> {
    [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
    ]
    .iter()
    .map(|s| s.parse::<IpNet>().expect("invalid bogon literal"))
    .collect()
}

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

/// A single ROA (Route Origin Authorization) entry.
#[derive(Debug, Clone)]
struct RoaEntry {
    authorized_asn: u32,
    max_length: u8,
}

/// AS relationship data for one AS.
#[derive(Debug, Clone)]
struct AsRelEntry {
    customers: Vec<u32>,
    providers: Vec<u32>,
    peers: Vec<u32>,
}

// ---------------------------------------------------------------------------
// AttackDetector
// ---------------------------------------------------------------------------

/// Thread-safe BGP attack detector that implements all 5 detection strategies.
pub struct AttackDetector {
    roa_database: HashMap<String, RoaEntry>,
    as_relationships: HashMap<String, AsRelEntry>,
    /// (prefix, origin_asn) -> list of unique-event timestamps (epoch seconds).
    flap_history: DashMap<(String, u32), Vec<f64>>,
    flap_window: f64,
    flap_threshold: usize,
    flap_dedup_seconds: f64,
    bogon_ranges: Vec<IpNet>,
}

impl AttackDetector {
    /// Create a new detector, loading the ROA and AS-relationship databases
    /// from JSON files on disk.
    ///
    /// # Arguments
    /// * `roa_path`       - Path to the ROA database JSON.
    /// * `as_rel_path`    - Path to the AS relationships JSON.
    /// * `flap_window`    - Sliding window length in seconds for flap detection.
    /// * `flap_threshold` - Number of events within the window to trigger.
    /// * `flap_dedup`     - Minimum seconds between counted events for the same key.
    pub fn new(
        roa_path: &str,
        as_rel_path: &str,
        flap_window: f64,
        flap_threshold: usize,
        flap_dedup: f64,
    ) -> Self {
        Self {
            roa_database: Self::load_roa_database(roa_path),
            as_relationships: Self::load_as_relationships(as_rel_path),
            flap_history: DashMap::new(),
            flap_window,
            flap_threshold,
            flap_dedup_seconds: flap_dedup,
            bogon_ranges: bogon_ranges(),
        }
    }

    // -----------------------------------------------------------------------
    // ROA validation
    // -----------------------------------------------------------------------

    /// Check if a (prefix, origin) pair matches a ROA entry.
    /// Returns true if the prefix exists in the ROA database AND the origin
    /// AS matches the authorized AS. Returns false otherwise (no ROA, or mismatch).
    pub fn roa_matches(&self, ip_prefix: &str, origin_asn: u32) -> bool {
        if let Some(roa) = self.roa_database.get(ip_prefix) {
            roa.authorized_asn == origin_asn
        } else {
            false
        }
    }

    // -----------------------------------------------------------------------
    // Public dispatcher
    // -----------------------------------------------------------------------

    /// Run all 5 detectors against a single BGP announcement and return every
    /// attack that fires. An empty `Vec` means the announcement looks clean.
    pub fn detect_attacks(
        &self,
        sender_asn: u32,
        ip_prefix: &str,
        as_path: &[u32],
        bgp_timestamp: f64,
    ) -> Vec<AttackDetection> {
        let mut detected: Vec<AttackDetection> = Vec::new();

        // 6 enabled detectors (one per control-plane attack category):
        //
        // 1. PREFIX_HIJACK       — Prefix Hijacking (exact match, ROA mismatch)
        // 2. SUBPREFIX_HIJACK    — Prefix Hijacking (more-specific)
        // 3. BOGON_INJECTION     — Invalid Injection category
        // 4. ROUTE_FLAPPING      — Control-Plane Instability category
        // 5. ROUTE_LEAK          — Policy Violation category
        // 6. PATH_POISONING      — Path Manipulation category

        // 1. PREFIX_HIJACK (exact prefix, different origin than ROA)
        if let Some(mut a) = self.detect_prefix_hijack(sender_asn, ip_prefix) {
            a.as_path = as_path.to_vec();
            detected.push(a);
        }

        // 2. SUBPREFIX_HIJACK (more-specific prefix with different origin)
        if let Some(mut a) = self.detect_subprefix_hijack(sender_asn, ip_prefix) {
            a.as_path = as_path.to_vec();
            detected.push(a);
        }

        // 2. BOGON_INJECTION (reserved/private prefix)
        if let Some(mut a) = self.detect_bogon_injection(ip_prefix) {
            a.as_path = as_path.to_vec();
            detected.push(a);
        }

        // 3. ROUTE_FLAPPING (rapid oscillation)
        // Use BGP timestamp (not wall-clock) so flap detection works
        // correctly regardless of simulation speed multiplier.
        if let Some(mut a) = self.detect_route_flapping(sender_asn, ip_prefix, bgp_timestamp) {
            a.as_path = as_path.to_vec();
            detected.push(a);
        }

        // 4. ROUTE_LEAK (valley-free violation)
        if let Some(a) = self.detect_route_leak(as_path) {
            detected.push(a);
        }

        // 5. PATH_POISONING (no CAIDA relationship between adjacent ASes)
        if let Some(a) = self.detect_path_poisoning(as_path) {
            detected.push(a);
        }

        detected
    }

    // -----------------------------------------------------------------------
    // 1. PREFIX_HIJACK — Prefix Hijacking category (exact match)
    // -----------------------------------------------------------------------

    /// Exact prefix match in ROA database with a different origin AS.
    fn detect_prefix_hijack(
        &self,
        sender_asn: u32,
        ip_prefix: &str,
    ) -> Option<AttackDetection> {
        if let Some(roa) = self.roa_database.get(ip_prefix) {
            if sender_asn != roa.authorized_asn {
                return Some(AttackDetection {
                    attack_type: "PREFIX_HIJACK".into(),
                    severity: "HIGH".into(),
                    description: format!(
                        "AS{} announces {} (ROA authorizes AS{})",
                        sender_asn, ip_prefix, roa.authorized_asn,
                    ),
                    as_path: vec![],
                    evidence: serde_json::json!({
                        "roa_prefix": ip_prefix,
                        "roa_authorized_as": roa.authorized_asn,
                        "announced_prefix": ip_prefix,
                        "announcing_as": sender_asn,
                    }),
                });
            }
        }
        None
    }

    // -----------------------------------------------------------------------
    // 2. SUBPREFIX_HIJACK — Prefix Hijacking category (more-specific)
    // -----------------------------------------------------------------------

    /// More-specific prefix announced by a different origin than the covering
    /// ROA entry.
    fn detect_subprefix_hijack(
        &self,
        sender_asn: u32,
        ip_prefix: &str,
    ) -> Option<AttackDetection> {
        let announced: IpNet = ip_prefix.parse().ok()?;

        for (roa_prefix_str, roa) in &self.roa_database {
            let roa_net: IpNet = match roa_prefix_str.parse() {
                Ok(n) => n,
                Err(_) => continue,
            };

            // Skip exact match (handled by prefix-hijack detector).
            if announced == roa_net {
                continue;
            }

            // Check if announced is a more-specific (subnet) of the ROA prefix.
            if is_subnet_of(announced, roa_net) && sender_asn != roa.authorized_asn {
                return Some(AttackDetection {
                    attack_type: "SUBPREFIX_HIJACK".into(),
                    severity: "HIGH".into(),
                    description: format!(
                        "AS{} announces {} (sub-prefix of {} owned by AS{})",
                        sender_asn, ip_prefix, roa_prefix_str, roa.authorized_asn,
                    ),
                    as_path: vec![],
                    evidence: serde_json::json!({
                        "roa_prefix": roa_prefix_str,
                        "roa_authorized_as": roa.authorized_asn,
                        "roa_max_length": roa.max_length,
                        "announced_prefix": ip_prefix,
                        "announced_length": announced.prefix_len(),
                        "announcing_as": sender_asn,
                    }),
                });
            }
        }

        None
    }

    // -----------------------------------------------------------------------
    // 3. BOGON_INJECTION
    // -----------------------------------------------------------------------

    /// Announced prefix falls within a reserved / bogon range.
    fn detect_bogon_injection(&self, ip_prefix: &str) -> Option<AttackDetection> {
        let announced: IpNet = ip_prefix.parse().ok()?;

        for bogon in &self.bogon_ranges {
            if is_subnet_of(announced, *bogon) || announced == *bogon {
                return Some(AttackDetection {
                    attack_type: "BOGON_INJECTION".into(),
                    severity: "CRITICAL".into(),
                    description: format!(
                        "Bogon prefix {} (falls within {})",
                        ip_prefix, bogon,
                    ),
                    as_path: vec![],
                    evidence: serde_json::json!({
                        "announced_prefix": ip_prefix,
                        "bogon_range": bogon.to_string(),
                    }),
                });
            }
        }

        None
    }

    // -----------------------------------------------------------------------
    // 3. ROUTE_FLAPPING — Control-Plane Instability category
    // -----------------------------------------------------------------------

    /// Sliding-window flap counter.  Uses `DashMap` for thread-safe mutation.
    fn detect_route_flapping(
        &self,
        sender_asn: u32,
        ip_prefix: &str,
        timestamp: f64,
    ) -> Option<AttackDetection> {
        let key = (ip_prefix.to_string(), sender_asn);
        let cutoff = timestamp - self.flap_window;

        let count = {
            let mut entry = self.flap_history.entry(key.clone()).or_default();
            let history = entry.value_mut();

            // Dedup: skip if last recorded event is within dedup window.
            if let Some(&last) = history.last() {
                if (timestamp - last) < self.flap_dedup_seconds {
                    return None;
                }
            }

            // Record this unique event.
            history.push(timestamp);

            // Trim to window.
            history.retain(|&t| t > cutoff);

            history.len()
        };

        if count > self.flap_threshold {
            Some(AttackDetection {
                attack_type: "ROUTE_FLAPPING".into(),
                severity: "MEDIUM".into(),
                description: format!(
                    "AS{} flapping prefix {} ({} announcements in {}s, threshold={})",
                    sender_asn, ip_prefix, count, self.flap_window, self.flap_threshold,
                ),
                as_path: vec![],
                evidence: serde_json::json!({
                    "prefix": ip_prefix,
                    "origin_asn": sender_asn,
                    "announcements_in_window": count,
                    "threshold": self.flap_threshold,
                }),
            })
        } else {
            None
        }
    }

    // -----------------------------------------------------------------------
    // 6. ROUTE_LEAK
    // -----------------------------------------------------------------------

    /// Valley-free violation: an AS re-announces a route received from a
    /// provider or peer upward (to another provider or peer).
    ///
    /// Requires at least 3 hops in the AS-path.
    fn detect_route_leak(&self, as_path: &[u32]) -> Option<AttackDetection> {
        if as_path.len() < 3 {
            return None;
        }

        for i in 0..as_path.len() - 2 {
            let prev_as = as_path[i];
            let current_as = as_path[i + 1];
            let next_as = as_path[i + 2];

            let current_str = current_as.to_string();
            let rels = match self.as_relationships.get(&current_str) {
                Some(r) => r,
                None => continue,
            };

            let prev_is_provider = rels.providers.contains(&prev_as);
            let prev_is_peer = rels.peers.contains(&prev_as);
            let next_is_provider = rels.providers.contains(&next_as);
            let next_is_peer = rels.peers.contains(&next_as);

            // Valley-free violation: received from provider/peer AND
            // forwarded to provider/peer.
            if (prev_is_provider || prev_is_peer) && (next_is_provider || next_is_peer) {
                let received_type = if prev_is_provider {
                    "provider"
                } else {
                    "peer"
                };
                let leaked_type = if next_is_provider {
                    "provider"
                } else {
                    "peer"
                };

                return Some(AttackDetection {
                    attack_type: "ROUTE_LEAK".into(),
                    severity: "MEDIUM".into(),
                    description: format!(
                        "AS{} leaked route from {} AS{} to {} AS{}",
                        current_as, received_type, prev_as, leaked_type, next_as,
                    ),
                    as_path: as_path.to_vec(),
                    evidence: serde_json::json!({
                        "received_from": prev_as,
                        "leaked_to": next_as,
                        "leaker": current_as,
                        "received_from_type": received_type,
                        "leaked_to_type": leaked_type,
                        "valley_free_violation": true,
                        "as_path": as_path,
                    }),
                });
            }
        }

        None
    }

    // -----------------------------------------------------------------------
    // 7. PATH_POISONING
    // -----------------------------------------------------------------------

    /// Consecutive AS pair with no documented CAIDA relationship — indicates a
    /// fabricated hop was inserted into the path.
    ///
    /// Conservative: only fires when both ASes of the pair appear in the local
    /// relationship database.
    fn detect_path_poisoning(&self, as_path: &[u32]) -> Option<AttackDetection> {
        if as_path.len() < 2 {
            return None;
        }

        for i in 0..as_path.len() - 1 {
            let a = as_path[i];
            let b = as_path[i + 1];

            let rels_a = match self.as_relationships.get(&a.to_string()) {
                Some(r) => r,
                None => continue,
            };
            let rels_b = match self.as_relationships.get(&b.to_string()) {
                Some(r) => r,
                None => continue,
            };

            let has_rel = rels_a.customers.contains(&b)
                || rels_a.providers.contains(&b)
                || rels_a.peers.contains(&b)
                || rels_b.customers.contains(&a)
                || rels_b.providers.contains(&a)
                || rels_b.peers.contains(&a);

            if !has_rel {
                return Some(AttackDetection {
                    attack_type: "PATH_POISONING".into(),
                    severity: "HIGH".into(),
                    description: format!(
                        "AS-path contains adjacency AS{}↔AS{} that has no documented \
                         CAIDA relationship (likely fabricated insertion)",
                        a, b,
                    ),
                    as_path: as_path.to_vec(),
                    evidence: serde_json::json!({
                        "no_relationship_between": [a, b],
                        "edge_position": i,
                        "path_length": as_path.len(),
                        "as_path": as_path,
                    }),
                });
            }
        }

        None
    }

    // -----------------------------------------------------------------------
    // Database loaders
    // -----------------------------------------------------------------------

    /// Load ROA database from a JSON file.
    ///
    /// Expected format:
    /// ```json
    /// {
    ///   "8.8.8.0/24": { "authorized_as": 15169, "max_length": 24 }
    /// }
    /// ```
    fn load_roa_database(path: &str) -> HashMap<String, RoaEntry> {
        let data = match fs::read_to_string(path) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to read ROA database at {}: {}", path, e);
                return HashMap::new();
            }
        };

        let raw: HashMap<String, Value> = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(e) => {
                warn!("Failed to parse ROA database JSON: {}", e);
                return HashMap::new();
            }
        };

        let mut db = HashMap::with_capacity(raw.len());
        for (prefix, entry) in raw {
            let authorized_asn = entry
                .get("authorized_as")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;

            // Derive default max_length from prefix length if not specified.
            let default_len = prefix
                .split('/')
                .nth(1)
                .and_then(|s| s.parse::<u8>().ok())
                .unwrap_or(24);

            let max_length = entry
                .get("max_length")
                .and_then(|v| v.as_u64())
                .map(|v| v as u8)
                .unwrap_or(default_len);

            db.insert(prefix, RoaEntry { authorized_asn, max_length });
        }

        db
    }

    /// Load AS relationships from a JSON file.
    ///
    /// Expected format:
    /// ```json
    /// {
    ///   "15169": { "customers": [1234], "providers": [], "peers": [5678] }
    /// }
    /// ```
    fn load_as_relationships(path: &str) -> HashMap<String, AsRelEntry> {
        let data = match fs::read_to_string(path) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to read AS relationships at {}: {}", path, e);
                return HashMap::new();
            }
        };

        let raw: HashMap<String, Value> = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(e) => {
                warn!("Failed to parse AS relationships JSON: {}", e);
                return HashMap::new();
            }
        };

        let mut db = HashMap::with_capacity(raw.len());
        for (asn_str, entry) in raw {
            let parse_list = |key: &str| -> Vec<u32> {
                entry
                    .get(key)
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_u64().map(|n| n as u32))
                            .collect()
                    })
                    .unwrap_or_default()
            };

            db.insert(
                asn_str,
                AsRelEntry {
                    customers: parse_list("customers"),
                    providers: parse_list("providers"),
                    peers: parse_list("peers"),
                },
            );
        }

        db
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Check if `inner` is a subnet of `outer` (like Python's
/// `ip_network.subnet_of`).
///
/// Both networks must be the same IP version. `inner` is a subnet of `outer`
/// when `outer` contains the network address of `inner` and `inner`'s prefix
/// length is >= `outer`'s prefix length.
fn is_subnet_of(inner: IpNet, outer: IpNet) -> bool {
    // Must be same address family.
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

    /// Build a minimal detector with inline data (no files needed).
    fn test_detector() -> AttackDetector {
        let mut roa = HashMap::new();
        roa.insert(
            "8.8.8.0/24".into(),
            RoaEntry { authorized_asn: 15169, max_length: 24 },
        );
        roa.insert(
            "1.2.0.0/16".into(),
            RoaEntry { authorized_asn: 6300, max_length: 24 },
        );

        let mut rels = HashMap::new();
        rels.insert(
            "1".into(),
            AsRelEntry { customers: vec![2, 3], providers: vec![], peers: vec![5, 7] },
        );
        rels.insert(
            "3".into(),
            AsRelEntry { customers: vec![6], providers: vec![1], peers: vec![5] },
        );
        rels.insert(
            "5".into(),
            AsRelEntry { customers: vec![8], providers: vec![7], peers: vec![1, 3] },
        );
        rels.insert(
            "7".into(),
            AsRelEntry { customers: vec![10], providers: vec![], peers: vec![5, 9] },
        );
        rels.insert(
            "100".into(),
            AsRelEntry { customers: vec![], providers: vec![], peers: vec![] },
        );
        rels.insert(
            "200".into(),
            AsRelEntry { customers: vec![], providers: vec![], peers: vec![] },
        );

        AttackDetector {
            roa_database: roa,
            as_relationships: rels,
            flap_history: DashMap::new(),
            flap_window: 60.0,
            flap_threshold: 3,
            flap_dedup_seconds: 2.0,
            bogon_ranges: bogon_ranges(),
        }
    }

    #[test]
    fn test_legitimate_announcement() {
        let d = test_detector();
        let attacks = d.detect_attacks(15169, "8.8.8.0/24", &[15169, 1, 3], 1000.0);
        // Origin matches ROA, no sub-prefix, not bogon — should be clean
        // (path-based detectors may or may not fire depending on rels)
        assert!(
            !attacks.iter().any(|a| a.attack_type == "PREFIX_HIJACK"),
            "should not flag prefix hijack for legitimate origin"
        );
    }

    #[test]
    fn test_prefix_hijack() {
        let d = test_detector();
        // 8.8.8.0/24 exact match, different origin (999 != 15169)
        let result = d.detect_prefix_hijack(999, "8.8.8.0/24");
        assert!(result.is_some());
        assert_eq!(result.unwrap().attack_type, "PREFIX_HIJACK");
    }

    #[test]
    fn test_prefix_hijack_same_origin() {
        let d = test_detector();
        // Same authorized origin — should NOT fire.
        assert!(d.detect_prefix_hijack(15169, "8.8.8.0/24").is_none());
    }

    #[test]
    fn test_prefix_hijack_unknown_prefix() {
        let d = test_detector();
        // Prefix not in ROA — should NOT fire (no ROA to compare against).
        assert!(d.detect_prefix_hijack(999, "4.4.4.0/24").is_none());
    }

    #[test]
    fn test_subprefix_hijack() {
        let d = test_detector();
        // 1.2.3.0/24 is a subnet of 1.2.0.0/16, different origin
        let result = d.detect_subprefix_hijack(999, "1.2.3.0/24");
        assert!(result.is_some());
        assert_eq!(result.unwrap().attack_type, "SUBPREFIX_HIJACK");
    }

    #[test]
    fn test_subprefix_same_origin() {
        let d = test_detector();
        // Same authorized origin — should NOT fire.
        assert!(d.detect_subprefix_hijack(6300, "1.2.3.0/24").is_none());
    }

    #[test]
    fn test_bogon_injection() {
        let d = test_detector();
        assert!(d.detect_bogon_injection("10.0.0.0/8").is_some());
        assert!(d.detect_bogon_injection("192.168.1.0/24").is_some());
        assert!(d.detect_bogon_injection("8.8.8.0/24").is_none());
    }

    #[test]
    fn test_route_flapping() {
        let d = test_detector();
        // Under threshold — should not fire.
        for t in 0..3 {
            assert!(
                d.detect_route_flapping(42, "1.0.0.0/8", t as f64 * 10.0)
                    .is_none()
            );
        }
        // 4th event crosses threshold of 3.
        let result = d.detect_route_flapping(42, "1.0.0.0/8", 30.0);
        assert!(result.is_some());
        assert_eq!(result.unwrap().attack_type, "ROUTE_FLAPPING");
    }

    #[test]
    fn test_flap_dedup() {
        let d = test_detector();
        d.detect_route_flapping(42, "1.0.0.0/8", 0.0);
        // Within dedup window — should be ignored.
        assert!(d.detect_route_flapping(42, "1.0.0.0/8", 0.5).is_none());
    }

    #[test]
    fn test_route_leak() {
        let d = test_detector();
        // AS5's providers=[7], peers=[1,3].  Path: [7, 5, 1]
        // AS5 received from provider 7 and leaked to peer 1 — valley-free violation.
        let result = d.detect_route_leak(&[7, 5, 1]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().attack_type, "ROUTE_LEAK");
    }

    #[test]
    fn test_route_leak_legitimate() {
        let d = test_detector();
        // AS5's customers=[8].  Path: [7, 5, 8] — provider to customer is OK.
        assert!(d.detect_route_leak(&[7, 5, 8]).is_none());
    }

    #[test]
    fn test_path_poisoning() {
        let d = test_detector();
        // AS100 and AS200 both exist in rels but have no relationship.
        let result = d.detect_path_poisoning(&[100, 200]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().attack_type, "PATH_POISONING");
    }

    #[test]
    fn test_path_poisoning_legitimate() {
        let d = test_detector();
        // AS1 and AS5 are peers — should NOT fire.
        assert!(d.detect_path_poisoning(&[1, 5]).is_none());
    }

    #[test]
    fn test_is_subnet_of() {
        let inner: IpNet = "10.1.0.0/16".parse().unwrap();
        let outer: IpNet = "10.0.0.0/8".parse().unwrap();
        assert!(is_subnet_of(inner, outer));
        assert!(!is_subnet_of(outer, inner));
    }
}
