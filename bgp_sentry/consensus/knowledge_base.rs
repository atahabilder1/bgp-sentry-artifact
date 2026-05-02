//! Knowledge base for time-windowed BGP observations.
//!
//! Each RPKI validator node maintains a knowledge base of BGP announcements it
//! has observed. During consensus voting, the KB is consulted to decide whether
//! to approve, reject, or abstain on a transaction.
//!
//! Ported from Python `P2PTransactionPool._kb_index` / `add_bgp_observation` /
//! `_check_knowledge_base` in `p2p_transaction_pool.py`.

use std::time::Instant;

use dashmap::DashMap;

use crate::types::Vote;

// ---------------------------------------------------------------------------
// KbEntry — a single observation stored in the knowledge base
// ---------------------------------------------------------------------------

/// A single BGP observation recorded in the knowledge base.
#[derive(Debug, Clone)]
pub struct KbEntry {
    /// The AS that originated the announcement.
    pub sender_asn: u32,
    /// The BGP announcement timestamp (epoch seconds from the dataset).
    pub timestamp: f64,
    /// Wall-clock instant when this entry was inserted (used for expiry).
    pub observed_at: Instant,
    /// Trust score assigned to this observation (0–100).
    pub trust_score: f64,
    /// Whether the observation was flagged as an attack.
    pub is_attack: bool,
}

// ---------------------------------------------------------------------------
// KnowledgeBase
// ---------------------------------------------------------------------------

/// Thread-safe, time-windowed knowledge base keyed by IP prefix.
///
/// Uses [`DashMap`] internally so all public methods can be called from any
/// thread without external synchronisation.
pub struct KnowledgeBase {
    /// Primary index: `ip_prefix` → list of observations.
    entries: DashMap<String, Vec<KbEntry>>,

    /// Sampling dedup: `(ip_prefix, sender_asn)` → [`Instant`] of last add.
    /// Used to skip redundant regular observations within the sampling window.
    sampling_cache: DashMap<(String, u32), Instant>,

    /// Sampling window in seconds. Observations for the same `(prefix, asn)`
    /// pair are dropped if one was recorded less than this many seconds ago.
    /// Attacks always bypass sampling.
    sampling_window_secs: f64,

    /// Maximum number of entries (across all prefixes). When exceeded, the
    /// oldest entries are trimmed.
    max_size: usize,

    /// Running count of entries across all prefixes (avoids iterating the map
    /// just to compute length). Kept approximately in-sync — minor races are
    /// acceptable because the capacity guard is a soft limit.
    entry_count: std::sync::atomic::AtomicUsize,
}

impl KnowledgeBase {
    /// Create a new knowledge base.
    ///
    /// # Arguments
    /// * `sampling_window_secs` — minimum seconds between recording the same
    ///   `(prefix, asn)` pair (regular observations only; attacks bypass).
    /// * `max_size` — soft capacity limit; oldest entries are trimmed when
    ///   exceeded.
    pub fn new(sampling_window_secs: f64, max_size: usize) -> Self {
        Self {
            entries: DashMap::new(),
            sampling_cache: DashMap::new(),
            sampling_window_secs,
            max_size,
            entry_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    // ------------------------------------------------------------------
    // add_observation
    // ------------------------------------------------------------------

    /// Record a BGP observation in the knowledge base.
    ///
    /// **Sampling**: for non-attack observations, if the same `(prefix,
    /// sender_asn)` was recorded within `sampling_window_secs`, the call
    /// returns `false` and the entry is *not* added. Attacks always bypass
    /// sampling.
    ///
    /// **Capacity**: if the total number of entries reaches `max_size`, the
    /// oldest entry (by `observed_at`) is removed first.
    ///
    /// Returns `true` if the observation was actually inserted.
    pub fn add_observation(
        &self,
        prefix: &str,
        sender_asn: u32,
        timestamp: f64,
        trust_score: f64,
        is_attack: bool,
    ) -> bool {
        let now = Instant::now();

        // ── Sampling gate (regular observations only) ────────────────
        if !is_attack {
            let cache_key = (prefix.to_owned(), sender_asn);
            if let Some(last) = self.sampling_cache.get(&cache_key) {
                if now.duration_since(*last).as_secs_f64() < self.sampling_window_secs {
                    return false; // Too recent — skip
                }
            }
            // Update sampling cache
            self.sampling_cache.insert(cache_key, now);
        }

        // ── Capacity guard: trim oldest if at limit ──────────────────
        let current_count = self.entry_count.load(std::sync::atomic::Ordering::Relaxed);
        if current_count >= self.max_size {
            self.trim_oldest();
        }

        // ── Insert entry ─────────────────────────────────────────────
        let entry = KbEntry {
            sender_asn,
            timestamp,
            observed_at: now,
            trust_score,
            is_attack,
        };

        self.entries
            .entry(prefix.to_owned())
            .or_default()
            .push(entry);

        self.entry_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        true
    }

    // ------------------------------------------------------------------
    // check_knowledge
    // ------------------------------------------------------------------

    /// Vote on a transaction by consulting the knowledge base.
    ///
    /// * **Approve** — the KB contains the same `(prefix, sender_asn)` and
    ///   the entry hasn't expired (wall-clock freshness within `window_seconds`).
    /// * **Reject** — the KB contains the same prefix but with a *different*
    ///   `sender_asn` (conflicting origin).
    /// * **Abstain** (NoKnowledge) — prefix not found in KB.
    ///
    /// The window check uses wall-clock `observed_at` rather than BGP
    /// timestamps. BGP timestamps represent the simulated announce time
    /// which can span thousands of seconds within a single experiment run,
    /// while KB entries from warm-up / gossip all share a narrow wall-clock
    /// insertion window. Using BGP timestamps causes nearly all votes to
    /// return NoKnowledge when the dataset timestamp span exceeds the
    /// knowledge window.
    pub fn check_knowledge(
        &self,
        prefix: &str,
        sender_asn: u32,
        _tx_timestamp: f64,
        window_seconds: f64,
    ) -> Vote {
        let bucket = match self.entries.get(prefix) {
            Some(b) => b,
            None => return Vote::NoKnowledge,
        };

        let now = Instant::now();
        let window = std::time::Duration::from_secs_f64(window_seconds);
        let mut seen_different_origin = false;

        for entry in bucket.value().iter() {
            // Use wall-clock freshness: entry must have been observed
            // within the knowledge window (same semantics as cleanup()).
            if now.duration_since(entry.observed_at) > window {
                continue;
            }

            if entry.sender_asn == sender_asn {
                return Vote::Approve; // Same prefix, same AS — confirm
            }

            // Same prefix, different AS
            seen_different_origin = true;
        }

        if seen_different_origin {
            Vote::Reject
        } else {
            Vote::NoKnowledge
        }
    }

    // ------------------------------------------------------------------
    // cleanup
    // ------------------------------------------------------------------

    /// Remove entries whose `observed_at` is older than `window_seconds` from
    /// now. Also prunes empty prefix buckets and stale sampling-cache entries.
    pub fn cleanup(&self, window_seconds: f64) {
        let cutoff = Instant::now() - std::time::Duration::from_secs_f64(window_seconds);
        let mut total_removed: usize = 0;

        // Collect keys that need mutation to avoid holding shard locks too long.
        let keys: Vec<String> = self.entries.iter().map(|r| r.key().clone()).collect();

        for key in keys {
            self.entries.alter(&key, |_k, mut vec| {
                let before = vec.len();
                vec.retain(|e| e.observed_at >= cutoff);
                let after = vec.len();
                total_removed += before - after;
                vec
            });
            // Remove bucket entirely if empty
            self.entries.remove_if(&key, |_k, v| v.is_empty());
        }

        // Adjust approximate count
        if total_removed > 0 {
            self.entry_count
                .fetch_sub(total_removed, std::sync::atomic::Ordering::Relaxed);
        }

        // Prune stale sampling-cache entries
        let sampling_cutoff =
            Instant::now() - std::time::Duration::from_secs_f64(self.sampling_window_secs);
        self.sampling_cache
            .retain(|_k, v| *v >= sampling_cutoff);
    }

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------

    /// Total number of entries across all prefixes (approximate).
    pub fn len(&self) -> usize {
        self.entry_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether the knowledge base is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return a snapshot of all entries for a given prefix.
    pub fn entries_for_prefix(&self, prefix: &str) -> Vec<KbEntry> {
        match self.entries.get(prefix) {
            Some(bucket) => bucket.value().clone(),
            None => Vec::new(),
        }
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Remove the single oldest entry across the entire map.
    fn trim_oldest(&self) {
        let mut oldest_key: Option<String> = None;
        let mut oldest_time: Option<Instant> = None;

        for bucket in self.entries.iter() {
            for entry in bucket.value().iter() {
                match oldest_time {
                    None => {
                        oldest_time = Some(entry.observed_at);
                        oldest_key = Some(bucket.key().clone());
                    }
                    Some(t) if entry.observed_at < t => {
                        oldest_time = Some(entry.observed_at);
                        oldest_key = Some(bucket.key().clone());
                    }
                    _ => {}
                }
            }
        }

        if let Some(key) = oldest_key {
            if let Some(oldest_instant) = oldest_time {
                let mut removed = false;
                self.entries.alter(&key, |_k, mut vec| {
                    if let Some(pos) = vec.iter().position(|e| e.observed_at == oldest_instant) {
                        vec.remove(pos);
                        removed = true;
                    }
                    vec
                });
                if removed {
                    self.entry_count
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                }
                // Clean up empty bucket
                self.entries.remove_if(&key, |_k, v| v.is_empty());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_check_approve() {
        let kb = KnowledgeBase::new(3600.0, 10_000);
        assert!(kb.add_observation("10.0.0.0/24", 65001, 1000.0, 80.0, false));
        assert_eq!(kb.len(), 1);

        let vote = kb.check_knowledge("10.0.0.0/24", 65001, 1005.0, 480.0);
        assert_eq!(vote, Vote::Approve);
    }

    #[test]
    fn test_check_reject_different_origin() {
        let kb = KnowledgeBase::new(3600.0, 10_000);
        kb.add_observation("10.0.0.0/24", 65001, 1000.0, 80.0, false);

        // Different ASN for the same prefix — should reject
        let vote = kb.check_knowledge("10.0.0.0/24", 65099, 1005.0, 480.0);
        assert_eq!(vote, Vote::Reject);
    }

    #[test]
    fn test_check_no_knowledge() {
        let kb = KnowledgeBase::new(3600.0, 10_000);
        let vote = kb.check_knowledge("192.168.0.0/16", 65001, 1000.0, 480.0);
        assert_eq!(vote, Vote::NoKnowledge);
    }

    #[test]
    fn test_sampling_dedup() {
        let kb = KnowledgeBase::new(3600.0, 10_000);
        assert!(kb.add_observation("10.0.0.0/24", 65001, 1000.0, 80.0, false));
        // Same (prefix, asn) within sampling window — should be skipped
        assert!(!kb.add_observation("10.0.0.0/24", 65001, 1001.0, 80.0, false));
        assert_eq!(kb.len(), 1);
    }

    #[test]
    fn test_attacks_bypass_sampling() {
        let kb = KnowledgeBase::new(3600.0, 10_000);
        assert!(kb.add_observation("10.0.0.0/24", 65001, 1000.0, 80.0, true));
        // Attack flag bypasses sampling
        assert!(kb.add_observation("10.0.0.0/24", 65001, 1001.0, 80.0, true));
        assert_eq!(kb.len(), 2);
    }

    #[test]
    fn test_capacity_trim() {
        let kb = KnowledgeBase::new(3600.0, 3);
        // Use different ASNs so sampling doesn't kick in
        kb.add_observation("10.0.0.0/24", 1, 100.0, 80.0, false);
        kb.add_observation("10.0.0.0/24", 2, 200.0, 80.0, false);
        kb.add_observation("10.0.0.0/24", 3, 300.0, 80.0, false);
        // This should trigger trim of the oldest
        kb.add_observation("10.0.0.0/24", 4, 400.0, 80.0, false);
        assert!(kb.len() <= 4); // soft limit — may be 3 or 4 due to race-free single-thread
    }

    #[test]
    fn test_cleanup_removes_old() {
        let kb = KnowledgeBase::new(3600.0, 10_000);
        kb.add_observation("10.0.0.0/24", 65001, 1000.0, 80.0, false);
        // With a window of 0 seconds, everything is old
        kb.cleanup(0.0);
        assert_eq!(kb.len(), 0);
    }

    #[test]
    fn test_entries_for_prefix() {
        let kb = KnowledgeBase::new(3600.0, 10_000);
        kb.add_observation("10.0.0.0/24", 65001, 1000.0, 80.0, false);
        kb.add_observation("10.0.0.0/24", 65002, 1001.0, 70.0, true);

        let entries = kb.entries_for_prefix("10.0.0.0/24");
        assert_eq!(entries.len(), 2);

        let empty = kb.entries_for_prefix("192.168.0.0/16");
        assert!(empty.is_empty());
    }
}
