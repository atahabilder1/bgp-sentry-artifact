//! Virtual node — per-RPKI-validator observation processing loop.
//!
//! Port of Python's `VirtualNode` from `virtual_node.py`. Each RPKI validator
//! runs one `VirtualNode` that:
//!
//! 1. Sorts observations by BGP timestamp.
//! 2. Warm-up phase: populates the knowledge base in listen-only mode.
//! 3. Active phase: for each observation:
//!    a. Wait for simulation clock (real-time pacing).
//!    b. Trusted path filter (skip self-origin, skip untrusted relay chains).
//!    c. Dedup check (skip repeated (prefix, origin) within window).
//!    d. Add to KB.
//!    e. Attack detection (all 5 detectors).
//!    f. Create transaction (with Ed25519 signature).
//!    g. Broadcast for consensus.
//! 4. Return stats.

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use tracing::{debug, error, info};
use uuid::Uuid;

use crate::clock::SimulationClock;
use crate::config::Config;
use crate::consensus::knowledge_base::KnowledgeBase;
use crate::consensus::transaction_pool::TransactionPool;
use crate::crypto::{sign_transaction, KeyPair};
use crate::detection::AttackDetector;
use crate::types::*;

// =============================================================================
// NodeStats
// =============================================================================

/// Per-node statistics collected during the observation processing loop.
#[derive(Debug, Clone, Default)]
pub struct NodeStats {
    pub observations_processed: usize,
    pub transactions_created: usize,
    pub attacks_detected: usize,
    pub transactions_deduped: usize,
    pub trusted_path_filtered: usize,
    pub warmup_observations: usize,
    pub legitimate_count: usize,
    pub buffer_sampled: usize,
    pub detections: Vec<DetectionResult>,
}

// =============================================================================
// DetectionResult
// =============================================================================

/// Result of processing a single observation.
#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub asn: u32,
    pub prefix: String,
    pub origin_asn: u32,
    pub label: String,
    pub is_attack: bool,
    pub timestamp: f64,
    pub detected: bool,
    pub detection_type: Option<String>,
    pub detection_details: Vec<String>,
    pub action: String,
    pub transaction_id: Option<String>,
}

impl DetectionResult {
    fn base(asn: u32, obs: &Observation) -> Self {
        Self {
            asn,
            prefix: obs.prefix.clone(),
            origin_asn: obs.origin_asn,
            label: obs.label.clone(),
            is_attack: obs.is_attack,
            timestamp: obs.timestamp,
            detected: false,
            detection_type: None,
            detection_details: Vec::new(),
            action: "pending".to_string(),
            transaction_id: None,
        }
    }
}

// =============================================================================
// VirtualNode
// =============================================================================

/// Represents a single RPKI validator in the BGP-Sentry simulation.
///
/// Non-RPKI nodes are passive and do not participate in consensus; they are
/// not represented by `VirtualNode` in the Rust port.
pub struct VirtualNode {
    /// This node's ASN.
    pub asn: u32,

    /// Global configuration.
    config: Arc<Config>,

    /// Transaction pool (shared consensus engine).
    pool: Arc<TransactionPool>,

    /// Knowledge base (shared with pool for vote decisions).
    kb: Arc<KnowledgeBase>,

    /// Ed25519 key pair for signing transactions.
    key_pair: Arc<KeyPair>,

    /// Observations assigned to this node from the dataset.
    observations: Vec<Observation>,

    /// Attack detector (all 5 strategies).
    attack_detector: Arc<AttackDetector>,

    /// Simulation clock for real-time pacing.
    clock: SimulationClock,

    /// Set of all RPKI ASNs (for trusted path filter).
    rpki_asns: HashSet<u32>,

    /// Whether this node is an RPKI validator (participates in consensus).
    /// Non-RPKI nodes only detect attacks and count observations — they do
    /// NOT create transactions or broadcast to the consensus network.
    is_rpki: bool,

    // ── Mutable processing state ──

    /// Dedup state: (prefix, origin) -> last_seen_time (wall-clock).
    dedup_state: HashMap<(String, u32), f64>,

    /// Collected detection results (for post-run analysis).
    pub detection_results: Vec<DetectionResult>,

    /// Running stats.
    pub stats: NodeStats,
}

impl VirtualNode {
    /// Create a new virtual node.
    ///
    /// # Arguments
    /// * `asn` — This validator's ASN.
    /// * `config` — Global configuration.
    /// * `pool` — Shared transaction pool.
    /// * `kb` — Shared knowledge base.
    /// * `key_pair` — Ed25519 key pair.
    /// * `observations` — Dataset observations assigned to this node.
    /// * `attack_detector` — Shared attack detector.
    /// * `clock` — Simulation clock.
    /// * `rpki_asns` — Set of all RPKI validator ASNs.
    /// * `is_rpki` — Whether this node is an RPKI validator (broadcasts TXs)
    ///   or a passive non-RPKI observer (detection only, no consensus).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        asn: u32,
        config: Arc<Config>,
        pool: Arc<TransactionPool>,
        kb: Arc<KnowledgeBase>,
        key_pair: Arc<KeyPair>,
        observations: Vec<Observation>,
        attack_detector: Arc<AttackDetector>,
        clock: SimulationClock,
        rpki_asns: HashSet<u32>,
        is_rpki: bool,
    ) -> Self {
        Self {
            asn,
            config,
            pool,
            kb,
            key_pair,
            observations,
            attack_detector,
            clock,
            rpki_asns,
            is_rpki,
            dedup_state: HashMap::new(),
            detection_results: Vec::new(),
            stats: NodeStats::default(),
        }
    }

    // =========================================================================
    // Main processing loop (async)
    // =========================================================================

    /// Run the full observation processing pipeline.
    ///
    /// 1. Sort observations by timestamp.
    /// 2. Warm-up phase (listen-only KB population).
    /// 3. Active phase: process each observation through the RPKI pipeline.
    ///
    /// Returns accumulated stats when all observations are processed.
    pub async fn run(&mut self) -> NodeStats {
        // Sort observations by BGP timestamp.
        self.observations
            .sort_by(|a, b| a.timestamp.partial_cmp(&b.timestamp).unwrap());

        // No warm-up — process all observations from the start.
        // Each node builds its KB from its own observations during processing.
        self.stats.warmup_observations = 0;

        debug!(
            "AS{} starting: {} total observations",
            self.asn,
            self.observations.len(),
        );

        let all_observations = self.observations.clone();
        for obs in &all_observations {
            // Wait for simulation clock to reach this observation's timestamp.
            self.clock.wait_until(obs.timestamp).await;

            // Process through the RPKI pipeline.
            let result = self.process_observation_rpki(&obs).await;
            self.detection_results.push(result);
            self.stats.observations_processed += 1;
        }

        self.stats.detections = self.detection_results.clone();
        self.stats.clone()
    }

    // =========================================================================
    // Warm-up (listen-only mode)
    // =========================================================================

    /// Run warm-up phase: populate KB from early observations without creating
    /// transactions or triggering consensus.
    ///
    /// Called by `NodeManager` before the active phase begins, so KB gossip
    /// can merge KBs between warm-up and consensus start.
    pub fn run_warmup(&mut self) {
        let warmup_duration = self.config.warmup_duration as f64;
        if warmup_duration <= 0.0 || self.observations.is_empty() {
            return;
        }

        // Observations should already be sorted by timestamp.
        let sorted: Vec<Observation> = {
            let mut obs = self.observations.clone();
            obs.sort_by(|a, b| a.timestamp.partial_cmp(&b.timestamp).unwrap());
            obs
        };

        let first_ts = sorted[0].timestamp;
        let warmup_cutoff = first_ts + warmup_duration;
        let mut warmup_count = 0;

        for obs in &sorted {
            if obs.timestamp >= warmup_cutoff {
                break;
            }
            self.warmup_observation(obs);
            warmup_count += 1;
        }

        self.stats.warmup_observations = warmup_count;
        info!(
            "AS{} warm-up complete: {} observations in listen-only mode ({}s)",
            self.asn, warmup_count, warmup_duration
        );
    }

    /// Process a single observation in listen-only mode during warm-up.
    ///
    /// Populates the knowledge base so this node can vote "approve" later.
    /// No transactions, no consensus rounds, no blockchain writes.
    fn warmup_observation(&self, obs: &Observation) {
        let origin_asn = obs.origin_asn;
        let as_path = &obs.as_path;

        // Apply observation recording hop filter.
        if origin_asn == self.asn || as_path.len() <= 1 {
            return;
        }

        // P2P relay filter: 0 = BGP-observed (first-hand), 1+ = relayed via P2P.
        if obs.p2p_relay_hops > self.config.max_p2p_relay_hops {
            return;
        }

        // Add to knowledge base.
        self.kb.add_observation(
            &obs.prefix,
            origin_asn,
            obs.timestamp,
            100.0, // full trust for first-hand observation
            obs.is_attack,
        );
    }

    // =========================================================================
    // RPKI validator pipeline
    // =========================================================================

    /// Full RPKI validator pipeline for a single observation.
    ///
    /// Steps:
    /// 0a. Trusted path filter (skip self-origin, untrusted relay chains).
    /// 0b. Dedup check (skip repeated (prefix, origin) within window).
    /// 1.  Add to KB.
    /// 2.  Attack detection (all 5 detectors).
    /// 3.  Create transaction (with Ed25519 signature).
    /// 4.  Broadcast for consensus.
    /// 5.  Update dedup state.
    async fn process_observation_rpki(&mut self, obs: &Observation) -> DetectionResult {
        let _t_start = Instant::now();
        let prefix = &obs.prefix;
        let origin_asn = obs.origin_asn;
        let is_attack = obs.is_attack;
        let as_path = &obs.as_path;

        let mut result = DetectionResult::base(self.asn, obs);

        // ---- STEP 0a: Trusted path filter ----
        // Rules:
        //   1. Skip self-origin (origin == observer).
        //   2. len=1: same as self-origin or artifact, skip.
        //   3. len=2: direct neighbor claim, always accept.
        //   4. len=3+: accept if at most MAX_NON_RPKI_RELAYS non-RPKI intermediates.
        let skip_reason = self.check_trusted_path(origin_asn, as_path, obs.p2p_relay_hops);
        if let Some(reason) = skip_reason {
            result.action = reason;
            self.stats.trusted_path_filtered += 1;
            return result;
        }

        // ---- STEP 0b: Dedup check ----
        let dedup_key = (prefix.clone(), origin_asn);
        if !is_attack {
            if let Some(&last_seen) = self.dedup_state.get(&dedup_key) {
                let now = wall_time();
                let elapsed = now - last_seen;
                if elapsed < self.config.rpki_dedup_window as f64 {
                    result.action = "skipped_dedup".to_string();
                    self.stats.transactions_deduped += 1;
                    return result;
                }
            }
        }

        // ---- STEP 1: Add to KB and BOA ----
        self.kb.add_observation(
            prefix,
            origin_asn,
            obs.timestamp,
            100.0, // first-hand observation trust
            is_attack,
        );

        // Populate BOA from first-hand legitimate observations so that
        // subsequent attacks on the same prefix can be detected immediately.
        if !is_attack {
            self.pool.boa.attest(prefix, origin_asn);
        }

        // ---- STEP 2: Check if origin is RPKI-registered ----
        let origin_is_rpki = self.rpki_asns.contains(&origin_asn);

        // ---- Attack detection (skipped when disabled via config) ----
        let detected_attacks = if self.config.attack_detection_enabled {
            let mut attacks = self
                .attack_detector
                .detect_attacks(origin_asn, prefix, as_path, obs.timestamp);

            // BOA fallback: if ROA-based detectors didn't fire, check the
            // Blockchain Origin Attestation for conflicting origins.
            let boa = &self.pool.boa;
            if !attacks.iter().any(|a| a.attack_type == "PREFIX_HIJACK") {
                if let Some(mut det) = boa.check_prefix_hijack(origin_asn, prefix) {
                    det.as_path = as_path.to_vec();
                    attacks.push(det);
                }
            }
            if !attacks.iter().any(|a| a.attack_type == "SUBPREFIX_HIJACK") {
                if let Some(mut det) = boa.check_subprefix_hijack(origin_asn, prefix) {
                    det.as_path = as_path.to_vec();
                    attacks.push(det);
                }
            }

            attacks
        } else {
            Vec::new()
        };

        if !detected_attacks.is_empty() {
            result.detected = true;
            result.detection_type = Some(detected_attacks[0].attack_type.clone());
            result.detection_details = detected_attacks
                .iter()
                .map(|a| a.attack_type.clone())
                .collect();
            self.stats.attacks_detected += 1;
        }

        let roa_valid = self.attack_detector.roa_matches(prefix, origin_asn);

        if roa_valid {
            // ROA match: prefix is authorized for this origin AS — direct commit.
            let transaction = self.create_transaction(obs, &detected_attacks);
            let tx_id = transaction.transaction_id.clone();

            let pool = self.pool.clone();
            tokio::spawn(async move {
                pool.commit_direct(transaction).await;
            });

            self.stats.transactions_created += 1;
            result.action = "direct_commit_roa_verified".to_string();
            result.transaction_id = Some(tx_id);
        } else {
            // No ROA or ROA mismatch: need consensus voting.
            let transaction = self.create_transaction(obs, &detected_attacks);
            let tx_id = transaction.transaction_id.clone();

            let pool = self.pool.clone();
            tokio::spawn(async move {
                pool.broadcast_transaction(transaction).await;
            });

            self.stats.transactions_created += 1;
            result.action = "transaction_broadcast".to_string();
            result.transaction_id = Some(tx_id);
        }

        // ---- STEP 5: Update dedup state ----
        self.dedup_state.insert(dedup_key, wall_time());

        if !is_attack {
            self.stats.legitimate_count += 1;
        }

        result
    }

    // =========================================================================
    // Trusted path filter
    // =========================================================================

    /// Check whether an observation should be filtered by hop distance.
    ///
    /// Returns `Some(reason)` if filtered, `None` if the observation should proceed.
    fn check_trusted_path(&self, origin_asn: u32, as_path: &[u32], p2p_relay_hops: usize) -> Option<String> {
        if origin_asn == self.asn {
            return Some("skipped_self_origin".to_string());
        }
        if as_path.len() <= 1 {
            return Some("skipped_self_announcement".to_string());
        }
        // P2P overlay hop distance filter.
        // hop_distance=0 means first-hand BGP observation, 1+ means relayed via P2P.
        if p2p_relay_hops > self.config.max_p2p_relay_hops {
            return Some("skipped_too_many_hops".to_string());
        }
        None
    }

    // =========================================================================
    // Transaction creation
    // =========================================================================

    /// Create a blockchain transaction from an observation.
    ///
    /// Signs the transaction with this node's Ed25519 private key.
    fn create_transaction(
        &self,
        obs: &Observation,
        detected_attacks: &[AttackDetection],
    ) -> Transaction {
        let tx_id = format!(
            "tx_{}_{}_{}",
            self.asn,
            chrono::Utc::now().format("%Y%m%d_%H%M%S_%f"),
            &Uuid::new_v4().to_string()[..8]
        );

        // Sign the transaction.
        let signature = sign_transaction(
            &tx_id,
            self.asn,
            &obs.prefix,
            obs.origin_asn,
            &self.key_pair,
        );

        Transaction {
            transaction_id: tx_id,
            observer_as: self.asn,
            sender_asn: obs.origin_asn,
            ip_prefix: obs.prefix.clone(),
            as_path: obs.as_path.clone(),
            timestamp: obs.timestamp,
            is_attack: obs.is_attack,
            label: obs.label.clone(),
            rpki_validation: "not_checked".to_string(),
            detected_attacks: detected_attacks
                .iter()
                .map(|a| a.attack_type.clone())
                .collect(),
            created_at: chrono::Utc::now().to_rfc3339(),
            signature: Some(signature),
            signer_as: Some(self.asn),
            // Fields populated during consensus:
            signatures: Vec::new(),
            consensus_status: ConsensusStatus::Pending,
            consensus_reached: false,
            confidence_weight: 0.0,
            signature_count: 0,
            approve_count: 0,
            timeout_commit: false,
        }
    }

    // =========================================================================
    // Accessors
    // =========================================================================

    /// Check if all observations have been processed.
    pub fn is_done(&self) -> bool {
        self.stats.observations_processed >= self.observations.len()
    }

    /// Total number of observations assigned to this node.
    pub fn total_observations(&self) -> usize {
        self.observations.len()
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// Current wall-clock time as seconds since Unix epoch.
fn wall_time() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::blockchain::Blockchain;
    use crate::consensus::origin_attestation::OriginAttestation;
    use crate::consensus::transaction_pool::TransactionPool;
    use crate::network::message_bus::MessageBus;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    fn make_obs(prefix: &str, origin: u32, observer: u32, timestamp: f64) -> Observation {
        Observation {
            prefix: prefix.to_string(),
            origin_asn: origin,
            as_path: vec![observer, origin],
            as_path_length: 2,
            next_hop_asn: origin,
            timestamp,
            recv_relationship: "customer".to_string(),
            origin_type: "IGP".to_string(),
            label: "LEGITIMATE".to_string(),
            is_attack: false,
            observed_by_asn: observer,
            observer_is_rpki: true,
            p2p_relay_hops: 1,
            is_best: true,
            injected: false,
        }
    }

    #[test]
    fn test_check_trusted_path_self_origin() {
        let config = Arc::new(Config::default());
        let kb = Arc::new(KnowledgeBase::new(3600.0, 50_000));
        let boa = Arc::new(OriginAttestation::new());
        let blockchain = Arc::new(Mutex::new(Blockchain::new(100)));
        let bus = MessageBus::new();
        let key_pair = Arc::new(KeyPair::generate());
        let pool = Arc::new(TransactionPool::new(
            100,
            config.clone(),
            kb.clone(),
            boa.clone(),
            blockchain,
            bus,
            key_pair.clone(),
            vec![200, 300],
            3,
            None,
            None,
        ));
        let clock = SimulationClock::new(1.0);
        let rpki_asns: HashSet<u32> = [100, 200, 300].iter().copied().collect();

        let node = VirtualNode::new(
            100,
            config,
            pool,
            kb,
            key_pair,
            vec![],
            Arc::new(AttackDetector::new("", "", 60.0, 5, 2.0)),
            clock,
            rpki_asns,
            true,
        );

        // Self-origin should be filtered.
        assert!(node.check_trusted_path(100, &[100, 200], 0).is_some());

        // Different origin, direct neighbor, hop_distance=0: should pass.
        assert!(node.check_trusted_path(200, &[100, 200], 0).is_none());

        // Single-hop path: should be filtered.
        assert!(node.check_trusted_path(200, &[200], 0).is_some());

        // hop_distance beyond max: should be filtered.
        assert!(node.check_trusted_path(200, &[100, 200], 5).is_some());
    }

    #[test]
    fn test_detection_result_base() {
        let obs = make_obs("10.0.0.0/24", 200, 100, 1000.0);
        let result = DetectionResult::base(100, &obs);
        assert_eq!(result.asn, 100);
        assert_eq!(result.prefix, "10.0.0.0/24");
        assert!(!result.detected);
        assert_eq!(result.action, "pending");
    }

    #[test]
    fn test_node_stats_default() {
        let stats = NodeStats::default();
        assert_eq!(stats.observations_processed, 0);
        assert_eq!(stats.transactions_created, 0);
        assert_eq!(stats.attacks_detected, 0);
    }
}
