//! Node Manager — creates all infrastructure and virtual nodes, manages the
//! experiment lifecycle.
//!
//! Port of Python's `NodeManager` from `node_manager.py`.
//!
//! Each RPKI validator gets its own independent blockchain, key pair,
//! transaction pool, and knowledge base. Non-RPKI nodes observe and report
//! but do not participate in consensus or blockchain writes.
//!
//! # Dependencies (add to Cargo.toml)
//! ```toml
//! anyhow = "1"
//! ```

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Instant;

use ed25519_dalek::VerifyingKey;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::clock::SimulationClock;
use crate::config::Config;
use crate::consensus::blockchain::Blockchain;
use crate::consensus::knowledge_base::KnowledgeBase;
use crate::consensus::origin_attestation::OriginAttestation;
use crate::consensus::transaction_pool::TransactionPool;
use crate::crypto::KeyPair;
use crate::dataset::Dataset;
use crate::detection::AttackDetector;
use crate::network::message_bus::{Message, MessageBus};
use crate::output::*;
use crate::types::Observation;
use crate::virtual_node::{NodeStats, VirtualNode};

// ---------------------------------------------------------------------------
// ExperimentResults
// ---------------------------------------------------------------------------

/// Aggregated results from one experiment run.
#[derive(Debug, serde::Serialize)]
pub struct ExperimentResults {
    pub summary: ExperimentSummary,
    pub blockchain_stats: BlockchainStats,
    pub consensus_log: ConsensusLog,
    pub bus_stats: MessageBusStats,
    pub detection_results: Vec<DetectionResult>,
    pub elapsed: f64,
}

// ---------------------------------------------------------------------------
// NodeManager
// ---------------------------------------------------------------------------

/// Orchestrates the creation and lifecycle of all virtual nodes for a
/// BGP-Sentry experiment.
///
/// Each RPKI node maintains its own independent blockchain — there is no
/// shared / primary chain. Forks are expected and resolved via merge blocks.
pub struct NodeManager {
    config: Arc<Config>,
    dataset: Arc<Dataset>,
    clock: SimulationClock,
    bus: Arc<MessageBus>,

    // ── Per-RPKI-node infrastructure ─────────────────────────────────
    pools: HashMap<u32, Arc<TransactionPool>>,
    blockchains: HashMap<u32, Arc<tokio::sync::Mutex<Blockchain>>>,
    knowledge_bases: HashMap<u32, Arc<KnowledgeBase>>,
    origin_attestations: HashMap<u32, Arc<OriginAttestation>>,
    key_pairs: HashMap<u32, Arc<KeyPair>>,

    detector: Arc<AttackDetector>,
    rpki_asns: Vec<u32>,
}

impl NodeManager {
    // ------------------------------------------------------------------
    // Construction
    // ------------------------------------------------------------------

    /// Create a new `NodeManager`, building all per-node infrastructure.
    ///
    /// This is the equivalent of `NodeManager.__init__` in Python:
    /// 1. Creates the simulation clock and anchors it to the dataset epoch.
    /// 2. Creates the message bus (single shared instance).
    /// 3. Creates the attack detector (shared, stateless except flap history).
    /// 4. Per-RPKI-node: generates Ed25519 key pair, independent blockchain,
    ///    knowledge base, and transaction pool.
    pub fn new(config: Arc<Config>, dataset: Arc<Dataset>) -> Self {
        // ── Simulation clock ────────────────────────────────────────
        let clock = SimulationClock::new(config.simulation_speed_multiplier);

        // Find the BGP timestamp range across all observations.
        let mut ts_min: f64 = f64::INFINITY;
        let mut ts_max: f64 = f64::NEG_INFINITY;
        for obs_list in dataset.observations.values() {
            for obs in obs_list {
                // Filter out bogus timestamps (< ~year 2001)
                if obs.timestamp > 1_000_000_000.0 {
                    if obs.timestamp < ts_min {
                        ts_min = obs.timestamp;
                    }
                    if obs.timestamp > ts_max {
                        ts_max = obs.timestamp;
                    }
                }
            }
        }
        if ts_min == f64::INFINITY {
            ts_min = 0.0;
        }
        if ts_max == f64::NEG_INFINITY {
            ts_max = 0.0;
        }
        clock.set_epoch(ts_min);

        info!(
            "BGP timestamp range: {:.1} – {:.1} (span {:.1}s)",
            ts_min,
            ts_max,
            ts_max - ts_min
        );

        // ── Message bus ─────────────────────────────────────────────
        let bus = MessageBus::new();

        // ── Resolve AS-relationship + ROA paths ─────────────────────
        // Prefer the dataset's own as_relationships.json (full topology
        // coverage), falling back to blockchain_data/state/ (global).
        let dataset_as_rel = dataset.path.join("as_relationships.json");
        let state_dir = std::env::current_dir()
            .unwrap_or_default()
            .join("blockchain_data")
            .join("state");
        let as_rel_path = if dataset_as_rel.exists() {
            info!("Using dataset AS-relationships: {}", dataset_as_rel.display());
            dataset_as_rel
        } else {
            info!("Using global AS-relationships: {}", state_dir.join("as_relationships.json").display());
            state_dir.join("as_relationships.json")
        };
        let dataset_roa = dataset.path.join("roa_database.json");
        let roa_path = if dataset_roa.exists() {
            info!("Using dataset ROA database: {}", dataset_roa.display());
            dataset_roa
        } else {
            info!("Using global ROA database: {}", state_dir.join("roa_database.json").display());
            state_dir.join("roa_database.json")
        };

        let detector = Arc::new(AttackDetector::new(
            roa_path.to_str().unwrap_or(""),
            as_rel_path.to_str().unwrap_or(""),
            config.flap_window_seconds as f64,
            config.flap_threshold as usize,
            config.flap_dedup_seconds as f64,
        ));

        // ── Per-RPKI-node components ────────────────────────────────
        let rpki_asns: Vec<u32> = dataset.rpki_asns().to_vec();
        let mut key_pairs: HashMap<u32, Arc<KeyPair>> = HashMap::new();
        let mut blockchains: HashMap<u32, Arc<tokio::sync::Mutex<Blockchain>>> = HashMap::new();
        let mut knowledge_bases: HashMap<u32, Arc<KnowledgeBase>> = HashMap::new();
        let mut origin_attestations: HashMap<u32, Arc<OriginAttestation>> = HashMap::new();
        let mut pools: HashMap<u32, Arc<TransactionPool>> = HashMap::new();

        for &asn in &rpki_asns {
            // Ed25519 key pair
            let kp = Arc::new(KeyPair::generate());
            key_pairs.insert(asn, kp);

            // Independent per-node blockchain
            let chain = Arc::new(tokio::sync::Mutex::new(Blockchain::new(asn)));
            blockchains.insert(asn, chain);

            // Knowledge base
            let kb = Arc::new(KnowledgeBase::new(
                config.sampling_window_seconds as f64,
                config.knowledge_base_max_size,
            ));
            knowledge_bases.insert(asn, kb);

            // Blockchain Origin Attestation (BOA)
            let boa = Arc::new(OriginAttestation::new());
            origin_attestations.insert(asn, boa);
        }

        info!(
            "Generated Ed25519 key pairs for {} RPKI nodes, \
             created {} independent per-node blockchains",
            rpki_asns.len(),
            blockchains.len(),
        );

        // ── Topology-aware voting peer selection ────────────────────
        let rpki_set: HashSet<u32> = rpki_asns.iter().copied().collect();
        let adjacency = build_adjacency_map(&as_rel_path);
        let use_topology = adjacency.is_some() && config.consensus_voting_hops > 0;

        info!(
            "Voting hops: {}, voter_selection_mode: {} (configurable via env vars)",
            config.consensus_voting_hops, config.voter_selection_mode
        );

        // Shared adjacency and RPKI set for origin_neighbors mode.
        let shared_adjacency: Option<Arc<HashMap<u32, HashSet<u32>>>> =
            adjacency.as_ref().map(|a| Arc::new(a.clone()));
        let shared_rpki_set: Option<Arc<HashSet<u32>>> =
            if config.voter_selection_mode == "origin_neighbors" {
                Some(Arc::new(rpki_set.clone()))
            } else {
                None
            };

        // ── Transaction pools (created after the registry is fully populated)
        let mut peer_count_sum: usize = 0;
        let mut peer_count_min: usize = usize::MAX;
        let mut peer_count_max: usize = 0;

        for &asn in &rpki_asns {
            let mut peer_nodes: Vec<u32> = if use_topology {
                compute_voting_peers(
                    asn,
                    &rpki_set,
                    adjacency.as_ref().unwrap(),
                    config.consensus_voting_hops,
                )
            } else {
                // Fallback: all other RPKI validators
                rpki_asns.iter().copied().filter(|&a| a != asn).collect()
            };

            // If topology BFS found 0 peers, fall back to all other RPKI
            // validators so the node is not isolated from consensus.
            if peer_nodes.is_empty() && use_topology {
                peer_nodes = rpki_asns.iter().copied().filter(|&a| a != asn).collect();
            }

            let n = peer_nodes.len();
            peer_count_sum += n;
            if n < peer_count_min {
                peer_count_min = n;
            }
            if n > peer_count_max {
                peer_count_max = n;
            }

            let total_nodes = rpki_asns.len();
            let pool = Arc::new(TransactionPool::new(
                asn,
                Arc::clone(&config),
                Arc::clone(knowledge_bases.get(&asn).unwrap()),
                Arc::clone(origin_attestations.get(&asn).unwrap()),
                Arc::clone(blockchains.get(&asn).unwrap()),
                Arc::clone(&bus),
                Arc::clone(key_pairs.get(&asn).unwrap()),
                peer_nodes,
                total_nodes,
                shared_adjacency.clone(),
                shared_rpki_set.clone(),
            ));
            pools.insert(asn, pool);
        }

        if !rpki_asns.is_empty() {
            if peer_count_min == usize::MAX {
                peer_count_min = 0;
            }
            let avg_peers = peer_count_sum as f64 / rpki_asns.len() as f64;
            info!(
                "Avg voting peers per validator: {:.1} (min={}, max={})",
                avg_peers, peer_count_min, peer_count_max
            );
        }

        let total_observers = dataset.observations.len();
        let non_rpki_count = total_observers.saturating_sub(rpki_asns.len());
        info!(
            "NodeManager ready: {} total observers ({} RPKI, {} non-RPKI)",
            total_observers,
            rpki_asns.len(),
            non_rpki_count,
        );

        Self {
            config,
            dataset,
            clock,
            bus,
            pools,
            blockchains,
            knowledge_bases,
            origin_attestations,
            key_pairs,
            detector,
            rpki_asns,
        }
    }

    // ------------------------------------------------------------------
    // Main experiment flow
    // ------------------------------------------------------------------

    /// Run the full experiment and return aggregated results.
    ///
    /// Phases:
    /// 1a. Register RPKI nodes with message bus.
    ///  2. Start the simulation clock.
    ///  3. Spawn tokio tasks for RPKI nodes (consensus + observation processing).
    ///  4. Non-RPKI nodes skipped (no consensus participation).
    ///  5. Wait for all nodes to complete.
    ///  6. Drain: stop ingestion, drain pending consensus rounds.
    ///  7. Collect and return results.
    ///
    /// No warm-up or KB gossip — each node builds knowledge only from its
    /// own observations during the active phase. Voting peers verify
    /// announcements against their own local observations.
    pub async fn run(&self) -> anyhow::Result<ExperimentResults> {
        let wall_start = Instant::now();

        // ── Phase 1a: Register RPKI nodes with message bus ──────────
        let mut message_rxs: HashMap<u32, mpsc::Receiver<Message>> = HashMap::new();
        for &asn in &self.rpki_asns {
            let rx = self.bus.register(asn);
            message_rxs.insert(asn, rx);
        }
        info!(
            "Registered {} RPKI nodes with message bus",
            self.rpki_asns.len()
        );

        // KB warm-up and gossip removed — nodes build knowledge from
        // their own observations during active phase only.
        info!("No KB warm-up or gossip — nodes start with empty knowledge base");

        // ── Phase 2: Start simulation clock ─────────────────────────
        self.clock.start();
        info!(
            "Simulation clock started (speed={:.1}x)",
            self.config.simulation_speed_multiplier
        );

        // ── Phase 3: Start pools, spawn timeout loops, spawn RPKI node tasks
        let mut handles: Vec<JoinHandle<(u32, NodeStats)>> = Vec::new();
        let mut bg_handles: Vec<JoinHandle<()>> = Vec::new();

        for &asn in &self.rpki_asns {
            let pool = Arc::clone(self.pools.get(&asn).unwrap());

            // Mark the pool as running so handle_message() accepts messages.
            pool.start();

            // Spawn the timeout loop (commits pending TXs after P2P timeout).
            let pool_t = Arc::clone(&pool);
            bg_handles.push(tokio::spawn(async move {
                pool_t.run_timeout_loop().await;
            }));

            // Spawn KB cleanup loop.
            let pool_k = Arc::clone(&pool);
            bg_handles.push(tokio::spawn(async move {
                pool_k.run_kb_cleanup_loop().await;
            }));

            // Spawn committed-TX cleanup loop.
            let pool_c = Arc::clone(&pool);
            bg_handles.push(tokio::spawn(async move {
                pool_c.run_committed_cleanup_loop().await;
            }));

            // Message handler task
            let pool_m = Arc::clone(&pool);
            let rx = message_rxs.remove(&asn).unwrap();
            bg_handles.push(tokio::spawn(message_handler_loop(pool_m, rx)));

            // Node observation processing task
            let mut node = self.create_virtual_node(asn, true);
            let handle = tokio::spawn(async move {
                let stats = node.run().await;
                (asn, stats)
            });
            handles.push(handle);
        }

        // ── Phase 4: Non-RPKI nodes skipped ──────────────────────────
        // Non-RPKI nodes do not participate in consensus, voting, or
        // blockchain writes. Their BGP observations already propagated
        // through BGPy and reached RPKI nodes. No need to simulate them.
        let all_asns = self.dataset.all_observer_asns();
        let non_rpki_count = all_asns.iter().filter(|a| !self.dataset.is_rpki(**a)).count();
        info!(
            "Skipped {} non-RPKI nodes (observe-only, no consensus participation)",
            non_rpki_count
        );

        info!("Spawned {} RPKI node tasks", handles.len());

        // ── Progress monitor: log consensus levels every 10s ────────
        let pools_monitor: Vec<Arc<TransactionPool>> =
            self.pools.values().map(|p| Arc::clone(p)).collect();
        bg_handles.push(tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                let (mut confirmed, mut insufficient, mut single, mut committed, mut created, mut pending) =
                    (0u64, 0u64, 0u64, 0u64, 0u64, 0usize);
                let (mut v_origin, mut v_path, mut v_random) = (0u64, 0u64, 0u64);
                for pool in &pools_monitor {
                    let s = pool.stats_snapshot();
                    confirmed += s.confirmed_count;
                    insufficient += s.insufficient_count;
                    single += s.single_witness_count;
                    committed += s.transactions_committed;
                    created += s.transactions_created;
                    pending += pool.pending_count();
                    v_origin += s.voters_from_origin_neighbors;
                    v_path += s.voters_from_as_path;
                    v_random += s.voters_from_random;
                }
                if created == 0 && pending == 0 {
                    continue;
                }
                let total = confirmed + insufficient + single;
                let pct_c = if total > 0 { 100.0 * confirmed as f64 / total as f64 } else { 0.0 };
                let pct_i = if total > 0 { 100.0 * insufficient as f64 / total as f64 } else { 0.0 };
                let pct_s = if total > 0 { 100.0 * single as f64 / total as f64 } else { 0.0 };
                let v_total = v_origin + v_path + v_random;
                let pv_o = if v_total > 0 { 100.0 * v_origin as f64 / v_total as f64 } else { 0.0 };
                let pv_p = if v_total > 0 { 100.0 * v_path as f64 / v_total as f64 } else { 0.0 };
                let pv_r = if v_total > 0 { 100.0 * v_random as f64 / v_total as f64 } else { 0.0 };
                info!(
                    "[PROGRESS] created={} committed={} pending={} | CONFIRMED={} ({:.1}%) INSUFFICIENT={} ({:.1}%) SINGLE_WITNESS={} ({:.1}%) | voters: origin_nbr={:.1}% path={:.1}% random={:.1}%",
                    created, committed, pending, confirmed, pct_c, insufficient, pct_i, single, pct_s, pv_o, pv_p, pv_r
                );
            }
        }));

        // ── Phase 5: Wait for all nodes to complete ─────────────────
        let timeout = tokio::time::Duration::from_secs(self.config.sim_duration);
        let mut node_stats: HashMap<u32, NodeStats> = HashMap::new();

        // Use a deadline rather than wrapping the entire await block, so that
        // when the deadline fires we can still abort individual handles and
        // collect whatever partial stats are available.
        let deadline = tokio::time::Instant::now() + timeout;

        for handle in handles {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                // Deadline already passed — abort remaining handles.
                handle.abort();
                continue;
            }
            match tokio::time::timeout(remaining, handle).await {
                Ok(Ok((asn, stats))) => {
                    node_stats.insert(asn, stats);
                }
                Ok(Err(e)) => {
                    warn!("Node task panicked: {}", e);
                }
                Err(_) => {
                    // This handle timed out — abort it so resources are freed.
                    // The stats from this node won't be included.
                    warn!(
                        "Node task timed out after {}s, {} nodes completed so far",
                        self.config.sim_duration,
                        node_stats.len()
                    );
                    // Don't break — try to collect already-finished handles.
                }
            }
        }

        info!(
            "{}/{} node tasks completed within {}s deadline",
            node_stats.len(),
            all_asns.len(),
            self.config.sim_duration
        );

        // ── Phase 6: Drain pending consensus ────────────────────────
        // First drain all pending transactions (commits them with partial consensus).
        for pool in self.pools.values() {
            pool.drain().await;
        }

        // Stop all pools — background loops will exit.
        for pool in self.pools.values() {
            pool.stop();
        }

        // Abort background tasks (timeout loops, cleanup loops, msg handlers).
        for handle in bg_handles {
            handle.abort();
        }

        // ── Phase 7: Collect results ────────────────────────────────
        let elapsed = wall_start.elapsed().as_secs_f64();
        let results = self.collect_results(node_stats, elapsed);

        info!("Experiment completed in {:.1}s", elapsed);

        Ok(results)
    }

    // ------------------------------------------------------------------
    // Warm-up
    // ------------------------------------------------------------------

    /// Populate each RPKI node's knowledge base with its local observations
    /// (the subset within the warm-up duration window).
    fn run_warmup(&self) {
        let warmup_secs = self.config.warmup_duration as f64;
        let mut total_entries = 0usize;

        for &asn in &self.rpki_asns {
            let kb = match self.knowledge_bases.get(&asn) {
                Some(kb) => kb,
                None => continue,
            };
            let obs_list = match self.dataset.observations.get(&asn) {
                Some(o) => o,
                None => continue,
            };

            // Find timestamp baseline for this node's observations
            let ts_min = obs_list
                .iter()
                .filter(|o| o.timestamp > 1_000_000_000.0)
                .map(|o| o.timestamp)
                .fold(f64::INFINITY, f64::min);

            if ts_min == f64::INFINITY {
                continue;
            }

            let cutoff = ts_min + warmup_secs;
            let mut added = 0usize;

            for obs in obs_list {
                if obs.timestamp > 1_000_000_000.0 && obs.timestamp <= cutoff {
                    if kb.add_observation(
                        &obs.prefix,
                        obs.origin_asn,
                        obs.timestamp,
                        80.0, // default trust score
                        obs.is_attack,
                    ) {
                        added += 1;
                    }
                }
            }

            total_entries += added;
        }

        info!(
            "Warm-up complete: {} total KB entries across {} RPKI nodes \
             (window={}s)",
            total_entries,
            self.rpki_asns.len(),
            warmup_secs
        );
    }

    // ------------------------------------------------------------------
    // KB Gossip
    // ------------------------------------------------------------------

    /// Merge all RPKI nodes' knowledge bases in a single pass (one-shot gossip).
    ///
    /// After warm-up each node has only local observations. This method
    /// collects all unique `(prefix, origin_asn)` entries and injects them
    /// into every peer's KB, mirroring standard bootstrap protocols (Bitcoin
    /// IBD, BGP full table exchange).
    fn run_kb_gossip(&self) {
        if self.rpki_asns.len() < 2 {
            info!(
                "KB gossip skipped: only {} RPKI nodes",
                self.rpki_asns.len()
            );
            return;
        }

        // Collect all unique KB entries: (prefix, origin_asn) -> (timestamp, source_asn)
        let mut all_entries: HashMap<(String, u32), (f64, u32)> = HashMap::new();

        for &asn in &self.rpki_asns {
            let kb = match self.knowledge_bases.get(&asn) {
                Some(kb) => kb,
                None => continue,
            };

            // Access all entries via the per-prefix accessor.
            // We iterate observations from the dataset that were added during
            // warm-up to reconstruct the (prefix, origin_asn) set.
            let obs_list = match self.dataset.observations.get(&asn) {
                Some(o) => o,
                None => continue,
            };

            for obs in obs_list {
                if obs.timestamp <= 0.0 {
                    continue;
                }
                let key = (obs.prefix.clone(), obs.origin_asn);
                all_entries.entry(key).or_insert((obs.timestamp, asn));
            }
        }

        if all_entries.is_empty() {
            info!(
                "KB gossip: no entries found across {} RPKI nodes",
                self.rpki_asns.len()
            );
            return;
        }

        // Inject merged entries into every peer's KB
        let mut max_injected: usize = 0;

        for &asn in &self.rpki_asns {
            let kb = match self.knowledge_bases.get(&asn) {
                Some(kb) => kb,
                None => continue,
            };

            let mut injected = 0usize;
            for ((prefix, origin_asn), (timestamp, _source)) in &all_entries {
                // Attempt to add — the KB's own sampling gate will skip
                // duplicates that were already added during warm-up.
                if kb.add_observation(prefix, *origin_asn, *timestamp, 80.0, false) {
                    injected += 1;
                }
            }
            if injected > max_injected {
                max_injected = injected;
            }
        }

        info!(
            "KB gossip: merged {} unique observations across {} RPKI peers \
             (up to {} new entries per peer)",
            all_entries.len(),
            self.rpki_asns.len(),
            max_injected,
        );
    }

    // ------------------------------------------------------------------
    // Virtual node factory
    // ------------------------------------------------------------------

    /// Create a `VirtualNode` for a given observer AS.
    ///
    /// RPKI nodes get the full consensus stack (pool, blockchain, KB, key
    /// pair). Non-RPKI nodes get only the detector and clock.
    fn create_virtual_node(&self, asn: u32, is_rpki: bool) -> VirtualNode {
        let raw_obs = self
            .dataset
            .observations
            .get(&asn)
            .cloned()
            .unwrap_or_default();

        // Convert RawObservation -> Observation (types module)
        let observations: Vec<Observation> = raw_obs
            .into_iter()
            .map(|r| Observation {
                prefix: r.prefix,
                origin_asn: r.origin_asn,
                as_path: r.as_path,
                as_path_length: r.as_path_length,
                next_hop_asn: r.next_hop_asn,
                timestamp: r.timestamp,
                recv_relationship: r.recv_relationship,
                origin_type: r.origin_type,
                label: r.label,
                is_attack: r.is_attack,
                observed_by_asn: r.observed_by_asn,
                observer_is_rpki: r.observer_is_rpki,
                p2p_relay_hops: r.p2p_relay_hops,
                is_best: r.is_best,
                injected: r.injected,
            })
            .collect();

        let rpki_set: HashSet<u32> = self.rpki_asns.iter().copied().collect();

        if is_rpki {
            VirtualNode::new(
                asn,
                Arc::clone(&self.config),
                Arc::clone(self.pools.get(&asn).unwrap()),
                Arc::clone(self.knowledge_bases.get(&asn).unwrap()),
                Arc::clone(self.key_pairs.get(&asn).unwrap()),
                observations,
                Arc::clone(&self.detector),
                self.clock.clone(),
                rpki_set,
                true,
            )
        } else {
            // Non-RPKI nodes are passive — use a dummy pool/kb/keypair.
            // Pick any RPKI node's resources (non-RPKI nodes don't create
            // transactions, so the pool won't be written to).
            let any_rpki = self.rpki_asns[0];
            VirtualNode::new(
                asn,
                Arc::clone(&self.config),
                Arc::clone(self.pools.get(&any_rpki).unwrap()),
                Arc::clone(self.knowledge_bases.get(&any_rpki).unwrap()),
                Arc::clone(self.key_pairs.get(&any_rpki).unwrap()),
                observations,
                Arc::clone(&self.detector),
                self.clock.clone(),
                rpki_set,
                false,
            )
        }
    }

    // ------------------------------------------------------------------
    // Results collection
    // ------------------------------------------------------------------

    /// Collect and aggregate all experiment results.
    fn collect_results(
        &self,
        node_stats: HashMap<u32, NodeStats>,
        elapsed: f64,
    ) -> ExperimentResults {
        let summary = self.collect_summary(&node_stats, elapsed);
        let blockchain_stats = self.collect_blockchain_stats();
        let consensus_log = self.collect_consensus_log();
        let bus = self.bus.stats();
        let bus_stats = MessageBusStats {
            sent: bus.sent,
            delivered: bus.delivered,
            dropped: bus.dropped,
        };
        let detection_results = self.collect_detection_results(&node_stats);

        ExperimentResults {
            summary,
            blockchain_stats,
            consensus_log,
            bus_stats,
            detection_results,
            elapsed,
        }
    }

    /// Build the top-level experiment summary.
    fn collect_summary(
        &self,
        node_stats: &HashMap<u32, NodeStats>,
        elapsed: f64,
    ) -> ExperimentSummary {
        let total_processed: usize = node_stats.values().map(|s| s.observations_processed).sum();
        let attacks_detected: usize = node_stats.values().map(|s| s.attacks_detected).sum();
        let legitimate_processed: usize = node_stats.values().map(|s| s.legitimate_count).sum();

        let timestamp = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S").to_string();

        ExperimentSummary {
            dataset: DatasetSummary {
                dataset_name: self.dataset.name.clone(),
                dataset_path: self.dataset.path.display().to_string(),
                total_ases: self.dataset.classification.total_ases,
                rpki_count: self.dataset.classification.rpki_count,
                non_rpki_count: self.dataset.classification.non_rpki_count,
                total_observations: self.dataset.total_observations,
                attack_observations: self.dataset.attack_observations,
                legitimate_observations: self.dataset.legitimate_observations,
            },
            node_summary: NodeSummary {
                total_nodes: node_stats.len(),
                rpki_nodes: self.rpki_asns.len(),
                non_rpki_nodes: node_stats.len().saturating_sub(self.rpki_asns.len()),
                nodes_done: node_stats.len(),
                total_observations_processed: total_processed,
                attacks_detected,
                legitimate_processed,
            },
            performance: PerformanceSummary {
                ground_truth_attacks: self.dataset.ground_truth.total_attacks,
                total_detections: attacks_detected,
                true_positives: 0,  // Computed post-hoc by result analysis
                false_positives: 0,
                false_negatives: 0,
                precision: 0.0,
                recall: 0.0,
                f1_score: 0.0,
            },
            elapsed_seconds: elapsed,
            timestamp,
        }
    }

    /// Aggregate blockchain statistics from all per-node chains.
    fn collect_blockchain_stats(&self) -> BlockchainStats {
        let mut blocks_counts: Vec<f64> = Vec::new();
        let mut tx_counts: Vec<f64> = Vec::new();
        let mut valid_chains = 0usize;
        let mut total_forks: u64 = 0;
        let mut total_resolved: u64 = 0;
        let mut total_merges: u64 = 0;

        // We cannot hold async Mutex across this sync function, so we use
        // try_lock which is fine post-experiment (all tasks have finished).
        for (&_asn, chain_mutex) in &self.blockchains {
            if let Ok(chain) = chain_mutex.try_lock() {
                let stats = chain.stats();
                blocks_counts.push(stats.block_count as f64);
                tx_counts.push(stats.transaction_count as f64);
                total_forks += stats.forks_detected;
                total_resolved += stats.forks_resolved;
                total_merges += stats.merge_blocks;
                if chain.is_valid() {
                    valid_chains += 1;
                }
            }
        }

        BlockchainStats {
            architecture: "per-node independent blockchains".into(),
            total_nodes: self.blockchains.len(),
            valid_chains,
            all_valid: valid_chains == self.blockchains.len(),
            blocks_per_node: dist_stats(&blocks_counts),
            transactions_per_node: dist_stats(&tx_counts),
            total_forks_detected: total_forks,
            total_forks_resolved: total_resolved,
            total_merge_blocks: total_merges,
        }
    }

    /// Aggregate consensus decision statistics across all RPKI chains.
    fn collect_consensus_log(&self) -> ConsensusLog {
        let mut total_committed: usize = 0;
        let mut total_pending: usize = 0;
        let mut total_created: usize = 0;

        let mut status_all: HashMap<String, usize> = HashMap::new();
        let mut status_unique: HashMap<String, std::collections::HashSet<String>> = HashMap::new();
        let mut block_type_counts: HashMap<String, usize> = HashMap::new();
        let mut unique_tx_ids: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        // Pool-level stats via stats_snapshot()
        for pool in self.pools.values() {
            let snap = pool.stats_snapshot();
            total_committed += snap.transactions_committed as usize;
            total_pending += pool.pending_count();
            total_created += snap.transactions_created as usize;
        }

        // Scan all per-node blockchains for per-transaction consensus status
        for chain_mutex in self.blockchains.values() {
            if let Ok(chain) = chain_mutex.try_lock() {
                for block in &chain.blocks {
                    let bt = block.block_type.to_string();
                    *block_type_counts.entry(bt).or_default() += 1;

                    for tx in &block.transactions {
                        unique_tx_ids.insert(tx.transaction_id.clone());
                        let cs = tx.consensus_status.to_string();
                        *status_all.entry(cs.clone()).or_default() += 1;
                        status_unique
                            .entry(cs)
                            .or_default()
                            .insert(tx.transaction_id.clone());
                    }
                }
            }
        }

        ConsensusLog {
            total_transactions_created: total_created,
            total_committed,
            total_pending,
            consensus_status_all_chains: status_all,
            consensus_status_unique: status_unique
                .into_iter()
                .map(|(k, v)| (k, v.len()))
                .collect(),
            unique_transactions_across_chains: unique_tx_ids.len(),
            block_type_counts,
        }
    }

    /// Collect detection results from all node stats.
    ///
    /// Converts `virtual_node::DetectionResult` into `output::DetectionResult`.
    fn collect_detection_results(
        &self,
        node_stats: &HashMap<u32, NodeStats>,
    ) -> Vec<DetectionResult> {
        let mut results = Vec::new();
        for (_asn, stats) in node_stats {
            for det in &stats.detections {
                results.push(DetectionResult {
                    asn: det.asn,
                    prefix: det.prefix.clone(),
                    origin_asn: det.origin_asn,
                    label: det.label.clone(),
                    is_attack: det.is_attack,
                    timestamp: det.timestamp,
                    detected: det.detected,
                    detection_type: det.detection_type.clone(),
                    action: det.action.clone(),
                    rpki_validation: String::new(),
                    transaction_id: det.transaction_id.clone().unwrap_or_default(),
                });
            }
        }
        results
    }

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------

    /// Reference to the simulation clock.
    pub fn clock(&self) -> &SimulationClock {
        &self.clock
    }

    /// Reference to the message bus.
    pub fn bus(&self) -> &Arc<MessageBus> {
        &self.bus
    }

    /// Reference to the configuration.
    pub fn config(&self) -> &Arc<Config> {
        &self.config
    }

    /// Sorted list of RPKI validator ASNs.
    pub fn rpki_asns(&self) -> &[u32] {
        &self.rpki_asns
    }
}

// ---------------------------------------------------------------------------
// Topology-aware voting peer selection
// ---------------------------------------------------------------------------

/// Build an adjacency map from the as_relationships.json file.
///
/// Returns `HashMap<u32, HashSet<u32>>` where each AS maps to all its
/// neighbors (customers + providers + peers, bidirectional).
fn build_adjacency_map(as_rel_path: &std::path::Path) -> Option<HashMap<u32, HashSet<u32>>> {
    let data = match std::fs::read_to_string(as_rel_path) {
        Ok(d) => d,
        Err(e) => {
            warn!(
                "Failed to read as_relationships.json at {}: {} — falling back to all-validators",
                as_rel_path.display(),
                e
            );
            return None;
        }
    };

    let raw: HashMap<String, serde_json::Value> = match serde_json::from_str(&data) {
        Ok(v) => v,
        Err(e) => {
            warn!(
                "Failed to parse as_relationships.json: {} — falling back to all-validators",
                e
            );
            return None;
        }
    };

    let mut adj: HashMap<u32, HashSet<u32>> = HashMap::new();
    for (asn_str, entry) in &raw {
        let a: u32 = match asn_str.parse() {
            Ok(v) => v,
            Err(_) => continue,
        };

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

        let neighbors: Vec<u32> = parse_list("customers")
            .into_iter()
            .chain(parse_list("providers"))
            .chain(parse_list("peers"))
            .collect();

        for &n in &neighbors {
            adj.entry(a).or_default().insert(n);
            adj.entry(n).or_default().insert(a);
        }
    }

    Some(adj)
}

/// Compute the voting peers for a validator using BFS up to `consensus_voting_hops`
/// distance in the AS topology.
///
/// The BFS traverses through ANY AS (RPKI or not) but only collects RPKI
/// validators as voting peers. This reflects that BGP announcements travel
/// through all ASes, but only RPKI validators can vote.
fn compute_voting_peers(
    asn: u32,
    rpki_set: &HashSet<u32>,
    adj: &HashMap<u32, HashSet<u32>>,
    consensus_voting_hops: u8,
) -> Vec<u32> {
    let empty = HashSet::new();
    let mut reachable_validators: Vec<u32> = Vec::new();
    let mut visited: HashSet<u32> = HashSet::new();
    let mut queue: VecDeque<(u32, u8)> = VecDeque::new();

    visited.insert(asn);
    queue.push_back((asn, 0));

    while let Some((node, depth)) = queue.pop_front() {
        if depth >= consensus_voting_hops {
            continue;
        }
        for &neighbor in adj.get(&node).unwrap_or(&empty) {
            if visited.contains(&neighbor) {
                continue;
            }
            visited.insert(neighbor);
            // Collect RPKI validators as voting peers
            if rpki_set.contains(&neighbor) && neighbor != asn {
                reachable_validators.push(neighbor);
            }
            // Continue BFS through any node (RPKI or not) if more hops available
            queue.push_back((neighbor, depth + 1));
        }
    }

    reachable_validators
}

// ---------------------------------------------------------------------------
// Message handler loop
// ---------------------------------------------------------------------------

/// Per-RPKI-node message handler task.
///
/// Receives messages from the bus and dispatches them to the node's
/// transaction pool (vote requests, vote responses, block replication).
async fn message_handler_loop(
    pool: Arc<TransactionPool>,
    mut rx: mpsc::Receiver<Message>,
) {
    while let Some(msg) = rx.recv().await {
        pool.handle_message(msg).await;
    }
}
