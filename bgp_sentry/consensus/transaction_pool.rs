//! Core consensus engine — async P2P transaction pool with voting.
//!
//! Port of Python's `AsyncP2PTransactionPool` from
//! `p2p_transaction_pool_async.py`. This is the central module that:
//!
//! 1. Broadcasts new transactions to adaptively-selected peers for voting.
//! 2. Handles incoming vote requests by consulting the knowledge base.
//! 3. Collects vote responses and commits when threshold is reached.
//! 4. Replicates committed blocks to a gossip subset of peers.
//! 5. Times out pending transactions and commits with partial consensus.
//!
//! Concurrency model: all shared state uses `DashMap` (lock-free concurrent
//! hash maps) or `AtomicU64` counters. The only `tokio::sync::Mutex` wraps
//! the `Blockchain` (which requires sequential block appends). No GIL.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use rand::seq::SliceRandom;
use rand::thread_rng;
use tokio::sync::{Mutex, Notify};
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::consensus::blockchain::Blockchain;
use crate::consensus::knowledge_base::KnowledgeBase;
use crate::consensus::origin_attestation::OriginAttestation;
use crate::crypto::{sign_vote, KeyPair};
use crate::network::message_bus::{Message, MessageBus};
use crate::types::*;

// =============================================================================
// PendingVote — tracks an in-flight consensus round
// =============================================================================

/// State for a single transaction awaiting consensus.
struct PendingVote {
    /// The transaction being voted on.
    transaction: Transaction,
    /// Collected votes so far.
    votes: Vec<VoteRecord>,
    /// Number of APPROVE votes needed for CONFIRMED status.
    needed: u32,
    /// Wall-clock instant when this round was created.
    created_at: Instant,
    /// Whether the underlying observation was flagged as an attack.
    is_attack: bool,
}

// =============================================================================
// PoolStats
// =============================================================================

/// Atomic counters for transaction pool activity.
pub struct PoolStats {
    pub transactions_created: AtomicU64,
    pub transactions_committed: AtomicU64,
    pub transactions_timed_out: AtomicU64,
    pub votes_cast: AtomicU64,
    pub blocks_replicated: AtomicU64,
    pub confirmed_count: AtomicU64,
    pub insufficient_count: AtomicU64,
    pub single_witness_count: AtomicU64,
    /// Voter selection layer stats.
    pub voters_from_origin_neighbors: AtomicU64,
    pub voters_from_as_path: AtomicU64,
    pub voters_from_random: AtomicU64,
}

impl PoolStats {
    fn new() -> Self {
        Self {
            transactions_created: AtomicU64::new(0),
            transactions_committed: AtomicU64::new(0),
            transactions_timed_out: AtomicU64::new(0),
            votes_cast: AtomicU64::new(0),
            blocks_replicated: AtomicU64::new(0),
            confirmed_count: AtomicU64::new(0),
            insufficient_count: AtomicU64::new(0),
            single_witness_count: AtomicU64::new(0),
            voters_from_origin_neighbors: AtomicU64::new(0),
            voters_from_as_path: AtomicU64::new(0),
            voters_from_random: AtomicU64::new(0),
        }
    }
}

/// Snapshot of pool stats (non-atomic, for reporting).
#[derive(Debug, Clone)]
pub struct PoolStatsSnapshot {
    pub transactions_created: u64,
    pub transactions_committed: u64,
    pub transactions_timed_out: u64,
    pub votes_cast: u64,
    pub blocks_replicated: u64,
    pub confirmed_count: u64,
    pub insufficient_count: u64,
    pub single_witness_count: u64,
    pub voters_from_origin_neighbors: u64,
    pub voters_from_as_path: u64,
    pub voters_from_random: u64,
}

// =============================================================================
// TransactionPool
// =============================================================================

/// The core consensus engine for a single RPKI validator node.
///
/// Manages transaction lifecycle: creation -> broadcast -> vote collection ->
/// blockchain commit. Thread-safe via `DashMap` and atomics; designed to be
/// wrapped in `Arc` and shared across tasks.
pub struct TransactionPool {
    /// ASN of this validator node.
    pub as_number: u32,

    /// Global configuration.
    config: Arc<Config>,

    /// This node's knowledge base (shared with the virtual node).
    kb: Arc<KnowledgeBase>,

    /// Blockchain Origin Attestation — consensus-derived origin registry
    /// (shared with the virtual node for BOA-based attack detection).
    pub boa: Arc<OriginAttestation>,

    /// This node's blockchain (mutex-protected for sequential appends).
    blockchain: Arc<Mutex<Blockchain>>,

    /// Async message bus for P2P communication.
    bus: Arc<MessageBus>,

    /// Ed25519 key pair for signing votes and transactions.
    key_pair: Arc<KeyPair>,

    /// All other RPKI validator ASNs (peers).
    peer_nodes: Vec<u32>,

    /// CAIDA topology adjacency map (for origin_neighbors voter selection).
    adjacency: Option<Arc<HashMap<u32, HashSet<u32>>>>,

    /// Set of all RPKI validator ASNs (for origin_neighbors lookup).
    rpki_set: Option<Arc<HashSet<u32>>>,

    /// Consensus threshold: minimum APPROVE votes for CONFIRMED status.
    consensus_threshold: u32,

    /// Total number of RPKI validator nodes in the network.
    total_nodes: usize,

    /// Pending consensus rounds: tx_id -> PendingVote.
    pending_votes: DashMap<String, PendingVote>,

    /// Network-wide dedup: (prefix, origin) pairs that already have a pending
    /// vote_request from this or another node. Prevents redundant TXs.
    pending_event_keys: DashMap<(String, u32), ()>,

    /// Committed transactions: tx_id -> commit wall-clock instant.
    committed_transactions: DashMap<String, Instant>,

    /// Pool running flag.
    running: AtomicBool,

    /// Drain mode: stop accepting new vote requests but keep processing
    /// in-flight rounds.
    draining: AtomicBool,

    /// Notifies the timeout loop that new transactions have been added.
    new_tx_notify: Notify,

    /// Aggregate statistics.
    pub stats: Arc<PoolStats>,
}

impl TransactionPool {
    /// Create a new transaction pool.
    ///
    /// # Arguments
    /// * `as_number` — This node's ASN.
    /// * `config` — Global configuration.
    /// * `kb` — Shared knowledge base.
    /// * `blockchain` — Mutex-protected per-node blockchain.
    /// * `bus` — Async message bus.
    /// * `key_pair` — Ed25519 key pair for signing.
    /// * `peer_nodes` — List of all other RPKI validator ASNs.
    /// * `total_nodes` — Total RPKI validator count (including self).
    pub fn new(
        as_number: u32,
        config: Arc<Config>,
        kb: Arc<KnowledgeBase>,
        boa: Arc<OriginAttestation>,
        blockchain: Arc<Mutex<Blockchain>>,
        bus: Arc<MessageBus>,
        key_pair: Arc<KeyPair>,
        peer_nodes: Vec<u32>,
        total_nodes: usize,
        adjacency: Option<Arc<HashMap<u32, HashSet<u32>>>>,
        rpki_set: Option<Arc<HashSet<u32>>>,
    ) -> Self {
        let consensus_threshold = config.consensus_threshold(total_nodes) as u32;
        Self {
            as_number,
            config,
            kb,
            boa,
            blockchain,
            bus,
            key_pair,
            peer_nodes,
            adjacency,
            rpki_set,
            consensus_threshold,
            total_nodes,
            pending_votes: DashMap::new(),
            pending_event_keys: DashMap::new(),
            committed_transactions: DashMap::new(),
            running: AtomicBool::new(false),
            draining: AtomicBool::new(false),
            new_tx_notify: Notify::new(),
            stats: Arc::new(PoolStats::new()),
        }
    }

    /// Mark the pool as running.
    pub fn start(&self) {
        self.running.store(true, Ordering::Release);
    }

    /// Stop the pool — background tasks should check `is_running()` and exit.
    pub fn stop(&self) {
        self.running.store(false, Ordering::Release);
        self.new_tx_notify.notify_waiters();
    }

    /// Check whether the pool is still running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    /// Enter drain mode: stop accepting new vote requests but keep processing
    /// vote responses and block replications so in-flight rounds complete.
    pub fn begin_drain(&self) {
        self.draining.store(true, Ordering::Release);
        info!(
            "AS{} drain mode ON -- {} pending transactions",
            self.as_number,
            self.pending_votes.len()
        );
    }

    /// Number of transactions still awaiting consensus.
    pub fn pending_count(&self) -> usize {
        self.pending_votes.len()
    }

    /// Number of transactions committed to blockchain.
    pub fn committed_count(&self) -> usize {
        self.stats.transactions_committed.load(Ordering::Relaxed) as usize
    }

    /// Number of transactions created (proposed).
    pub fn created_count(&self) -> usize {
        self.stats.transactions_created.load(Ordering::Relaxed) as usize
    }

    /// Directly commit a ROA-verified transaction to the blockchain.
    ///
    /// Used for RPKI-origin announcements where the ROA provides
    /// cryptographic proof — no consensus voting needed.
    pub async fn commit_direct(&self, mut transaction: Transaction) {
        transaction.consensus_reached = true;
        transaction.consensus_status = ConsensusStatus::Confirmed;
        transaction.confidence_weight = self.config.consensus_weight_confirmed;
        transaction.rpki_validation = "roa_verified".to_string();
        transaction.timeout_commit = false;

        let tx_id = transaction.transaction_id.clone();

        // Write to blockchain.
        let committed_block = {
            let mut chain = self.blockchain.lock().await;
            chain.add_transaction(transaction)
        };

        if let Some(block) = committed_block {
            debug!(
                "AS{} direct-committed TX {} (ROA-verified, no voting)",
                self.as_number, tx_id,
            );

            // Populate BOA from confirmed legitimate transaction.
            for tx in &block.transactions {
                if !tx.is_attack && tx.consensus_status == ConsensusStatus::Confirmed {
                    self.boa.attest(&tx.ip_prefix, tx.sender_asn);
                }
            }

            self.stats
                .transactions_committed
                .fetch_add(1, Ordering::Relaxed);
            self.stats.confirmed_count.fetch_add(1, Ordering::Relaxed);

            // Replicate block to gossip subset.
            self.replicate_block_to_peers(&block);
        }
    }

    /// Return a stats snapshot.
    pub fn stats_snapshot(&self) -> PoolStatsSnapshot {
        PoolStatsSnapshot {
            transactions_created: self.stats.transactions_created.load(Ordering::Relaxed),
            transactions_committed: self.stats.transactions_committed.load(Ordering::Relaxed),
            transactions_timed_out: self.stats.transactions_timed_out.load(Ordering::Relaxed),
            votes_cast: self.stats.votes_cast.load(Ordering::Relaxed),
            blocks_replicated: self.stats.blocks_replicated.load(Ordering::Relaxed),
            confirmed_count: self.stats.confirmed_count.load(Ordering::Relaxed),
            insufficient_count: self.stats.insufficient_count.load(Ordering::Relaxed),
            single_witness_count: self.stats.single_witness_count.load(Ordering::Relaxed),
            voters_from_origin_neighbors: self.stats.voters_from_origin_neighbors.load(Ordering::Relaxed),
            voters_from_as_path: self.stats.voters_from_as_path.load(Ordering::Relaxed),
            voters_from_random: self.stats.voters_from_random.load(Ordering::Relaxed),
        }
    }

    // =========================================================================
    // Message dispatch
    // =========================================================================

    /// Handle an incoming message from the message bus.
    ///
    /// During drain mode, vote responses and block replications are still
    /// processed so that in-flight consensus rounds complete naturally.
    /// Only new vote requests are rejected.
    pub async fn handle_message(&self, message: Message) {
        if !self.is_running() {
            return;
        }
        match message {
            Message::VoteRequest {
                from_as,
                transaction,
            } => {
                if self.draining.load(Ordering::Acquire) {
                    return; // Don't start new consensus rounds during drain
                }
                self.handle_vote_request(from_as, transaction).await;
            }
            Message::VoteResponse {
                from_as,
                transaction_id,
                vote,
                timestamp,
                signature,
            } => {
                self.handle_vote_response(from_as, &transaction_id, vote, timestamp, signature)
                    .await;
            }
            Message::BlockReplicate { from_as: _, block } => {
                self.handle_block_replicate(block).await;
            }
        }
    }

    // =========================================================================
    // Broadcasting
    // =========================================================================

    /// Broadcast a transaction to adaptively-selected peers for consensus voting.
    ///
    /// Peer selection uses a 3-layer priority system:
    /// - Layer 0: RPKI peers on the observed AS-path (guaranteed knowers).
    /// - Layer 1: Relevant neighbors (placeholder — returns empty).
    /// - Layer 2: Random fill from remaining peers.
    ///
    /// Broadcast size: `max(threshold * 2, sqrt(N_peers))`.
    pub async fn broadcast_transaction(&self, transaction: Transaction) {
        let tx_id = transaction.transaction_id.clone();
        let sender_asn = transaction.sender_asn;
        let ip_prefix = transaction.ip_prefix.clone();

        // Network-wide dedup: if another node already proposed a TX for this
        // (prefix, origin), skip (our vote was already cast via vote_request).
        let event_key = (ip_prefix.clone(), sender_asn);
        if self.pending_event_keys.contains_key(&event_key) {
            debug!(
                "AS{} skipping redundant TX for {}/AS{} -- already proposed by peer",
                self.as_number, ip_prefix, sender_asn
            );
            return;
        }

        // Mark this event as proposed (by us).
        self.pending_event_keys.insert(event_key, ());

        // Capacity check: if pending_votes is at capacity, force-timeout oldest.
        if self.pending_votes.len() >= self.config.pending_votes_max_capacity {
            if let Some(oldest_id) = self.find_oldest_pending() {
                warn!(
                    "AS{} pending_votes at capacity ({}), force-timing-out oldest: {}",
                    self.as_number, self.config.pending_votes_max_capacity, oldest_id
                );
                self.handle_timed_out_transaction(&oldest_id).await;
            }
        }

        // Register pending vote entry.
        self.pending_votes.insert(
            tx_id.clone(),
            PendingVote {
                transaction: transaction.clone(),
                votes: Vec::new(),
                needed: self.consensus_threshold,
                created_at: Instant::now(),
                is_attack: transaction.is_attack,
            },
        );

        // ---- Adaptive peer selection ----
        let n_peers = self.peer_nodes.len();
        let broadcast_size = (self.consensus_threshold as usize * 2)
            .max((n_peers as f64).sqrt().ceil() as usize)
            .min(n_peers);

        let as_path = &transaction.as_path;
        let origin_asn = transaction.sender_asn;
        let mut target_set: HashSet<u32> = HashSet::new();

        let mut count_origin_nbr: u64 = 0;
        let mut count_as_path: u64 = 0;
        let mut count_random: u64 = 0;

        if self.config.voter_selection_mode == "origin_neighbors" {
            // ── origin_neighbors mode ──
            // Layer 0: RPKI validators that are direct neighbors of the ORIGIN
            // in the CAIDA topology. These have the strongest independent
            // evidence — they received the announcement directly from the origin.
            if let (Some(adj), Some(rpki)) = (&self.adjacency, &self.rpki_set) {
                let empty = HashSet::new();
                let origin_nbrs = adj.get(&origin_asn).unwrap_or(&empty);
                for &nbr in origin_nbrs {
                    if nbr == self.as_number {
                        continue;
                    }
                    if rpki.contains(&nbr) {
                        target_set.insert(nbr);
                        count_origin_nbr += 1;
                        if target_set.len() >= broadcast_size {
                            break;
                        }
                    }
                }
            }

            // Layer 1: AS-path RPKI peers (same chain, weaker independence).
            if target_set.len() < broadcast_size {
                let peer_set: HashSet<u32> = self.peer_nodes.iter().copied().collect();
                for &asn in as_path {
                    if asn == self.as_number || target_set.contains(&asn) {
                        continue;
                    }
                    if peer_set.contains(&asn) {
                        target_set.insert(asn);
                        count_as_path += 1;
                        if target_set.len() >= broadcast_size {
                            break;
                        }
                    }
                }
            }
        } else {
            // ── proposer_path mode (default) ──
            // Layer 0: RPKI peers on the observed AS-path.
            let peer_set: HashSet<u32> = self.peer_nodes.iter().copied().collect();
            for &asn in as_path {
                if asn == self.as_number {
                    continue;
                }
                if peer_set.contains(&asn) {
                    target_set.insert(asn);
                    count_as_path += 1;
                    if target_set.len() >= broadcast_size {
                        break;
                    }
                }
            }
        }

        // Layer 2 (both modes): Random fill from remaining peers.
        if target_set.len() < broadcast_size {
            let remaining: Vec<u32> = self
                .peer_nodes
                .iter()
                .copied()
                .filter(|asn| !target_set.contains(asn))
                .collect();

            let needed = broadcast_size - target_set.len();
            let mut rng = thread_rng();
            let fill: Vec<u32> = if remaining.len() <= needed {
                remaining
            } else {
                remaining
                    .choose_multiple(&mut rng, needed)
                    .copied()
                    .collect()
            };

            count_random = fill.len() as u64;
            target_set.extend(fill);
        }

        // Track voter selection layer stats.
        self.stats.voters_from_origin_neighbors.fetch_add(count_origin_nbr, Ordering::Relaxed);
        self.stats.voters_from_as_path.fetch_add(count_as_path, Ordering::Relaxed);
        self.stats.voters_from_random.fetch_add(count_random, Ordering::Relaxed);

        // Send vote requests to all selected peers.
        for &peer_as in &target_set {
            self.bus.send(
                self.as_number,
                peer_as,
                Message::VoteRequest {
                    from_as: self.as_number,
                    transaction: transaction.clone(),
                },
            );
        }

        debug!(
            "AS{} broadcast {} to {} peers",
            self.as_number,
            tx_id,
            target_set.len()
        );

        self.stats
            .transactions_created
            .fetch_add(1, Ordering::Relaxed);
        self.new_tx_notify.notify_waiters();
    }

    // =========================================================================
    // Vote request handling
    // =========================================================================

    /// Handle an incoming vote request from a peer proposer.
    ///
    /// 1. Record the (prefix, origin) as already-proposed (network dedup).
    /// 2. Consult the knowledge base to decide: approve / reject / no_knowledge.
    /// 3. Send the vote response back to the proposer.
    /// 4. Speculatively add the observation to our KB as a 3rd-party witness
    ///    (post-vote, so the vote reflects genuine prior knowledge).
    async fn handle_vote_request(&self, from_as: u32, transaction: Transaction) {
        let ip_prefix = transaction.ip_prefix.clone();
        let sender_asn = transaction.sender_asn;
        let tx_id = transaction.transaction_id.clone();
        let tx_timestamp = transaction.timestamp;
        let is_attack = transaction.is_attack;

        // Record that this (prefix, origin) is already being proposed.
        let event_key = (ip_prefix.clone(), sender_asn);
        self.pending_event_keys.insert(event_key, ());

        // Consult KB for vote decision.
        let vote = self.kb.check_knowledge(
            &ip_prefix,
            sender_asn,
            tx_timestamp,
            self.config.voting_observation_window as f64,
        );

        // Convert KB vote to wire vote type.
        let vote_str = match &vote {
            Vote::Approve => "APPROVE",
            Vote::Reject => "REJECT",
            Vote::NoKnowledge => "NO_KNOWLEDGE",
        };

        debug!(
            "AS{} vote on {} from AS{}: {} (prefix={}, origin={}, tx_ts={:.1}, kb_size={})",
            self.as_number, tx_id, from_as, vote_str, ip_prefix, sender_asn, tx_timestamp, self.kb.len()
        );

        // Sign the vote.
        let signature = sign_vote(&tx_id, self.as_number, vote_str, &self.key_pair);

        // Send response.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        self.bus.send(
            self.as_number,
            from_as,
            Message::VoteResponse {
                from_as: self.as_number,
                transaction_id: tx_id,
                vote,
                timestamp: now,
                signature: Some(signature),
            },
        );

        self.stats.votes_cast.fetch_add(1, Ordering::Relaxed);

        // 3rd-party witness KB backfill DISABLED — nodes vote only based
        // on their own first-hand BGP observations. No second-hand knowledge.
        // if !ip_prefix.is_empty() && sender_asn != 0 {
        //     self.kb.add_observation(
        //         &ip_prefix, sender_asn, tx_timestamp,
        //         65.0, is_attack,
        //     );
        // }
    }

    // =========================================================================
    // Vote response handling
    // =========================================================================

    /// Handle an incoming vote response and check if consensus threshold is met.
    ///
    /// On APPROVE vote, signals the neighbor cache (placeholder) so future
    /// broadcasts prioritize this peer.
    async fn handle_vote_response(
        &self,
        from_as: u32,
        tx_id: &str,
        vote: Vote,
        timestamp: f64,
        signature: Option<String>,
    ) {
        // Quick checks outside the mutable entry.
        if !self.pending_votes.contains_key(tx_id) {
            debug!(
                "AS{} vote response from AS{} for {} DROPPED: not in pending_votes",
                self.as_number, from_as, tx_id
            );
            return;
        }
        if self.committed_transactions.contains_key(tx_id) {
            debug!(
                "AS{} vote response from AS{} for {} DROPPED: already committed",
                self.as_number, from_as, tx_id
            );
            return;
        }

        debug!(
            "AS{} received vote {} from AS{} for {}",
            self.as_number, vote, from_as, tx_id
        );

        let mut should_commit = false;
        // Capture (origin_as, voter_as) on approve for neighbor cache.
        let mut approver_signal: Option<(u32, u32)> = None;

        // Scoped mutable access to the pending vote entry.
        if let Some(mut entry) = self.pending_votes.get_mut(tx_id) {
            let pv = entry.value_mut();

            // Duplicate vote guard.
            if pv.votes.iter().any(|v| v.from_as == from_as) {
                return;
            }
            // Overflow guard.
            if pv.votes.len() >= self.total_nodes {
                return;
            }

            // Record the vote.
            pv.votes.push(VoteRecord {
                from_as,
                vote: vote.clone(),
                timestamp: Some(timestamp),
                signature,
            });

            // Capture approve signal for neighbor cache learning (Fix #5).
            if vote == Vote::Approve && from_as != self.as_number {
                let sender_asn = pv.transaction.sender_asn;
                if sender_asn != 0 {
                    approver_signal = Some((sender_asn, from_as));
                }
            }

            // Count approvals.
            let approve_count = pv.votes.iter().filter(|v| v.vote == Vote::Approve).count();
            if approve_count >= self.consensus_threshold as usize {
                self.committed_transactions
                    .insert(tx_id.to_string(), Instant::now());
                should_commit = true;
            }
        }

        // Neighbor cache update on approve (placeholder for Layer 1).
        if let Some((_origin_as, _voter_as)) = approver_signal {
            // TODO: self.neighbor_cache.record_observation(origin_as, voter_as);
        }

        if should_commit {
            self.commit_to_blockchain(tx_id).await;
        }
    }

    // =========================================================================
    // Block replication handling
    // =========================================================================

    /// Handle a replicated block from a peer.
    ///
    /// In addition to appending the block to this node's chain, propagates each
    /// CONFIRMED transaction into the knowledge base (Fix #9 + #3: backfills
    /// direct KB so peers that voted "no_knowledge" learn the committed event).
    async fn handle_block_replicate(&self, block: Block) {
        // Append to local chain (handles fork detection/merge internally).
        let accepted = {
            let mut chain = self.blockchain.lock().await;
            chain.append_replicated_block(&block)
        };

        if !accepted {
            return;
        }

        self.stats
            .blocks_replicated
            .fetch_add(1, Ordering::Relaxed);

        // Propagate knowledge from CONFIRMED transactions.
        for tx in &block.transactions {
            if tx.consensus_status != ConsensusStatus::Confirmed {
                continue;
            }
            let prefix = &tx.ip_prefix;
            let origin_asn = tx.sender_asn;
            let tx_timestamp = tx.timestamp;
            let is_attack = tx.is_attack;

            if prefix.is_empty() || origin_asn == 0 {
                continue;
            }

            // Block replication KB backfill DISABLED — nodes vote only based
            // on their own first-hand BGP observations. No second-hand knowledge.
            // self.kb
            //     .add_observation(prefix, origin_asn, tx_timestamp, 70.0, is_attack);

            // TODO: Update prefix_ownership_state (Source 2) for non-attack TXs.
        }
    }

    // =========================================================================
    // Commit path — fast (CONFIRMED)
    // =========================================================================

    /// Commit a transaction that has reached the CONFIRMED consensus threshold.
    async fn commit_to_blockchain(&self, tx_id: &str) {
        // Extract and prepare the transaction.
        let prepared = {
            let entry = match self.pending_votes.get(tx_id) {
                Some(e) => e,
                None => return,
            };
            let pv = entry.value();
            let mut tx = pv.transaction.clone();
            // Snapshot votes (don't share the mutable list — prevents late-arriving
            // votes from mutating the block content after its hash is computed).
            tx.signatures = pv.votes.clone();
            tx.consensus_reached = true;
            tx.consensus_status = ConsensusStatus::Confirmed;
            tx.confidence_weight = self.config.consensus_weight_confirmed;
            tx.signature_count = tx.signatures.len();
            tx.approve_count = tx
                .signatures
                .iter()
                .filter(|v| v.vote == Vote::Approve)
                .count();
            tx
        };

        // Write to blockchain.
        let committed_block = {
            let mut chain = self.blockchain.lock().await;
            chain.add_transaction(prepared)
        };

        if let Some(block) = committed_block {
            info!(
                "AS{} committed TX {} (CONFIRMED, {} signatures)",
                self.as_number,
                tx_id,
                block.transactions.first().map_or(0, |t| t.signature_count)
            );

            self.stats
                .transactions_committed
                .fetch_add(1, Ordering::Relaxed);
            self.stats.confirmed_count.fetch_add(1, Ordering::Relaxed);

            // Replicate block to gossip subset.
            self.replicate_block_to_peers(&block);

            // Remove from pending.
            self.pending_votes.remove(tx_id);
        } else {
            error!(
                "AS{} failed to write TX {} to blockchain",
                self.as_number, tx_id
            );
            // Remove from committed so timeout handler can retry.
            self.committed_transactions.remove(tx_id);
        }
    }

    // =========================================================================
    // Commit path — timeout (INSUFFICIENT / SINGLE_WITNESS)
    // =========================================================================

    /// Handle a timed-out transaction by committing with partial consensus.
    async fn handle_timed_out_transaction(&self, tx_id: &str) {
        // Check guards.
        if !self.pending_votes.contains_key(tx_id) {
            return;
        }
        if self.committed_transactions.contains_key(tx_id) {
            return;
        }

        // Determine consensus status from collected votes.
        let (consensus_status, approve_count) = {
            let entry = match self.pending_votes.get(tx_id) {
                Some(e) => e,
                None => return,
            };
            let pv = entry.value();
            let approve_count = pv.votes.iter().filter(|v| v.vote == Vote::Approve).count();
            let status = if approve_count >= self.consensus_threshold as usize {
                ConsensusStatus::Confirmed
            } else if approve_count >= 1 {
                ConsensusStatus::InsufficientConsensus
            } else {
                ConsensusStatus::SingleWitness
            };
            (status, approve_count)
        };

        // Mark as committed.
        self.committed_transactions
            .insert(tx_id.to_string(), Instant::now());

        self.commit_unconfirmed(tx_id, consensus_status, approve_count)
            .await;
    }

    /// Commit a transaction with partial consensus status (timeout path).
    async fn commit_unconfirmed(
        &self,
        tx_id: &str,
        consensus_status: ConsensusStatus,
        approve_count: usize,
    ) {
        let prepared = {
            let entry = match self.pending_votes.get(tx_id) {
                Some(e) => e,
                None => return,
            };
            let pv = entry.value();
            let mut tx = pv.transaction.clone();

            // Snapshot votes.
            tx.signatures = pv.votes.clone();
            tx.consensus_status = consensus_status.clone();
            tx.consensus_reached = consensus_status == ConsensusStatus::Confirmed;
            tx.signature_count = tx.signatures.len();
            tx.approve_count = approve_count;
            tx.timeout_commit = true;

            // Confidence weight from config.
            tx.confidence_weight = match &consensus_status {
                ConsensusStatus::Confirmed => self.config.consensus_weight_confirmed,
                ConsensusStatus::InsufficientConsensus => {
                    self.config.consensus_weight_insufficient
                }
                ConsensusStatus::SingleWitness => self.config.consensus_weight_single_witness,
                ConsensusStatus::Pending => 0.0,
            };

            tx
        };

        let confidence = prepared.confidence_weight;

        // Write to blockchain.
        let committed_block = {
            let mut chain = self.blockchain.lock().await;
            chain.add_transaction(prepared)
        };

        if let Some(block) = committed_block {
            info!(
                "AS{} committed TX {} status={} ({} approve, confidence={}, timeout)",
                self.as_number, tx_id, consensus_status, approve_count, confidence
            );

            // Populate BOA from confirmed legitimate transactions.
            if consensus_status == ConsensusStatus::Confirmed {
                for tx in &block.transactions {
                    if !tx.is_attack && tx.consensus_status == ConsensusStatus::Confirmed {
                        self.boa.attest(&tx.ip_prefix, tx.sender_asn);
                    }
                }
            }

            self.stats
                .transactions_committed
                .fetch_add(1, Ordering::Relaxed);
            self.stats
                .transactions_timed_out
                .fetch_add(1, Ordering::Relaxed);

            match consensus_status {
                ConsensusStatus::Confirmed => {
                    self.stats.confirmed_count.fetch_add(1, Ordering::Relaxed);
                }
                ConsensusStatus::InsufficientConsensus => {
                    self.stats
                        .insufficient_count
                        .fetch_add(1, Ordering::Relaxed);
                }
                ConsensusStatus::SingleWitness => {
                    self.stats
                        .single_witness_count
                        .fetch_add(1, Ordering::Relaxed);
                }
                ConsensusStatus::Pending => {}
            }

            // Replicate confirmed and insufficient to peers.
            if confidence >= self.config.consensus_weight_insufficient {
                self.replicate_block_to_peers(&block);
            }

            // Remove from pending.
            self.pending_votes.remove(tx_id);
        } else {
            error!(
                "AS{} failed to write timed-out TX {} to blockchain",
                self.as_number, tx_id
            );
            // Remove from committed so timeout handler can retry.
            self.committed_transactions.remove(tx_id);
        }
    }

    // =========================================================================
    // Block replication to peers
    // =========================================================================

    /// Broadcast a committed block to a gossip subset of peers.
    fn replicate_block_to_peers(&self, block: &Block) {
        let all_peers: Vec<u32> = self
            .peer_nodes
            .iter()
            .copied()
            .filter(|&asn| asn != self.as_number)
            .collect();

        if all_peers.is_empty() {
            return;
        }

        let gossip_size = 3usize.max((all_peers.len() as f64).sqrt().ceil() as usize);
        let mut rng = thread_rng();
        let targets: Vec<u32> = if all_peers.len() <= gossip_size {
            all_peers
        } else {
            all_peers
                .choose_multiple(&mut rng, gossip_size)
                .copied()
                .collect()
        };

        let message = Message::BlockReplicate {
            from_as: self.as_number,
            block: block.clone(),
        };

        self.bus
            .broadcast(self.as_number, message, &targets);
    }

    // =========================================================================
    // Background task: timeout loop
    // =========================================================================

    /// Background task that periodically checks for timed-out pending
    /// transactions and commits them with partial consensus.
    ///
    /// Should be spawned as `tokio::spawn(pool.clone().run_timeout_loop())`.
    pub async fn run_timeout_loop(self: Arc<Self>) {
        // Brief initial delay.
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        while self.is_running() {
            // Calculate sleep duration based on soonest timeout.
            let sleep_duration = self.calculate_timeout_sleep();

            // Wait for either new transactions or the computed sleep.
            tokio::select! {
                _ = self.new_tx_notify.notified() => {},
                _ = tokio::time::sleep(sleep_duration) => {},
            }

            if !self.is_running() {
                break;
            }

            // Find timed-out transactions.
            let now = Instant::now();
            let timed_out: Vec<String> = self
                .pending_votes
                .iter()
                .filter_map(|entry| {
                    let tx_id = entry.key().clone();
                    let pv = entry.value();

                    // Skip already committed.
                    if self.committed_transactions.contains_key(&tx_id) {
                        return None;
                    }

                    let timeout_dur = if self.draining.load(Ordering::Acquire) {
                        std::time::Duration::from_secs(1)
                    } else if pv.is_attack {
                        std::time::Duration::from_secs(self.config.p2p_attack_timeout)
                    } else {
                        std::time::Duration::from_secs(self.config.p2p_regular_timeout)
                    };

                    if now.duration_since(pv.created_at) >= timeout_dur {
                        Some(tx_id)
                    } else {
                        None
                    }
                })
                .collect();

            for tx_id in timed_out {
                self.handle_timed_out_transaction(&tx_id).await;
            }
        }
    }

    /// Calculate how long to sleep before the next timeout check.
    fn calculate_timeout_sleep(&self) -> std::time::Duration {
        if self.pending_votes.is_empty() {
            return std::time::Duration::from_secs(5);
        }

        let now = Instant::now();
        let mut soonest: Option<std::time::Duration> = None;

        for entry in self.pending_votes.iter() {
            let pv = entry.value();

            let timeout_dur = if self.draining.load(Ordering::Acquire) {
                std::time::Duration::from_secs(1)
            } else if pv.is_attack {
                std::time::Duration::from_secs(self.config.p2p_attack_timeout)
            } else {
                std::time::Duration::from_secs(self.config.p2p_regular_timeout)
            };

            let elapsed = now.duration_since(pv.created_at);
            let remaining = if elapsed >= timeout_dur {
                std::time::Duration::from_millis(50) // Already expired
            } else {
                timeout_dur - elapsed + std::time::Duration::from_millis(50)
            };

            soonest = Some(match soonest {
                None => remaining,
                Some(s) => s.min(remaining),
            });
        }

        soonest.unwrap_or(std::time::Duration::from_secs(2))
    }

    // =========================================================================
    // Background task: KB cleanup
    // =========================================================================

    /// Background task that periodically cleans expired observations from the
    /// knowledge base.
    ///
    /// Should be spawned as `tokio::spawn(pool.clone().run_kb_cleanup_loop())`.
    pub async fn run_kb_cleanup_loop(self: Arc<Self>) {
        let interval = std::time::Duration::from_secs(self.config.knowledge_cleanup_interval);

        // Initial delay.
        tokio::time::sleep(interval).await;

        while self.is_running() {
            self.kb
                .cleanup(self.config.voting_observation_window as f64);
            tokio::time::sleep(interval).await;
        }
    }

    // =========================================================================
    // Background task: committed TX cleanup
    // =========================================================================

    /// Background task that periodically evicts old committed transaction IDs.
    pub async fn run_committed_cleanup_loop(self: Arc<Self>) {
        let interval =
            std::time::Duration::from_secs(self.config.committed_tx_cleanup_interval);

        // Initial delay.
        tokio::time::sleep(std::time::Duration::from_secs(15)).await;

        while self.is_running() {
            tokio::time::sleep(interval).await;

            let cutoff = Instant::now() - interval;

            // Remove entries older than cutoff.
            self.committed_transactions
                .retain(|_tx_id, ts| *ts > cutoff);

            // Hard cap.
            if self.committed_transactions.len() > self.config.committed_tx_max_size {
                // DashMap doesn't support sorted iteration, so just remove
                // some entries to get below the cap.
                let excess = self.committed_transactions.len() - self.config.committed_tx_max_size;
                let to_remove: Vec<String> = self
                    .committed_transactions
                    .iter()
                    .take(excess)
                    .map(|e| e.key().clone())
                    .collect();
                for key in to_remove {
                    self.committed_transactions.remove(&key);
                }
            }

            // Clean up stale pending event keys (conservative: clear all).
            // In production you'd track timestamps, but for simulation this
            // prevents unbounded growth.
            if self.pending_event_keys.len() > self.config.committed_tx_max_size {
                self.pending_event_keys.clear();
            }
        }
    }

    // =========================================================================
    // Drain: flush all pending transactions
    // =========================================================================

    /// Flush all remaining pending transactions by committing them with their
    /// current vote tallies. Called at end-of-simulation.
    pub async fn drain(&self) {
        self.begin_drain();

        // Wait briefly for in-flight responses.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Commit everything that remains.
        let remaining: Vec<String> = self
            .pending_votes
            .iter()
            .map(|e| e.key().clone())
            .collect();

        for tx_id in remaining {
            if !self.committed_transactions.contains_key(&tx_id) {
                self.handle_timed_out_transaction(&tx_id).await;
            }
        }
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    /// Find the oldest pending transaction ID (by creation time).
    fn find_oldest_pending(&self) -> Option<String> {
        let mut oldest_key: Option<String> = None;
        let mut oldest_time: Option<Instant> = None;

        for entry in self.pending_votes.iter() {
            let created = entry.value().created_at;
            match oldest_time {
                None => {
                    oldest_time = Some(created);
                    oldest_key = Some(entry.key().clone());
                }
                Some(t) if created < t => {
                    oldest_time = Some(created);
                    oldest_key = Some(entry.key().clone());
                }
                _ => {}
            }
        }

        oldest_key
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pool() -> Arc<TransactionPool> {
        let config = Arc::new(Config::default());
        let kb = Arc::new(KnowledgeBase::new(3600.0, 50_000));
        let boa = Arc::new(OriginAttestation::new());
        let blockchain = Arc::new(Mutex::new(Blockchain::new(100)));
        let bus = MessageBus::new();
        let key_pair = Arc::new(KeyPair::generate());
        let peer_nodes = vec![200, 300, 400, 500, 600];
        let total_nodes = 6;

        let pool = TransactionPool::new(
            100,
            config,
            kb,
            boa,
            blockchain,
            bus,
            key_pair,
            peer_nodes,
            total_nodes,
            None,
            None,
        );
        pool.start();
        Arc::new(pool)
    }

    fn make_tx(tx_id: &str, prefix: &str, sender: u32) -> Transaction {
        Transaction {
            transaction_id: tx_id.to_string(),
            observer_as: 100,
            sender_asn: sender,
            ip_prefix: prefix.to_string(),
            as_path: vec![100, sender],
            timestamp: 1000.0,
            is_attack: false,
            label: "LEGITIMATE".to_string(),
            rpki_validation: "VALID".to_string(),
            detected_attacks: vec![],
            created_at: "2026-01-01T00:00:00Z".to_string(),
            signature: None,
            signer_as: Some(100),
            signatures: vec![],
            consensus_status: ConsensusStatus::Pending,
            consensus_reached: false,
            confidence_weight: 0.0,
            signature_count: 0,
            approve_count: 0,
            timeout_commit: false,
        }
    }

    #[tokio::test]
    async fn test_broadcast_registers_pending() {
        let pool = make_pool();
        let tx = make_tx("tx-1", "10.0.0.0/24", 200);

        pool.broadcast_transaction(tx).await;

        assert!(pool.pending_votes.contains_key("tx-1"));
        assert_eq!(pool.pending_count(), 1);
        assert_eq!(
            pool.stats.transactions_created.load(Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn test_dedup_skips_redundant_broadcast() {
        let pool = make_pool();

        let tx1 = make_tx("tx-1", "10.0.0.0/24", 200);
        pool.broadcast_transaction(tx1).await;

        // Same (prefix, origin) — should be deduped.
        let tx2 = make_tx("tx-2", "10.0.0.0/24", 200);
        pool.broadcast_transaction(tx2).await;

        // Only the first should be pending.
        assert_eq!(pool.pending_count(), 1);
        assert!(pool.pending_votes.contains_key("tx-1"));
        assert!(!pool.pending_votes.contains_key("tx-2"));
    }

    #[tokio::test]
    async fn test_vote_request_adds_to_kb() {
        let pool = make_pool();
        let tx = make_tx("tx-vote", "10.0.0.0/24", 200);

        pool.handle_vote_request(300, tx).await;

        // The observation should be in the KB.
        let entries = pool.kb.entries_for_prefix("10.0.0.0/24");
        assert!(!entries.is_empty());
    }

    #[tokio::test]
    async fn test_timeout_commits_single_witness() {
        let pool = make_pool();
        let tx = make_tx("tx-timeout", "10.0.0.0/24", 200);

        pool.broadcast_transaction(tx).await;

        // Directly invoke timeout handler.
        pool.handle_timed_out_transaction("tx-timeout").await;

        // Should be committed and removed from pending.
        assert!(!pool.pending_votes.contains_key("tx-timeout"));
        assert!(pool.committed_transactions.contains_key("tx-timeout"));
        assert_eq!(
            pool.stats.single_witness_count.load(Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn test_stats_snapshot() {
        let pool = make_pool();
        let snap = pool.stats_snapshot();
        assert_eq!(snap.transactions_created, 0);
        assert_eq!(snap.transactions_committed, 0);
    }

    /// Simulate the full multi-node vote round-trip with concurrent message
    /// handler loops (mimicking the real NodeManager orchestration).
    #[tokio::test]
    async fn test_full_vote_roundtrip_concurrent() {
        // Create a shared bus and multiple pools (simulating 4 RPKI nodes).
        let bus = MessageBus::new();
        let config = Arc::new(Config::default());

        let asns = [100u32, 200, 300, 400];
        let mut pools: std::collections::HashMap<u32, Arc<TransactionPool>> =
            std::collections::HashMap::new();

        // Register nodes and start message handler loops (like NodeManager).
        let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

        for &asn in &asns {
            let rx = bus.register(asn);

            let peers: Vec<u32> = asns.iter().copied().filter(|&a| a != asn).collect();
            let kb = Arc::new(KnowledgeBase::new(3600.0, 50_000));
            let boa = Arc::new(OriginAttestation::new());
            let blockchain = Arc::new(Mutex::new(Blockchain::new(asn)));
            let key_pair = Arc::new(KeyPair::generate());

            // Pre-populate KB so peers can vote APPROVE.
            kb.add_observation("10.0.0.0/24", 500, 1000.0, 80.0, false);

            let pool = Arc::new(TransactionPool::new(
                asn,
                Arc::clone(&config),
                kb,
                boa,
                blockchain,
                Arc::clone(&bus),
                key_pair,
                peers,
                asns.len(),
                None,
                None,
            ));
            pool.start();
            pools.insert(asn, Arc::clone(&pool));

            // Spawn message handler loop (like NodeManager does).
            let pool_m = Arc::clone(&pool);
            handles.push(tokio::spawn(async move {
                let mut rx = rx;
                while let Some(msg) = rx.recv().await {
                    pool_m.handle_message(msg).await;
                }
            }));

            // Spawn timeout loop.
            let pool_t = Arc::clone(&pool);
            handles.push(tokio::spawn(async move {
                pool_t.run_timeout_loop().await;
            }));
        }

        // Node 100 broadcasts a transaction.
        let tx = make_tx("tx-conc", "10.0.0.0/24", 500);
        pools[&100].broadcast_transaction(tx).await;

        // Wait for consensus to complete (either confirmed or timed out).
        let timeout = tokio::time::Duration::from_secs(2);
        let start = tokio::time::Instant::now();
        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            if !pools[&100].pending_votes.contains_key("tx-conc") {
                break;
            }
            if start.elapsed() > timeout {
                break;
            }
        }

        // Check results.
        let snap = pools[&100].stats_snapshot();
        eprintln!(
            "Concurrent test: confirmed={}, insufficient={}, single_witness={}, committed={}",
            snap.confirmed_count, snap.insufficient_count,
            snap.single_witness_count, snap.transactions_committed
        );

        // Clean up.
        for pool in pools.values() {
            pool.stop();
        }
        for h in &handles {
            h.abort();
        }

        assert_eq!(snap.confirmed_count, 1, "Expected 1 CONFIRMED transaction");
        assert_eq!(snap.single_witness_count, 0, "Expected 0 SINGLE_WITNESS");
    }

    /// Test that check_knowledge uses wall-clock freshness (not BGP timestamp).
    /// After the fix, BGP timestamp differences should NOT cause NoKnowledge.
    #[test]
    fn test_knowledge_window_wall_clock() {
        let kb = KnowledgeBase::new(3600.0, 50_000);
        // Add entry with BGP timestamp 1000 (but observed_at = now).
        kb.add_observation("10.0.0.0/24", 500, 1000.0, 80.0, false);

        // TX with VERY DIFFERENT BGP timestamp should still approve
        // because the wall-clock observed_at is within the window.
        assert_eq!(
            kb.check_knowledge("10.0.0.0/24", 500, 5000.0, 480.0),
            Vote::Approve,
            "Different BGP timestamp should still approve (wall-clock fresh)"
        );

        // Different prefix should still be NoKnowledge.
        assert_eq!(
            kb.check_knowledge("192.168.0.0/16", 500, 1000.0, 480.0),
            Vote::NoKnowledge,
            "Unknown prefix should be NoKnowledge"
        );
    }

    /// Test vote round-trip with realistic timestamps from the dataset.
    /// After the fix, even late BGP timestamps should get CONFIRMED votes
    /// because the KB uses wall-clock freshness.
    #[tokio::test]
    async fn test_vote_with_realistic_timestamps() {
        let bus = MessageBus::new();
        let config = Arc::new(Config::default());

        let asns = [100u32, 200, 300, 400];
        let mut pools: std::collections::HashMap<u32, Arc<TransactionPool>> =
            std::collections::HashMap::new();
        let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

        let base_ts = 1776117389.0_f64;
        let warmup_ts = base_ts + 100.0;
        let active_ts = base_ts + 900.0; // 800s after warmup_ts

        for &asn in &asns {
            let rx = bus.register(asn);

            let peers: Vec<u32> = asns.iter().copied().filter(|&a| a != asn).collect();
            let kb = Arc::new(KnowledgeBase::new(3600.0, 50_000));
            let boa = Arc::new(OriginAttestation::new());
            let blockchain = Arc::new(Mutex::new(Blockchain::new(asn)));
            let key_pair = Arc::new(KeyPair::generate());

            // Simulate warm-up + gossip: KB entry has early BGP timestamp
            // but wall-clock observed_at is NOW.
            kb.add_observation("10.0.0.0/24", 500, warmup_ts, 80.0, false);

            let pool = Arc::new(TransactionPool::new(
                asn,
                Arc::clone(&config),
                kb,
                boa,
                blockchain,
                Arc::clone(&bus),
                key_pair,
                peers,
                asns.len(),
                None,
                None,
            ));
            pool.start();
            pools.insert(asn, Arc::clone(&pool));

            let pool_m = Arc::clone(&pool);
            handles.push(tokio::spawn(async move {
                let mut rx = rx;
                while let Some(msg) = rx.recv().await {
                    pool_m.handle_message(msg).await;
                }
            }));
        }

        // Node 100 broadcasts with LATE BGP timestamp.
        let mut tx = make_tx("tx-late", "10.0.0.0/24", 500);
        tx.timestamp = active_ts;
        pools[&100].broadcast_transaction(tx).await;

        // Wait for consensus to complete.
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        let snap = pools[&100].stats_snapshot();
        eprintln!(
            "Realistic timestamps test (fixed): confirmed={}, insufficient={}, single_witness={}",
            snap.confirmed_count, snap.insufficient_count, snap.single_witness_count,
        );

        // After fix: should be CONFIRMED (wall-clock fresh entries).
        assert_eq!(snap.confirmed_count, 1, "Expected CONFIRMED after wall-clock fix");
        assert_eq!(snap.single_witness_count, 0, "Should not be SINGLE_WITNESS");

        for pool in pools.values() { pool.stop(); }
        for h in &handles { h.abort(); }
    }

    /// Simulate the full multi-node vote round-trip: proposer broadcasts,
    /// peers receive vote request and respond, proposer counts votes.
    #[tokio::test]
    async fn test_full_vote_roundtrip() {
        // Create a shared bus and multiple pools (simulating 4 RPKI nodes).
        let bus = MessageBus::new();
        let config = Arc::new(Config::default());

        let asns = [100u32, 200, 300, 400];
        let mut pools: std::collections::HashMap<u32, Arc<TransactionPool>> =
            std::collections::HashMap::new();
        let mut rxs: std::collections::HashMap<u32, tokio::sync::mpsc::Receiver<Message>> =
            std::collections::HashMap::new();

        for &asn in &asns {
            let rx = bus.register(asn);
            rxs.insert(asn, rx);

            let peers: Vec<u32> = asns.iter().copied().filter(|&a| a != asn).collect();
            let kb = Arc::new(KnowledgeBase::new(3600.0, 50_000));
            let boa = Arc::new(OriginAttestation::new());
            let blockchain = Arc::new(Mutex::new(Blockchain::new(asn)));
            let key_pair = Arc::new(KeyPair::generate());

            // Pre-populate KB so peers can vote APPROVE.
            kb.add_observation("10.0.0.0/24", 500, 1000.0, 80.0, false);

            let pool = Arc::new(TransactionPool::new(
                asn,
                Arc::clone(&config),
                kb,
                boa,
                blockchain,
                Arc::clone(&bus),
                key_pair,
                peers,
                asns.len(),
                None,
                None,
            ));
            pool.start();
            pools.insert(asn, pool);
        }

        // Node 100 broadcasts a transaction.
        let tx = make_tx("tx-roundtrip", "10.0.0.0/24", 500);
        pools[&100].broadcast_transaction(tx).await;

        // Verify vote requests were sent.
        let bus_stats = bus.stats();
        assert!(
            bus_stats.sent > 0,
            "Expected vote requests to be sent, got sent={}",
            bus_stats.sent
        );

        // Manually drain each peer's message queue and process.
        // This simulates what the message_handler_loop does.
        for &asn in &[200u32, 300, 400] {
            let rx = rxs.get_mut(&asn).unwrap();
            while let Ok(msg) = rx.try_recv() {
                pools[&asn].handle_message(msg).await;
            }
        }

        // Now process vote responses on node 100.
        let rx_100 = rxs.get_mut(&100).unwrap();
        let mut vote_count = 0;
        while let Ok(msg) = rx_100.try_recv() {
            match &msg {
                Message::VoteResponse { vote, .. } => {
                    eprintln!("Node 100 received vote response: {:?}", vote);
                    vote_count += 1;
                }
                _ => {}
            }
            pools[&100].handle_message(msg).await;
        }

        eprintln!(
            "Vote responses delivered to node 100: {}",
            vote_count
        );

        // Check if any votes were counted.
        let pending = pools[&100].pending_votes.get("tx-roundtrip");
        if let Some(pv) = pending {
            eprintln!(
                "Pending vote for tx-roundtrip: {} votes collected, {} approve",
                pv.votes.len(),
                pv.votes.iter().filter(|v| v.vote == Vote::Approve).count()
            );
            assert!(
                !pv.votes.is_empty(),
                "Expected votes to be collected, but got 0"
            );
        } else {
            // Check if it was committed (meaning threshold was reached).
            let committed = pools[&100].committed_transactions.contains_key("tx-roundtrip");
            let snap = pools[&100].stats_snapshot();
            eprintln!(
                "tx-roundtrip not in pending_votes. committed={}, stats: confirmed={}, committed={}",
                committed, snap.confirmed_count, snap.transactions_committed
            );
            assert!(
                committed,
                "tx-roundtrip neither pending nor committed"
            );
        }
    }
}
