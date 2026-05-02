//! Per-node blockchain for BGP-Sentry.
//!
//! Each RPKI validator maintains its own independent chain of blocks. Blocks
//! are linked by SHA-256 hashes. When a replicated block from a peer conflicts
//! with the local tip, a fork-merge block is created that incorporates novel
//! transactions from the peer's block.
//!
//! Ported from Python `BlockchainInterface` in `blockchain_interface.py`.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

use crate::types::{Block, BlockType, Transaction};

// ---------------------------------------------------------------------------
// BlockchainStats
// ---------------------------------------------------------------------------

/// Snapshot of blockchain counters.
#[derive(Debug, Clone)]
pub struct BlockchainStats {
    pub block_count: usize,
    pub transaction_count: usize,
    pub forks_detected: u64,
    pub forks_resolved: u64,
    pub merge_blocks: u64,
}

// ---------------------------------------------------------------------------
// Blockchain
// ---------------------------------------------------------------------------

/// A single node's append-only blockchain.
///
/// Thread safety: the struct itself is `Send + Sync` because the counters use
/// atomics. Callers that need to perform multi-step read-modify-write sequences
/// on `blocks` should wrap the `Blockchain` in an `Arc<Mutex<..>>` or
/// equivalent — this mirrors the Python design where `BlockchainInterface`
/// holds an `RLock`.
pub struct Blockchain {
    /// Ordered list of blocks (index 0 is genesis).
    pub blocks: Vec<Block>,

    /// AS number of the node that owns this chain.
    pub as_number: u32,

    /// Set of recently-seen transaction IDs for dedup.
    recent_tx_ids: HashSet<String>,

    /// Number of recent blocks to index for dedup.
    recent_tx_window: usize,

    // ── Fork tracking ────────────────────────────────────────────────
    pub forks_detected: AtomicU64,
    pub forks_resolved: AtomicU64,
    pub merge_blocks: AtomicU64,
}

impl Blockchain {
    /// Create a new blockchain with a genesis block.
    pub fn new(as_number: u32) -> Self {
        let mut chain = Self {
            blocks: Vec::new(),
            as_number,
            recent_tx_ids: HashSet::new(),
            recent_tx_window: 500,
            forks_detected: AtomicU64::new(0),
            forks_resolved: AtomicU64::new(0),
            merge_blocks: AtomicU64::new(0),
        };
        chain.create_genesis_block();
        chain
    }

    // ------------------------------------------------------------------
    // Genesis
    // ------------------------------------------------------------------

    fn create_genesis_block(&mut self) {
        let genesis = Block {
            block_number: 0,
            timestamp: current_epoch(),
            transactions: Vec::new(),
            previous_hash: "0".repeat(64),
            block_hash: String::new(),
            proposer: self.as_number,
            block_type: BlockType::Genesis,
        };
        let hash = Self::calculate_block_hash(&genesis);
        let mut genesis = genesis;
        genesis.block_hash = hash;
        self.blocks.push(genesis);
    }

    // ------------------------------------------------------------------
    // add_transaction — single-tx block
    // ------------------------------------------------------------------

    /// Create a new block containing a single transaction and append it.
    ///
    /// Returns the newly created block, or `None` if the transaction ID is a
    /// duplicate.
    pub fn add_transaction(&mut self, transaction: Transaction) -> Option<Block> {
        // Dedup guard
        if self.recent_tx_ids.contains(&transaction.transaction_id) {
            return None;
        }

        let previous_hash = self
            .blocks
            .last()
            .map(|b| b.block_hash.clone())
            .unwrap_or_else(|| "0".repeat(64));

        let mut block = Block {
            block_number: self.blocks.len(),
            timestamp: current_epoch(),
            transactions: vec![transaction],
            previous_hash,
            block_hash: String::new(),
            proposer: self.as_number,
            block_type: BlockType::Transaction,
        };
        block.block_hash = Self::calculate_block_hash(&block);

        // Update dedup index
        for tx in &block.transactions {
            self.recent_tx_ids.insert(tx.transaction_id.clone());
        }
        self.maybe_trim_tx_index();

        self.blocks.push(block.clone());
        Some(block)
    }

    // ------------------------------------------------------------------
    // add_batch — multi-tx block
    // ------------------------------------------------------------------

    /// Create a new block containing multiple transactions and append it.
    ///
    /// Duplicate transactions (by ID) are silently filtered out. Returns the
    /// new block, or `None` if *all* transactions were duplicates.
    pub fn add_batch(&mut self, transactions: Vec<Transaction>) -> Option<Block> {
        let unique: Vec<Transaction> = transactions
            .into_iter()
            .filter(|tx| !self.recent_tx_ids.contains(&tx.transaction_id))
            .collect();

        if unique.is_empty() {
            return None;
        }

        let previous_hash = self
            .blocks
            .last()
            .map(|b| b.block_hash.clone())
            .unwrap_or_else(|| "0".repeat(64));

        let mut block = Block {
            block_number: self.blocks.len(),
            timestamp: current_epoch(),
            transactions: unique,
            previous_hash,
            block_hash: String::new(),
            proposer: self.as_number,
            block_type: BlockType::Batch,
        };
        block.block_hash = Self::calculate_block_hash(&block);

        for tx in &block.transactions {
            self.recent_tx_ids.insert(tx.transaction_id.clone());
        }
        self.maybe_trim_tx_index();

        self.blocks.push(block.clone());
        Some(block)
    }

    // ------------------------------------------------------------------
    // append_replicated_block — peer replication + fork resolution
    // ------------------------------------------------------------------

    /// Attempt to append a block replicated from a peer.
    ///
    /// * If `block.previous_hash` matches the local tip hash, the block is
    ///   deep-cloned and appended normally.
    /// * If the hashes diverge, a **fork** is detected: a merge block is
    ///   created containing only the novel transactions from the incoming
    ///   block.
    /// * If hash verification fails, the block is rejected (`false`).
    pub fn append_replicated_block(&mut self, block: &Block) -> bool {
        // Verify block hash integrity
        let calculated = Self::calculate_block_hash(block);
        if calculated != block.block_hash {
            return false;
        }

        let local_tip = match self.blocks.last() {
            Some(b) => b,
            None => {
                // Only genesis — just append a clone
                self.blocks.push(block.clone());
                self.index_block_txs(block);
                return true;
            }
        };

        if block.previous_hash == local_tip.block_hash {
            // ── Normal append: block extends our tip ─────────────────
            self.blocks.push(block.clone());
            self.index_block_txs(block);
            return true;
        }

        // ── Fork detected ────────────────────────────────────────────
        self.forks_detected.fetch_add(1, Ordering::Relaxed);

        // Extract novel transactions not already on our chain
        let novel_txs: Vec<Transaction> = block
            .transactions
            .iter()
            .filter(|tx| !self.recent_tx_ids.contains(&tx.transaction_id))
            .cloned()
            .collect();

        if novel_txs.is_empty() {
            // Fork detected but no new data — still counts as resolved
            self.forks_resolved.fetch_add(1, Ordering::Relaxed);
            return true;
        }

        // Create a merge block on top of our local tip
        let local_tip_hash = local_tip.block_hash.clone();
        let mut merge = Block {
            block_number: self.blocks.len(),
            timestamp: current_epoch(),
            transactions: novel_txs,
            previous_hash: local_tip_hash,
            block_hash: String::new(),
            proposer: self.as_number,
            block_type: BlockType::ForkMerge,
        };
        merge.block_hash = Self::calculate_block_hash(&merge);

        for tx in &merge.transactions {
            self.recent_tx_ids.insert(tx.transaction_id.clone());
        }
        self.maybe_trim_tx_index();

        self.blocks.push(merge);

        self.forks_resolved.fetch_add(1, Ordering::Relaxed);
        self.merge_blocks.fetch_add(1, Ordering::Relaxed);

        true
    }

    // ------------------------------------------------------------------
    // Hashing
    // ------------------------------------------------------------------

    /// Compute the SHA-256 hash of a block.
    ///
    /// The hash covers: `previous_hash`, transactions (serialised as JSON),
    /// `timestamp`, and `proposer`. The existing `block_hash` field is excluded
    /// so that the function can be used both for creation and verification.
    pub fn calculate_block_hash(block: &Block) -> String {
        let tx_json = serde_json::to_string(&block.transactions).unwrap_or_default();

        let mut hasher = Sha256::new();
        hasher.update(block.previous_hash.as_bytes());
        hasher.update(tx_json.as_bytes());
        hasher.update(block.timestamp.to_bits().to_le_bytes());
        hasher.update(block.proposer.to_le_bytes());
        hex::encode(hasher.finalize())
    }

    // ------------------------------------------------------------------
    // Validation
    // ------------------------------------------------------------------

    /// Verify the entire hash chain from genesis to tip.
    ///
    /// Returns `true` if every block's stored hash matches its computed hash
    /// and every `previous_hash` links to the preceding block's hash.
    pub fn is_valid(&self) -> bool {
        for (i, block) in self.blocks.iter().enumerate() {
            // Verify self-hash
            let computed = Self::calculate_block_hash(block);
            if computed != block.block_hash {
                return false;
            }
            // Verify linkage (skip genesis)
            if i > 0 {
                let prev = &self.blocks[i - 1];
                if block.previous_hash != prev.block_hash {
                    return false;
                }
            }
        }
        true
    }

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------

    /// Reference to the last block, or `None` if the chain is empty.
    pub fn get_last_block(&self) -> Option<&Block> {
        self.blocks.last()
    }

    /// Total number of blocks (including genesis).
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Aggregate statistics snapshot.
    pub fn stats(&self) -> BlockchainStats {
        let transaction_count: usize = self.blocks.iter().map(|b| b.transactions.len()).sum();
        BlockchainStats {
            block_count: self.blocks.len(),
            transaction_count,
            forks_detected: self.forks_detected.load(Ordering::Relaxed),
            forks_resolved: self.forks_resolved.load(Ordering::Relaxed),
            merge_blocks: self.merge_blocks.load(Ordering::Relaxed),
        }
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Add all transaction IDs in a block to the dedup index.
    fn index_block_txs(&mut self, block: &Block) {
        for tx in &block.transactions {
            self.recent_tx_ids.insert(tx.transaction_id.clone());
        }
        self.maybe_trim_tx_index();
    }

    /// If the dedup index exceeds 2x the window, rebuild from the tail.
    fn maybe_trim_tx_index(&mut self) {
        if self.recent_tx_ids.len() > self.recent_tx_window * 2 {
            self.rebuild_tx_index();
        }
    }

    /// Rebuild the dedup index from the last `recent_tx_window` blocks.
    fn rebuild_tx_index(&mut self) {
        self.recent_tx_ids.clear();
        let start = self.blocks.len().saturating_sub(self.recent_tx_window);
        for block in &self.blocks[start..] {
            for tx in &block.transactions {
                self.recent_tx_ids.insert(tx.transaction_id.clone());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Current wall-clock time as seconds since the Unix epoch.
fn current_epoch() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Transaction;

    fn make_tx(id: &str) -> Transaction {
        use crate::types::ConsensusStatus;
        Transaction {
            transaction_id: id.to_owned(),
            observer_as: 1,
            ip_prefix: "10.0.0.0/24".to_owned(),
            sender_asn: 65001,
            as_path: vec![65001],
            timestamp: current_epoch(),
            is_attack: false,
            label: "LEGIT".to_owned(),
            rpki_validation: "VALID".to_owned(),
            detected_attacks: vec![],
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            signature: None,
            signer_as: None,
            signatures: Vec::new(),
            consensus_status: ConsensusStatus::Pending,
            consensus_reached: false,
            confidence_weight: 0.0,
            signature_count: 0,
            approve_count: 0,
            timeout_commit: false,
        }
    }

    #[test]
    fn test_genesis_block() {
        let bc = Blockchain::new(1);
        assert_eq!(bc.block_count(), 1);
        assert!(bc.is_valid());

        let genesis = bc.get_last_block().unwrap();
        assert_eq!(genesis.block_number, 0);
        assert_eq!(genesis.previous_hash, "0".repeat(64));
    }

    #[test]
    fn test_add_transaction() {
        let mut bc = Blockchain::new(1);
        let block = bc.add_transaction(make_tx("tx1"));
        assert!(block.is_some());
        assert_eq!(bc.block_count(), 2);
        assert!(bc.is_valid());
    }

    #[test]
    fn test_duplicate_rejected() {
        let mut bc = Blockchain::new(1);
        bc.add_transaction(make_tx("tx1"));
        let dup = bc.add_transaction(make_tx("tx1"));
        assert!(dup.is_none());
        assert_eq!(bc.block_count(), 2);
    }

    #[test]
    fn test_add_batch() {
        let mut bc = Blockchain::new(1);
        let txs = vec![make_tx("tx1"), make_tx("tx2"), make_tx("tx3")];
        let block = bc.add_batch(txs);
        assert!(block.is_some());
        assert_eq!(bc.block_count(), 2);
        assert_eq!(block.unwrap().transactions.len(), 3);
        assert!(bc.is_valid());
    }

    #[test]
    fn test_replicate_extends_tip() {
        let mut bc1 = Blockchain::new(1);
        let block = bc1.add_transaction(make_tx("tx1")).unwrap();

        let mut bc2 = Blockchain::new(2);
        // bc2 has only genesis, so previous_hash will NOT match bc2's genesis.
        // This tests the fork path. We need to replicate the block that
        // *extends* bc2's tip. Build a block that points to bc2's genesis:
        let mut compat = block.clone();
        compat.previous_hash = bc2.get_last_block().unwrap().block_hash.clone();
        compat.block_hash = Blockchain::calculate_block_hash(&compat);

        assert!(bc2.append_replicated_block(&compat));
        assert_eq!(bc2.block_count(), 2);
    }

    #[test]
    fn test_replicate_fork_merge() {
        let mut bc1 = Blockchain::new(1);
        let mut bc2 = Blockchain::new(2);

        // Both chains add different local blocks
        bc1.add_transaction(make_tx("tx_a"));
        bc2.add_transaction(make_tx("tx_b"));

        // Now replicate bc1's block onto bc2 — should fork-merge
        let bc1_block = &bc1.blocks[1]; // The block after genesis
        let ok = bc2.append_replicated_block(bc1_block);
        assert!(ok);

        let stats = bc2.stats();
        assert!(stats.forks_detected >= 1);
        assert!(stats.forks_resolved >= 1);
        assert!(stats.merge_blocks >= 1);
        // bc2 should now have: genesis + tx_b block + merge block = 3
        assert_eq!(bc2.block_count(), 3);
        assert!(bc2.is_valid());
    }

    #[test]
    fn test_reject_tampered_block() {
        let mut bc = Blockchain::new(1);
        let mut block = bc.add_transaction(make_tx("tx1")).unwrap();
        // Tamper with the hash
        block.block_hash = "bad_hash".to_owned();
        let mut bc2 = Blockchain::new(2);
        assert!(!bc2.append_replicated_block(&block));
    }

    #[test]
    fn test_stats() {
        let mut bc = Blockchain::new(1);
        bc.add_transaction(make_tx("tx1"));
        bc.add_batch(vec![make_tx("tx2"), make_tx("tx3")]);

        let s = bc.stats();
        assert_eq!(s.block_count, 3); // genesis + 1 + 1
        assert_eq!(s.transaction_count, 3);
    }
}
