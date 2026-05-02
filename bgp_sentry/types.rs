// =============================================================================
// BGP-Sentry Shared Data Types (Rust port)
// =============================================================================
//
// All core data structures used across consensus, detection, network, and
// blockchain modules.
// =============================================================================

use serde::{Deserialize, Serialize};
use std::fmt;

// =============================================================================
// Consensus Status
// =============================================================================

/// The consensus outcome for a transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConsensusStatus {
    /// 3+ approve votes — full consensus, highest trust weight.
    Confirmed,
    /// 1-2 approve votes — partial corroboration, medium trust weight.
    InsufficientConsensus,
    /// 0 approve votes — only the proposer saw it, lowest trust weight.
    SingleWitness,
    /// Not yet finalized.
    Pending,
}

impl fmt::Display for ConsensusStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConsensusStatus::Confirmed => write!(f, "CONFIRMED"),
            ConsensusStatus::InsufficientConsensus => write!(f, "INSUFFICIENT_CONSENSUS"),
            ConsensusStatus::SingleWitness => write!(f, "SINGLE_WITNESS"),
            ConsensusStatus::Pending => write!(f, "PENDING"),
        }
    }
}

impl From<&str> for ConsensusStatus {
    fn from(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "CONFIRMED" => ConsensusStatus::Confirmed,
            "INSUFFICIENT_CONSENSUS" | "INSUFFICIENT" => ConsensusStatus::InsufficientConsensus,
            "SINGLE_WITNESS" => ConsensusStatus::SingleWitness,
            "PENDING" => ConsensusStatus::Pending,
            _ => ConsensusStatus::Pending,
        }
    }
}

impl From<String> for ConsensusStatus {
    fn from(s: String) -> Self {
        ConsensusStatus::from(s.as_str())
    }
}

impl From<ConsensusStatus> for String {
    fn from(status: ConsensusStatus) -> Self {
        status.to_string()
    }
}

// =============================================================================
// Vote
// =============================================================================

/// A peer's vote on a transaction during consensus.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Vote {
    /// Peer corroborates the observation.
    Approve,
    /// Peer has no knowledge of this (prefix, origin) — abstention.
    NoKnowledge,
    /// Peer actively disputes the observation.
    Reject,
}

impl fmt::Display for Vote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Vote::Approve => write!(f, "APPROVE"),
            Vote::NoKnowledge => write!(f, "NO_KNOWLEDGE"),
            Vote::Reject => write!(f, "REJECT"),
        }
    }
}

impl From<&str> for Vote {
    fn from(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "APPROVE" => Vote::Approve,
            "NO_KNOWLEDGE" | "NOKNOWLEDGE" | "ABSTAIN" => Vote::NoKnowledge,
            "REJECT" => Vote::Reject,
            _ => Vote::NoKnowledge,
        }
    }
}

impl From<String> for Vote {
    fn from(s: String) -> Self {
        Vote::from(s.as_str())
    }
}

impl From<Vote> for String {
    fn from(vote: Vote) -> Self {
        vote.to_string()
    }
}

// =============================================================================
// Vote Record
// =============================================================================

/// A single vote cast by a peer validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteRecord {
    /// ASN of the voting peer.
    pub from_as: u32,
    /// The vote decision.
    pub vote: Vote,
    /// Timestamp when the vote was cast (BGP time).
    pub timestamp: Option<f64>,
    /// Cryptographic signature over the transaction hash.
    pub signature: Option<String>,
}

// =============================================================================
// Transaction
// =============================================================================

/// A blockchain transaction representing a BGP observation that has gone
/// through (or is going through) the consensus process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Unique identifier (UUID v4).
    pub transaction_id: String,
    /// ASN of the node that observed the BGP announcement.
    pub observer_as: u32,
    /// ASN that sent the announcement to the observer.
    pub sender_asn: u32,
    /// The IP prefix being announced (e.g. "1.0.0.0/24").
    pub ip_prefix: String,
    /// Full AS-path from the BGP announcement.
    pub as_path: Vec<u32>,
    /// BGP timestamp of the observation.
    pub timestamp: f64,
    /// Ground-truth attack flag (from dataset labels).
    pub is_attack: bool,
    /// Human-readable label from the dataset.
    pub label: String,
    /// RPKI validation status (e.g. "VALID", "INVALID", "NOT_FOUND").
    pub rpki_validation: String,
    /// Attack types detected by local detectors.
    pub detected_attacks: Vec<String>,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// Proposer's cryptographic signature.
    pub signature: Option<String>,
    /// ASN that signed the transaction (proposer).
    pub signer_as: Option<u32>,
    /// Collected peer votes.
    pub signatures: Vec<VoteRecord>,
    /// Final consensus outcome.
    pub consensus_status: ConsensusStatus,
    /// Whether consensus has been reached (no longer pending).
    pub consensus_reached: bool,
    /// Confidence weight derived from consensus level.
    pub confidence_weight: f64,
    /// Total number of vote signatures collected.
    pub signature_count: usize,
    /// Number of APPROVE votes.
    pub approve_count: usize,
    /// Whether this transaction was committed due to timeout (no quorum).
    pub timeout_commit: bool,
}

impl Transaction {
    /// Deduplication key: (prefix, origin_asn).
    pub fn dedup_key(&self) -> (String, u32) {
        let origin = self.as_path.last().copied().unwrap_or(self.observer_as);
        (self.ip_prefix.clone(), origin)
    }
}

// =============================================================================
// Block Type
// =============================================================================

/// The type/purpose of a block in a node's chain.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BlockType {
    /// Normal block containing consensus-validated transactions.
    Transaction,
    /// Batch block containing multiple transactions committed together.
    Batch,
    /// Fork-merge block incorporating novel transactions from a peer's chain.
    ForkMerge,
    /// Genesis block (first block in each node's chain).
    Genesis,
    /// Block recording an attack verdict from multi-validator detection.
    AttackVerdict,
}

impl fmt::Display for BlockType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockType::Transaction => write!(f, "TRANSACTION"),
            BlockType::Batch => write!(f, "BATCH"),
            BlockType::ForkMerge => write!(f, "FORK_MERGE"),
            BlockType::Genesis => write!(f, "GENESIS"),
            BlockType::AttackVerdict => write!(f, "ATTACK_VERDICT"),
        }
    }
}

impl From<&str> for BlockType {
    fn from(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "TRANSACTION" => BlockType::Transaction,
            "BATCH" => BlockType::Batch,
            "FORK_MERGE" | "FORKMERGE" => BlockType::ForkMerge,
            "GENESIS" => BlockType::Genesis,
            "ATTACK_VERDICT" | "ATTACKVERDICT" => BlockType::AttackVerdict,
            _ => BlockType::Transaction,
        }
    }
}

impl From<String> for BlockType {
    fn from(s: String) -> Self {
        BlockType::from(s.as_str())
    }
}

impl From<BlockType> for String {
    fn from(bt: BlockType) -> Self {
        bt.to_string()
    }
}

// =============================================================================
// Block
// =============================================================================

/// A block in a node's per-node blockchain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    /// Sequential block number (0 = genesis).
    pub block_number: usize,
    /// SHA-256 hash of the previous block.
    pub previous_hash: String,
    /// SHA-256 hash of this block's contents.
    pub block_hash: String,
    /// Timestamp when the block was created.
    pub timestamp: f64,
    /// ASN of the node that produced this block.
    pub proposer: u32,
    /// Transactions included in this block.
    pub transactions: Vec<Transaction>,
    /// The purpose of this block.
    pub block_type: BlockType,
}

// =============================================================================
// Observation
// =============================================================================

/// A raw BGP observation from the dataset, before it enters the blockchain
/// pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    /// The IP prefix being announced (e.g. "1.0.0.0/24").
    pub prefix: String,
    /// Origin ASN from the AS-path.
    pub origin_asn: u32,
    /// Full AS-path.
    pub as_path: Vec<u32>,
    /// Length of the AS-path.
    pub as_path_length: usize,
    /// Next-hop ASN.
    pub next_hop_asn: u32,
    /// BGP timestamp.
    pub timestamp: f64,
    /// Relationship to the receiver (e.g. "customer", "peer", "provider").
    pub recv_relationship: String,
    /// Origin type from BGP (e.g. "IGP", "EGP", "INCOMPLETE").
    pub origin_type: String,
    /// Ground-truth label from the dataset.
    pub label: String,
    /// Whether this observation is an attack (ground truth).
    pub is_attack: bool,
    /// ASN of the node that observed this announcement.
    pub observed_by_asn: u32,
    /// Whether the observer is an RPKI-enabled validator.
    pub observer_is_rpki: bool,
    /// Number of P2P overlay relay hops. 0 = BGP-observed (first-hand),
    /// 1+ = relayed via blockchain P2P network.
    #[serde(alias = "hop_distance")]
    pub p2p_relay_hops: usize,
    /// Whether this is the best route for the prefix at the observer.
    pub is_best: bool,
    /// Whether this observation was synthetically injected (for ROUTE_LEAK /
    /// PATH_POISONING testing).
    #[serde(default)]
    pub injected: bool,
}

// =============================================================================
// AS Classification
// =============================================================================

/// Classification of ASes in the topology into RPKI and non-RPKI sets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsClassification {
    /// ASNs that are RPKI-enabled validators (blockchain participants).
    pub rpki_asns: Vec<u32>,
    /// Total number of ASes in the topology.
    pub total_ases: usize,
    /// Number of RPKI-enabled ASes.
    pub rpki_count: usize,
    /// Number of non-RPKI ASes.
    pub non_rpki_count: usize,
}

// =============================================================================
// Attack Detection
// =============================================================================

/// Result from a local attack detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackDetection {
    /// Attack type identifier (e.g. "PREFIX_HIJACK", "BOGON_INJECTION").
    pub attack_type: String,
    /// Severity level (e.g. "HIGH", "MEDIUM", "LOW").
    pub severity: String,
    /// Human-readable description of the detected attack.
    pub description: String,
    /// AS-path from the suspicious announcement.
    pub as_path: Vec<u32>,
    /// Additional structured evidence (detector-specific).
    pub evidence: serde_json::Value,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consensus_status_roundtrip() {
        let statuses = [
            ConsensusStatus::Confirmed,
            ConsensusStatus::InsufficientConsensus,
            ConsensusStatus::SingleWitness,
            ConsensusStatus::Pending,
        ];
        for status in &statuses {
            let s: String = status.clone().into();
            let back = ConsensusStatus::from(s.as_str());
            assert_eq!(&back, status);
        }
    }

    #[test]
    fn test_vote_roundtrip() {
        let votes = [Vote::Approve, Vote::NoKnowledge, Vote::Reject];
        for vote in &votes {
            let s: String = vote.clone().into();
            let back = Vote::from(s.as_str());
            assert_eq!(&back, vote);
        }
    }

    #[test]
    fn test_block_type_roundtrip() {
        let types = [
            BlockType::Transaction,
            BlockType::Batch,
            BlockType::ForkMerge,
            BlockType::Genesis,
            BlockType::AttackVerdict,
        ];
        for bt in &types {
            let s: String = bt.clone().into();
            let back = BlockType::from(s.as_str());
            assert_eq!(&back, bt);
        }
    }

    #[test]
    fn test_consensus_status_display() {
        assert_eq!(ConsensusStatus::Confirmed.to_string(), "CONFIRMED");
        assert_eq!(
            ConsensusStatus::InsufficientConsensus.to_string(),
            "INSUFFICIENT_CONSENSUS"
        );
        assert_eq!(ConsensusStatus::SingleWitness.to_string(), "SINGLE_WITNESS");
        assert_eq!(ConsensusStatus::Pending.to_string(), "PENDING");
    }

    #[test]
    fn test_transaction_dedup_key() {
        let tx = Transaction {
            transaction_id: "test".into(),
            observer_as: 100,
            sender_asn: 200,
            ip_prefix: "1.0.0.0/24".into(),
            as_path: vec![200, 300, 400],
            timestamp: 0.0,
            is_attack: false,
            label: "LEGIT".into(),
            rpki_validation: "VALID".into(),
            detected_attacks: vec![],
            created_at: "2026-01-01T00:00:00Z".into(),
            signature: None,
            signer_as: None,
            signatures: vec![],
            consensus_status: ConsensusStatus::Pending,
            consensus_reached: false,
            confidence_weight: 0.0,
            signature_count: 0,
            approve_count: 0,
            timeout_commit: false,
        };
        // Origin is last element of as_path
        assert_eq!(tx.dedup_key(), ("1.0.0.0/24".to_string(), 400));
    }

    #[test]
    fn test_observation_serde() {
        let obs = Observation {
            prefix: "10.0.0.0/8".into(),
            origin_asn: 65001,
            as_path: vec![65001],
            as_path_length: 1,
            next_hop_asn: 65001,
            timestamp: 1000.0,
            recv_relationship: "customer".into(),
            origin_type: "IGP".into(),
            label: "LEGIT".into(),
            is_attack: false,
            observed_by_asn: 65002,
            observer_is_rpki: true,
            p2p_relay_hops: 1,
            is_best: true,
            injected: false,
        };
        let json = serde_json::to_string(&obs).unwrap();
        let back: Observation = serde_json::from_str(&json).unwrap();
        assert_eq!(back.prefix, "10.0.0.0/8");
        assert_eq!(back.origin_asn, 65001);
    }

    #[test]
    fn test_attack_detection_evidence() {
        let det = AttackDetection {
            attack_type: "BOGON_INJECTION".into(),
            severity: "HIGH".into(),
            description: "Reserved prefix advertised".into(),
            as_path: vec![100, 200],
            evidence: serde_json::json!({
                "prefix": "10.0.0.0/8",
                "bogon_type": "RFC1918"
            }),
        };
        assert_eq!(det.evidence["bogon_type"], "RFC1918");
    }
}
