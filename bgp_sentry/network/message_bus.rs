//! Async message bus for inter-node P2P communication.
//!
//! Port of Python's `AsyncMessageBus` — replaces GIL-bound threading with
//! lock-free tokio mpsc channels.  Each registered node gets a dedicated
//! channel; sending is a non-blocking `try_send` on the hot path (no mutexes).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::mpsc;
use tracing::warn;

use crate::types::{Block, Transaction, Vote};

// ---------------------------------------------------------------------------
// Message type
// ---------------------------------------------------------------------------

/// Messages exchanged between RPKI validator nodes.
#[derive(Debug, Clone)]
pub enum Message {
    VoteRequest {
        from_as: u32,
        transaction: Transaction,
    },
    VoteResponse {
        from_as: u32,
        transaction_id: String,
        vote: Vote,
        timestamp: f64,
        signature: Option<String>,
    },
    BlockReplicate {
        from_as: u32,
        block: Block,
    },
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

/// Snapshot of message bus counters.
#[derive(Debug, Clone)]
pub struct BusStats {
    pub sent: u64,
    pub delivered: u64,
    pub dropped: u64,
}

// ---------------------------------------------------------------------------
// MessageBus
// ---------------------------------------------------------------------------

/// Per-node channel capacity.  Sized to absorb short bursts without
/// back-pressure while bounding memory usage per node.
const CHANNEL_CAPACITY: usize = 4096;

/// Lock-free, async message bus backed by tokio mpsc channels.
///
/// Intended usage: wrap in `Arc<MessageBus>` and clone the `Arc` into every
/// spawned node task.
pub struct MessageBus {
    /// ASN -> sender half of that node's channel.
    senders: DashMap<u32, mpsc::Sender<Message>>,
    sent: AtomicU64,
    delivered: AtomicU64,
    dropped: AtomicU64,
}

impl MessageBus {
    /// Create a new, empty message bus.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            senders: DashMap::new(),
            sent: AtomicU64::new(0),
            delivered: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        })
    }

    /// Register a node and return the receiver half of its channel.
    ///
    /// If the ASN was already registered the old channel is replaced (the
    /// previous receiver will see a closed channel).
    pub fn register(&self, asn: u32) -> mpsc::Receiver<Message> {
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        self.senders.insert(asn, tx);
        rx
    }

    /// Unregister a node, dropping its sender.
    pub fn unregister(&self, asn: u32) {
        self.senders.remove(&asn);
    }

    /// Send a message to a specific node (non-blocking).
    ///
    /// Increments `sent` unconditionally.  On success the message enters the
    /// target's channel and `delivered` is bumped; on failure (node not found
    /// or channel full) `dropped` is bumped instead.
    pub fn send(&self, _from: u32, to: u32, message: Message) {
        self.sent.fetch_add(1, Ordering::Relaxed);
        if let Some(tx) = self.senders.get(&to) {
            match tx.try_send(message) {
                Ok(()) => {
                    self.delivered.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        } else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Broadcast a message to multiple target nodes.
    ///
    /// Each target gets its own clone of the message.
    pub fn broadcast(&self, from: u32, message: Message, targets: &[u32]) {
        for &target in targets {
            self.send(from, target, message.clone());
        }
    }

    /// Return a snapshot of the current counters.
    pub fn stats(&self) -> BusStats {
        BusStats {
            sent: self.sent.load(Ordering::Relaxed),
            delivered: self.delivered.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
        }
    }

    /// List all currently registered ASNs.
    pub fn registered_nodes(&self) -> Vec<u32> {
        self.senders.iter().map(|entry| *entry.key()).collect()
    }

    /// Number of currently registered nodes.
    pub fn node_count(&self) -> usize {
        self.senders.len()
    }

    /// Reset all counters to zero (useful between experiment runs).
    pub fn reset_stats(&self) {
        self.sent.store(0, Ordering::Relaxed);
        self.delivered.store(0, Ordering::Relaxed);
        self.dropped.store(0, Ordering::Relaxed);
    }
}

impl Default for MessageBus {
    fn default() -> Self {
        Self {
            senders: DashMap::new(),
            sent: AtomicU64::new(0),
            delivered: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn register_and_send() {
        let bus = MessageBus::new();
        let mut rx = bus.register(100);

        let tx = Transaction {
            transaction_id: "tx-1".into(),
            observer_as: 100,
            ip_prefix: "10.0.0.0/8".into(),
            sender_asn: 200,
            as_path: vec![100, 200],
            timestamp: 1.0,
            is_attack: false,
            label: "LEGIT".into(),
            rpki_validation: "VALID".into(),
            detected_attacks: vec![],
            created_at: "2026-01-01T00:00:00Z".into(),
            signature: None,
            signer_as: None,
            signatures: vec![],
            consensus_status: crate::types::ConsensusStatus::Pending,
            consensus_reached: false,
            confidence_weight: 0.0,
            signature_count: 0,
            approve_count: 0,
            timeout_commit: false,
        };

        bus.send(
            999,
            100,
            Message::VoteRequest {
                from_as: 999,
                transaction: tx,
            },
        );

        let msg = rx.recv().await.expect("should receive message");
        match msg {
            Message::VoteRequest { from_as, .. } => assert_eq!(from_as, 999),
            _ => panic!("unexpected message variant"),
        }

        let s = bus.stats();
        assert_eq!(s.sent, 1);
        assert_eq!(s.delivered, 1);
        assert_eq!(s.dropped, 0);
    }

    #[tokio::test]
    async fn send_to_missing_node_drops() {
        let bus = MessageBus::new();
        bus.send(
            1,
            999,
            Message::VoteResponse {
                from_as: 1,
                transaction_id: "tx-1".into(),
                vote: Vote::Approve,
                timestamp: 1.0,
                signature: None,
            },
        );

        let s = bus.stats();
        assert_eq!(s.sent, 1);
        assert_eq!(s.dropped, 1);
        assert_eq!(s.delivered, 0);
    }

    #[tokio::test]
    async fn broadcast_delivers_to_all_targets() {
        let bus = MessageBus::new();
        let mut rx1 = bus.register(10);
        let mut rx2 = bus.register(20);
        let _rx3 = bus.register(30); // not a target

        let tx = Transaction {
            transaction_id: "tx-b".into(),
            observer_as: 1,
            ip_prefix: "1.0.0.0/8".into(),
            sender_asn: 2,
            as_path: vec![1, 2],
            timestamp: 2.0,
            is_attack: false,
            label: "LEGIT".into(),
            rpki_validation: "VALID".into(),
            detected_attacks: vec![],
            created_at: "2026-01-01T00:00:00Z".into(),
            signature: None,
            signer_as: None,
            signatures: vec![],
            consensus_status: crate::types::ConsensusStatus::Pending,
            consensus_reached: false,
            confidence_weight: 0.0,
            signature_count: 0,
            approve_count: 0,
            timeout_commit: false,
        };

        bus.broadcast(
            1,
            Message::VoteRequest {
                from_as: 1,
                transaction: tx,
            },
            &[10, 20],
        );

        assert!(rx1.recv().await.is_some());
        assert!(rx2.recv().await.is_some());

        let s = bus.stats();
        assert_eq!(s.sent, 2);
        assert_eq!(s.delivered, 2);
    }
}
