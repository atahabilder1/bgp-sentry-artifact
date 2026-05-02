// =============================================================================
// BGP-Sentry Configuration Loader (Rust port)
// =============================================================================
//
// Reads tunable hyperparameters from .env files so that every module gets a
// single, consistent set of values.
//
// Usage:
//     let cfg = Config::load(Some(".env.50"));
//     let timeout = cfg.p2p_regular_timeout;
// =============================================================================

use serde::{Deserialize, Serialize};
use std::env;
use std::path::Path;

/// Helper: read an env var and parse it, falling back to a default.
macro_rules! env_or {
    ($key:expr, $default:expr, $T:ty) => {{
        env::var($key)
            .ok()
            .and_then(|v| {
                // Strip inline comments (e.g. "3  # comment")
                let cleaned = v.split('#').next().unwrap_or("").trim().to_string();
                cleaned.parse::<$T>().ok()
            })
            .unwrap_or($default)
    }};
}

/// Helper for bool env vars: "true", "1", "yes" → true.
fn env_bool(key: &str, default: bool) -> bool {
    env::var(key)
        .map(|v| matches!(v.to_lowercase().trim(), "true" | "1" | "yes"))
        .unwrap_or(default)
}

/// All tunable parameters for BGP-Sentry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    // ── Consensus ────────────────────────────────────────────────────
    pub consensus_min_signatures: i32,
    pub consensus_cap_signatures: i32,
    pub consensus_weight_confirmed: f64,
    pub consensus_weight_insufficient: f64,
    pub consensus_weight_single_witness: f64,

    // ── P2P Network ─────────────────────────────────────────────────
    pub p2p_regular_timeout: u64,
    pub p2p_attack_timeout: u64,
    pub p2p_max_broadcast_peers: u64,
    pub p2p_base_port: u16,
    /// Consensus voting radius in AS-level hops.
    /// Default: max_p2p_relay_hops + 1 (if not explicitly set).
    pub consensus_voting_hops: u8,
    /// Voter selection mode: "origin_neighbors" or "proposer_path".
    /// origin_neighbors: prioritize RPKI validators that are direct neighbors
    ///   of the origin AS in the CAIDA topology (independent first-hand witnesses).
    /// proposer_path: prioritize RPKI validators on the observed AS-path
    ///   (current behavior, same propagation chain).
    pub voter_selection_mode: String,

    // ── Deduplication & Sampling ────────────────────────────────────
    pub rpki_dedup_window: u64,
    pub nonrpki_dedup_window: u64,
    pub sampling_window_seconds: u64,

    // ── Voting Observation Window ─────────────────────────────────────
    /// Voter only considers observations from the last N seconds.
    /// Default: 300s (5 minutes).
    pub voting_observation_window: u64,
    pub knowledge_cleanup_interval: u64,

    // ── Buffer Capacity Limits ──────────────────────────────────────
    pub pending_votes_max_capacity: usize,
    pub committed_tx_max_size: usize,
    pub committed_tx_cleanup_interval: u64,
    pub knowledge_base_max_size: usize,
    pub last_seen_cache_max_size: usize,
    pub ingestion_buffer_max_size: usize,

    // ── Attack Detection — Route Flapping ───────────────────────────
    pub flap_window_seconds: u64,
    pub flap_threshold: u64,
    pub flap_dedup_seconds: u64,

    // ── BGPCOIN Economy ─────────────────────────────────────────────
    pub bgpcoin_total_supply: u64,

    pub bgpcoin_reward_block_commit: f64,
    pub bgpcoin_reward_vote_approve: f64,
    pub bgpcoin_reward_first_commit_bonus: f64,
    pub bgpcoin_reward_attack_detection: f64,
    pub bgpcoin_reward_daily_monitoring: f64,

    pub bgpcoin_penalty_false_reject: f64,
    pub bgpcoin_penalty_false_approve: f64,
    pub bgpcoin_penalty_missed_participation: f64,

    pub bgpcoin_multiplier_accuracy_min: f64,
    pub bgpcoin_multiplier_accuracy_max: f64,
    pub bgpcoin_multiplier_participation_min: f64,
    pub bgpcoin_multiplier_participation_max: f64,
    pub bgpcoin_multiplier_quality_min: f64,
    pub bgpcoin_multiplier_quality_max: f64,

    // ── Non-RPKI Trust Rating ───────────────────────────────────────
    pub rating_initial_score: i32,
    pub rating_min_score: i32,
    pub rating_max_score: i32,

    pub rating_penalty_prefix_hijack: i32,
    pub rating_penalty_subprefix_hijack: i32,
    pub rating_penalty_bogon_injection: i32,
    pub rating_penalty_route_flapping: i32,
    pub rating_penalty_route_leak: i32,
    pub rating_penalty_forged_origin: i32,
    pub rating_penalty_accidental_route_leak: i32,
    pub rating_penalty_repeated_attack: i32,
    pub rating_penalty_persistent_attacker: i32,

    pub rating_reward_monthly_good_behavior: i32,
    pub rating_reward_false_accusation_cleared: i32,
    pub rating_reward_per_100_legitimate: i32,
    pub rating_reward_highly_trusted_bonus: i32,

    pub rating_threshold_highly_trusted: i32,
    pub rating_threshold_trusted: i32,
    pub rating_threshold_neutral: i32,
    pub rating_threshold_suspicious: i32,

    // ── Attack Consensus ────────────────────────────────────────────
    pub attack_consensus_min_votes: i32,
    pub attack_consensus_reward_detection: f64,
    pub attack_consensus_reward_correct_vote: f64,
    pub attack_consensus_penalty_false_accusation: f64,

    // ── Transaction Batching ────────────────────────────────────────
    pub batch_size: usize,
    pub batch_timeout: f64,

    // ── Simulation Timing ───────────────────────────────────────────
    pub simulation_speed_multiplier: f64,
    pub warmup_duration: u64,
    pub sim_duration: u64,

    // ── Observation Recording Filter ──────────────────────────────────
    /// Maximum AS-path hop count for an RPKI node to record an announcement.
    /// Announcements from origins farther than this many hops are ignored.
    pub max_p2p_relay_hops: usize,

    // ── Async Mode ──────────────────────────────────────────────────
    pub use_async: bool,

    // ── Attack Detection Toggle ─────────────────────────────────────
    /// When false, all attack detectors are skipped (observations are still
    /// recorded on the blockchain but no detection logic runs).
    pub attack_detection_enabled: bool,
}

impl Config {
    /// Load configuration from environment files.
    ///
    /// - If `dataset_env_path` is `Some(".env.50")`, loads `.env.common` first
    ///   then overlays the dataset-specific file.
    /// - If `None`, only loads `.env.common` (if it exists).
    ///
    /// Files are resolved relative to the project root (the directory
    /// containing `Cargo.toml`).
    pub fn load(dataset_env_path: Option<&str>) -> Self {
        let project_root = Self::find_project_root();

        // Capture any process environment overrides BEFORE loading .env files.
        // dotenvy::from_path_override would clobber them, so we save and restore.
        let saved_env: Vec<(String, String)> = env::vars().collect();

        // Load .env first (base settings), then fall back to .env.common
        let env_path = project_root.join(".env");
        let common_path = project_root.join(".env.common");
        if env_path.exists() {
            let _ = dotenvy::from_path_override(&env_path);
        } else if common_path.exists() {
            let _ = dotenvy::from_path_override(&common_path);
        }

        // Overlay dataset-specific .env file (overrides common settings)
        if let Some(env_file) = dataset_env_path {
            let overlay_path = project_root.join(env_file);
            if overlay_path.exists() {
                let _ = dotenvy::from_path_override(&overlay_path);
            }
        }

        // Restore process environment overrides (CLI/shell env vars win).
        for (key, value) in saved_env {
            env::set_var(&key, &value);
        }

        Self::from_env()
    }

    /// Build a Config by reading all parameters from the current environment.
    fn from_env() -> Self {
        let mut cfg = Config {
            // ── Consensus ────────────────────────────────────────────
            consensus_min_signatures: env_or!("CONSENSUS_MIN_SIGNATURES", 3, i32),
            consensus_cap_signatures: env_or!("CONSENSUS_CAP_SIGNATURES", 3, i32),
            consensus_weight_confirmed: env_or!("CONSENSUS_WEIGHT_CONFIRMED", 1.0, f64),
            consensus_weight_insufficient: env_or!("CONSENSUS_WEIGHT_INSUFFICIENT", 0.5, f64),
            consensus_weight_single_witness: env_or!("CONSENSUS_WEIGHT_SINGLE_WITNESS", 0.2, f64),

            // ── P2P Network ──────────────────────────────────────────
            p2p_regular_timeout: env_or!("P2P_REGULAR_TIMEOUT", 30, u64),
            p2p_attack_timeout: env_or!("P2P_ATTACK_TIMEOUT", 60, u64),
            p2p_max_broadcast_peers: env_or!("P2P_MAX_BROADCAST_PEERS", 10, u64),
            p2p_base_port: env_or!("P2P_BASE_PORT", 8000, u16),
            // consensus_voting_hops: set below after max_p2p_relay_hops is known
            consensus_voting_hops: 0, // placeholder
            voter_selection_mode: env::var("VOTER_SELECTION_MODE")
                .unwrap_or_else(|_| "origin_neighbors".to_string())
                .trim().to_lowercase(),

            // ── Deduplication & Sampling ──────────────────────────────
            rpki_dedup_window: env_or!("RPKI_DEDUP_WINDOW", 3600, u64),
            nonrpki_dedup_window: env_or!("NONRPKI_DEDUP_WINDOW", 10, u64),
            sampling_window_seconds: env_or!("SAMPLING_WINDOW_SECONDS", 3600, u64),

            // ── Voting Observation Window ─────────────────────────────
            voting_observation_window: env_or!("VOTING_OBSERVATION_WINDOW", 300, u64),
            knowledge_cleanup_interval: env_or!("KNOWLEDGE_CLEANUP_INTERVAL", 60, u64),

            // ── Buffer Capacity Limits ────────────────────────────────
            pending_votes_max_capacity: env_or!("PENDING_VOTES_MAX_CAPACITY", 5000, usize),
            committed_tx_max_size: env_or!("COMMITTED_TX_MAX_SIZE", 50000, usize),
            committed_tx_cleanup_interval: env_or!("COMMITTED_TX_CLEANUP_INTERVAL", 300, u64),
            knowledge_base_max_size: env_or!("KNOWLEDGE_BASE_MAX_SIZE", 50000, usize),
            last_seen_cache_max_size: env_or!("LAST_SEEN_CACHE_MAX_SIZE", 100000, usize),
            ingestion_buffer_max_size: env_or!("INGESTION_BUFFER_MAX_SIZE", 1000, usize),

            // ── Attack Detection — Route Flapping ─────────────────────
            flap_window_seconds: env_or!("FLAP_WINDOW_SECONDS", 60, u64),
            flap_threshold: env_or!("FLAP_THRESHOLD", 3, u64),
            flap_dedup_seconds: env_or!("FLAP_DEDUP_SECONDS", 2, u64),

            // ── BGPCOIN Economy ───────────────────────────────────────
            bgpcoin_total_supply: env_or!("BGPCOIN_TOTAL_SUPPLY", 10_000_000, u64),

            bgpcoin_reward_block_commit: env_or!("BGPCOIN_REWARD_BLOCK_COMMIT", 10.0, f64),
            bgpcoin_reward_vote_approve: env_or!("BGPCOIN_REWARD_VOTE_APPROVE", 1.0, f64),
            bgpcoin_reward_first_commit_bonus: env_or!(
                "BGPCOIN_REWARD_FIRST_COMMIT_BONUS",
                5.0,
                f64
            ),
            bgpcoin_reward_attack_detection: env_or!(
                "BGPCOIN_REWARD_ATTACK_DETECTION",
                100.0,
                f64
            ),
            bgpcoin_reward_daily_monitoring: env_or!(
                "BGPCOIN_REWARD_DAILY_MONITORING",
                10.0,
                f64
            ),

            bgpcoin_penalty_false_reject: env_or!("BGPCOIN_PENALTY_FALSE_REJECT", 2.0, f64),
            bgpcoin_penalty_false_approve: env_or!("BGPCOIN_PENALTY_FALSE_APPROVE", 5.0, f64),
            bgpcoin_penalty_missed_participation: env_or!(
                "BGPCOIN_PENALTY_MISSED_PARTICIPATION",
                1.0,
                f64
            ),

            bgpcoin_multiplier_accuracy_min: env_or!(
                "BGPCOIN_MULTIPLIER_ACCURACY_MIN",
                0.5,
                f64
            ),
            bgpcoin_multiplier_accuracy_max: env_or!(
                "BGPCOIN_MULTIPLIER_ACCURACY_MAX",
                1.5,
                f64
            ),
            bgpcoin_multiplier_participation_min: env_or!(
                "BGPCOIN_MULTIPLIER_PARTICIPATION_MIN",
                0.8,
                f64
            ),
            bgpcoin_multiplier_participation_max: env_or!(
                "BGPCOIN_MULTIPLIER_PARTICIPATION_MAX",
                1.2,
                f64
            ),
            bgpcoin_multiplier_quality_min: env_or!("BGPCOIN_MULTIPLIER_QUALITY_MIN", 0.9, f64),
            bgpcoin_multiplier_quality_max: env_or!("BGPCOIN_MULTIPLIER_QUALITY_MAX", 1.3, f64),

            // ── Non-RPKI Trust Rating ─────────────────────────────────
            rating_initial_score: env_or!("RATING_INITIAL_SCORE", 50, i32),
            rating_min_score: env_or!("RATING_MIN_SCORE", 0, i32),
            rating_max_score: env_or!("RATING_MAX_SCORE", 100, i32),

            rating_penalty_prefix_hijack: env_or!("RATING_PENALTY_PREFIX_HIJACK", -20, i32),
            rating_penalty_subprefix_hijack: env_or!("RATING_PENALTY_SUBPREFIX_HIJACK", -18, i32),
            rating_penalty_bogon_injection: env_or!("RATING_PENALTY_BOGON_INJECTION", -25, i32),
            rating_penalty_route_flapping: env_or!("RATING_PENALTY_ROUTE_FLAPPING", -10, i32),
            rating_penalty_route_leak: env_or!("RATING_PENALTY_ROUTE_LEAK", -15, i32),
            rating_penalty_forged_origin: env_or!("RATING_PENALTY_FORGED_ORIGIN", -30, i32),
            rating_penalty_accidental_route_leak: env_or!(
                "RATING_PENALTY_ACCIDENTAL_ROUTE_LEAK",
                -8,
                i32
            ),
            rating_penalty_repeated_attack: env_or!("RATING_PENALTY_REPEATED_ATTACK", -30, i32),
            rating_penalty_persistent_attacker: env_or!(
                "RATING_PENALTY_PERSISTENT_ATTACKER",
                -50,
                i32
            ),

            rating_reward_monthly_good_behavior: env_or!(
                "RATING_REWARD_MONTHLY_GOOD_BEHAVIOR",
                5,
                i32
            ),
            rating_reward_false_accusation_cleared: env_or!(
                "RATING_REWARD_FALSE_ACCUSATION_CLEARED",
                2,
                i32
            ),
            rating_reward_per_100_legitimate: env_or!(
                "RATING_REWARD_PER_100_LEGITIMATE",
                1,
                i32
            ),
            rating_reward_highly_trusted_bonus: env_or!(
                "RATING_REWARD_HIGHLY_TRUSTED_BONUS",
                10,
                i32
            ),

            rating_threshold_highly_trusted: env_or!("RATING_THRESHOLD_HIGHLY_TRUSTED", 90, i32),
            rating_threshold_trusted: env_or!("RATING_THRESHOLD_TRUSTED", 70, i32),
            rating_threshold_neutral: env_or!("RATING_THRESHOLD_NEUTRAL", 50, i32),
            rating_threshold_suspicious: env_or!("RATING_THRESHOLD_SUSPICIOUS", 30, i32),

            // ── Attack Consensus ──────────────────────────────────────
            attack_consensus_min_votes: env_or!("ATTACK_CONSENSUS_MIN_VOTES", 3, i32),
            attack_consensus_reward_detection: env_or!(
                "ATTACK_CONSENSUS_REWARD_DETECTION",
                10.0,
                f64
            ),
            attack_consensus_reward_correct_vote: env_or!(
                "ATTACK_CONSENSUS_REWARD_CORRECT_VOTE",
                2.0,
                f64
            ),
            attack_consensus_penalty_false_accusation: env_or!(
                "ATTACK_CONSENSUS_PENALTY_FALSE_ACCUSATION",
                -20.0,
                f64
            ),

            // ── Transaction Batching ──────────────────────────────────
            batch_size: env_or!("BATCH_SIZE", 1, usize),
            batch_timeout: env_or!("BATCH_TIMEOUT", 0.5, f64),

            // ── Simulation Timing ─────────────────────────────────────
            simulation_speed_multiplier: env_or!("SIMULATION_SPEED_MULTIPLIER", 1.0, f64),
            warmup_duration: env_or!("WARMUP_DURATION", 60, u64),
            sim_duration: env_or!("SIM_DURATION", 2100, u64),

            // ── Observation Recording Filter ─────────────────────────
            max_p2p_relay_hops: env::var("MAX_P2P_RELAY_HOPS")
                .or_else(|_| env::var("MAX_OBSERVATION_RECORDING_HOPS"))
                .ok()
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(1),

            // ── Async Mode ────────────────────────────────────────────
            use_async: env_bool("USE_ASYNC", false),

            // ── Attack Detection Toggle ──────────────────────────────
            attack_detection_enabled: env_bool("ATTACK_DETECTION_ENABLED", true),
        };

        // Default consensus_voting_hops = max_p2p_relay_hops + 1
        // unless explicitly set via CONSENSUS_VOTING_HOPS env var.
        cfg.consensus_voting_hops = match env::var("CONSENSUS_VOTING_HOPS") {
            Ok(val) => val.parse::<u8>().unwrap_or((cfg.max_p2p_relay_hops + 1) as u8),
            Err(_) => (cfg.max_p2p_relay_hops + 1) as u8,
        };

        cfg
    }

    /// Walk upward from the executable / current dir to find the project root
    /// (the directory containing `Cargo.toml`).
    fn find_project_root() -> std::path::PathBuf {
        // Try CARGO_MANIFEST_DIR first (set during `cargo run`)
        if let Ok(dir) = env::var("CARGO_MANIFEST_DIR") {
            return std::path::PathBuf::from(dir);
        }

        // Fallback: walk up from current directory
        let mut dir = env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        loop {
            if dir.join("Cargo.toml").exists() {
                return dir;
            }
            if !dir.pop() {
                // Give up — use current directory
                return env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
            }
        }
    }

    /// Compute the effective consensus threshold for a given number of RPKI
    /// validators: `max(min_signatures, min(n/3 + 1, cap_signatures))`.
    pub fn consensus_threshold(&self, num_validators: usize) -> usize {
        let dynamic = num_validators / 3 + 1;
        let capped = dynamic.min(self.consensus_cap_signatures as usize);
        capped.max(self.consensus_min_signatures as usize)
    }

    /// Compute adaptive broadcast peer count:
    /// `max(threshold * 2, sqrt(N))` — scales sublinearly with network size.
    pub fn adaptive_broadcast_peers(&self, num_validators: usize) -> usize {
        let threshold = self.consensus_threshold(num_validators);
        let sqrt_n = (num_validators as f64).sqrt().ceil() as usize;
        (threshold * 2).max(sqrt_n)
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            consensus_min_signatures: 3,
            consensus_cap_signatures: 3,
            consensus_weight_confirmed: 1.0,
            consensus_weight_insufficient: 0.5,
            consensus_weight_single_witness: 0.2,

            p2p_regular_timeout: 30,
            p2p_attack_timeout: 60,
            p2p_max_broadcast_peers: 10,
            p2p_base_port: 8000,
            consensus_voting_hops: 2, // default: max_p2p_relay_hops(1) + 1
            voter_selection_mode: "origin_neighbors".to_string(),

            rpki_dedup_window: 3600,
            nonrpki_dedup_window: 10,
            sampling_window_seconds: 3600,

            voting_observation_window: 300,
            knowledge_cleanup_interval: 60,

            pending_votes_max_capacity: 5000,
            committed_tx_max_size: 50000,
            committed_tx_cleanup_interval: 300,
            knowledge_base_max_size: 50000,
            last_seen_cache_max_size: 100000,
            ingestion_buffer_max_size: 1000,

            flap_window_seconds: 60,
            flap_threshold: 3,
            flap_dedup_seconds: 2,

            bgpcoin_total_supply: 10_000_000,

            bgpcoin_reward_block_commit: 10.0,
            bgpcoin_reward_vote_approve: 1.0,
            bgpcoin_reward_first_commit_bonus: 5.0,
            bgpcoin_reward_attack_detection: 100.0,
            bgpcoin_reward_daily_monitoring: 10.0,

            bgpcoin_penalty_false_reject: 2.0,
            bgpcoin_penalty_false_approve: 5.0,
            bgpcoin_penalty_missed_participation: 1.0,

            bgpcoin_multiplier_accuracy_min: 0.5,
            bgpcoin_multiplier_accuracy_max: 1.5,
            bgpcoin_multiplier_participation_min: 0.8,
            bgpcoin_multiplier_participation_max: 1.2,
            bgpcoin_multiplier_quality_min: 0.9,
            bgpcoin_multiplier_quality_max: 1.3,

            rating_initial_score: 50,
            rating_min_score: 0,
            rating_max_score: 100,

            rating_penalty_prefix_hijack: -20,
            rating_penalty_subprefix_hijack: -18,
            rating_penalty_bogon_injection: -25,
            rating_penalty_route_flapping: -10,
            rating_penalty_route_leak: -15,
            rating_penalty_forged_origin: -30,
            rating_penalty_accidental_route_leak: -8,
            rating_penalty_repeated_attack: -30,
            rating_penalty_persistent_attacker: -50,

            rating_reward_monthly_good_behavior: 5,
            rating_reward_false_accusation_cleared: 2,
            rating_reward_per_100_legitimate: 1,
            rating_reward_highly_trusted_bonus: 10,

            rating_threshold_highly_trusted: 90,
            rating_threshold_trusted: 70,
            rating_threshold_neutral: 50,
            rating_threshold_suspicious: 30,

            attack_consensus_min_votes: 3,
            attack_consensus_reward_detection: 10.0,
            attack_consensus_reward_correct_vote: 2.0,
            attack_consensus_penalty_false_accusation: -20.0,

            batch_size: 1,
            batch_timeout: 0.5,

            simulation_speed_multiplier: 1.0,
            warmup_duration: 60,
            sim_duration: 2100,

            max_p2p_relay_hops: 2,

            use_async: false,

            attack_detection_enabled: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = Config::default();
        assert_eq!(cfg.consensus_min_signatures, 3);
        assert_eq!(cfg.p2p_base_port, 8000);
        assert!((cfg.consensus_weight_confirmed - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_consensus_threshold() {
        let cfg = Config::default();
        // With 9 validators: 9/3+1 = 4, min(4, 3) = 3, max(3, 3) = 3
        assert_eq!(cfg.consensus_threshold(9), 3);
        // With 3 validators: 3/3+1 = 2, min(2, 3) = 2, max(2, 3) = 3
        assert_eq!(cfg.consensus_threshold(3), 3);
    }

    #[test]
    fn test_adaptive_broadcast() {
        let cfg = Config::default();
        // With 100 validators: threshold=3, sqrt(100)=10, max(6, 10) = 10
        assert_eq!(cfg.adaptive_broadcast_peers(100), 10);
    }
}
