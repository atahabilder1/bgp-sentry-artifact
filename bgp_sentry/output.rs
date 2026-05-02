//! Result output — writes experiment results to JSON files.
//!
//! Produces the same output format as the Python main_experiment.py
//! so results are directly comparable.

use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::info;

/// Summary of an experiment run.
#[derive(Debug, Serialize)]
pub struct ExperimentSummary {
    pub dataset: DatasetSummary,
    pub node_summary: NodeSummary,
    pub performance: PerformanceSummary,
    pub elapsed_seconds: f64,
    pub timestamp: String,
}

#[derive(Debug, Serialize)]
pub struct DatasetSummary {
    pub dataset_name: String,
    pub dataset_path: String,
    pub total_ases: usize,
    pub rpki_count: usize,
    pub non_rpki_count: usize,
    pub total_observations: usize,
    pub attack_observations: usize,
    pub legitimate_observations: usize,
}

#[derive(Debug, Serialize)]
pub struct NodeSummary {
    pub total_nodes: usize,
    pub rpki_nodes: usize,
    pub non_rpki_nodes: usize,
    pub nodes_done: usize,
    pub total_observations_processed: usize,
    pub attacks_detected: usize,
    pub legitimate_processed: usize,
}

#[derive(Debug, Serialize)]
pub struct PerformanceSummary {
    pub ground_truth_attacks: usize,
    pub total_detections: usize,
    pub true_positives: usize,
    pub false_positives: usize,
    pub false_negatives: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
}

#[derive(Debug, Serialize)]
pub struct ConsensusLog {
    pub total_transactions_created: usize,
    pub total_committed: usize,
    pub total_pending: usize,
    pub consensus_status_all_chains: HashMap<String, usize>,
    pub consensus_status_unique: HashMap<String, usize>,
    pub unique_transactions_across_chains: usize,
    pub block_type_counts: HashMap<String, usize>,
}

#[derive(Debug, Serialize)]
pub struct BlockchainStats {
    pub architecture: String,
    pub total_nodes: usize,
    pub valid_chains: usize,
    pub all_valid: bool,
    pub blocks_per_node: DistStats,
    pub transactions_per_node: DistStats,
    pub total_forks_detected: u64,
    pub total_forks_resolved: u64,
    pub total_merge_blocks: u64,
}

#[derive(Debug, Serialize)]
pub struct DistStats {
    pub min: f64,
    pub max: f64,
    pub mean: f64,
}

#[derive(Debug, Serialize)]
pub struct MessageBusStats {
    pub sent: u64,
    pub delivered: u64,
    pub dropped: u64,
}

#[derive(Debug, Serialize)]
pub struct DetectionResult {
    pub asn: u32,
    pub prefix: String,
    pub origin_asn: u32,
    pub label: String,
    pub is_attack: bool,
    pub timestamp: f64,
    pub detected: bool,
    pub detection_type: Option<String>,
    pub action: String,
    pub rpki_validation: String,
    pub transaction_id: String,
}

/// Create the output directory and return its path.
///
/// Directory structure: `results/<dataset>/hop<N>_<timestamp>/`
pub fn create_output_dir(base: &Path, dataset_name: &str) -> std::io::Result<PathBuf> {
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
    let hop_count = std::env::var("MAX_P2P_RELAY_HOPS")
        .or_else(|_| std::env::var("MAX_OBSERVATION_RECORDING_HOPS"))
        .unwrap_or_else(|_| "1".to_string());
    let run_name = format!("hop{}_{}", hop_count, timestamp);
    let dir = base.join("results").join(dataset_name).join(&run_name);
    std::fs::create_dir_all(&dir)?;
    info!("Output directory: {}", dir.display());
    Ok(dir)
}

/// Write a JSON file to the output directory.
pub fn write_json<T: Serialize>(dir: &Path, filename: &str, data: &T) -> std::io::Result<()> {
    let path = dir.join(filename);
    let json = serde_json::to_string_pretty(data)?;
    std::fs::write(&path, json)?;
    Ok(())
}

/// Compute distribution stats from a slice.
pub fn dist_stats(values: &[f64]) -> DistStats {
    if values.is_empty() {
        return DistStats {
            min: 0.0,
            max: 0.0,
            mean: 0.0,
        };
    }
    let min = values.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let sum: f64 = values.iter().sum();
    let mean = sum / values.len() as f64;
    DistStats { min, max, mean }
}
