//! BGP-Sentry-RS — Blockchain-based BGP security simulation (Rust port).
//!
//! Entry point: parses CLI arguments, loads config + dataset, creates a
//! `NodeManager`, runs the experiment, and writes results.
//!
//! # Dependencies note
//! Add `anyhow = "1"` to Cargo.toml [dependencies].

// ── Module declarations ─────────────────────────────────────────────────
pub mod clock;
pub mod config;
pub mod consensus;
pub mod crypto;
pub mod dataset;
pub mod detection;
pub mod network;
pub mod node_manager;
pub mod output;
pub mod types;
pub mod virtual_node;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::dataset::Dataset;
use crate::node_manager::NodeManager;
use crate::output::{create_output_dir, write_json};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// BGP-Sentry blockchain-based BGP security simulation.
#[derive(Parser)]
#[command(name = "bgp-sentry")]
#[command(about = "BGP-Sentry blockchain-based BGP security simulation")]
struct Cli {
    /// Dataset name (e.g., caida_50, caida_1600).
    #[arg(long)]
    dataset: String,

    /// Simulation duration override (seconds).
    #[arg(long)]
    duration: Option<u64>,

    /// Path to common .env file.
    #[arg(long, default_value = ".env.common")]
    env_common: String,

    /// Path to dataset-specific .env file (auto-detected from dataset name if
    /// not provided).
    #[arg(long)]
    env_dataset: Option<String>,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    // ── 1. Parse CLI arguments ──────────────────────────────────────
    let cli = Cli::parse();

    // ── 2. Setup tracing / logging ──────────────────────────────────
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .with_thread_ids(false)
        .init();

    info!("==================================================");
    info!("BGP-SENTRY-RS EXPERIMENT STARTING");
    info!("==================================================");

    // ── 3. Load config (.env.common + .env.N) ───────────────────────
    let dataset_env = cli.env_dataset.unwrap_or_else(|| {
        // Auto-detect: caida_50 -> .env.50
        if let Some(suffix) = cli.dataset.strip_prefix("caida_") {
            format!(".env.{}", suffix)
        } else {
            String::new()
        }
    });

    let mut config = if dataset_env.is_empty() {
        Config::load(None)
    } else {
        Config::load(Some(&dataset_env))
    };

    // Apply CLI duration override
    if let Some(dur) = cli.duration {
        config.sim_duration = dur;
    }

    // Scale BGP-time-sensitive parameters by speed multiplier.
    // At 10x speed, BGP events arrive 10x faster in wall-clock time.
    // Without scaling, a 15s dedup window covers 150s of BGP time at 10x.
    // Dividing by speed keeps the effective BGP-time window unchanged.
    let speed = config.simulation_speed_multiplier;
    if speed > 1.0 {
        config.rpki_dedup_window = (config.rpki_dedup_window as f64 / speed).ceil() as u64;
        config.nonrpki_dedup_window = (config.nonrpki_dedup_window as f64 / speed).ceil() as u64;
        config.voting_observation_window = (config.voting_observation_window as f64 / speed).ceil() as u64;
        config.sampling_window_seconds = (config.sampling_window_seconds as f64 / speed).ceil() as u64;
        // NOTE: flap_window_seconds and flap_dedup_seconds are NOT scaled
        // because the flap detector now uses BGP timestamps directly
        // (not wall-clock), so it operates in BGP time regardless of speed.
        info!(
            "Speed {:.0}x: scaled BGP-time windows (dedup={}s, KB={}s, flap={}s unscaled)",
            speed, config.rpki_dedup_window, config.voting_observation_window, config.flap_window_seconds,
        );
    }

    info!(
        "Config loaded (speed={:.1}x, duration={}s, consensus_threshold={})",
        config.simulation_speed_multiplier, config.sim_duration, config.consensus_min_signatures,
    );

    let config = Arc::new(config);

    // ── 4. Resolve and load dataset ─────────────────────────────────
    let dataset_path =
        resolve_dataset_path(&cli.dataset).context("Failed to resolve dataset path")?;

    let dataset = Dataset::load(&dataset_path).context("Failed to load dataset")?;

    info!(
        "Dataset: {} -- {} ASes ({} RPKI, {} non-RPKI), {} observations ({} attacks)",
        dataset.name,
        dataset.classification.total_ases,
        dataset.classification.rpki_count,
        dataset.classification.non_rpki_count,
        dataset.total_observations,
        dataset.attack_observations,
    );

    let dataset = Arc::new(dataset);

    // ── 5. Build AS relationships + observer map ────────────────────
    // In the Python version these are built by scripts/build_as_relationships.py
    // and scripts/build_observer_map.py. For the Rust port, we assume they have
    // already been generated and are available in blockchain_data/state/.
    ensure_state_directory().context("Failed to create blockchain_data/state directory")?;

    // ── 6. Create NodeManager ───────────────────────────────────────
    let wall_start = Instant::now();
    let manager = NodeManager::new(Arc::clone(&config), Arc::clone(&dataset));

    // ── 7. Run experiment ───────────────────────────────────────────
    info!("Duration limit: {}s", config.sim_duration);
    let results = manager.run().await?;

    // ── 8. Write results to output directory ────────────────────────
    let project_root = find_project_root();
    let output_dir = create_output_dir(&project_root, &dataset.name)
        .context("Failed to create output directory")?;

    write_json(&output_dir, "experiment_summary.json", &results.summary)
        .context("Failed to write experiment_summary.json")?;
    write_json(
        &output_dir,
        "blockchain_stats.json",
        &results.blockchain_stats,
    )
    .context("Failed to write blockchain_stats.json")?;
    write_json(&output_dir, "consensus_log.json", &results.consensus_log)
        .context("Failed to write consensus_log.json")?;
    write_json(
        &output_dir,
        "message_bus_stats.json",
        &results.bus_stats,
    )
    .context("Failed to write message_bus_stats.json")?;
    write_json(
        &output_dir,
        "detection_results.json",
        &results.detection_results,
    )
    .context("Failed to write detection_results.json")?;
    write_json(&output_dir, "config.json", config.as_ref())
        .context("Failed to write config.json")?;

    // ── 9. Print summary ────────────────────────────────────────────
    let total_elapsed = wall_start.elapsed().as_secs_f64();
    info!("==================================================");
    info!("EXPERIMENT COMPLETED in {:.1}s", total_elapsed);
    info!(
        "  Nodes: {} RPKI + {} non-RPKI",
        results.summary.node_summary.rpki_nodes, results.summary.node_summary.non_rpki_nodes,
    );
    info!(
        "  Observations processed: {}",
        results.summary.node_summary.total_observations_processed,
    );
    info!(
        "  Attacks detected: {}",
        results.summary.node_summary.attacks_detected,
    );
    info!(
        "  Blockchain: {} valid chains, {} forks detected, {} resolved",
        results.blockchain_stats.valid_chains,
        results.blockchain_stats.total_forks_detected,
        results.blockchain_stats.total_forks_resolved,
    );
    info!(
        "  Consensus: {} committed, {} unique across chains",
        results.consensus_log.total_committed,
        results.consensus_log.unique_transactions_across_chains,
    );
    info!(
        "  Message bus: {} sent, {} delivered, {} dropped",
        results.bus_stats.sent, results.bus_stats.delivered, results.bus_stats.dropped,
    );
    info!("  Results: {}", output_dir.display());
    info!("==================================================");

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve a dataset name (e.g. "caida_50") to its full path on disk.
///
/// Searches:
/// 1. `<project_root>/dataset/<name>/`
/// 2. The name itself as an absolute or relative path.
fn resolve_dataset_path(dataset_name: &str) -> Result<PathBuf> {
    // Try relative to project root
    let project_root = find_project_root();
    let candidate = project_root.join("dataset").join(dataset_name);
    if candidate.exists() {
        return Ok(candidate);
    }

    // Try as absolute/relative path
    let as_path = PathBuf::from(dataset_name);
    if as_path.exists() {
        return Ok(as_path.canonicalize()?);
    }

    bail!(
        "Dataset '{}' not found. Looked in: {}",
        dataset_name,
        candidate.display()
    );
}

/// Walk upward from the current directory (or CARGO_MANIFEST_DIR) to find
/// the project root containing `Cargo.toml`.
fn find_project_root() -> PathBuf {
    if let Ok(dir) = std::env::var("CARGO_MANIFEST_DIR") {
        return PathBuf::from(dir);
    }

    let mut dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    loop {
        if dir.join("Cargo.toml").exists() {
            return dir;
        }
        if !dir.pop() {
            return std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        }
    }
}

/// Ensure the `blockchain_data/state/` directory exists (for ROA + AS
/// relationship databases).
fn ensure_state_directory() -> Result<()> {
    let state_dir = find_project_root()
        .join("blockchain_data")
        .join("state");
    std::fs::create_dir_all(&state_dir)?;
    Ok(())
}

/// Collect system information for benchmark metadata.
#[allow(dead_code)]
fn get_system_info() -> serde_json::Value {
    let mut info = serde_json::Map::new();

    info.insert(
        "platform".into(),
        serde_json::Value::String(std::env::consts::OS.to_string()),
    );
    info.insert(
        "arch".into(),
        serde_json::Value::String(std::env::consts::ARCH.to_string()),
    );

    // CPU count
    if let Some(count) = std::thread::available_parallelism()
        .ok()
        .map(|p| p.get())
    {
        info.insert("cpu_count".into(), serde_json::json!(count));
    }

    // Memory (Linux)
    if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
        for line in meminfo.lines() {
            if line.starts_with("MemTotal:") {
                if let Some(kb_str) = line.split_whitespace().nth(1) {
                    if let Ok(kb) = kb_str.parse::<u64>() {
                        let gb = kb as f64 / 1024.0 / 1024.0;
                        info.insert(
                            "memory_total_gb".into(),
                            serde_json::json!(format!("{:.1}", gb)),
                        );
                    }
                }
                break;
            }
        }
    }

    serde_json::Value::Object(info)
}
