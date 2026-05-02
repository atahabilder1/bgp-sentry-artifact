//! Dataset loader — reads BGP-Sentry JSON observation files.
//!
//! Reads `dataset/caida_N/observations/AS*.json` and
//! `dataset/caida_N/as_classification.json` + `ground_truth/ground_truth.json`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// A single BGP observation from the dataset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawObservation {
    pub prefix: String,
    pub origin_asn: u32,
    pub as_path: Vec<u32>,
    #[serde(default)]
    pub as_path_length: usize,
    #[serde(default)]
    pub next_hop_asn: u32,
    pub timestamp: f64,
    #[serde(default)]
    pub recv_relationship: String,
    #[serde(default)]
    pub origin_type: String,
    #[serde(default = "default_label")]
    pub label: String,
    #[serde(default)]
    pub is_attack: bool,
    #[serde(default)]
    pub observed_by_asn: u32,
    #[serde(default)]
    pub observer_is_rpki: bool,
    #[serde(default, rename = "hop_distance")]
    pub p2p_relay_hops: usize,
    #[serde(default)]
    pub is_best: bool,
    /// Injected synthetic attacks have this set to true
    #[serde(default, rename = "_injected")]
    pub injected: bool,
}

fn default_label() -> String {
    "LEGITIMATE".to_string()
}

/// Per-AS observation file structure.
#[derive(Debug, Deserialize)]
pub struct ObservationFile {
    pub asn: u32,
    #[serde(default)]
    pub is_rpki_node: bool,
    #[serde(default)]
    pub total_observations: usize,
    #[serde(default)]
    pub attack_observations: usize,
    #[serde(default)]
    pub legitimate_observations: usize,
    pub observations: Vec<RawObservation>,
}

/// AS classification data.
#[derive(Debug, Clone, Deserialize)]
pub struct AsClassification {
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub total_ases: usize,
    #[serde(default)]
    pub rpki_count: usize,
    #[serde(default)]
    pub non_rpki_count: usize,
    #[serde(default)]
    pub rpki_asns: Vec<u32>,
}

/// Ground truth attack entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundTruthAttack {
    #[serde(default)]
    pub timestamp: f64,
    #[serde(default)]
    pub prefix: String,
    #[serde(default)]
    pub origin_asn: u32,
    #[serde(default)]
    pub attack_type: String,
    #[serde(default)]
    pub as_path: Vec<u32>,
}

/// Ground truth file structure.
#[derive(Debug, Deserialize)]
pub struct GroundTruth {
    #[serde(default)]
    pub total_attacks: usize,
    #[serde(default)]
    pub attack_types: HashMap<String, usize>,
    #[serde(default)]
    pub attacks: Vec<GroundTruthAttack>,
}

/// Complete loaded dataset.
pub struct Dataset {
    pub name: String,
    pub path: PathBuf,
    pub classification: AsClassification,
    pub ground_truth: GroundTruth,
    /// Per-AS observations: ASN -> sorted observations
    pub observations: HashMap<u32, Vec<RawObservation>>,
    pub total_observations: usize,
    pub attack_observations: usize,
    pub legitimate_observations: usize,
}

impl Dataset {
    /// Load a dataset from `dataset/caida_N/`.
    pub fn load(dataset_path: &Path) -> anyhow::Result<Self> {
        let name = dataset_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        info!("Loading dataset: {} from {}", name, dataset_path.display());

        // Load AS classification
        let class_path = dataset_path.join("as_classification.json");
        let classification: AsClassification = if class_path.exists() {
            let data = std::fs::read_to_string(&class_path)?;
            serde_json::from_str(&data)?
        } else {
            warn!("as_classification.json not found, using defaults");
            AsClassification {
                description: String::new(),
                total_ases: 0,
                rpki_count: 0,
                non_rpki_count: 0,
                rpki_asns: Vec::new(),
            }
        };
        info!(
            "  AS classification: {} total, {} RPKI, {} non-RPKI",
            classification.total_ases, classification.rpki_count, classification.non_rpki_count
        );

        // Load ground truth
        let gt_path = dataset_path.join("ground_truth").join("ground_truth.json");
        let ground_truth: GroundTruth = if gt_path.exists() {
            let data = std::fs::read_to_string(&gt_path)?;
            serde_json::from_str(&data)?
        } else {
            warn!("ground_truth.json not found");
            GroundTruth {
                total_attacks: 0,
                attack_types: HashMap::new(),
                attacks: Vec::new(),
            }
        };
        info!(
            "  Ground truth: {} attacks, types: {:?}",
            ground_truth.total_attacks, ground_truth.attack_types
        );

        // Load all observation files
        let obs_dir = dataset_path.join("observations");
        let mut observations: HashMap<u32, Vec<RawObservation>> = HashMap::new();
        let mut total_obs = 0usize;
        let mut attack_obs = 0usize;

        if obs_dir.exists() {
            let mut entries: Vec<_> = std::fs::read_dir(&obs_dir)?
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.path()
                        .file_name()
                        .map(|n| n.to_string_lossy().starts_with("AS") && n.to_string_lossy().ends_with(".json"))
                        .unwrap_or(false)
                })
                .collect();
            entries.sort_by_key(|e| e.file_name());

            for entry in &entries {
                let data = std::fs::read_to_string(entry.path())?;
                let obs_file: ObservationFile = serde_json::from_str(&data)?;
                let asn = obs_file.asn;
                let obs_count = obs_file.observations.len();
                let atk_count = obs_file.observations.iter().filter(|o| o.is_attack).count();
                total_obs += obs_count;
                attack_obs += atk_count;
                observations.insert(asn, obs_file.observations);
            }
            info!(
                "  Loaded {} observation files, {} total obs ({} attacks, {} legit)",
                entries.len(),
                total_obs,
                attack_obs,
                total_obs - attack_obs
            );
        } else {
            warn!("  observations/ directory not found at {}", obs_dir.display());
        }

        Ok(Dataset {
            name,
            path: dataset_path.to_path_buf(),
            classification,
            ground_truth,
            observations,
            total_observations: total_obs,
            attack_observations: attack_obs,
            legitimate_observations: total_obs - attack_obs,
        })
    }

    /// Get sorted RPKI ASNs (validators).
    pub fn rpki_asns(&self) -> &[u32] {
        &self.classification.rpki_asns
    }

    /// Check if an ASN is RPKI.
    pub fn is_rpki(&self, asn: u32) -> bool {
        self.classification.rpki_asns.contains(&asn)
    }

    /// Get all observer ASNs (both RPKI and non-RPKI).
    pub fn all_observer_asns(&self) -> Vec<u32> {
        self.observations.keys().copied().collect()
    }
}
