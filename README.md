# BGP-Sentry: Reproducibility Artifact

This repository provides the complete open-science reproducibility package for
**"BGP-Sentry: A Blockchain-Based Framework for Collaborative BGP Attack Detection"** (ACM CCS 2026).

It contains: (1) the dataset generation pipeline built on the BGPy framework
with real CAIDA topology and RPKI data, (2) the full source code of the
BGP-Sentry blockchain consensus simulation, and (3) all evaluation and
visualization scripts needed to reproduce every figure and table in the
Evaluation section.

---

## Repository Structure

```
bgp-sentry-artifact/
│
├── README.md
├── Cargo.toml                        Rust project manifest
├── Cargo.lock                        Pinned Rust dependency versions
├── .env                              Simulation hyperparameters
│
├── bgp_sentry/                       BGP-Sentry source code (Rust)
│   ├── main.rs                         Entry point and CLI
│   ├── virtual_node.rs                 Per-AS blockchain node logic
│   ├── node_manager.rs                 Orchestrates all nodes in the simulation
│   ├── config.rs                       Configuration loader (.env parsing)
│   ├── clock.rs                        Simulation clock
│   ├── crypto.rs                       Ed25519 signing and verification
│   ├── dataset.rs                      Dataset reader (loads per-AS observations)
│   ├── output.rs                       Results serialization
│   ├── types.rs                        Shared type definitions
│   ├── consensus/                      Consensus protocol
│   │   ├── mod.rs                        Module entry
│   │   ├── blockchain.rs                 Per-node blockchain (block production, forks)
│   │   ├── transaction_pool.rs           Voting and consensus classification
│   │   ├── knowledge_base.rs            Observation memory per node
│   │   └── origin_attestation.rs        Origin validation logic
│   ├── detection/                      Attack detection
│   │   └── mod.rs                        7 detectors (hijack, bogon, flap, leak, etc.)
│   └── network/                        P2P overlay
│       ├── mod.rs                        Module entry
│       └── message_bus.rs               Inter-node message routing
│
├── dataset_generation/                Dataset generation pipeline
│   ├── step1_generate_dataset.py       Main generator (BGPy Gao-Rexford simulation)
│   ├── pyproject.toml                  Python package configuration
│   ├── setup.cfg                       Package metadata
│   ├── requirements.txt               Python dependencies
│   ├── LICENSE.txt                     BGPy license
│   ├── bgpy/                           BGPy framework source
│   │   ├── simulation_engine/            Gao-Rexford BGP propagation engine
│   │   ├── simulation_framework/         Scenario and attack injection framework
│   │   └── as_graphs/                    AS graph construction from CAIDA data
│   ├── scripts/                        Post-generation processing
│   │   ├── inject_path_poisoning.py      Inject PATH_POISONING attack campaigns
│   │   ├── inject_route_leak.py          Inject ROUTE_LEAK attack campaigns
│   │   ├── extract_regional_topology.py  Extract regional subgraphs from CAIDA
│   │   └── verify_dataset.py            Validate dataset integrity
│   └── dataset/                        Topology definitions and source data
│       ├── METHODOLOGY.md                Dataset generation methodology
│       ├── source_data/                  Real-world input data
│       │   ├── downloaded_caida_as_relationships_20260401.txt
│       │   ├── downloaded_rpki_vrps_20260418.json
│       │   └── computed_from_downloaded_rpki_vrps_unique_asns_20260418.json
│       ├── 904_afrinic_transit_mh/       Topology configs (per region)
│       ├── 2030_arin_transit/
│       ├── 3152_lacnic_afrinic_transit/
│       └── 5008_lacnic_5plus_mh/
│           Each topology folder contains:
│             as_relationships.json    — Inter-AS links (customer/provider/peer)
│             as_classification.json   — RPKI vs non-RPKI AS classification
│             roa_database.json        — Route Origin Authorizations for the region
│
└── evaluation/                          Evaluation and visualization
    ├── score_detection.py              Compute detection accuracy (precision/recall/F1)
    ├── create_rpki_ablation.py         Generate RPKI coverage ablation datasets
    ├── rpki_ablation_multiseed.py      Run ablation across multiple seeds
    └── figures/                        Paper figure generation (one script per figure)
        ├── consensus_stats.py            Consensus status distribution
        ├── p2p_scalability.py            P2P message delivery scalability
        ├── tps_scalability.py            Transactions-per-second scaling
        ├── tps_projection.py             TPS projection to larger networks
        ├── observation_completeness.py   Observation coverage analysis
        ├── observation_redundancy.py     Redundancy across observers
        ├── announcement_coverage.py      Announcement coverage metrics
        ├── announcement_coverage_dual.py Announcement + RPKI adoption dual chart
        ├── plot_rpki_ablation.py         RPKI ablation study results
        ├── topology_schematic.py         Network topology visualization
        └── full_topology_schematic.py    Full CAIDA topology (k-core layout)
```

---

## Prerequisites

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Rust | 1.75+ | Build BGP-Sentry binary |
| Python | 3.10+ | Dataset generation, evaluation, plotting |
| RAM | 32 GB+ | Large topology simulations |
| Disk | ~500 GB | Generated observation datasets |

---

## Reproducing Results

### Step 1 — Generate Datasets

The observation datasets are generated deterministically from real CAIDA
AS-relationship data using the BGPy Gao-Rexford propagation model. All runs
use seed `42` for full reproducibility.

```bash
cd dataset_generation
python3 -m venv venv
source venv/bin/activate
pip install -e .
pip install numpy roa-checker
```

Generate each topology (12-hour simulated timeline per topology):

```bash
# AFRINIC (904 ASes, with attacks — for detection evaluation)
python3 step1_generate_dataset.py \
    --from-topology dataset/904_afrinic_transit_mh/ \
    --output dataset --timeline-duration 43200 \
    --target-rate 0.064 --attacks-per-type 5 --seed 42

# ARIN (2030 ASes, no attacks)
python3 step1_generate_dataset.py \
    --from-topology dataset/2030_arin_transit/ \
    --output dataset --timeline-duration 43200 \
    --target-rate 0.15 --no-attacks --seed 42

# LACNIC+AFRINIC (3152 ASes, no attacks)
python3 step1_generate_dataset.py \
    --from-topology dataset/3152_lacnic_afrinic_transit/ \
    --output dataset --timeline-duration 43200 \
    --target-rate 0.23 --no-attacks --seed 42

# LACNIC (5008 ASes, no attacks)
python3 step1_generate_dataset.py \
    --from-topology dataset/5008_lacnic_5plus_mh/ \
    --output dataset --timeline-duration 43200 \
    --target-rate 0.37 --no-attacks --seed 42

```

Copy generated datasets to the project root:

```bash
cd ..
mkdir -p dataset
cp -r dataset_generation/dataset/904_afrinic_attack dataset/
cp -r dataset_generation/dataset/2030_arin_transit dataset/
cp -r dataset_generation/dataset/3152_lacnic_afrinic_transit dataset/
cp -r dataset_generation/dataset/5008_lacnic_5plus_mh dataset/
```

**Generated topologies:**

| Dataset | Region | Total ASes | RPKI Validators | Attacks |
|---------|--------|-----------|-----------------|---------|
| `904_afrinic_attack` | AFRINIC | 904 | 445 (49.2%) | Yes |
| `2030_arin_transit` | ARIN | 2,030 | 1,371 (67.5%) | No |
| `3152_lacnic_afrinic_transit` | LACNIC+AFRINIC | 3,152 | 1,930 (61.2%) | No |
| `5008_lacnic_5plus_mh` | LACNIC | 5,008 | 2,671 (53.3%) | No |

### Step 2 — Build BGP-Sentry

```bash
cargo build --release
```

The compiled binary is placed at `./target/release/bgp-sentry`.

### Step 3 — Run Experiments

Run BGP-Sentry on each topology. The default configuration uses
`MAX_P2P_RELAY_HOPS=0` (first-hand BGP observations only):

```bash
./target/release/bgp-sentry --dataset 904_afrinic_attack
./target/release/bgp-sentry --dataset 2030_arin_transit
./target/release/bgp-sentry --dataset 3152_lacnic_afrinic_transit
./target/release/bgp-sentry --dataset 5008_lacnic_5plus_mh
```

Results are written to `results/<topology>/<timestamp>/`.

### Step 4 — Evaluate and Visualize Results

Score the attack detection results for `904_afrinic_attack` against ground truth:

```bash
python3 evaluation/score_detection.py results/904_afrinic_attack/<run_dir>/
```

This outputs precision, recall, and F1 scores per attack type and overall.

Generate all paper figures (consensus distribution, scalability, coverage, topology).
Output is saved to `output/figures/`:

```bash
pip install matplotlib numpy networkx
mkdir -p output/figures

python3 evaluation/figures/consensus_stats.py
python3 evaluation/figures/p2p_scalability.py
python3 evaluation/figures/tps_scalability.py
python3 evaluation/figures/tps_projection.py
python3 evaluation/figures/observation_completeness.py
python3 evaluation/figures/observation_redundancy.py
python3 evaluation/figures/announcement_coverage.py
python3 evaluation/figures/topology_schematic.py
python3 evaluation/figures/plot_rpki_ablation.py
```

---

## Configuration

Simulation hyperparameters are set in `.env`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `SIM_DURATION` | 43200 | Simulated time window (seconds; 43200 = 12 hours) |
| `MAX_P2P_RELAY_HOPS` | 0 | P2P relay depth (0 = first-hand only, 1 = one relay hop) |
| `CONSENSUS_MIN_SIGNATURES` | 3 | Minimum peer votes for CONFIRMED status |
| `CONSENSUS_CAP_SIGNATURES` | 3 | Maximum votes solicited per transaction |
| `VOTER_SELECTION_MODE` | origin_neighbors | Voter strategy (`origin_neighbors` or `proposer_path`) |
| `VOTING_OBSERVATION_WINDOW` | 300 | Window (seconds) for voter observation lookup |
| `RPKI_DEDUP_WINDOW` | 15 | Deduplication window for repeated (prefix, origin) pairs |
| `FLAP_THRESHOLD` | 3 | Oscillation count before triggering ROUTE_FLAPPING |
| `FLAP_WINDOW_SECONDS` | 60 | Time window for counting route flaps |
| `SIMULATION_SPEED_MULTIPLIER` | 20 | Replay speed (20x real-time) |

---

## Data Provenance

| Data Source | Description | Date |
|-------------|-------------|------|
| CAIDA AS Relationships | Inter-AS business relationships inferred from RouteViews/RIPE RIS | 2026-04-01 |
| RPKI VRP Snapshot | Validated ROA Payloads via rpki-client (all 5 RIR TALs) | 2026-04-18 |
| BGPy Framework | Gao-Rexford BGP propagation simulation engine | v6.x |

All topology subgraphs are extracted from the global CAIDA dataset using real AS
numbers and their actual RPKI enrollment status. No synthetic edges or artificial
RPKI assignments are introduced.

---

## Determinism

All experiments are fully deterministic:
- Dataset generation: `--seed 42` (Python `random` + NumPy random state)
- Rust simulation: deterministic event scheduling (no randomized ordering)
- Consensus voting: fixed peer-selection algorithm seeded by topology structure

Re-running the pipeline with identical parameters produces identical results.
