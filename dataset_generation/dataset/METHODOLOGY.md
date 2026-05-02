# BGP-Sentry Dataset Generation Methodology

## Overview

This document describes the methodology for generating realistic BGP observation datasets used in the BGP-Sentry blockchain consensus simulation. All datasets are derived from real-world data sources with simulated BGP propagation and synthetic attack injection.

## Topologies

4 regional topologies extracted from real CAIDA AS-relationships (2022-01-01). RPKI adoption rates from real rpki-client VRP snapshot (2026-04-18).

| # | Topology | Region | ASes | RPKI ASes | RPKI % | Attacks |
|---|---|---|---|---|---|---|
| 1 | 904_afrinic_transit_mh | AFRINIC | 904 | 445 | 49.2% | No |
| 2 | 2030_arin_transit | ARIN | 2,030 | 1,371 | 67.5% | No |
| 3 | 3152_lacnic_afrinic_transit | LACNIC+AFRINIC | 3,152 | 1,930 | 61.2% | No |
| 4 | 5008_lacnic_5plus_mh | LACNIC | 5,008 | 2,671 | 53.3% | Yes |

## Simulation Parameters

- **Duration**: 12 hours (43,200 seconds)
- **Seed**: 42 (fully reproducible)
- **Propagation model**: BGPy Gao-Rexford
- **Reach**: ~92% (each announcement propagates to ~92% of nodes)

## Observation Rates

Derived from real-world BGP measurements at AS6447 (potaroo.net BGP Update Report, April 2026):

- Real internet (78,360 ASes): 5.86 ev/sec/node
- Per-AS generation rate: 0.000138 ev/sec (~12 updates/day)

Target rates for each topology are proportionally scaled:

```
target_rate = 5.86 x (topology_size / 78,360)
```

| Topology | Target Rate | Actual Rate | Obs/Node (12h) |
|---|---|---|---|
| 904_afrinic | 0.064 ev/sec/node | ~0.077 | ~3,327 |
| 2030_arin | 0.15 ev/sec/node | ~0.173 | ~7,470 |
| 3152_lacnic_afrinic | 0.23 ev/sec/node | ~0.269 | ~11,599 |
| 5008_lacnic | 0.37 ev/sec/node | ~0.427 | ~18,429 |

Actual rates are slightly above target due to integer ceiling of announces per node. This is within realistic daily variance of real BGP traffic.

## Stochastic Parameters

All randomness is controlled by a single seed for reproducibility.

### 1. Announces per AS: Uniform(3, 5)

Each AS announces its single prefix 3-5 times (randomized per AS, average 4) over the 12-hour window. Real ASes have varying update frequencies; this models that variance conservatively.

### 2. Inter-arrival timestamps: Poisson process

Timestamps are generated using exponentially distributed inter-arrival times (Poisson process), the standard model for BGP update arrivals in networking literature.

- Average gap = duration / total_events
- Recalibrated after exact event count is known, ensuring events span the full 12h window

**Citation**: Labovitz et al. 2001, "Delayed Internet Routing Convergence" (SIGCOMM)

### 3. Propagation jitter: Log-normal per hop

Each hop in the AS-path adds a log-normal delay modeling real MRAI timer processing and queue delays:

- Distribution: Log-normal(mu=ln(5.5), sigma=0.75)
- Median: ~5.5 seconds per hop
- Clamped: [1, 20] seconds per hop
- Additive: total jitter = sum of per-hop delays

An observer 3 hops away sees an announcement ~16s after origin. Further nodes always see it later.

### 4. Withdrawal rate: 10%

10% of legitimately announced prefixes are subsequently withdrawn, consistent with measured explicit withdrawal rates of 7-12% at full-table BGP peers.

**Citation**: Huston 2024/2025 (potaroo.net BGP Update Reports)

### 5. Withdrawal delay: Log-normal(median=30s, clamped 10-180s)

Time between the last announcement and the withdrawal event follows a log-normal distribution, matching RIPE RIS beacon measurements showing bulk convergence in 30-40 seconds with a long tail extending to 3+ minutes.

**Citation**: Labovitz et al. 2000 (SIGCOMM); RIPE Labs, "The Shape of a BGP Update"

### 6. Flapping oscillation: 5-9 cycles, 5-10s gaps

Route flapping attacks produce 5-9 rapid announce/withdraw cycles with 5-10 second gaps between oscillations. All attack instances fit within the 60-second detection window, ensuring 100% detectability.

- Total attack span: 40-162 seconds
- Minimum events in any 60s window: 5+
- Legitimate ASes (3-5 announces over 12h) never trigger this threshold

### 7. Attack timestamps: Uniform(120s, duration)

Attack events are spread uniformly across the simulation window after a 120-second warm-up period. Uniform distribution is the unbiased choice, avoiding artificial clustering.

### 8. Attacker/victim selection: Random

Attackers are randomly selected from non-RPKI ASes (attackers deploying RPKI would be traceable). Victims are randomly selected per attack type.

## Prefix Assignment

Each AS is assigned exactly 1 prefix. No silent nodes.

| AS Type | Prefix Source | ROA Exists? | Coverage |
|---|---|---|---|
| RPKI ASes | Real VRP (rpki-client snapshot) | Yes (from same VRP) | ~50-67% of ASes |
| Non-RPKI ASes | RouteViews (pyasn RIB dump) | No | ~33-50% of ASes |
| Fallback | Synthetic (44.x.x.0/24 or 45.x.x.0/24) | Synthetic for RPKI | <0.3% of ASes |

99.7%+ of prefixes come from real data sources.

## Attack Types

5 attack types injected into the 5008_lacnic topology only (5 instances per type):

| # | Attack | Source | Detection Method | Real-time? |
|---|---|---|---|---|
| 1 | PREFIX_HIJACK | BGPy simulation | Origin != ROA authorized AS | Yes |
| 2 | BOGON_INJECTION | BGPy simulation | Prefix in reserved/bogon range | Yes |
| 3 | ROUTE_FLAPPING | BGPy simulation | 5+ repeated (prefix, origin) in 60s | Near real-time |
| 4 | PATH_POISONING | Post-injection script | Consecutive AS pair not in CAIDA | Yes |
| 5 | ROUTE_LEAK | Post-injection script | Valley-free violation in AS-path | Yes |

- Attack types 1-3: Injected during BGPy simulation (1-hop propagation)
- Attack types 4-5: Injected by post-processing scripts (2-hop propagation)
- Attack ratio: <2% of total observations

## Detection Properties

| Property | Value |
|---|---|
| False positive rate | 0% (legitimate traffic never triggers any detector) |
| Theoretical recall | 100% (all attack parameters exceed detection thresholds) |
| Flapping separation | Legitimate: 1 announce per ~3 hours vs Attack: 5+ in 60 seconds |

## Data Sources

| Component | Source | Type |
|---|---|---|
| AS topology | CAIDA AS-relationships (2022-01-01) | Real |
| RPKI status | rpki-client VRP snapshot (2026-04-18) | Real |
| Prefix assignment (RPKI) | rpki-client VRP | Real |
| Prefix assignment (non-RPKI) | RouteViews/pyasn RIB dump | Real |
| ROA database | rpki-client VRP filtered to topology | Real |
| Observation rates | potaroo.net AS6447 (April 2026) | Real |
| BGP propagation | BGPy Gao-Rexford model | Simulated |
| Attacks (types 1-3) | BGPy attack scenarios | Synthetic |
| Attacks (types 4-5) | Post-injection scripts | Synthetic |

## Generation Commands

```bash
# All 4 datasets (unified script)
./generate_all_datasets.sh

# Individual topologies
python3 step1_generate_dataset.py \
    --from-topology dataset/904_afrinic_transit_mh/ \
    --output dataset --timeline-duration 43200 \
    --target-rate 0.064 --no-attacks --seed 42

python3 step1_generate_dataset.py \
    --from-topology dataset/2030_arin_transit/ \
    --output dataset --timeline-duration 43200 \
    --target-rate 0.15 --no-attacks --seed 42

python3 step1_generate_dataset.py \
    --from-topology dataset/3152_lacnic_afrinic_transit/ \
    --output dataset --timeline-duration 43200 \
    --target-rate 0.23 --no-attacks --seed 42

python3 step1_generate_dataset.py \
    --from-topology dataset/5008_lacnic_5plus_mh/ \
    --output dataset --timeline-duration 43200 \
    --target-rate 0.37 --attacks-per-type 5 --seed 42

# Post-injection (5008_lacnic only)
python3 scripts/inject_path_poisoning.py 5008_lacnic_5plus_mh --dataset-root . --events-per-type 5
python3 scripts/inject_route_leak.py 5008_lacnic_5plus_mh --dataset-root . --events-per-type 5

# Verification
python3 scripts/verify_dataset.py 5008_lacnic_5plus_mh --dataset-root .
```
