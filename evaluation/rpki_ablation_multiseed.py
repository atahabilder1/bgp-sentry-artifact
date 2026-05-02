#!/usr/bin/env python3
"""
RPKI ablation coverage analysis — reads coverage from actual created datasets.

Extracts 1-hop and 2-hop non-RPKI AS coverage from the datasets generated
by create_rpki_ablation.py for each seed. Reports mean and std across seeds.

Usage:
    python3 evaluation/rpki_ablation_multiseed.py
"""

import json
import statistics
from collections import defaultdict
from pathlib import Path

DATASET_ROOT = Path("dataset")
RESULTS_DIR = Path("results/rpki_ablation_904")

ZONES = ["arin", "apnic", "lacnic", "afrinic", "ripe"]
RPKI_PCTS = {"arin": 50, "apnic": 54, "lacnic": 59, "afrinic": 63, "ripe": 75}

# Seed 42 datasets don't have _s42 suffix (original run)
SEEDS = [42, 43, 44]


def load_json(path):
    with open(path) as f:
        return json.load(f)


def build_adjacency(as_rels):
    adj = defaultdict(set)
    for asn_str, rels in as_rels.items():
        asn = int(asn_str)
        for neighbor in rels.get("customers", []):
            adj[asn].add(neighbor)
            adj[neighbor].add(asn)
        for neighbor in rels.get("providers", []):
            adj[asn].add(neighbor)
            adj[neighbor].add(asn)
        for neighbor in rels.get("peers", []):
            adj[asn].add(neighbor)
            adj[neighbor].add(asn)
    return adj


def compute_hop_coverage(rpki_set, non_rpki_set, adjacency, max_hops):
    if not non_rpki_set:
        return 100.0
    covered = 0
    for nr_asn in non_rpki_set:
        visited = {nr_asn}
        frontier = {nr_asn}
        found = False
        for _ in range(max_hops):
            next_frontier = set()
            for node in frontier:
                for neighbor in adjacency.get(node, set()):
                    if neighbor not in visited:
                        if neighbor in rpki_set:
                            found = True
                            break
                        visited.add(neighbor)
                        next_frontier.add(neighbor)
                if found:
                    break
            if found:
                break
            frontier = next_frontier
        if found:
            covered += 1
    return covered / len(non_rpki_set) * 100


def get_dataset_dir(zone, seed):
    """Return the dataset directory for a given zone and seed."""
    if seed == 42:
        # Original run — no _s42 suffix
        d = DATASET_ROOT / f"rpki_ablation_904_{zone}"
    else:
        d = DATASET_ROOT / f"rpki_ablation_904_{zone}_s{seed}"
    return d if d.exists() else None


def main():
    # Load topology (same for all variants)
    source_rels = load_json("dataset/904_afrinic_transit_mh/as_relationships.json")
    adjacency = build_adjacency(source_rels)
    all_asns = set(int(a) for a in source_rels.keys())

    print(f"Topology: {len(all_asns)} ASes, avg degree "
          f"{sum(len(v) for v in adjacency.values()) / len(adjacency):.1f}")
    print(f"Seeds: {SEEDS}")
    print()

    results = {}
    for zone in ZONES:
        pct = RPKI_PCTS[zone]
        hop1_vals = []
        hop2_vals = []

        for seed in SEEDS:
            ds_dir = get_dataset_dir(zone, seed)
            if ds_dir is None:
                print(f"  WARNING: missing dataset for {zone} seed {seed}")
                continue

            # Read the actual RPKI classification used by this dataset
            cls = load_json(ds_dir / "as_classification.json")
            rpki_set = set(cls["rpki_asns"])
            non_rpki_set = all_asns - rpki_set

            h1 = compute_hop_coverage(rpki_set, non_rpki_set, adjacency, 1)
            h2 = compute_hop_coverage(rpki_set, non_rpki_set, adjacency, 2)
            hop1_vals.append(h1)
            hop2_vals.append(h2)
            print(f"  {zone} s{seed}: 1-hop={h1:.1f}%  2-hop={h2:.1f}%  "
                  f"(RPKI={len(rpki_set)}, non={len(non_rpki_set)})")

        h1_mean = statistics.mean(hop1_vals)
        h1_std = statistics.stdev(hop1_vals) if len(hop1_vals) > 1 else 0
        h2_mean = statistics.mean(hop2_vals)
        h2_std = statistics.stdev(hop2_vals) if len(hop2_vals) > 1 else 0

        results[str(pct)] = {
            "zone": zone,
            "ratio_pct": pct,
            "rpki_count": round(len(all_asns) * pct / 100),
            "non_rpki_count": len(all_asns) - round(len(all_asns) * pct / 100),
            "seeds": SEEDS,
            "hop1_mean": round(h1_mean, 2),
            "hop1_std": round(h1_std, 2),
            "hop1_values": [round(v, 2) for v in hop1_vals],
            "hop2_mean": round(h2_mean, 2),
            "hop2_std": round(h2_std, 2),
            "hop2_values": [round(v, 2) for v in hop2_vals],
        }
        print(f"  => {zone} mean: 1-hop={h1_mean:.1f}% ±{h1_std:.1f}%  "
              f"2-hop={h2_mean:.1f}% ±{h2_std:.1f}%")
        print()

    # Summary
    print(f"{'Rate':>5}  {'1-hop mean':>10}  {'1-hop std':>9}  {'2-hop mean':>10}  {'2-hop std':>9}")
    print("-" * 50)
    for zone in ZONES:
        pct = RPKI_PCTS[zone]
        r = results[str(pct)]
        print(f"{pct}%  {r['hop1_mean']:>10.1f}%  {r['hop1_std']:>8.1f}%  "
              f"{r['hop2_mean']:>10.1f}%  {r['hop2_std']:>8.1f}%")

    # Save
    output = {
        "topology": "dataset/904_afrinic_transit_mh",
        "total_ases": len(all_asns),
        "seeds": SEEDS,
        "source": "Coverage computed from actual created datasets (create_rpki_ablation.py)",
        "rpki_ratios_source": "bgp.he.net RPKI & ASPA Adoption Report (April 2026)",
        "results": results,
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS_DIR / "ablation_multiseed.json"
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nSaved to {out_path}")


if __name__ == "__main__":
    main()
