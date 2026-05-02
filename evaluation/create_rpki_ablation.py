#!/usr/bin/env python3
"""
Create RPKI ablation datasets from the 904_afrinic_transit_mh topology.

For each of the 5 RIR zones, creates a copy of the 904 dataset with the
RPKI ratio adjusted to match real-world adoption (from bgp.he.net, 2026):

    ARIN:     50%
    APNIC:    54%
    LACNIC:   59%
    AFRINIC:  63%
    RIPE:     75%

Each variant:
  - Randomly selects ASes as RPKI to match the target ratio
  - Updates as_classification.json
  - Updates roa_database.json (only RPKI ASes get ROAs)
  - Updates observer_is_rpki + is_rpki_node in observation files
  - Computes 1-hop and 2-hop non-RPKI coverage stats

No attack detection — this is a pure RPKI coverage analysis.

Usage:
    python3 evaluation/create_rpki_ablation.py [--seed 42]
"""

import argparse
import copy
import json
import os
import random
import shutil
import sys
from collections import defaultdict
from pathlib import Path


# ── Real-world RPKI ratios per RIR zone (bgp.he.net, April 2026) ──────────
RPKI_RATIOS = {
    "arin":    0.50,
    "apnic":   0.54,
    "lacnic":  0.59,
    "afrinic": 0.63,
    "ripe":    0.75,
}

SOURCE_DATASET = "dataset/904_afrinic_transit_mh"
OUTPUT_PREFIX  = "dataset/rpki_ablation_904"


def load_json(path):
    with open(path) as f:
        return json.load(f)


def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  Wrote {path}")


def build_adjacency(as_rels):
    """Build undirected adjacency map from AS relationships."""
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
    """
    For each non-RPKI AS, check if it's within `max_hops` of any RPKI AS.
    Returns the count and percentage of covered non-RPKI ASes.
    """
    if not non_rpki_set:
        return 0, 0, 100.0

    covered = set()
    for nr_asn in non_rpki_set:
        # BFS from this non-RPKI AS up to max_hops
        visited = {nr_asn}
        frontier = {nr_asn}
        found = False
        for _hop in range(max_hops):
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
            covered.add(nr_asn)

    pct = len(covered) / len(non_rpki_set) * 100 if non_rpki_set else 0
    return len(covered), len(non_rpki_set), pct


def build_roa_database(rpki_asns, original_roa, as_to_prefix):
    """
    Build ROA database for the new RPKI set.
    - ASes that were RPKI in original and remain RPKI: keep their real ROA
    - ASes newly promoted to RPKI: create synthetic ROA from their prefix
    """
    new_roa = {}
    rpki_set = set(rpki_asns)

    # Keep existing ROAs for ASes still in RPKI set
    for prefix, entry in original_roa.items():
        auth_as = entry.get("authorized_as", 0)
        if auth_as in rpki_set:
            new_roa[prefix] = entry

    # Add ROAs for newly-RPKI ASes using their assigned prefix
    covered_asns = {entry.get("authorized_as") for entry in new_roa.values()}
    for asn in rpki_asns:
        if asn not in covered_asns and asn in as_to_prefix:
            prefix = as_to_prefix[asn]
            prefix_len = int(prefix.split("/")[1]) if "/" in prefix else 24
            new_roa[prefix] = {
                "authorized_as": asn,
                "max_length": prefix_len,
            }

    return new_roa


def extract_as_to_prefix(obs_dir):
    """
    Extract AS -> prefix mapping from observation files.
    Each AS file contains observations; the AS's own prefix is the one where
    it appears as origin_asn most frequently.
    """
    as_to_prefix = {}
    for fname in os.listdir(obs_dir):
        if not fname.startswith("AS") or not fname.endswith(".json"):
            continue
        asn = int(fname[2:].replace(".json", ""))
        data = load_json(os.path.join(obs_dir, fname))
        # Count prefixes where this AS is the origin
        prefix_counts = defaultdict(int)
        for obs in data.get("observations", []):
            if obs.get("origin_asn") == asn:
                prefix_counts[obs["prefix"]] += 1
        if prefix_counts:
            best_prefix = max(prefix_counts, key=prefix_counts.get)
            as_to_prefix[asn] = best_prefix
    return as_to_prefix


def create_variant(zone_name, target_ratio, all_asns, adjacency,
                   source_dir, original_cls, original_roa, as_to_prefix, rng):
    """Create one ablation variant for a given RIR zone."""
    target_rpki_count = round(len(all_asns) * target_ratio)
    actual_pct = target_rpki_count / len(all_asns) * 100

    print(f"\n{'='*60}")
    print(f"  Zone: {zone_name.upper()}  |  Target: {target_ratio*100:.0f}%  "
          f"|  RPKI ASes: {target_rpki_count}/{len(all_asns)}  ({actual_pct:.1f}%)")
    print(f"{'='*60}")

    # Randomly select RPKI ASes
    shuffled = list(all_asns)
    rng.shuffle(shuffled)
    rpki_asns = sorted(shuffled[:target_rpki_count])
    non_rpki_asns = sorted(shuffled[target_rpki_count:])
    rpki_set = set(rpki_asns)
    non_rpki_set = set(non_rpki_asns)

    # ── Output directory ──────────────────────────────────────────────
    out_dir = f"{OUTPUT_PREFIX}_{zone_name}"
    if os.path.exists(out_dir):
        shutil.rmtree(out_dir)

    # Copy the full source dataset
    shutil.copytree(source_dir, out_dir)
    print(f"  Copied {source_dir} -> {out_dir}")

    # ── Update as_classification.json ─────────────────────────────────
    new_cls = copy.deepcopy(original_cls)
    new_cls["rpki_count"] = len(rpki_asns)
    new_cls["non_rpki_count"] = len(non_rpki_asns)
    new_cls["rpki_asns"] = rpki_asns
    new_cls["non_rpki_asns"] = non_rpki_asns
    new_cls["description"] = (
        f"RPKI ablation study — {zone_name.upper()} zone "
        f"({target_ratio*100:.0f}% RPKI adoption)"
    )
    # Update role mapping
    if "role" in new_cls:
        new_cls["role"] = {}
    if "classification" in new_cls:
        new_cls["classification"] = {
            str(asn): "rpki" if asn in rpki_set else "non_rpki"
            for asn in all_asns
        }
    save_json(os.path.join(out_dir, "as_classification.json"), new_cls)

    # ── Update roa_database.json ──────────────────────────────────────
    new_roa = build_roa_database(rpki_asns, original_roa, as_to_prefix)
    save_json(os.path.join(out_dir, "roa_database.json"), new_roa)
    print(f"  ROA entries: {len(new_roa)} (was {len(original_roa)})")

    # ── Update observation files ──────────────────────────────────────
    obs_dir = os.path.join(out_dir, "observations")
    updated_files = 0
    for fname in os.listdir(obs_dir):
        if not fname.startswith("AS") or not fname.endswith(".json"):
            continue
        fpath = os.path.join(obs_dir, fname)
        data = load_json(fpath)
        asn = data["asn"]
        data["is_rpki_node"] = asn in rpki_set

        for obs in data.get("observations", []):
            obs_asn = obs.get("observed_by_asn", 0)
            obs["observer_is_rpki"] = obs_asn in rpki_set

        save_json(fpath, data)
        updated_files += 1

    print(f"  Updated {updated_files} observation files")

    # ── Compute hop coverage ──────────────────────────────────────────
    cov1_n, cov1_total, cov1_pct = compute_hop_coverage(
        rpki_set, non_rpki_set, adjacency, max_hops=1)
    cov2_n, cov2_total, cov2_pct = compute_hop_coverage(
        rpki_set, non_rpki_set, adjacency, max_hops=2)

    print(f"  1-hop coverage: {cov1_n}/{cov1_total} non-RPKI ASes "
          f"({cov1_pct:.1f}%) are within 1 hop of an RPKI validator")
    print(f"  2-hop coverage: {cov2_n}/{cov2_total} non-RPKI ASes "
          f"({cov2_pct:.1f}%) are within 2 hops of an RPKI validator")

    return {
        "zone": zone_name,
        "target_ratio": target_ratio,
        "actual_ratio": actual_pct,
        "rpki_count": len(rpki_asns),
        "non_rpki_count": len(non_rpki_asns),
        "total_ases": len(all_asns),
        "roa_entries": len(new_roa),
        "hop_1_coverage_count": cov1_n,
        "hop_1_coverage_total": cov1_total,
        "hop_1_coverage_pct": round(cov1_pct, 2),
        "hop_2_coverage_count": cov2_n,
        "hop_2_coverage_total": cov2_total,
        "hop_2_coverage_pct": round(cov2_pct, 2),
        "dataset_path": out_dir,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Create RPKI ablation datasets from 904 topology")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed for reproducibility (default: 42)")
    parser.add_argument("--source", type=str, default=SOURCE_DATASET,
                        help="Source dataset directory")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    source_dir = args.source

    if not os.path.isdir(source_dir):
        print(f"ERROR: Source dataset not found: {source_dir}")
        sys.exit(1)

    print(f"Source: {source_dir}")
    print(f"Seed: {args.seed}")
    print(f"Zones: {', '.join(f'{k.upper()} ({v*100:.0f}%)' for k, v in RPKI_RATIOS.items())}")

    # ── Load source data ──────────────────────────────────────────────
    original_cls = load_json(os.path.join(source_dir, "as_classification.json"))
    original_roa = load_json(os.path.join(source_dir, "roa_database.json"))
    as_rels = load_json(os.path.join(source_dir, "as_relationships.json"))

    all_asns = sorted(int(a) for a in as_rels.keys())
    adjacency = build_adjacency(as_rels)

    print(f"Total ASes: {len(all_asns)}")
    print(f"Original RPKI: {original_cls['rpki_count']} ({original_cls['rpki_count']/len(all_asns)*100:.1f}%)")

    # Extract AS-to-prefix mapping for ROA generation
    print("Extracting AS-to-prefix mapping from observations...")
    as_to_prefix = extract_as_to_prefix(os.path.join(source_dir, "observations"))
    print(f"  Found prefixes for {len(as_to_prefix)}/{len(all_asns)} ASes")

    # ── Create variants ───────────────────────────────────────────────
    results = []
    for zone_name, ratio in RPKI_RATIOS.items():
        result = create_variant(
            zone_name, ratio, all_asns, adjacency,
            source_dir, original_cls, original_roa, as_to_prefix, rng,
        )
        results.append(result)

    # ── Summary ───────────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print("SUMMARY — RPKI Ablation Study (904 topology)")
    print(f"{'='*70}")
    print(f"{'Zone':<10} {'RPKI%':>6} {'RPKI':>5} {'nonRPKI':>8} "
          f"{'1-hop%':>7} {'2-hop%':>7} {'ROAs':>5}")
    print("-" * 55)
    for r in results:
        print(f"{r['zone'].upper():<10} {r['actual_ratio']:>5.1f}% "
              f"{r['rpki_count']:>5} {r['non_rpki_count']:>8} "
              f"{r['hop_1_coverage_pct']:>6.1f}% {r['hop_2_coverage_pct']:>6.1f}% "
              f"{r['roa_entries']:>5}")

    # Save summary
    summary_path = f"{OUTPUT_PREFIX}_summary.json"
    save_json(summary_path, {
        "seed": args.seed,
        "source_dataset": source_dir,
        "total_ases": len(all_asns),
        "rpki_ratios_source": "bgp.he.net RPKI & ASPA Adoption Report (April 2026)",
        "variants": results,
    })
    print(f"\nSummary saved to {summary_path}")


if __name__ == "__main__":
    main()
