#!/usr/bin/env python3
"""
Verify a generated dataset for correctness and realism.

Checks each node's observation file — these are BGP observations
(what each AS received from its neighbors), NOT announcements
(what each AS originated).

Usage:
  python3 scripts/verify_dataset.py afrinic_transit_mh
  python3 scripts/verify_dataset.py all
"""

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path


def verify_dataset(dataset_path: Path) -> dict:
    """Run all verification checks on a dataset. Returns summary dict."""

    obs_dir = dataset_path / "observations"
    cls_path = dataset_path / "as_classification.json"
    rel_path = dataset_path / "as_relationships.json"
    gt_path = dataset_path / "ground_truth" / "ground_truth.json"

    results = {"name": dataset_path.name, "checks": {}, "pass": True}

    if not obs_dir.exists():
        results["checks"]["obs_dir"] = "FAIL — observations/ not found"
        results["pass"] = False
        return results

    # Load classification
    cls_data = {}
    rpki_set = set()
    non_rpki_set = set()
    if cls_path.exists():
        cls_data = json.load(open(cls_path))
        rpki_set = set(cls_data.get("rpki_asns", []))
        non_rpki_set = set(cls_data.get("non_rpki_asns", []))

    # Load relationships
    rel_data = {}
    topology_asns = set()
    if rel_path.exists():
        rel_data = json.load(open(rel_path))
        topology_asns = set(int(a) for a in rel_data.keys())

    # Load ground truth
    gt_data = {}
    if gt_path.exists():
        gt_data = json.load(open(gt_path))

    # ── Collect stats from all observation files ──
    obs_files = sorted(obs_dir.glob("AS*.json"))
    total_files = len(obs_files)

    total_obs = 0
    total_attack = 0
    total_legit = 0
    obs_per_node = []
    attack_types = Counter()
    prefix_lengths = Counter()
    rpki_mismatches = 0
    duplicates = 0
    out_of_order = 0
    as_path_outside_topology = 0
    prefix_gt24 = 0

    # Per-event tracking (for propagation check)
    event_observers = defaultdict(set)  # (prefix, origin, label) -> set of observer ASNs

    seen_per_node = set()  # for duplicate check within a node

    for fpath in obs_files:
        data = json.load(open(fpath))
        node_asn = data.get("asn")
        node_rpki_file = data.get("is_rpki_node")
        observations = data.get("observations", [])

        obs_per_node.append(len(observations))

        # Check 5: RPKI label sync
        if node_asn is not None:
            expected_rpki = node_asn in rpki_set
            if node_rpki_file != expected_rpki:
                rpki_mismatches += 1

        prev_ts = 0
        seen_per_node.clear()

        for o in observations:
            total_obs += 1
            prefix = o.get("prefix", "")
            origin = o.get("origin_asn")
            ts = o.get("timestamp", 0)
            as_path = o.get("as_path", [])
            label = o.get("label", "UNKNOWN")
            is_attack = o.get("is_attack", False)

            if is_attack:
                total_attack += 1
                attack_types[label] += 1
            else:
                total_legit += 1

            # Check 4: prefix lengths (allow /25 for SUBPREFIX_HIJACK attacks)
            if "/" in prefix:
                plen = int(prefix.split("/")[1])
                prefix_lengths[plen] += 1
                if plen > 24 and not is_attack:
                    prefix_gt24 += 1

            # Check 7: timestamp ordering
            if ts < prev_ts:
                out_of_order += 1
            prev_ts = ts

            # Check 10: duplicates (same prefix, origin, observer, timestamp, as_path)
            dup_key = (prefix, origin, node_asn, ts, tuple(as_path))
            if dup_key in seen_per_node:
                duplicates += 1
            seen_per_node.add(dup_key)

            # Check 6: AS-path validity (all ASes in topology)
            if topology_asns:
                for asn in as_path:
                    if asn not in topology_asns:
                        as_path_outside_topology += 1
                        break

            # Check 9: track observers per event
            if is_attack:
                event_key = (label, origin, prefix)
                event_observers[event_key].add(node_asn)

            # Check RPKI consistency in observation
            obs_rpki = o.get("observer_is_rpki")
            if obs_rpki is not None and node_asn is not None:
                expected = node_asn in rpki_set
                if obs_rpki != expected:
                    rpki_mismatches += 1

    # ── Compute metrics ──
    sim_duration = 0
    if obs_per_node:
        # Estimate duration from timestamps
        all_ts = []
        sample_file = obs_files[0]
        sample_data = json.load(open(sample_file))
        for o in sample_data.get("observations", []):
            all_ts.append(o.get("timestamp", 0))
        if len(all_ts) >= 2:
            sim_duration = max(all_ts) - min(all_ts)

    avg_obs = sum(obs_per_node) / len(obs_per_node) if obs_per_node else 0
    rate = avg_obs / sim_duration if sim_duration > 0 else 0
    attack_pct = total_attack / total_obs * 100 if total_obs > 0 else 0

    # ── Run checks ──
    checks = {}

    # Check 1: obs per node
    checks["1_obs_per_node"] = {
        "avg": round(avg_obs, 1),
        "min": min(obs_per_node) if obs_per_node else 0,
        "max": max(obs_per_node) if obs_per_node else 0,
        "status": "OK" if avg_obs > 0 else "FAIL",
    }

    # Check 2: attack ratio
    checks["2_attack_ratio"] = {
        "attack": total_attack,
        "legit": total_legit,
        "pct": round(attack_pct, 1),
        "status": "OK" if attack_pct < 50 else "WARN — attack ratio > 50%",
    }

    # Check 3: attack types
    checks["3_attack_types"] = {
        "types": dict(attack_types),
        "count": len(attack_types),
        "status": "OK" if len(attack_types) >= 5 else f"WARN — only {len(attack_types)} types",
    }

    # Check 4: prefix lengths
    checks["4_prefix_lengths"] = {
        "gt24": prefix_gt24,
        "distribution": {f"/{k}": v for k, v in sorted(prefix_lengths.items())},
        "status": "OK" if prefix_gt24 == 0 else f"FAIL — {prefix_gt24} prefixes > /24",
    }

    # Check 5: RPKI sync
    checks["5_rpki_sync"] = {
        "mismatches": rpki_mismatches,
        "status": "OK" if rpki_mismatches == 0 else f"FAIL — {rpki_mismatches} mismatches",
    }

    # Check 6: AS-path validity
    checks["6_as_path_validity"] = {
        "outside_topology": as_path_outside_topology,
        "status": "OK" if as_path_outside_topology == 0 else f"WARN — {as_path_outside_topology} paths with external ASes",
    }

    # Check 7: timestamp ordering
    checks["7_timestamp_order"] = {
        "out_of_order": out_of_order,
        "status": "OK" if out_of_order == 0 else f"FAIL — {out_of_order} out of order",
    }

    # Check 8: propagation delay (check from sample)
    checks["8_propagation"] = {
        "sim_duration_est": sim_duration,
        "status": "OK" if sim_duration > 0 else "WARN — cannot estimate",
    }

    # Check 9: observers per event
    observer_counts = [len(v) for v in event_observers.values()]
    checks["9_observers_per_event"] = {
        "events": len(event_observers),
        "min_observers": min(observer_counts) if observer_counts else 0,
        "avg_observers": round(sum(observer_counts) / len(observer_counts), 1) if observer_counts else 0,
        "max_observers": max(observer_counts) if observer_counts else 0,
        "status": "OK" if observer_counts else "WARN — no attack events",
    }

    # Check 10: duplicates
    checks["10_duplicates"] = {
        "count": duplicates,
        "status": "OK" if duplicates == 0 else f"FAIL — {duplicates} duplicates",
    }

    # Check 11: ground truth consistency
    gt_attack_count = gt_data.get("total_attacks", 0)
    checks["11_ground_truth"] = {
        "gt_attacks": gt_attack_count,
        "obs_attacks": total_attack,
        "match": gt_attack_count == total_attack,
        "status": "OK" if gt_attack_count == total_attack else f"FAIL — GT={gt_attack_count} vs OBS={total_attack}",
    }

    # Check 12: topology files present
    checks["12_topology_files"] = {
        "as_classification": cls_path.exists(),
        "as_relationships": rel_path.exists(),
        "status": "OK" if cls_path.exists() and rel_path.exists() else "FAIL — missing topology files",
    }

    # Check 13: non-RPKI prefix coverage
    # Every non-RPKI AS in the topology should originate at least 1 announcement
    # so it can be rated/evaluated by the blockchain consensus system.
    all_observer_asns = set()
    all_origin_asns = set()
    for f in obs_files:
        asn = int(f.stem.replace("AS", ""))
        all_observer_asns.add(asn)

    # Re-scan for unique origin ASNs
    for f in obs_files:
        data = json.load(open(f))
        for o in data.get("observations", []):
            origin = o.get("origin_asn", 0)
            if origin > 0:
                all_origin_asns.add(origin)

    non_rpki_in_topology = all_observer_asns - rpki_set
    non_rpki_with_announcement = non_rpki_in_topology & all_origin_asns
    non_rpki_without = non_rpki_in_topology - all_origin_asns
    coverage_pct = len(non_rpki_with_announcement) / len(non_rpki_in_topology) * 100 if non_rpki_in_topology else 0

    checks["13_non_rpki_coverage"] = {
        "non_rpki_in_topology": len(non_rpki_in_topology),
        "non_rpki_with_announcement": len(non_rpki_with_announcement),
        "non_rpki_without_announcement": len(non_rpki_without),
        "coverage_pct": round(coverage_pct, 1),
        "status": f"OK — {coverage_pct:.1f}% coverage ({len(non_rpki_with_announcement)}/{len(non_rpki_in_topology)})"
                  if coverage_pct >= 90
                  else f"WARN — only {coverage_pct:.1f}% non-RPKI coverage ({len(non_rpki_with_announcement)}/{len(non_rpki_in_topology)}, {len(non_rpki_without)} ASes have no announcement)",
    }

    # Overall
    results["checks"] = checks
    results["summary"] = {
        "total_files": total_files,
        "total_obs": total_obs,
        "total_attack": total_attack,
        "total_legit": total_legit,
        "attack_pct": round(attack_pct, 1),
        "avg_obs_per_node": round(avg_obs, 1),
        "per_node_rate": round(rate, 4),
        "attack_types": len(attack_types),
        "non_rpki_coverage_pct": round(coverage_pct, 1),
    }

    # Determine overall pass/fail
    for name, check in checks.items():
        status = check.get("status", "")
        if "FAIL" in status:
            results["pass"] = False

    return results


def print_results(results: dict):
    """Print verification results."""
    name = results["name"]
    passed = results["pass"]

    print(f"\n{'=' * 60}")
    print(f"  Dataset: {name}")
    print(f"  Result:  {'PASS' if passed else 'FAIL'}")
    print(f"{'=' * 60}")

    if "summary" in results:
        s = results["summary"]
        print(f"  Files:          {s['total_files']}")
        print(f"  Total obs:      {s['total_obs']:,}")
        print(f"  Legit:          {s['total_legit']:,} ({100 - s['attack_pct']:.1f}%)")
        print(f"  Attack:         {s['total_attack']:,} ({s['attack_pct']:.1f}%)")
        print(f"  Obs/node:       {s['avg_obs_per_node']}")
        print(f"  Rate:           {s['per_node_rate']} obs/sec")
        print(f"  Attack types:   {s['attack_types']}")
        print(f"  Non-RPKI cov:   {s.get('non_rpki_coverage_pct', 0)}%")

    print()
    for name, check in results.get("checks", {}).items():
        status = check.get("status", "?")
        icon = "OK" if "OK" in status else "!!"
        print(f"  [{icon}] {name}: {status}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Verify dataset correctness")
    parser.add_argument("target", help="Dataset name or 'all'")
    parser.add_argument("--dataset-root", type=str, default=None,
                        help="Root path containing dataset/ folder (default: script parent directory)")
    args = parser.parse_args()

    base = Path(args.dataset_root) / "dataset" if args.dataset_root else Path(__file__).resolve().parent.parent / "dataset"

    if args.target == "all":
        datasets = sorted(
            d.name for d in base.iterdir()
            if d.is_dir() and (d / "observations").is_dir()
        )
    else:
        datasets = [args.target]

    all_pass = True
    for name in datasets:
        path = base / name
        if not path.exists():
            print(f"  [FAIL] {name}: not found at {path}")
            all_pass = False
            continue
        results = verify_dataset(path)
        print_results(results)
        if not results["pass"]:
            all_pass = False

    print(f"{'=' * 60}")
    print(f"  Overall: {'ALL PASSED' if all_pass else 'SOME FAILED'}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    sys.exit(main() or 0)
