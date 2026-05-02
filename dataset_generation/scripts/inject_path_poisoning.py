#!/usr/bin/env python3
"""
Inject 2-hop PATH_POISONING attack events into regional datasets.

Detection model:
  The observer sees a path [observer, phantom_AS, origin] where
  phantom_AS has no documented CAIDA relationship with origin.
  This indicates a fabricated AS was inserted into the path.

  Path: [observer, phantom, origin]  — length 3, hop=2
  Check: phantom↔origin have no CAIDA relationship → PATH_POISONING

Usage:
  python3 scripts/inject_path_poisoning.py 904_afrinic_transit_mh
  python3 scripts/inject_path_poisoning.py all
  python3 scripts/inject_path_poisoning.py all --events-per-type 5
"""
import argparse
import json
import math
import random
from collections import defaultdict
from datetime import datetime
from pathlib import Path


REGIONAL_DATASETS = [
    "904_afrinic_transit_mh",
    "2030_arin_transit",
    "3152_lacnic_afrinic_transit",
    "5008_lacnic_5plus_mh",
]

EVENTS_PER_TYPE_DEFAULT = {
    "904_afrinic_transit_mh": 5,
    "2030_arin_transit": 5,
    "3152_lacnic_afrinic_transit": 5,
    "5008_lacnic_5plus_mh": 5,
}


def load_as_relationships(ds_path: Path) -> dict:
    rel_path = ds_path / "as_relationships.json"
    if not rel_path.exists():
        raise FileNotFoundError(f"as_relationships.json not found in {ds_path}")
    with open(rel_path) as f:
        return json.load(f)


def get_all_neighbors(asn: int, relationships: dict) -> set:
    """Get all neighbors (customers + providers + peers) of an AS."""
    rels = relationships.get(str(asn), {})
    neighbors = set()
    neighbors.update(rels.get("customers", []))
    neighbors.update(rels.get("providers", []))
    neighbors.update(rels.get("peers", []))
    return neighbors


def find_no_rel_pair(relationships: dict, rpki_set: set) -> list:
    """
    Find (observer, phantom, origin) triples where:
    - observer is RPKI (it will be the validator)
    - observer is a neighbor of phantom (so the announcement can reach it)
    - phantom and origin are both in the relationship DB
    - phantom has NO relationship with origin (the poisoning signal)
    """
    candidates = []
    all_asns = [int(k) for k in relationships.keys()]

    # For efficiency, precompute neighbor sets
    neighbor_cache = {}
    for asn in all_asns:
        neighbor_cache[asn] = get_all_neighbors(asn, relationships)

    # For each potential phantom AS, find origins with no relationship
    for phantom in all_asns:
        phantom_neighbors = neighbor_cache.get(phantom, set())
        if not phantom_neighbors:
            continue

        # Observers: RPKI nodes that are neighbors of phantom
        rpki_observers = [n for n in phantom_neighbors if n in rpki_set]
        if not rpki_observers:
            continue

        # Origins: ASes in DB with no relationship to phantom
        # (check both directions)
        for origin in all_asns:
            if origin == phantom:
                continue
            if origin in phantom_neighbors:
                continue
            # Check reverse: is phantom in origin's neighbors?
            origin_neighbors = neighbor_cache.get(origin, set())
            if phantom in origin_neighbors:
                continue
            # Found a valid pair
            for obs in rpki_observers[:2]:  # limit per phantom to avoid explosion
                candidates.append((obs, phantom, origin))

        if len(candidates) > 50000:
            break  # enough candidates

    return candidates


def pick_victim_prefix(all_files: dict) -> tuple:
    for f, data in all_files.items():
        legit = [o for o in data.get("observations", [])
                 if not o.get("is_attack") and o.get("prefix")]
        if legit:
            o = random.choice(legit)
            return o["origin_asn"], o["prefix"]
    raise RuntimeError("No legit observation found")


def make_observation(observer_asn: int, prefix: str, origin_asn: int,
                     as_path: list, timestamp: float) -> dict:
    return {
        "prefix": prefix,
        "origin_asn": origin_asn,
        "as_path": as_path,
        "as_path_length": len(as_path),
        "next_hop_asn": as_path[1] if len(as_path) > 1 else origin_asn,
        "timestamp": timestamp,
        "timestamp_readable": datetime.fromtimestamp(timestamp).isoformat(sep=" "),
        "recv_relationship": "CUSTOMERS",
        "origin_type": "ATTACKER",
        "label": "PATH_POISONING",
        "is_attack": True,
        "bgp_update": {
            "type": "UPDATE",
            "withdrawn_routes": [],
            "path_attributes": {
                "ORIGIN": "INCOMPLETE",
                "AS_PATH": as_path,
                "NEXT_HOP": as_path[1] if len(as_path) > 1 else origin_asn,
                "LOCAL_PREF": 100,
                "MED": 20,
                "COMMUNITIES": [f"{origin_asn}:999"],
            },
            "nlri": [prefix],
        },
        "communities": [f"{origin_asn}:999"],
        "is_withdrawal": False,
        "observed_by_asn": observer_asn,
        "observer_is_rpki": True,
        "hop_distance": len(as_path) - 1,
        "is_best": True,
        "_injected": True,
    }


def inject_for_dataset(dataset_name: str, events_per_type: int, base: Path):
    ds = base / "dataset" / dataset_name
    obs_dir = ds / "observations"
    gt_path = ds / "ground_truth" / "ground_truth.json"

    if not obs_dir.exists():
        print(f"  SKIP {dataset_name}: no observations/ directory")
        return False

    relationships = load_as_relationships(ds)
    as_class = json.load(open(ds / "as_classification.json"))
    rpki_set = set(as_class.get("rpki_asns", []))

    print(f"  {dataset_name}: finding (observer, phantom, origin) triples...")
    candidates = find_no_rel_pair(relationships, rpki_set)
    if not candidates:
        print(f"  SKIP {dataset_name}: no valid triples found")
        return False
    print(f"  {dataset_name}: found {len(candidates)} candidate triples")

    # Load observation files
    all_files = {}
    for f in sorted(obs_dir.glob("AS*.json")):
        with open(f) as fh:
            all_files[f] = json.load(fh)

    file_by_asn = {int(f.stem.replace("AS", "")): f for f in all_files.keys()}

    timestamps = []
    for data in all_files.values():
        for o in data.get("observations", []):
            if "timestamp" in o:
                timestamps.append(o["timestamp"])
    ts_min, ts_max = min(timestamps), max(timestamps)

    k_observers = max(3, int(math.sqrt(len(rpki_set))))

    # Remove previously injected PATH_POISONING
    removed_count = 0
    for f, data in all_files.items():
        before = len(data["observations"])
        data["observations"] = [
            o for o in data["observations"]
            if not (o.get("_injected") and o.get("label") == "PATH_POISONING")
        ]
        removed_count += before - len(data["observations"])

    if removed_count > 0:
        print(f"  Removed {removed_count} previously injected PATH_POISONING observations")

    # Inject
    random.seed(f"path_poisoning_2hop_{dataset_name}")
    injected_count = 0
    per_file_new = defaultdict(list)
    used_phantoms = set()
    random.shuffle(candidates)

    for i in range(events_per_type):
        triple = None
        for c in candidates:
            if c[1] not in used_phantoms:  # unique phantom per event
                triple = c
                used_phantoms.add(c[1])
                break
        if triple is None:
            break

        observer, phantom, origin = triple
        _, victim_prefix = pick_victim_prefix(all_files)

        ts = ts_min + (ts_max - ts_min) * (i + 1) / (events_per_type + 1)

        # Primary observer: [observer, phantom, origin] — 2 hops
        as_path = [observer, phantom, origin]

        if observer not in file_by_asn:
            continue

        obs = make_observation(observer, victim_prefix, origin, as_path, ts)
        per_file_new[file_by_asn[observer]].append(obs)
        injected_count += 1

        # Extra observers: other RPKI neighbors of phantom
        phantom_neighbors = get_all_neighbors(phantom, relationships)
        extra_pool = [a for a in phantom_neighbors & rpki_set
                      if a != observer and a != origin and a in file_by_asn]
        extra_observers = random.sample(extra_pool, min(k_observers - 1, len(extra_pool)))

        for obs_asn in extra_observers:
            obs2 = make_observation(
                obs_asn, victim_prefix, origin,
                [obs_asn, phantom, origin], ts + random.uniform(-2, 2),
            )
            per_file_new[file_by_asn[obs_asn]].append(obs2)
            injected_count += 1

    # Write back
    for f, data in all_files.items():
        new_obs = per_file_new.get(f, [])
        if not new_obs and removed_count == 0:
            continue
        data["observations"].extend(new_obs)
        data["observations"].sort(key=lambda o: o.get("timestamp", 0))
        data["total_observations"] = len(data["observations"])
        data["attack_observations"] = sum(1 for o in data["observations"] if o.get("is_attack"))
        data["legitimate_observations"] = data["total_observations"] - data["attack_observations"]
        with open(f, "w") as fh:
            json.dump(data, fh, indent=2)

    # Update ground truth
    if gt_path.exists():
        with open(gt_path) as fh:
            gt = json.load(fh)
        per_type = defaultdict(int)
        total_attacks = 0
        for f in all_files:
            with open(f) as fh:
                data = json.load(fh)
            for o in data.get("observations", []):
                if o.get("is_attack"):
                    per_type[o.get("label", "UNKNOWN")] += 1
                    total_attacks += 1
        gt["total_attacks"] = total_attacks
        gt["attack_types"] = dict(per_type)
        gt.setdefault("_injection", {})
        gt["_injection"][f"path_poisoning_2hop_{datetime.now().isoformat()}"] = {
            "events_per_type": events_per_type,
            "observations_added": injected_count,
            "path_length": 3,
            "hop_distance": 2,
            "script": "scripts/inject_path_poisoning.py",
        }
        with open(gt_path, "w") as fh:
            json.dump(gt, fh, indent=2)

    print(f"  Done {dataset_name}: injected {injected_count} PATH_POISONING observations "
          f"({events_per_type} unique events, path_len=3, hop=2)")
    return True


def main():
    p = argparse.ArgumentParser(description="Inject 2-hop PATH_POISONING events")
    p.add_argument("target", help="Dataset name or 'all'")
    p.add_argument("--events-per-type", type=int, default=None)
    p.add_argument("--dataset-root", type=str, default=None,
                   help="Root path containing dataset/ folder (default: script parent directory)")
    args = p.parse_args()

    if args.dataset_root:
        base = Path(args.dataset_root)
    else:
        base = Path(__file__).resolve().parent.parent

    targets = REGIONAL_DATASETS if args.target == "all" else [args.target]

    for name in targets:
        n = args.events_per_type or EVENTS_PER_TYPE_DEFAULT.get(name, 5)
        inject_for_dataset(name, n, base)


if __name__ == "__main__":
    main()
