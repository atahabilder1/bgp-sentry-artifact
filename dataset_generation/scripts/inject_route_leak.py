#!/usr/bin/env python3
"""
Inject 2-hop ROUTE_LEAK (valley-free violation) events into regional datasets.

Detection model:
  The observer IS the provider of the leaking AS. The leaker receives a
  route from its provider (the observer) and re-announces it to a peer —
  a textbook valley-free violation detectable at hop=2.

  Path: [observer/provider, leaker, peer_of_leaker]
  Triplet checked: (observer, leaker, peer) where:
    - observer is leaker's provider (received from upstream)
    - peer is leaker's peer (forwarded sideways)
    → valley-free violation

This matches real-world route leak detection: providers are the first to
see their customers leaking routes, and have authoritative relationship
knowledge to identify the violation (MANRS best practice).

Usage:
  python3 scripts/inject_route_leak.py 904_afrinic_transit_mh
  python3 scripts/inject_route_leak.py all
  python3 scripts/inject_route_leak.py all --events-per-type 5
"""
import argparse
import json
import math
import random
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path


REGIONAL_DATASETS = [
    "904_afrinic_transit_mh",
    "2030_arin_transit",
    "3152_lacnic_afrinic_transit",
    "5008_lacnic_5plus_mh",
]

# Default events per type — scales with dataset size
EVENTS_PER_TYPE_DEFAULT = {
    "904_afrinic_transit_mh": 5,
    "2030_arin_transit": 5,
    "3152_lacnic_afrinic_transit": 5,
    "5008_lacnic_5plus_mh": 5,
}


def load_as_relationships(ds_path: Path) -> dict:
    """Load AS relationships from the dataset directory."""
    rel_path = ds_path / "as_relationships.json"
    if not rel_path.exists():
        raise FileNotFoundError(f"as_relationships.json not found in {ds_path}")
    with open(rel_path) as f:
        return json.load(f)


def find_leaker_candidates(relationships: dict, rpki_set: set) -> list:
    """
    Find (provider_observer, leaker, peer) triples where:
    - provider_observer is an RPKI node (so it can be the observer)
    - leaker has provider_observer as its provider
    - leaker has at least one peer
    - Path will be [provider_observer, leaker, peer] — 2 hops
    """
    candidates = []
    for as_str, rels in relationships.items():
        leaker = int(as_str)
        providers = rels.get("providers", [])
        peers = rels.get("peers", [])

        if not providers or not peers:
            continue

        # Find providers that are RPKI nodes (they will be observers)
        rpki_providers = [p for p in providers if p in rpki_set]
        if not rpki_providers:
            continue

        for provider in rpki_providers:
            for peer in peers:
                if peer != provider and peer != leaker:
                    candidates.append((provider, leaker, peer))

    return candidates


def pick_victim_prefix(all_files: dict) -> tuple:
    """Pick a random legitimate (origin_asn, prefix) from the dataset."""
    for f, data in all_files.items():
        legit = [o for o in data.get("observations", [])
                 if not o.get("is_attack") and o.get("origin_asn") and o.get("prefix")]
        if legit:
            o = random.choice(legit)
            return o["origin_asn"], o["prefix"]
    raise RuntimeError("No legit observation found")


def make_observation(observer_asn: int, prefix: str, origin_asn: int,
                     as_path: list, timestamp: float) -> dict:
    """Build a ROUTE_LEAK observation matching the dataset format."""
    return {
        "prefix": prefix,
        "origin_asn": origin_asn,
        "as_path": as_path,
        "as_path_length": len(as_path),
        "next_hop_asn": as_path[1] if len(as_path) > 1 else origin_asn,
        "timestamp": timestamp,
        "timestamp_readable": datetime.fromtimestamp(timestamp).isoformat(sep=" "),
        "recv_relationship": "CUSTOMERS",  # observer receives from its customer (the leaker)
        "origin_type": "TRANSIT_VIA_ATTACKER",
        "label": "ROUTE_LEAK",
        "is_attack": True,
        "bgp_update": {
            "type": "UPDATE",
            "withdrawn_routes": [],
            "path_attributes": {
                "ORIGIN": "IGP",
                "AS_PATH": as_path,
                "NEXT_HOP": as_path[1] if len(as_path) > 1 else origin_asn,
                "LOCAL_PREF": 100,
                "MED": 100,
                "COMMUNITIES": [f"{origin_asn}:100"],
            },
            "nlri": [prefix],
        },
        "communities": [f"{origin_asn}:100"],
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

    # Load relationships
    relationships = load_as_relationships(ds)

    # Load AS classification for RPKI set
    as_class_path = ds / "as_classification.json"
    with open(as_class_path) as f:
        as_class = json.load(f)
    rpki_set = set(as_class.get("rpki_asns", []))

    # Find all valid (provider, leaker, peer) triples
    candidates = find_leaker_candidates(relationships, rpki_set)
    if not candidates:
        print(f"  SKIP {dataset_name}: no valid (provider, leaker, peer) triples found")
        return False

    print(f"  {dataset_name}: found {len(candidates)} candidate triples")

    # Load observation files
    all_files = {}
    for f in sorted(obs_dir.glob("AS*.json")):
        with open(f) as fh:
            all_files[f] = json.load(fh)

    file_by_asn = {int(f.stem.replace("AS", "")): f for f in all_files.keys()}

    # Get timestamp range
    timestamps = []
    for data in all_files.values():
        for o in data.get("observations", []):
            if "timestamp" in o:
                timestamps.append(o["timestamp"])
    ts_min, ts_max = min(timestamps), max(timestamps)

    # How many observers per event
    k_observers = max(3, int(math.sqrt(len(rpki_set))))

    # Remove any previously injected ROUTE_LEAK observations
    removed_count = 0
    for f, data in all_files.items():
        before = len(data["observations"])
        data["observations"] = [
            o for o in data["observations"]
            if not (o.get("_injected") and o.get("label") == "ROUTE_LEAK")
        ]
        removed_count += before - len(data["observations"])

    if removed_count > 0:
        print(f"  Removed {removed_count} previously injected ROUTE_LEAK observations")

    # Inject new events
    random.seed(f"route_leak_2hop_{dataset_name}")
    injected_count = 0
    per_file_new = defaultdict(list)

    used_triples = set()
    random.shuffle(candidates)

    for i in range(events_per_type):
        # Pick a unique triple
        triple = None
        for c in candidates:
            if c not in used_triples:
                triple = c
                used_triples.add(c)
                break
        if triple is None:
            break

        provider_observer, leaker, peer_r = triple
        victim_origin, victim_prefix = pick_victim_prefix(all_files)

        # Timestamp spread uniformly
        ts = ts_min + (ts_max - ts_min) * (i + 1) / (events_per_type + 1)

        # The provider IS the observer — 2-hop path
        # Path: [provider/observer, leaker, peer_r]
        # The detector checks: leaker received from provider (upstream),
        # leaked to peer_r (sideways) → valley-free violation
        as_path = [provider_observer, leaker, peer_r]

        # Only inject to the provider/observer's file (it's the one that sees it)
        if provider_observer not in file_by_asn:
            continue

        obs = make_observation(
            provider_observer, victim_prefix, peer_r,  # origin = peer_r (end of path)
            as_path, ts + random.uniform(-2, 2),
        )
        per_file_new[file_by_asn[provider_observer]].append(obs)
        injected_count += 1

        # Also inject to other RPKI providers/peers of the leaker
        # These also have authoritative relationship data to detect the leak
        leaker_rels = relationships.get(str(leaker), {})
        leaker_providers = set(leaker_rels.get("providers", []))
        leaker_peers = set(leaker_rels.get("peers", []))
        related_rpki = [a for a in (leaker_providers | leaker_peers) & rpki_set
                        if a != provider_observer and a != peer_r and a in file_by_asn]
        extra_observers = random.sample(related_rpki, min(k_observers - 1, len(related_rpki)))

        for obs_asn in extra_observers:
            # Path: [obs (another provider/peer), leaker, peer_r]
            # obs is leaker's provider or peer → detector fires on the triplet
            obs2 = make_observation(
                obs_asn, victim_prefix, peer_r,
                [obs_asn, leaker, peer_r], ts + random.uniform(-2, 2),
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

        # Recount attack types from files
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
        gt["_injection"][f"route_leak_2hop_{datetime.now().isoformat()}"] = {
            "events_per_type": events_per_type,
            "route_leak_observations_added": injected_count,
            "path_length": 3,
            "hop_distance": 2,
            "detection_model": "provider-edge valley-free violation",
            "script": "scripts/inject_route_leak.py",
        }
        with open(gt_path, "w") as fh:
            json.dump(gt, fh, indent=2)

    print(f"  Done {dataset_name}: injected {injected_count} ROUTE_LEAK observations "
          f"({events_per_type} unique events, ~{k_observers} observers/event, "
          f"path_len=3, hop=2)")
    return True


def main():
    p = argparse.ArgumentParser(description="Inject 2-hop ROUTE_LEAK events")
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
