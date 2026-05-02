#!/usr/bin/env python3
"""
BGPSentry Dataset Generator — CAIDA-Anchored Simulation Edition (v3, 2026)

Generates a labeled dataset of BGP announcements with individual AS observations.
Each AS (RPKI and non-RPKI) gets its own JSON file with the announcements it observed.

Data provenance:
- Topology: Real CAIDA AS Relationships 2022-01-01 (customer-provider and peer
  links from RouteViews/RIS inference). No synthetic edges.
- Sampling: v3 stratified (scaled clique floor, realistic tier quotas,
  unlimited bridge reconnection along real CAIDA paths).
- RPKI: NLnet Labs/OpenBSD rpki-client Validated ROA Payloads, 2022-06-18
  snapshot (Wayback Machine), all 5 RIR TALs. Natural sample RPKI rate is
  normalized to 36.3% (global AS-level rate at the same snapshot) via
  uniform random demotion to correct for subgraph backbone bias.
- Propagation: BGPy Gao-Rexford SimulationEngine on the real subgraph.
- Attacks: Injected at elevated rate for statistical evaluability.

Attack Types (6):
- PREFIX_HIJACK, SUBPREFIX_HIJACK, BOGON_INJECTION, ROUTE_FLAPPING,
- FORGED_ORIGIN_PREFIX_HIJACK (post-ROV), ACCIDENTAL_ROUTE_LEAK

Output Structure:
    dataset/caida_200/
    ├── observations/            # Individual AS observations (ALL nodes, real ASNs)
    │   ├── AS7018.json         # AT&T (RPKI validator)
    │   ├── AS13335.json        # Cloudflare (RPKI validator)
    │   └── ...
    ├── ground_truth/            # Attack labels
    │   ├── ground_truth.csv
    │   ├── ground_truth.json
    │   └── as_classification.json
    ├── as_classification.json   # Real RPKI data from rov-collector
    └── README.md

Usage:
    python generate_rpki_dataset.py                                          # default 200 nodes
    python generate_rpki_dataset.py --nodes 200 --attacks-per-type 5 --seed 42
    python generate_rpki_dataset.py --small --seed 42                        # small mode (rank>=50, ~25 ASes)
    python generate_rpki_dataset.py --rank-threshold 10 --seed 42            # rank-threshold mode
    python generate_rpki_dataset.py --topology ASN                           # Zoo (legacy)
"""

import math
import re
import json
import gzip
import time
import random
import shutil
import argparse
import ipaddress
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, FrozenSet, Optional
from collections import defaultdict, deque

import numpy as np

from roa_checker import ROA
from ipaddress import ip_network

from bgpy.simulation_engine import ROV, BGP, SimulationEngine, Announcement
from bgpy.simulation_framework import (
    ScenarioConfig,
    PrefixHijack,
    SubprefixHijack,
    BogonInjection,
    RouteFlapping,
    ValidPrefix,
    ForgedOriginPrefixHijack,
    AccidentalRouteLeak,
    ValleyFreeRouteLeak,
    PathPoisoning,
)
from bgpy.simulation_framework.scenarios.custom_scenarios.victims_prefix import VictimsPrefix
from bgpy.as_graphs import (
    ASGraph,
    ASGraphInfo,
    CAIDAASGraphConstructor,
    CustomerProviderLink as CPLink,
    PeerLink,
)
from bgpy.shared.enums import Timestamps, Relationships, Prefixes, ASGroups
from bgpy.utils import get_real_world_rov_asn_cls_dict

# Path to Topology Zoo GML files bundled with bgpy
TOPOLOGY_DIR = Path(__file__).parent / "bgpy" / "as_graphs" / "topologies"

# Available Zoo topologies: name -> GML filename
ZOO_TOPOLOGIES = {
    "ASN": "ASN/ASN.gml",
    "Vlt": "Vlt/Vlt.gml",
    "Tiscali": "Tiscali/Tiscali.gml",
}

def _write_json(path: Path, data, compress: bool = False, indent: int | None = 2):
    """Write JSON to file, optionally gzip-compressed."""
    if compress:
        gz_path = path.with_suffix(path.suffix + ".gz") if not str(path).endswith(".gz") else path
        with gzip.open(gz_path, "wt", compresslevel=6, encoding="utf-8") as f:
            json.dump(data, f)
    else:
        with open(path, "w") as f:
            json.dump(data, f, indent=indent)


def _read_json(path: Path):
    """Read JSON from file, auto-detecting gzip."""
    if str(path).endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8") as f:
            return json.load(f)
    else:
        with open(path) as f:
            return json.load(f)


# Reserved/bogon ranges for bogon injection attacks
BOGON_RANGES = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",   # RFC 6598 Shared Address Space
    "198.18.0.0/15",   # RFC 2544 Benchmarking
]


# ── Real Prefix-to-ASN Mapping (RouteViews via pyasn) ─────────────
# Uses pyasn to download real RouteViews RIB dumps and map each ASN
# to its actual advertised prefixes, replacing synthetic 44.0.0.0+ allocation.

PYASN_CACHE_DIR = Path.home() / ".cache" / "bgpy" / "pyasn"


def download_real_prefix_mapping() -> "pyasn.pyasn":
    """Download and cache a RouteViews RIB dump for real prefix-to-ASN mapping.

    Uses pyasn utilities to:
    1. Download the latest RouteViews RIB dump
    2. Convert it to a pyasn database file
    3. Cache in ~/.cache/bgpy/pyasn/ for reuse

    Returns:
        pyasn.pyasn database object for prefix lookups.

    Citation: RouteViews Project (University of Oregon)
    """
    import pyasn

    PYASN_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    db_file = PYASN_CACHE_DIR / "ipasn_db.dat"

    if db_file.exists():
        print(f"[PYASN] Using cached prefix database: {db_file}")
        return pyasn.pyasn(str(db_file))

    print(f"[PYASN] Downloading RouteViews RIB dump...")

    # Download RIB dump using pyasn utility (downloads to cwd)
    # pyasn v1.6+ uses --latestv4; older versions use --latest
    try:
        result = subprocess.run(
            ["pyasn_util_download.py", "--latestv4"],
            check=True,
            capture_output=True,
            text=True,
            cwd=str(PYASN_CACHE_DIR),
        )
        print(f"[PYASN] Download output: {result.stdout.strip()}")
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        # Fallback: try --latest flag for older pyasn
        try:
            result = subprocess.run(
                ["pyasn_util_download.py", "--latest"],
                check=True,
                capture_output=True,
                text=True,
                cwd=str(PYASN_CACHE_DIR),
            )
            print(f"[PYASN] Download output: {result.stdout.strip()}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError(f"Failed to download RouteViews RIB: {e}")

    # Find the actual downloaded file (pyasn names it rib.YYYYMMDD.HHMM.bz2)
    rib_files = sorted(PYASN_CACHE_DIR.glob("rib.*.bz2"))
    if not rib_files:
        raise FileNotFoundError("No RIB files found after download")
    rib_file = rib_files[-1]  # Latest
    print(f"[PYASN] Downloaded RIB: {rib_file.name}")

    print(f"[PYASN] Converting RIB to pyasn database...")
    try:
        subprocess.run(
            ["pyasn_util_convert.py", "--single", str(rib_file), str(db_file)],
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fallback: try with full path
        import shutil as _shutil
        convert_path = _shutil.which("pyasn_util_convert.py")
        if convert_path:
            subprocess.run(
                [convert_path, "--single", str(rib_file), str(db_file)],
                check=True,
                capture_output=True,
                text=True,
            )
        else:
            raise RuntimeError("pyasn_util_convert.py not found in PATH")

    print(f"[PYASN] Prefix database ready: {db_file}")
    return pyasn.pyasn(str(db_file))


def generate_real_prefix_assignments(
    as_graph: "ASGraph",
    subgraph_asns: set[int],
    asndb: "pyasn.pyasn",
    type_caps: Optional[dict[str, int]] = None,
) -> dict[int, list[str]]:
    """Assign real-world prefixes to each AS using pyasn RouteViews data.

    For each ASN in the subgraph:
    1. Query pyasn for all prefixes originated by that ASN
    2. If the AS has real prefixes, use them (capped by type-based limits)
    3. If no real prefixes found, skip — the AS still participates in
       routing/forwarding but does not originate any prefixes (realistic:
       some ASes are pure transit, IXP route servers, or recently decommissioned)

    Args:
        as_graph: The ASGraph for type lookups.
        subgraph_asns: Set of ASNs in the subgraph.
        asndb: pyasn database object.
        type_caps: Optional dict overriding max prefixes per AS type.
            Default: clique=50, transit=20, multihomed=5, stub=3.

    Returns:
        dict[asn] -> list of real prefix strings (CIDR).
        ASes without real prefixes are omitted (no synthetic fallback).

    Citation: RouteViews Project (University of Oregon)
    """
    assignments: dict[int, list[str]] = {}
    real_count = 0
    skipped_asns: list[int] = []

    # Type-based prefix caps (max prefixes to use per AS type)
    if type_caps is None:
        type_caps = {
            "clique": 50,
            "transit": 20,
            "multihomed": 5,
            "stub": 3,
        }

    for asn in sorted(subgraph_asns):
        as_obj = as_graph.as_dict[asn]

        # Determine AS type for cap
        if as_obj.input_clique:
            as_type = "clique"
        elif as_obj.transit and not as_obj.input_clique:
            as_type = "transit"
        elif as_obj.multihomed:
            as_type = "multihomed"
        else:
            as_type = "stub"

        cap = type_caps[as_type]

        # Try to get real prefixes from pyasn
        try:
            real_prefixes = asndb.get_as_prefixes(asn)
        except Exception:
            real_prefixes = None

        if real_prefixes:
            # Filter to IPv4 only, sort for determinism
            ipv4_prefixes = sorted(
                p for p in real_prefixes
                if ":" not in p  # exclude IPv6
            )
            if ipv4_prefixes:
                # Cap to reasonable count
                selected = ipv4_prefixes[:cap]
                assignments[asn] = selected
                real_count += 1
                continue

        # No real prefixes — skip (AS still routes/forwards, just doesn't originate)
        skipped_asns.append(asn)

    total_prefixes = sum(len(v) for v in assignments.values())
    print(f"[PREFIX] Assigned {total_prefixes} real prefixes to {real_count} ASes")
    print(f"[PREFIX] Skipped {len(skipped_asns)} ASes with no RouteViews prefixes "
          f"(still participate in routing)")
    if skipped_asns and len(skipped_asns) <= 30:
        print(f"[PREFIX] Skipped ASNs: {skipped_asns}")
    return assignments


# Path to the downloaded VRP file
VRP_FILE = Path(__file__).parent / "dataset" / "source_data" / "downloaded_rpki_vrps_20260418.json"


def load_vrp_prefixes() -> dict[int, list[dict]]:
    """Load the real VRP snapshot and return {ASN -> [{prefix, maxLength}]}.

    Only includes IPv4 prefixes.
    """
    if not VRP_FILE.exists():
        print(f"[VRP] WARNING: VRP file not found at {VRP_FILE}")
        return {}

    with open(VRP_FILE) as f:
        data = json.load(f)

    vrp_by_asn: dict[int, list[dict]] = defaultdict(list)
    for roa in data.get("roas", []):
        prefix = roa.get("prefix", "")
        if ":" in prefix:  # skip IPv6
            continue
        asn = roa.get("asn", 0)
        vrp_by_asn[asn].append({
            "prefix": prefix,
            "maxLength": roa.get("maxLength", int(prefix.split("/")[1]) if "/" in prefix else 24),
        })

    print(f"[VRP] Loaded {sum(len(v) for v in vrp_by_asn.values())} IPv4 ROAs "
          f"for {len(vrp_by_asn)} ASes from {VRP_FILE.name}")
    return dict(vrp_by_asn)


def generate_prefix_assignments_from_vrp(
    subgraph_asns: set[int],
    rpki_asns: frozenset[int],
    vrp_by_asn: dict[int, list[dict]],
    asndb: "pyasn.pyasn | None" = None,
) -> tuple[dict[int, list[str]], dict[str, dict]]:
    """Assign prefixes using real VRP for RPKI ASes, RouteViews for non-RPKI.

    For RPKI ASes: pick 1 prefix from their real VRP entries (authorized).
    For non-RPKI ASes: pick 1 prefix from RouteViews via pyasn (announced).

    Returns:
        (prefix_assignments, roa_database)
        - prefix_assignments: {asn -> [prefix_str]}
        - roa_database: {prefix_str -> {authorized_as, max_length}} for Rust detector
    """
    assignments: dict[int, list[str]] = {}
    roa_db: dict[str, dict] = {}
    rpki_ok = 0
    rpki_skip = 0
    non_rpki_ok = 0
    non_rpki_skip = 0

    for asn in sorted(subgraph_asns):
        if asn in rpki_asns:
            # RPKI AS: use real VRP prefix
            vrp_entries = vrp_by_asn.get(asn, [])
            ipv4_entries = [e for e in vrp_entries if ":" not in e["prefix"]]
            if ipv4_entries:
                # Pick 1 prefix (prefer shorter prefix = more specific)
                entry = sorted(ipv4_entries, key=lambda e: -int(e["prefix"].split("/")[1]))[0]
                prefix = entry["prefix"]
                assignments[asn] = [prefix]
                roa_db[prefix] = {
                    "authorized_as": asn,
                    "max_length": entry["maxLength"],
                }
                rpki_ok += 1
            else:
                # RPKI AS but no IPv4 VRP — try RouteViews fallback
                got_fallback = False
                if asndb is not None:
                    try:
                        rv_prefixes = asndb.get_as_prefixes(asn)
                    except Exception:
                        rv_prefixes = None
                    rv_ipv4 = sorted(p for p in (rv_prefixes or []) if ":" not in p)
                    if rv_ipv4:
                        prefix = rv_ipv4[0]
                        assignments[asn] = [prefix]
                        prefix_len = int(prefix.split("/")[1])
                        roa_db[prefix] = {
                            "authorized_as": asn,
                            "max_length": prefix_len,
                        }
                        rpki_ok += 1
                        got_fallback = True
                if not got_fallback:
                    # Last resort: synthetic prefix
                    octet2 = (asn >> 8) & 0xFF
                    octet3 = asn & 0xFF
                    prefix = f"45.{octet2}.{octet3}.0/24"
                    assignments[asn] = [prefix]
                    roa_db[prefix] = {"authorized_as": asn, "max_length": 24}
                    rpki_ok += 1
        else:
            # Non-RPKI AS: use RouteViews prefix (no ROA)
            # Fallback: generate a realistic synthetic prefix if RouteViews has nothing
            got_prefix = False
            if asndb is not None:
                try:
                    real_prefixes = asndb.get_as_prefixes(asn)
                except Exception:
                    real_prefixes = None
                ipv4 = sorted(p for p in (real_prefixes or []) if ":" not in p)
                if ipv4:
                    assignments[asn] = [ipv4[0]]  # pick 1
                    non_rpki_ok += 1
                    got_prefix = True

            if not got_prefix:
                # Synthetic fallback: generate a realistic /24 prefix
                # Uses ASN to seed a deterministic but realistic-looking prefix
                # in the 44.0.0.0/8 - 45.255.0.0/8 range (IANA allocations)
                octet2 = (asn >> 8) & 0xFF
                octet3 = asn & 0xFF
                prefix = f"44.{octet2}.{octet3}.0/24"
                assignments[asn] = [prefix]
                non_rpki_ok += 1

    total = rpki_ok + non_rpki_ok
    print(f"[PREFIX] RPKI ASes:     {rpki_ok} assigned from VRP, {rpki_skip} skipped")
    print(f"[PREFIX] Non-RPKI ASes: {non_rpki_ok} assigned from RouteViews, {non_rpki_skip} skipped")
    print(f"[PREFIX] Total: {total} ASes with 1 prefix each")
    print(f"[PREFIX] ROA database: {len(roa_db)} entries")
    return assignments, roa_db



# ── Realistic Timeline (Weibull Inter-Arrival) ───────────────────────
# Replaces per-scenario Timestamps.set_base_timestamp() with a global
# 30-minute timeline using Weibull-distributed inter-arrival times.
# Citation: Downey 2001, Labovitz et al. 2000, RFC 4271

class RealisticTimeline:
    """Global timeline with Poisson-process inter-arrival times.

    Generates timestamps spread across the full simulation window using
    exponentially distributed inter-arrival times (Poisson process),
    which is the standard model for BGP update arrival in networking
    literature.

    The average gap between events scales with the simulation duration
    and expected number of scenarios, ensuring events are spread across
    the entire window regardless of duration.

    Args:
        total_duration: Duration of the timeline in seconds.
        seed: Random seed for reproducibility.
        expected_events: Expected total number of events (legit + attack).
            Used to compute average inter-arrival gap.

    Citation:
        Labovitz et al. 2001 ("Delayed Internet Routing Convergence")
        Huston 2024/2025 (BGP update rate measurements)
    """

    def __init__(
        self,
        total_duration: int = 43200,
        seed: int | None = None,
        expected_events: int = 100,
    ):
        self.total_duration = total_duration
        self.base_timestamp = int(time.time())
        self._rng = np.random.RandomState(seed)
        self._legit_cursor = 0.0
        # Average gap = duration / expected_events (Poisson rate)
        self._avg_gap = total_duration / max(expected_events, 1)

    def next_timestamp(self) -> int:
        """Get the next timestamp using exponential inter-arrival (Poisson)."""
        gap = float(self._rng.exponential(scale=self._avg_gap))
        self._legit_cursor += gap
        offset = min(self._legit_cursor, self.total_duration)
        return self.base_timestamp + int(offset)

    def get_legitimate_timestamp(self) -> int:
        """Get next legitimate event timestamp (Poisson inter-arrival)."""
        gap = float(self._rng.exponential(scale=self._avg_gap))
        self._legit_cursor += gap
        offset = min(self._legit_cursor, self.total_duration)
        return self.base_timestamp + int(offset)

    def get_attack_timestamp(self) -> int:
        """Get a timestamp uniformly distributed AFTER the warm-up period.

        Attacks are spread uniformly across the simulation window
        (after 120s warm-up) rather than clustered.
        """
        warmup = 120
        offset = float(self._rng.uniform(warmup, self.total_duration))
        return self.base_timestamp + int(offset)

    def recalibrate(self, actual_events: int) -> None:
        """Update avg_gap based on actual number of events.

        Call this after the true event count is known (e.g. after building
        the announcement schedule) to ensure timestamps are spread across
        the full simulation window.
        """
        self._avg_gap = self.total_duration / max(actual_events, 1)
        self._legit_cursor = 0.0  # reset cursor
        print(f"[TIMELINE] Recalibrated: {actual_events} events, "
              f"avg_gap={self._avg_gap:.1f}s")

    def get_withdrawal_timestamp(self, after_ts: int) -> int:
        """Get a timestamp for a withdrawal event after a given timestamp.

        Log-normal delay (median 30s, clamped 10-180s) matching RIPE RIS
        beacon measurements: bulk convergence in 30-40s with long tail
        (Labovitz et al. 2000, RIPE Labs "Shape of a BGP Update").
        """
        import math
        delay = self._rng.lognormal(mean=math.log(30), sigma=0.7)
        delay = max(10.0, min(180.0, delay))
        return after_ts + int(delay)


# ── CAIDA Subgraph Extraction (Stratified Hierarchical Sampling) ────
# Extracts a connected subgraph from the full CAIDA AS-level topology
# (~73K real ASes) using stratified sampling that preserves the Internet's
# hierarchical tier structure.


def _union_find_components(asns: set[int], adjacency: dict[int, set[int]]) -> list[set[int]]:
    """Find connected components using union-find."""
    parent: dict[int, int] = {a: a for a in asns}
    rank: dict[int, int] = {a: 0 for a in asns}

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: int, y: int) -> None:
        rx, ry = find(x), find(y)
        if rx == ry:
            return
        if rank[rx] < rank[ry]:
            rx, ry = ry, rx
        parent[ry] = rx
        if rank[rx] == rank[ry]:
            rank[rx] += 1

    for asn in asns:
        for neighbor_asn in adjacency.get(asn, set()):
            if neighbor_asn in asns:
                union(asn, neighbor_asn)

    components: dict[int, set[int]] = defaultdict(set)
    for asn in asns:
        components[find(asn)].add(asn)
    return list(components.values())


def load_pre_extracted_topology(
    topo_dir: str,
) -> tuple[ASGraphInfo, frozenset[int], frozenset[int]]:
    """Load a pre-extracted regional topology from *topo_dir*.

    The directory must contain:
      - ``as_classification.json`` with rpki_asns, non_rpki_asns, classification
      - ``as_relationships.json`` with per-AS customers/providers/peers

    Returns:
        (ASGraphInfo, subgraph_asns, rpki_asns) — the graph info compatible with
        BGPy's ``ASGraph(as_graph_info)`` constructor, the full set of ASNs in
        the topology, and the set of RPKI-adopting ASNs (no normalization).
    """
    topo_path = Path(topo_dir)
    cls_path = topo_path / "as_classification.json"
    rel_path = topo_path / "as_relationships.json"

    if not cls_path.exists():
        raise FileNotFoundError(f"as_classification.json not found in {topo_dir}")
    if not rel_path.exists():
        raise FileNotFoundError(f"as_relationships.json not found in {topo_dir}")

    with open(cls_path) as f:
        cls_data = json.load(f)
    with open(rel_path) as f:
        rel_data = json.load(f)

    # Extract ASN sets
    rpki_asns = frozenset(int(a) for a in cls_data.get("rpki_asns", []))
    non_rpki_asns = frozenset(int(a) for a in cls_data.get("non_rpki_asns", []))
    all_asns = rpki_asns | non_rpki_asns

    # Build CP links and peer links from relationships
    cp_links: set[CPLink] = set()
    peer_links: set[PeerLink] = set()
    seen_peers: set[tuple[int, int]] = set()

    for asn_str, rels in rel_data.items():
        asn = int(asn_str)
        # Customer-provider: this AS is provider, each entry is a customer
        for cust in rels.get("customers", []):
            cp_links.add(CPLink(customer_asn=int(cust), provider_asn=asn))
        # Peer links (deduplicate by canonical ordering)
        for peer in rels.get("peers", []):
            key = (min(asn, int(peer)), max(asn, int(peer)))
            if key not in seen_peers:
                seen_peers.add(key)
                peer_links.add(PeerLink(key[0], key[1]))

    # Identify input clique ASNs — ASes that have no providers are likely
    # Tier-1 / input clique members.  This is a reasonable heuristic for
    # regional topologies where true clique metadata is unavailable.
    input_clique_asns = frozenset(
        int(asn_str) for asn_str, rels in rel_data.items()
        if not rels.get("providers", [])
    )

    # Find unlinked ASNs (those with no links)
    linked_asns: set[int] = set()
    for link in cp_links:
        linked_asns.add(link.customer_asn)
        linked_asns.add(link.provider_asn)
    for link in peer_links:
        linked_asns.update(link.asns)
    unlinked = frozenset(all_asns - linked_asns)

    as_graph_info = ASGraphInfo(
        customer_provider_links=frozenset(cp_links),
        peer_links=frozenset(peer_links),
        input_clique_asns=input_clique_asns,
        ixp_asns=frozenset(),
        unlinked_asns=unlinked,
    )

    print(f"\n[TOPOLOGY] Loaded pre-extracted topology from {topo_dir}")
    print(f"    Total ASes: {len(all_asns)}")
    print(f"    RPKI ASes: {len(rpki_asns)} ({len(rpki_asns)/len(all_asns)*100:.1f}%)")
    print(f"    CP links: {len(cp_links)}")
    print(f"    Peer links: {len(peer_links)}")
    print(f"    Input clique (no providers): {len(input_clique_asns)}")
    if unlinked:
        print(f"    Unlinked ASes: {len(unlinked)}")

    return as_graph_info, frozenset(all_asns), rpki_asns


def extract_caida_subgraph(
    max_size: int = 200,
    seed_asn: Optional[int] = None,
) -> tuple[ASGraphInfo, set[int], "ASGraph"]:
    """Extract a connected subgraph via realistic stratified sampling.

    Algorithm (v3, 2026 rewrite):
    1. Build full CAIDA graph, access pre-computed tier groups
    2. Sample with a *scaled* clique floor (not the full 19-AS clique), realistic
       tier quotas (18% transit / 50% multihomed / rest stubs of the non-clique
       budget) to avoid the old "force all tier-1" backbone-bias artifact.
    3. Bridge reconnection: for each disconnected component, BFS in the full
       CAIDA graph to find the shortest path to the main component, walk the
       path, and add any real intermediate ASes. Bridging is **unlimited** —
       connectivity is a correctness constraint, not a size budget. Actual
       output size will typically exceed `max_size` by ~50-100%.
    4. Extract real CP/peer links where BOTH endpoints are in the subgraph.
       No synthetic edges — every edge is a real CAIDA relationship.

    Args:
        max_size: Seed size for tier quotas. Final output will be larger
            due to bridge reconnection (typically 1.5-2x).
        seed_asn: Ignored (kept for CLI compat). Sampling is stratified.

    Returns:
        (ASGraphInfo, set_of_real_asns, full_graph) — subgraph info, ASN set,
        and full graph reference (caller should del when done).
    """
    print(f"\n[CAIDA] Building full CAIDA AS topology...")
    full_graph = CAIDAASGraphConstructor().run()
    print(f"[CAIDA] Full topology: {len(full_graph.as_dict)} ASes")

    # Access pre-computed tier groups (ASN sets)
    clique_asns = frozenset(full_graph.asn_groups.get(ASGroups.INPUT_CLIQUE.value, frozenset()))
    # "etc" = transit ASes that aren't input_clique, stub, or multihomed
    etc_asns = frozenset(full_graph.asn_groups.get(ASGroups.ETC.value, frozenset()))
    mh_asns = frozenset(full_graph.asn_groups.get(ASGroups.MULTIHOMED.value, frozenset()))
    stub_asns = frozenset(full_graph.asn_groups.get(ASGroups.STUBS.value, frozenset()))

    print(f"[CAIDA] Tier distribution in full graph:")
    print(f"    Input clique: {len(clique_asns)}")
    print(f"    Transit (etc): {len(etc_asns)}")
    print(f"    Multihomed: {len(mh_asns)}")
    print(f"    Stubs: {len(stub_asns)}")

    # --- v5 clustered sampling: realistic tier distribution ---
    # Strategy: pick a few transit providers first, then sample their
    # stub customers. This avoids bridge explosion because stubs are
    # already connected to their sampled provider.
    #
    # Models: incremental regional deployment — a provider and its
    # customer cone deploy BGP-Sentry together.
    #
    # Target: ~2% clique, ~7% transit, ~5% multihomed, ~86% stubs

    # Build provider→stubs mapping from the full graph
    provider_stubs: dict[int, list[int]] = defaultdict(list)
    for stub_asn in stub_asns:
        stub_obj = full_graph.as_dict.get(stub_asn)
        if stub_obj is None:
            continue
        for neighbor in stub_obj.neighbors:
            if neighbor.asn in etc_asns or neighbor.asn in clique_asns:
                provider_stubs[neighbor.asn].append(stub_asn)

    # Sort providers by how many stubs they serve (largest customer cone first)
    sorted_providers = sorted(provider_stubs.keys(),
                              key=lambda p: len(provider_stubs[p]),
                              reverse=True)

    # Calculate quotas
    clique_quota = max(1, min(3, int(max_size * 0.02)))
    clique_quota = min(clique_quota, len(clique_asns))
    remaining = max_size - clique_quota
    transit_quota = max(2, int(remaining * 0.07))
    mh_quota = max(2, int(remaining * 0.05))
    stub_quota = remaining - transit_quota - mh_quota

    # Step 1: Pick clique ASes
    sampled: set[int] = set()
    sampled.update(random.sample(sorted(clique_asns), min(clique_quota, len(clique_asns))))

    # Step 2: Pick transit providers with the most stubs (clustered sampling)
    selected_providers = []
    for prov in sorted_providers:
        if len(selected_providers) >= transit_quota:
            break
        if prov not in sampled:
            selected_providers.append(prov)
            sampled.add(prov)

    # Step 3: Sample stubs FROM the selected providers' customer cones
    available_stubs = []
    for prov in selected_providers:
        available_stubs.extend(provider_stubs[prov])
    # Deduplicate (a stub may appear under multiple providers)
    available_stubs = list(set(available_stubs) - sampled)
    random.shuffle(available_stubs)

    stubs_to_add = min(stub_quota, len(available_stubs))
    sampled.update(available_stubs[:stubs_to_add])

    # Step 4: Add multihomed ASes
    available_mh = sorted(mh_asns - sampled)
    if available_mh:
        mh_to_add = min(mh_quota, len(available_mh))
        sampled.update(random.sample(available_mh, mh_to_add))

    actual_clique = len(sampled & clique_asns)
    actual_transit = len(sampled & etc_asns)
    actual_mh = len(sampled & mh_asns)
    actual_stub = len(sampled & stub_asns)

    print(f"[CAIDA] v5 clustered seed sample: {len(sampled)} ASes "
          f"(clique={actual_clique}, transit={actual_transit}, "
          f"mh={actual_mh}, stub={actual_stub})")
    print(f"[CAIDA] Stub ratio: {actual_stub/len(sampled)*100:.1f}% "
          f"(target: ~86%)")

    # Build adjacency for subgraph connectivity check
    full_adjacency: dict[int, set[int]] = defaultdict(set)
    for asn in full_graph.as_dict:
        as_obj = full_graph.as_dict[asn]
        for n in as_obj.neighbors:
            full_adjacency[asn].add(n.asn)

    # Bridge reconnection: detect disconnected components, add bridge ASes
    def _rebuild_subgraph_adj(current_sampled):
        adj = defaultdict(set)
        for asn in current_sampled:
            for neighbor_asn in full_adjacency[asn]:
                if neighbor_asn in current_sampled:
                    adj[asn].add(neighbor_asn)
                    adj[neighbor_asn].add(asn)
        return adj

    subgraph_adj = _rebuild_subgraph_adj(sampled)
    components = _union_find_components(sampled, subgraph_adj)
    bridges_added = 0

    if len(components) > 1:
        print(f"[CAIDA] {len(components)} disconnected components, reconnecting (unlimited budget)...")
        # Sort components largest-first; connect each smaller component to the main.
        components.sort(key=len, reverse=True)
        main_component = set(components[0])

        for comp in components[1:]:
            # BFS in full graph from any node in comp to find shortest path
            # to any node in main_component. No budget cap — connectivity is
            # a correctness requirement.
            start = next(iter(comp))
            visited_bfs: dict[int, int | None] = {start: None}
            queue_bfs: deque[int] = deque([start])
            found_target: int | None = None

            while queue_bfs and found_target is None:
                current = queue_bfs.popleft()
                for neighbor_asn in sorted(full_adjacency.get(current, set())):
                    if neighbor_asn in visited_bfs:
                        continue
                    visited_bfs[neighbor_asn] = current
                    if neighbor_asn in main_component:
                        found_target = neighbor_asn
                        break
                    queue_bfs.append(neighbor_asn)

            if found_target is not None:
                # Trace path and add intermediate ASes
                path_asn: int | None = found_target
                while path_asn is not None:
                    if path_asn not in sampled:
                        sampled.add(path_asn)
                        bridges_added += 1
                    path_asn = visited_bfs[path_asn]
                # Merge this component into main
                main_component = main_component | comp
                main_component.update(
                    a for a in visited_bfs if a in sampled
                )

        # Verify connectivity after bridging
        subgraph_adj2 = _rebuild_subgraph_adj(sampled)
        final_components = _union_find_components(sampled, subgraph_adj2)
        print(f"[CAIDA] After bridging: {len(final_components)} component(s), "
              f"{bridges_added} bridge ASes added, "
              f"actual size {len(sampled)} (seed target was {max_size})")

    subgraph_asns = frozenset(sampled)

    # Reconstruct links (only where BOTH endpoints are in subgraph)
    cp_links: set[CPLink] = set()
    peer_links_set: set[PeerLink] = set()

    for asn in subgraph_asns:
        as_obj = full_graph.as_dict[asn]
        for provider in as_obj.providers:
            if provider.asn in subgraph_asns:
                cp_links.add(CPLink(customer_asn=asn, provider_asn=provider.asn))
        for customer in as_obj.customers:
            if customer.asn in subgraph_asns:
                cp_links.add(CPLink(customer_asn=customer.asn, provider_asn=asn))
        for peer in as_obj.peers:
            if peer.asn in subgraph_asns:
                peer_links_set.add(PeerLink(as_obj.asn, peer.asn))

    # Filter input_clique and IXP ASNs to subgraph
    input_clique_asns = frozenset(
        asn for asn in subgraph_asns if full_graph.as_dict[asn].input_clique
    )
    ixp_asns = frozenset(
        asn for asn in subgraph_asns if full_graph.as_dict[asn].ixp
    )

    # Compute topology stats
    stubs_count = sum(
        1 for asn in subgraph_asns
        if full_graph.as_dict[asn].stub
    )
    transit_count = sum(
        1 for asn in subgraph_asns
        if full_graph.as_dict[asn].transit
    )
    mh_count = sum(
        1 for asn in subgraph_asns
        if full_graph.as_dict[asn].multihomed
    )

    print(f"[CAIDA] Subgraph: {len(subgraph_asns)} ASes (stratified sampling)")
    print(f"[CAIDA] Subgraph links: {len(cp_links)} CP + {len(peer_links_set)} peer")
    print(f"[CAIDA] Input clique: {len(input_clique_asns)}, Transit: {transit_count}, "
          f"Multihomed: {mh_count}, Stubs: {stubs_count}")

    # Find ASes that appear in no link (disconnected singleton components)
    linked_asns: set[int] = set()
    for link in cp_links:
        linked_asns.add(link.customer_asn)
        linked_asns.add(link.provider_asn)
    for link in peer_links_set:
        linked_asns.update(link.asns)
    unlinked = frozenset(subgraph_asns - linked_asns)
    if unlinked:
        print(f"[CAIDA] {len(unlinked)} ASes have no links in subgraph (added as unlinked)")

    as_graph_info = ASGraphInfo(
        customer_provider_links=frozenset(cp_links),
        peer_links=frozenset(peer_links_set),
        input_clique_asns=input_clique_asns,
        ixp_asns=ixp_asns,
        unlinked_asns=unlinked,
    )

    return as_graph_info, set(subgraph_asns), full_graph


def extract_caida_subgraph_by_rank(
    rank_threshold: int = 5,
) -> tuple[ASGraphInfo, set[int], "ASGraph"]:
    """Extract a deterministic subgraph based on CAIDA propagation rank threshold.

    Unlike extract_caida_subgraph() which uses random sampling, this method
    is fully deterministic from a CAIDA snapshot: it includes ALL ASes whose
    propagation_rank >= rank_threshold, plus bridge ASes for connectivity.

    Natural rank boundaries (from CAIDA ~73K AS topology):
        rank >= 40  →  ~250 ASes   (Transit Core: Tier-1 + top transit)
        rank >= 5   →  ~950 ASes   (Upper Transit)
        rank >= 2   →  ~4,200 ASes (Full Transit)
        rank >= 1   →  ~11,300 ASes (All Transit)

    Args:
        rank_threshold: Minimum propagation rank to include an AS.

    Returns:
        (ASGraphInfo, set_of_real_asns, full_graph) — subgraph info, ASN set,
        and full graph reference (caller should del when done).
    """
    print(f"\n[CAIDA] Building full CAIDA AS topology...")
    full_graph = CAIDAASGraphConstructor().run()
    print(f"[CAIDA] Full topology: {len(full_graph.as_dict)} ASes")

    # Collect all ASes with propagation_rank >= threshold
    sampled: set[int] = set()
    rank_distribution: dict[int, int] = defaultdict(int)

    for asn, as_obj in full_graph.as_dict.items():
        rank = as_obj.propagation_rank
        if rank is not None and rank >= rank_threshold:
            sampled.add(asn)
            rank_distribution[rank] += 1

    print(f"[CAIDA] Rank threshold >= {rank_threshold}: {len(sampled)} ASes selected")

    # Print rank distribution summary
    sorted_ranks = sorted(rank_distribution.keys())
    if sorted_ranks:
        print(f"[CAIDA] Rank range: {sorted_ranks[0]} to {sorted_ranks[-1]}")
        # Show top 5 and bottom 5 ranks
        if len(sorted_ranks) <= 10:
            for r in sorted_ranks:
                print(f"    Rank {r}: {rank_distribution[r]} ASes")
        else:
            for r in sorted_ranks[-5:]:
                print(f"    Rank {r}: {rank_distribution[r]} ASes")
            print(f"    ... ({len(sorted_ranks) - 10} more ranks) ...")
            for r in sorted_ranks[:5]:
                print(f"    Rank {r}: {rank_distribution[r]} ASes")

    # Access tier group info for logging
    clique_asns = set(full_graph.asn_groups.get(ASGroups.INPUT_CLIQUE.value, frozenset()))
    etc_asns = set(full_graph.asn_groups.get(ASGroups.ETC.value, frozenset()))
    mh_asns = set(full_graph.asn_groups.get(ASGroups.MULTIHOMED.value, frozenset()))
    stub_asns = set(full_graph.asn_groups.get(ASGroups.STUBS.value, frozenset()))

    clique_in = sampled & clique_asns
    transit_in = sampled & etc_asns
    mh_in = sampled & mh_asns
    stub_in = sampled & stub_asns

    print(f"[CAIDA] Tier breakdown in rank-threshold selection:")
    print(f"    Input clique: {len(clique_in)}/{len(clique_asns)}")
    print(f"    Transit (ETC): {len(transit_in)}/{len(etc_asns)}")
    print(f"    Multihomed: {len(mh_in)}/{len(mh_asns)}")
    print(f"    Stubs: {len(stub_in)}/{len(stub_asns)}")

    # Build full adjacency for bridge reconnection
    full_adjacency: dict[int, set[int]] = defaultdict(set)
    for asn in full_graph.as_dict:
        as_obj = full_graph.as_dict[asn]
        for n in as_obj.neighbors:
            full_adjacency[asn].add(n.asn)

    # Bridge reconnection: detect disconnected components, add bridge ASes
    def _rebuild_subgraph_adj(current_sampled):
        adj = defaultdict(set)
        for asn in current_sampled:
            for neighbor_asn in full_adjacency[asn]:
                if neighbor_asn in current_sampled:
                    adj[asn].add(neighbor_asn)
                    adj[neighbor_asn].add(asn)
        return adj

    subgraph_adj = _rebuild_subgraph_adj(sampled)
    components = _union_find_components(sampled, subgraph_adj)
    bridge_budget = int(len(sampled) * 0.50)  # 50% of selection for bridges
    bridges_added = 0

    if len(components) > 1:
        print(f"[CAIDA] {len(components)} disconnected components, reconnecting...")
        components.sort(key=len, reverse=True)
        main_component = set(components[0])

        for comp in components[1:]:
            if bridges_added >= bridge_budget:
                break
            start = next(iter(comp))
            visited_bfs: dict[int, int | None] = {start: None}
            queue_bfs: deque[int] = deque([start])
            found_target: int | None = None

            while queue_bfs and found_target is None:
                current = queue_bfs.popleft()
                for neighbor_asn in full_adjacency.get(current, set()):
                    if neighbor_asn in visited_bfs:
                        continue
                    visited_bfs[neighbor_asn] = current
                    if neighbor_asn in main_component:
                        found_target = neighbor_asn
                        break
                    queue_bfs.append(neighbor_asn)

            if found_target is not None:
                path_asn = found_target
                while path_asn is not None:
                    if path_asn not in sampled:
                        sampled.add(path_asn)
                        bridges_added += 1
                    path_asn = visited_bfs[path_asn]
                main_component = main_component | comp

        subgraph_adj2 = _rebuild_subgraph_adj(sampled)
        final_components = _union_find_components(sampled, subgraph_adj2)
        print(f"[CAIDA] After bridging: {len(final_components)} component(s), "
              f"{bridges_added} bridge ASes added")
    else:
        print(f"[CAIDA] Graph is connected (1 component)")

    subgraph_asns = frozenset(sampled)

    # Reconstruct links (only where BOTH endpoints are in subgraph)
    cp_links: set[CPLink] = set()
    peer_links_set: set[PeerLink] = set()

    for asn in subgraph_asns:
        as_obj = full_graph.as_dict[asn]
        for provider in as_obj.providers:
            if provider.asn in subgraph_asns:
                cp_links.add(CPLink(customer_asn=asn, provider_asn=provider.asn))
        for customer in as_obj.customers:
            if customer.asn in subgraph_asns:
                cp_links.add(CPLink(customer_asn=customer.asn, provider_asn=asn))
        for peer in as_obj.peers:
            if peer.asn in subgraph_asns:
                peer_links_set.add(PeerLink(as_obj.asn, peer.asn))

    input_clique_asns = frozenset(
        asn for asn in subgraph_asns if full_graph.as_dict[asn].input_clique
    )
    ixp_asns = frozenset(
        asn for asn in subgraph_asns if full_graph.as_dict[asn].ixp
    )

    stubs_count = sum(1 for asn in subgraph_asns if full_graph.as_dict[asn].stub)
    transit_count = sum(1 for asn in subgraph_asns if full_graph.as_dict[asn].transit)
    mh_count = sum(1 for asn in subgraph_asns if full_graph.as_dict[asn].multihomed)

    print(f"[CAIDA] Subgraph: {len(subgraph_asns)} ASes (rank-threshold >= {rank_threshold})")
    print(f"[CAIDA] Subgraph links: {len(cp_links)} CP + {len(peer_links_set)} peer")
    print(f"[CAIDA] Input clique: {len(input_clique_asns)}, Transit: {transit_count}, "
          f"Multihomed: {mh_count}, Stubs: {stubs_count}")

    # Find unlinked ASes
    linked_asns: set[int] = set()
    for link in cp_links:
        linked_asns.add(link.customer_asn)
        linked_asns.add(link.provider_asn)
    for link in peer_links_set:
        linked_asns.update(link.asns)
    unlinked = frozenset(subgraph_asns - linked_asns)
    if unlinked:
        print(f"[CAIDA] {len(unlinked)} ASes have no links in subgraph (added as unlinked)")

    as_graph_info = ASGraphInfo(
        customer_provider_links=frozenset(cp_links),
        peer_links=frozenset(peer_links_set),
        input_clique_asns=input_clique_asns,
        ixp_asns=ixp_asns,
        unlinked_asns=unlinked,
    )

    return as_graph_info, set(subgraph_asns), full_graph


def extract_caida_subgraph_bfs(
    seed_asn: int = 174,
    target_size: int = 200,
) -> tuple[ASGraphInfo, set[int], "ASGraph"]:
    """Extract a connected subgraph via BFS expansion from a seed AS.

    BFS from a Tier-1 seed AS produces a naturally connected subgraph —
    no bridge reconnection needed, no tuning, deterministic for a given
    seed_asn and target_size.

    Args:
        seed_asn: ASN to start BFS from (default: 174 = Cogent, Tier-1).
        target_size: Stop BFS when this many ASes have been visited.

    Returns:
        (ASGraphInfo, set of ASNs in subgraph, full ASGraph)
    """
    from collections import deque

    print(f"\n[CAIDA-BFS] Building full CAIDA graph...")
    full_graph = CAIDAASGraphConstructor().run()

    if seed_asn not in full_graph.as_dict:
        raise ValueError(f"Seed ASN {seed_asn} not found in CAIDA graph")

    print(f"[CAIDA-BFS] BFS from AS{seed_asn}, target size={target_size}")

    visited: set[int] = set()
    queue: deque[int] = deque([seed_asn])
    visited.add(seed_asn)

    while queue and len(visited) < target_size:
        current = queue.popleft()
        as_obj = full_graph.as_dict[current]

        # Collect all neighbors and sort by ASN for determinism
        neighbors: list[int] = []
        for provider in as_obj.providers:
            neighbors.append(provider.asn)
        for customer in as_obj.customers:
            neighbors.append(customer.asn)
        for peer in as_obj.peers:
            neighbors.append(peer.asn)
        neighbors.sort()

        for neighbor_asn in neighbors:
            if neighbor_asn not in visited:
                visited.add(neighbor_asn)
                queue.append(neighbor_asn)
                if len(visited) >= target_size:
                    break

    subgraph_asns = frozenset(visited)

    # Reconstruct links (only where BOTH endpoints are in subgraph)
    cp_links: set[CPLink] = set()
    peer_links_set: set[PeerLink] = set()

    for asn in subgraph_asns:
        as_obj = full_graph.as_dict[asn]
        for provider in as_obj.providers:
            if provider.asn in subgraph_asns:
                cp_links.add(CPLink(customer_asn=asn, provider_asn=provider.asn))
        for customer in as_obj.customers:
            if customer.asn in subgraph_asns:
                cp_links.add(CPLink(customer_asn=customer.asn, provider_asn=asn))
        for peer in as_obj.peers:
            if peer.asn in subgraph_asns:
                peer_links_set.add(PeerLink(as_obj.asn, peer.asn))

    # Filter input_clique and IXP ASNs to subgraph
    input_clique_asns = frozenset(
        asn for asn in subgraph_asns if full_graph.as_dict[asn].input_clique
    )
    ixp_asns = frozenset(
        asn for asn in subgraph_asns if full_graph.as_dict[asn].ixp
    )

    # Compute topology stats
    stubs_count = sum(
        1 for asn in subgraph_asns if full_graph.as_dict[asn].stub
    )
    transit_count = sum(
        1 for asn in subgraph_asns if full_graph.as_dict[asn].transit
    )
    mh_count = sum(
        1 for asn in subgraph_asns if full_graph.as_dict[asn].multihomed
    )

    print(f"[CAIDA-BFS] Subgraph: {len(subgraph_asns)} ASes (BFS from AS{seed_asn})")
    print(f"[CAIDA-BFS] Subgraph links: {len(cp_links)} CP + {len(peer_links_set)} peer")
    print(f"[CAIDA-BFS] Input clique: {len(input_clique_asns)}, Transit: {transit_count}, "
          f"Multihomed: {mh_count}, Stubs: {stubs_count}")

    # Find ASes that appear in no link
    linked_asns: set[int] = set()
    for link in cp_links:
        linked_asns.add(link.customer_asn)
        linked_asns.add(link.provider_asn)
    for link in peer_links_set:
        linked_asns.update(link.asns)
    unlinked = frozenset(subgraph_asns - linked_asns)
    if unlinked:
        print(f"[CAIDA-BFS] {len(unlinked)} ASes have no links in subgraph (added as unlinked)")

    as_graph_info = ASGraphInfo(
        customer_provider_links=frozenset(cp_links),
        peer_links=frozenset(peer_links_set),
        input_clique_asns=input_clique_asns,
        ixp_asns=ixp_asns,
        unlinked_asns=unlinked,
    )

    return as_graph_info, set(subgraph_asns), full_graph


# ── Topology Graph Generation ─────────────────────────────────────────

def generate_topology_graph(
    as_graph_info: ASGraphInfo,
    subgraph_asns: set[int],
    rpki_asns: frozenset[int],
    full_graph: Optional["ASGraph"],
    output_dir: Path,
) -> dict:
    """Generate topology.json and topology.dot for small datasets.

    Produces:
    - Nodes list with ASN, type, RPKI status, degree, neighbors
    - Edges list with source, target, relationship
    - Adjacency list per ASN
    - DOT format string for Graphviz rendering
    - Summary stats

    Args:
        as_graph_info: The ASGraphInfo for the subgraph.
        subgraph_asns: Set of ASNs in the subgraph.
        rpki_asns: Set of RPKI-enabled ASNs.
        full_graph: Full CAIDA graph (for type lookup), or None.
        output_dir: Directory to save topology.json and topology.dot.

    Returns:
        The topology dict (also saved to disk).
    """
    # Build adjacency from links
    adjacency: dict[int, dict[str, list[int]]] = {
        asn: {"customers": [], "providers": [], "peers": []}
        for asn in subgraph_asns
    }

    edges: list[dict] = []
    for link in as_graph_info.customer_provider_links:
        if link.customer_asn in subgraph_asns and link.provider_asn in subgraph_asns:
            adjacency[link.customer_asn]["providers"].append(link.provider_asn)
            adjacency[link.provider_asn]["customers"].append(link.customer_asn)
            edges.append({
                "source": link.provider_asn,
                "target": link.customer_asn,
                "relationship": "customer-provider",
                "provider": link.provider_asn,
                "customer": link.customer_asn,
            })

    for link in as_graph_info.peer_links:
        asn_list = sorted(link.asns)
        if len(asn_list) == 2 and all(a in subgraph_asns for a in asn_list):
            adjacency[asn_list[0]]["peers"].append(asn_list[1])
            adjacency[asn_list[1]]["peers"].append(asn_list[0])
            edges.append({
                "source": asn_list[0],
                "target": asn_list[1],
                "relationship": "peer-peer",
            })

    # Build nodes list
    nodes: list[dict] = []
    for asn in sorted(subgraph_asns):
        adj = adjacency[asn]
        degree = len(adj["customers"]) + len(adj["providers"]) + len(adj["peers"])

        # Determine AS type
        if asn in as_graph_info.input_clique_asns:
            as_type = "clique"
        elif full_graph and asn in full_graph.as_dict:
            as_obj = full_graph.as_dict[asn]
            if as_obj.stub:
                as_type = "stub"
            elif as_obj.multihomed:
                as_type = "multihomed"
            elif as_obj.transit:
                as_type = "transit"
            else:
                as_type = "unknown"
        else:
            as_type = "unknown"

        neighbors = sorted(set(adj["customers"] + adj["providers"] + adj["peers"]))
        nodes.append({
            "asn": asn,
            "type": as_type,
            "rpki": asn in rpki_asns,
            "degree": degree,
            "neighbors": neighbors,
        })

    # Build DOT format string
    dot_lines = ['digraph topology {', '    rankdir=TB;', '    node [shape=box];', '']
    # Node declarations with styling
    for node in nodes:
        rpki_label = "RPKI" if node["rpki"] else "non-RPKI"
        style = 'style=filled,fillcolor=lightgreen' if node["rpki"] else 'style=filled,fillcolor=lightyellow'
        if node["type"] == "clique":
            style += ',shape=doubleoctagon'
        elif node["type"] == "transit":
            style += ',shape=hexagon'
        elif node["type"] == "multihomed":
            style += ',shape=ellipse'
        else:
            style += ',shape=box'
        dot_lines.append(
            f'    AS{node["asn"]} [label="AS{node["asn"]}\\n'
            f'{node["type"]}\\n{rpki_label}",{style}];'
        )
    dot_lines.append('')

    # Edge declarations
    for edge in edges:
        if edge["relationship"] == "customer-provider":
            dot_lines.append(
                f'    AS{edge["provider"]} -> AS{edge["customer"]} '
                f'[label="c-p",color=blue];'
            )
        else:
            dot_lines.append(
                f'    AS{edge["source"]} -> AS{edge["target"]} '
                f'[label="peer",color=red,dir=both,style=dashed];'
            )
    dot_lines.append('}')
    dot_string = '\n'.join(dot_lines)

    # Summary stats
    type_counts = {}
    for node in nodes:
        type_counts[node["type"]] = type_counts.get(node["type"], 0) + 1

    summary = {
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "cp_edges": sum(1 for e in edges if e["relationship"] == "customer-provider"),
        "peer_edges": sum(1 for e in edges if e["relationship"] == "peer-peer"),
        "tier_distribution": type_counts,
        "rpki_nodes": sum(1 for n in nodes if n["rpki"]),
        "non_rpki_nodes": sum(1 for n in nodes if not n["rpki"]),
    }

    topology = {
        "nodes": nodes,
        "edges": edges,
        "adjacency": {str(asn): adjacency[asn] for asn in sorted(subgraph_asns)},
        "dot": dot_string,
        "summary": summary,
    }

    # Save files
    with open(output_dir / "topology.json", 'w') as f:
        json.dump(topology, f, indent=2)

    with open(output_dir / "topology.dot", 'w') as f:
        f.write(dot_string)

    print(f"[TOPOLOGY] Saved topology.json and topology.dot ({len(nodes)} nodes, {len(edges)} edges)")
    return topology


# ── Community Generation Helper ─────────────────────────────────────

def _generate_communities(
    ann: Announcement,
    recv_relationship,
) -> list[str]:
    """Generate realistic BGP community strings for an announcement.

    Generates communities matching real-world distributions:
    - "<origin_asn>:100" informational origin community
    - "no-export" for customer-learned or self-originated routes
    - "<transit_asn>:666" blackhole community (~1% of announcements)
    - Geographic communities for transit/clique ASes
    - ~75% of announcements should have at least one community

    These are output-only — bgpy's engine doesn't process them.

    Citation: IMC 2021 "AS-level BGP Community Usage Classification"
    """
    communities: list[str] = []
    origin_asn = ann.origin

    # ~25% chance of no communities at all (matching real data)
    if random.random() < 0.25:
        return communities

    # Informational origin community (very common)
    communities.append(f"{origin_asn}:100")

    rel_name = recv_relationship.name if hasattr(recv_relationship, 'name') else str(recv_relationship)
    if rel_name in ("CUSTOMERS", "ORIGIN"):
        communities.append("no-export")

    # Blackhole community (~1% of announcements)
    if random.random() < 0.01:
        # Use a transit ASN from the path if available
        transit_asn = ann.as_path[0] if ann.as_path else origin_asn
        communities.append(f"{transit_asn}:666")

    # Geographic community for large ASes (~30% chance)
    if random.random() < 0.30:
        geo_codes = [
            f"{origin_asn}:1000",   # North America
            f"{origin_asn}:2000",   # Europe
            f"{origin_asn}:3000",   # Asia-Pacific
            f"{origin_asn}:4000",   # Latin America
        ]
        communities.append(random.choice(geo_codes))

    # Action community (~15% chance)
    if random.random() < 0.15:
        action_communities = [
            f"{origin_asn}:300",    # Learned from customer
            f"{origin_asn}:400",    # Learned from peer
            f"{origin_asn}:500",    # Learned from upstream
        ]
        communities.append(random.choice(action_communities))

    return communities


# ── Real-World RPKI Data ─────────────────────────────────────────────
# Uses rov-collector (6 live sources including RoVista) to determine
# which ASNs have deployed RPKI/ROV in the real world.
# These ASes become blockchain validators in Proof of Population.

def get_rpki_asns_from_rov_collector(
    subgraph_asns: set[int],
) -> frozenset[int]:
    """Fetch real-world RPKI/ROV deployment data and filter to subgraph ASNs.

    Uses rov-collector which aggregates data from 6 sources:
    - RoVista (Li et al., IMC 2023)
    - APNIC
    - TMA
    - FRIENDS
    - IsBGPSafeYet
    - rpki.net

    RPKI-enabled ASes are the blockchain validators in Proof of Population.
    Non-RPKI ASes submit observations but cannot vote.

    Args:
        subgraph_asns: Set of ASNs in the subgraph to filter against.

    Returns:
        Frozen set of ASNs that have real-world RPKI/ROV deployment.
    """
    print(f"\n[RPKI] Fetching real-world ROV data from rov-collector...")
    print(f"[RPKI] Sources: RoVista, APNIC, TMA, FRIENDS, IsBGPSafeYet, rpki.net")

    rov_dict = get_real_world_rov_asn_cls_dict()
    print(f"[RPKI] Total ROV-enabled ASes worldwide: {len(rov_dict)}")

    # Filter to only ASNs in our subgraph
    rpki_asns = frozenset(asn for asn in rov_dict if asn in subgraph_asns)

    pct = len(rpki_asns) / len(subgraph_asns) * 100 if subgraph_asns else 0
    print(f"[RPKI] ROV-enabled ASes in subgraph: {len(rpki_asns)}/{len(subgraph_asns)} "
          f"({pct:.1f}%)")
    print(f"[RPKI] These {len(rpki_asns)} ASes are blockchain validators (Proof of Population)")
    print(f"[RPKI] The remaining {len(subgraph_asns) - len(rpki_asns)} ASes are observers")

    return rpki_asns


# Path to the rpki-client VRP-derived ASN list (RPKI signing, not ROV enforcement).
# rpki-client VRP dump (2026-04-17) from https://console.rpki-client.org/vrps.json
# Contains 58,721 unique ASes with at least one registered ROA.
# JSON format with "rpki_asns" key.
RPKI_CLIENT_VRPS_ASNS_PATH = Path(__file__).resolve().parent / "dataset" / "source_data" / "computed_from_downloaded_rpki_vrps_unique_asns_20260418.json"
RPKI_CLIENT_VRPS_SNAPSHOT = "rpki-client 2026-04-17 (NLnet Labs/OpenBSD, all 5 RIR TALs)"

# Target RPKI ratio for label normalization.
# Updated to match 2025 global IPv4 ROA coverage (~56% by prefix, ~50% by AS count).
# Using AS-count metric since we're classifying individual ASes.
RPKI_TARGET_RATIO = 0.50


def get_rpki_signing_asns_from_rpki_client(
    subgraph_asns: set[int],
    vrps_path: Path = RPKI_CLIENT_VRPS_ASNS_PATH,
) -> frozenset[int]:
    """Return the ASNs in `subgraph_asns` that have at least one registered ROA.

    Uses the NLnet Labs/OpenBSD **rpki-client** Validated ROA Payload (VRP)
    dump — the canonical RPKI validator output — from the 2022-06-18 snapshot
    retrieved via the Internet Archive's Wayback Machine. This dump covers
    all five RIR Trust Anchor Locations (ARIN, APNIC, RIPE NCC, LACNIC,
    AFRINIC) and is the standard citeable source for global RPKI signing
    deployment.

    **Important semantic note:** this measures RPKI **signing** (has at least
    one registered ROA) — the property required for an AS to act as a
    blockchain validator anchored to the RPKI trust chain. This is distinct
    from ROV **enforcement** (actively dropping invalid routes), which is a
    stricter and smaller set (~12% via rov-collector). For BGP-Sentry's
    Proof-of-Population consensus, signing is the correct metric because
    what anchors a validator is its cryptographic identity at an RIR TAL,
    not its inbound filtering policy.

    At the 2022-06-18 snapshot, 30,849 ASNs globally have at least one ROA,
    of which 26,631 are present in the CAIDA 2022-01-01 graph — a 36.3%
    AS-level RPKI signing rate, matching the paper's reported value.

    Args:
        subgraph_asns: The subgraph ASNs to intersect against.
        vrps_path: Path to the one-ASN-per-line file produced from vrps.json.

    Returns:
        Frozen set of ASNs in the subgraph that have at least one ROA.
    """
    print(f"\n[RPKI] Loading RPKI signing data from rpki-client VRP dump...")
    print(f"[RPKI] Source: {RPKI_CLIENT_VRPS_SNAPSHOT}")
    print(f"[RPKI] File: {vrps_path}")

    if not vrps_path.exists():
        raise FileNotFoundError(
            f"rpki-client VRP ASN list not found at {vrps_path}. "
            f"Re-download the rpki-client VRP snapshot or re-compute from "
            f"2022-06-18 snapshot from the Wayback Machine."
        )

    if str(vrps_path).endswith(".json"):
        import json as _json
        with vrps_path.open() as f:
            data = _json.load(f)
        if isinstance(data, dict) and "rpki_asns" in data:
            all_signing_asns = {int(a) for a in data["rpki_asns"]}
        elif isinstance(data, list):
            all_signing_asns = {int(a) for a in data}
        else:
            all_signing_asns = set()
    else:
        with vrps_path.open() as f:
            all_signing_asns = {int(line.strip()) for line in f if line.strip()}
    print(f"[RPKI] ROA-signing ASes worldwide: {len(all_signing_asns)}")

    rpki_asns = frozenset(asn for asn in all_signing_asns if asn in subgraph_asns)
    pct = len(rpki_asns) / len(subgraph_asns) * 100 if subgraph_asns else 0
    print(f"[RPKI] ROA-signing ASes in subgraph (natural): {len(rpki_asns)}/{len(subgraph_asns)} "
          f"({pct:.1f}%)")

    return rpki_asns


def normalize_rpki_labels(
    subgraph_asns: set[int],
    natural_rpki_asns: frozenset[int],
    target_ratio: float = RPKI_TARGET_RATIO,
    seed: Optional[int] = None,
) -> tuple[frozenset[int], int]:
    """Downsample the RPKI set in the subgraph to match the target global ratio.

    Connected CAIDA subgraphs are structurally biased above the global 36.3%
    RPKI signing rate, because bridge reconnection walks through backbone
    transit ASes which have disproportionately high RPKI adoption (~65% vs.
    36% universe). Typical natural ratio in a sampled subgraph is 45-55%.

    To make the dataset reflect realistic global deployment density (rather
    than backbone bias), we uniformly downsample RPKI labels in the subgraph
    until the final RPKI ratio matches the target. ASes selected for demotion
    have their classification flipped from RPKI to non-RPKI in
    `as_classification.json` — their real rpki-client status is unchanged,
    but for simulation purposes they act as non-RPKI observers.

    This is a controlled experimental adjustment, transparently documented,
    and uses a seed-derived deterministic RNG (separate from the sampling
    RNG) so results are reproducible.

    Args:
        subgraph_asns: All ASes in the subgraph (RPKI and non-RPKI).
        natural_rpki_asns: The natural RPKI set (from rpki-client VRPs).
        target_ratio: Target fraction of ASes to keep as RPKI (default 0.363).
        seed: Seed for the normalization RNG. A separate RNG is used so
            demotion is independent of sampling randomness.

    Returns:
        (final_rpki_asns, demoted_count) — the downsampled RPKI set and the
        number of ASes demoted from RPKI to non-RPKI.
    """
    # Use a dedicated RNG keyed on ("label_norm", seed) so this is independent
    # of the global `random` state used during sampling and scenario runs.
    label_rng = random.Random(("label_norm", seed, len(subgraph_asns)))

    natural_in_sample = natural_rpki_asns & frozenset(subgraph_asns)
    target_count = round(len(subgraph_asns) * target_ratio)

    if len(natural_in_sample) <= target_count:
        # Natural rate is already at or below target — keep as-is.
        # (Does not happen for sizes we care about, but defensive.)
        print(f"[RPKI-norm] Natural RPKI count {len(natural_in_sample)} "
              f"already <= target {target_count}, no demotion needed.")
        return frozenset(natural_in_sample), 0

    excess = len(natural_in_sample) - target_count
    demoted = set(label_rng.sample(sorted(natural_in_sample), excess))
    final_rpki = frozenset(natural_in_sample - demoted)

    print(f"[RPKI-norm] Natural RPKI: {len(natural_in_sample)}/{len(subgraph_asns)} "
          f"({100*len(natural_in_sample)/len(subgraph_asns):.2f}%)")
    print(f"[RPKI-norm] Target: {target_count}/{len(subgraph_asns)} "
          f"({100*target_ratio:.2f}%)")
    print(f"[RPKI-norm] Demoted {excess} ASes from RPKI to non-RPKI "
          f"(deterministic, seed={seed})")
    print(f"[RPKI-norm] Final RPKI: {len(final_rpki)}/{len(subgraph_asns)} "
          f"({100*len(final_rpki)/len(subgraph_asns):.2f}%)")

    return final_rpki, excess


# ── Dynamic Prefix-to-AS Assignment ─────────────────────────────────
# Each AS gets a realistic number of prefixes based on its type.
# Prefixes are allocated sequentially from non-reserved IP space (44.0.0.0+).


class _PrefixAllocator:
    """Sequentially allocates non-overlapping prefixes from 44.0.0.0+."""

    def __init__(self) -> None:
        # Start at 44.0.0.0 (after ARPANET/military blocks, before multicast)
        self._next_ip = int(ipaddress.IPv4Address("44.0.0.0"))

    def allocate(self, prefix_len: int) -> str:
        """Allocate the next available /<prefix_len> block."""
        block_size = 2 ** (32 - prefix_len)
        # Align to block boundary
        if self._next_ip % block_size != 0:
            self._next_ip += block_size - (self._next_ip % block_size)
        addr = ipaddress.IPv4Address(self._next_ip)
        prefix = f"{addr}/{prefix_len}"
        self._next_ip += block_size
        # Skip reserved ranges (224.0.0.0+ multicast, 240.0.0.0+ reserved)
        if self._next_ip >= int(ipaddress.IPv4Address("224.0.0.0")):
            raise RuntimeError("Exhausted allocatable IPv4 space")
        return prefix


def generate_prefix_assignments(
    as_graph: ASGraph,
    subgraph_asns: set[int],
) -> dict[int, list[str]]:
    """Assign realistic prefix counts to each AS based on its type.

    - Stubs: 1-3 prefixes (mostly /24s)
    - Multihomed: 2-5 prefixes (/22-/24)
    - Transit (etc): 5-20 prefixes (/18-/24)
    - Input clique: 20-50 prefixes (/16-/20)

    Returns:
        dict[asn] -> list of prefix strings (CIDR)
    """
    allocator = _PrefixAllocator()
    assignments: dict[int, list[str]] = {}

    for asn in sorted(subgraph_asns):
        as_obj = as_graph.as_dict[asn]
        prefixes: list[str] = []

        if as_obj.input_clique:
            count = random.randint(20, 50)
            for _ in range(count):
                plen = random.choice([16, 17, 18, 19, 20])
                prefixes.append(allocator.allocate(plen))
        elif as_obj.transit and not as_obj.input_clique:
            count = random.randint(5, 20)
            for _ in range(count):
                plen = random.choice([18, 19, 20, 21, 22, 23, 24])
                prefixes.append(allocator.allocate(plen))
        elif as_obj.multihomed:
            count = random.randint(2, 5)
            for _ in range(count):
                plen = random.choice([22, 23, 24])
                prefixes.append(allocator.allocate(plen))
        else:
            # Stub
            count = random.randint(1, 3)
            for _ in range(count):
                prefixes.append(allocator.allocate(24))

        assignments[asn] = prefixes

    total_prefixes = sum(len(v) for v in assignments.values())
    print(f"[PREFIX] Assigned {total_prefixes} prefixes to {len(assignments)} ASes")
    return assignments


def _generate_subprefix(prefix: str) -> str:
    """Generate a more-specific subprefix from a given prefix.

    E.g., 44.0.0.0/16 -> 44.0.0.0/24 or 44.0.128.0/17
    """
    net = ipaddress.ip_network(prefix, strict=False)
    current_len = net.prefixlen
    if current_len >= 28:
        # Already very specific, just go +1
        new_len = min(current_len + 1, 32)
    else:
        # Jump to a more-specific prefix (2-8 bits more specific)
        new_len = min(current_len + random.randint(2, 8), 28)
    # Pick the first subnet of the new length
    subnets = list(net.subnets(new_prefix=new_len))
    return str(random.choice(subnets))


# ── Attack Announcement Builders ────────────────────────────────────

def _build_attack_announcements(
    attack_type: str,
    victim_asn: int,
    attacker_asn: int,
    victim_prefix: str,
    prefix_assignments: dict[int, list[str]],
    timeline: Optional["RealisticTimeline"] = None,
    override_timestamp: Optional[int] = None,
) -> tuple[tuple[Announcement, ...], tuple[ROA, ...], str, list[dict]]:
    """Build override announcements for a given attack type.

    Returns:
        (announcements_tuple, roas_tuple, scenario_type_label, flap_metadata)
        flap_metadata is non-empty only for route_flapping attacks.
    """
    if override_timestamp is not None:
        victim_ts = override_timestamp
        attacker_ts = override_timestamp + random.randint(1, 10)
    elif timeline:
        Timestamps.set_base_timestamp()
        victim_ts = Timestamps.get_victim_timestamp()
        attacker_ts = Timestamps.get_attacker_timestamp()

    victim_ann = Announcement(
        prefix=victim_prefix,
        as_path=(victim_asn,),
        next_hop_asn=victim_asn,
        seed_asn=victim_asn,
        timestamp=victim_ts,
        recv_relationship=Relationships.ORIGIN,
    )
    victim_roa = ROA(ip_network(victim_prefix, strict=False), victim_asn)
    flap_metadata: list[dict] = []

    if attack_type == "prefix_hijack":
        attacker_ann = Announcement(
            prefix=victim_prefix,
            as_path=(attacker_asn,),
            next_hop_asn=attacker_asn,
            seed_asn=attacker_asn,
            timestamp=attacker_ts,
            recv_relationship=Relationships.ORIGIN,
        )
        anns = (victim_ann, attacker_ann)
        roas = (victim_roa,)

    elif attack_type == "subprefix_hijack":
        subprefix = _generate_subprefix(victim_prefix)
        attacker_ann = Announcement(
            prefix=subprefix,
            as_path=(attacker_asn,),
            next_hop_asn=attacker_asn,
            seed_asn=attacker_asn,
            timestamp=attacker_ts,
            recv_relationship=Relationships.ORIGIN,
        )
        anns = (victim_ann, attacker_ann)
        roas = (victim_roa,)

    elif attack_type == "bogon_injection":
        bogon_prefix = random.choice(BOGON_RANGES)
        attacker_ann = Announcement(
            prefix=bogon_prefix,
            as_path=(attacker_asn,),
            next_hop_asn=attacker_asn,
            seed_asn=attacker_asn,
            timestamp=attacker_ts,
            recv_relationship=Relationships.ORIGIN,
        )
        anns = (victim_ann, attacker_ann)
        roas = (victim_roa,)

    elif attack_type == "route_flapping":
        # Route flapping: generate 3-8 announce/withdraw cycles
        # Citation: Mao et al. 2002, RFC 2439
        attacker_ann = Announcement(
            prefix=victim_prefix,
            as_path=(attacker_asn,),
            next_hop_asn=attacker_asn,
            seed_asn=attacker_asn,
            timestamp=attacker_ts,
            recv_relationship=Relationships.ORIGIN,
        )
        anns = (victim_ann, attacker_ann)
        roas = (victim_roa,)

        # Generate oscillation metadata for post-processing
        # 5-9 cycles with 5-10s gaps ensures all attacks exceed the
        # detection threshold (5+ events in 60s sliding window)
        num_cycles = random.randint(5, 9)
        t = attacker_ts
        for cycle in range(num_cycles):
            # Announce
            flap_metadata.append({
                "flap_sequence": cycle * 2 + 1,
                "is_withdrawal": False,
                "timestamp": t,
                "prefix": victim_prefix,
                "attacker_asn": attacker_asn,
            })
            # Withdraw after 5-10 seconds (rapid oscillation)
            t += random.randint(5, 10)
            flap_metadata.append({
                "flap_sequence": cycle * 2 + 2,
                "is_withdrawal": True,
                "timestamp": t,
                "prefix": victim_prefix,
                "attacker_asn": attacker_asn,
            })
            # Re-announce after 3-8 seconds (aggressive flapping)
            t += random.randint(3, 8)

    elif attack_type == "forged_origin_prefix_hijack":
        # Forged-origin: attacker appends victim's ASN to path to bypass ROV
        # as_path=(attacker, victim) makes ROA check pass (origin=victim)
        # Citation: ROV++ (NDSS 2022), Securing BGP ASAP (NDSS 2025)
        attacker_ann = Announcement(
            prefix=victim_prefix,
            as_path=(attacker_asn, victim_asn),
            next_hop_asn=attacker_asn,
            seed_asn=attacker_asn,
            timestamp=attacker_ts,
            recv_relationship=Relationships.ORIGIN,
        )
        anns = (victim_ann, attacker_ann)
        roas = (victim_roa,)

    elif attack_type == "accidental_route_leak":
        # Route leak: attacker re-originates victim's route to all neighbors
        # This is handled specially in run_route_leak_scenario() but we still
        # need the victim announcement and ROA for the initial seed
        attacker_ann = Announcement(
            prefix=victim_prefix,
            as_path=(attacker_asn, victim_asn),
            next_hop_asn=attacker_asn,
            seed_asn=attacker_asn,
            timestamp=attacker_ts,
            recv_relationship=Relationships.ORIGIN,
        )
        anns = (victim_ann, attacker_ann)
        roas = (victim_roa,)

    else:
        raise ValueError(f"Unknown attack type: {attack_type}")

    if not timeline:
        Timestamps.reset_base_timestamp()
    return anns, roas, attack_type, flap_metadata


# ── Timestamp Convergence Jitter ────────────────────────────────────

def apply_convergence_jitter(all_as_observations: dict[int, list[dict]]) -> None:
    """Add per-hop convergence delay to timestamps in-place.

    Per-hop delay uses a log-normal distribution clamped to [1, 20] seconds,
    modeling real BGP convergence where most hops are fast (~5s MRAI processing)
    and few are slow (queue delays, route dampening):
        per_hop = clamp(lognormal(mu=ln(5.5), sigma=0.75), 1, 20)
        median ~5.5s, mean ~7s, max 20s per hop

    Citation: Labovitz et al. 2001, Mao et al. 2003, RFC 4271
    """
    import math
    _jitter_mu = math.log(5.5)
    _jitter_sigma = 0.75

    for asn, observations in all_as_observations.items():
        for obs in observations:
            # Skip observations with invalid timestamps (BGPy default=0)
            if obs.get("timestamp", 0) < 1_000_000_000:
                continue
            path_len = obs.get("as_path_length", 1)
            jitter = sum(
                max(1.0, min(20.0, random.lognormvariate(_jitter_mu, _jitter_sigma)))
                for _ in range(path_len)
            )
            obs["timestamp"] = int(obs["timestamp"] + jitter)
            if obs["timestamp"] > 0:
                obs["timestamp_readable"] = datetime.fromtimestamp(
                    obs["timestamp"]
                ).strftime('%Y-%m-%d %H:%M:%S')


# ── WITHDRAW Message Generation ──────────────────────────────────────
# Real BGP has 10-15% withdrawals daily (Huston 2024/2025).
# Citation: RIPE Labs "The Shape of a BGP Update", Huston "BGP Updates 2024/2025"

def generate_withdrawal_observations(
    all_as_observations: dict[int, list[dict]],
    timeline: "RealisticTimeline",
    withdrawal_rate: float = 0.10,
) -> int:
    """Generate realistic WITHDRAW observations and add to all_as_observations.

    After legitimate scenarios, ~10-12% of previously announced prefixes
    are "withdrawn". Each withdrawal generates an observation for all ASes
    that had received the original announcement.

    According to RIPE Labs ("The Shape of a BGP Update"):
    - Withdrawal generates ~3.6x more messages than announcement (path exploration)
    - 90% of withdrawal convergence completes within 3 minutes
    - Only 25% of messages during withdrawal are actual WITHDRAWs; rest are re-announcements

    For simplicity, we generate explicit WITHDRAW records with realistic timing.

    Args:
        all_as_observations: Current observations dict (modified in-place).
        timeline: RealisticTimeline instance for timestamp generation.
        withdrawal_rate: Fraction of observations to withdraw (default 0.12 = 12%).

    Returns:
        Number of withdrawal observations added.
    """
    withdrawal_count = 0

    # Build index in one pass: (prefix, origin) → {latest_ts, observers: {asn → obs}}
    # This avoids repeated O(N) scans over all observations.
    index: dict[tuple[str, int], dict] = {}
    for asn, observations in all_as_observations.items():
        for obs in observations:
            if not obs.get("is_attack", False) and not obs.get("is_withdrawal", False):
                key = (obs["prefix"], obs["origin_asn"])
                if key not in index:
                    index[key] = {"latest_ts": 0, "observers": {}}
                ts = obs.get("timestamp", 0)
                if ts > index[key]["latest_ts"]:
                    index[key]["latest_ts"] = ts
                if asn not in index[key]["observers"]:
                    index[key]["observers"][asn] = obs

    # Select which (prefix, origin) pairs to withdraw
    all_keys = list(index.keys())
    n_withdraw = max(1, int(len(all_keys) * withdrawal_rate))
    if n_withdraw > len(all_keys):
        n_withdraw = len(all_keys)
    withdraw_keys = random.sample(all_keys, n_withdraw)

    for prefix, origin_asn in withdraw_keys:
        entry = index[(prefix, origin_asn)]
        latest_ts = entry["latest_ts"]

        withdraw_ts = timeline.get_withdrawal_timestamp(latest_ts) if latest_ts > 0 else timeline.next_timestamp()

        # Generate withdrawal observation for each observer
        for asn, original in entry["observers"].items():

            # Create withdrawal observation
            withdraw_obs = {
                "prefix": prefix,
                "origin_asn": origin_asn,
                "as_path": original.get("as_path", []),
                "as_path_length": original.get("as_path_length", 0),
                "next_hop_asn": original.get("next_hop_asn", origin_asn),
                "timestamp": withdraw_ts + random.randint(0, 30),  # Small jitter per observer
                "timestamp_readable": datetime.fromtimestamp(
                    withdraw_ts
                ).strftime('%Y-%m-%d %H:%M:%S'),
                "recv_relationship": original.get("recv_relationship", "UNKNOWN"),
                "origin_type": "TRANSIT",
                "label": "LEGITIMATE",
                "is_attack": False,
                "observed_by_asn": asn,
                "observer_is_rpki": original.get("observer_is_rpki", False),
                "hop_distance": original.get("hop_distance", 0),
                "relayed_by_asn": original.get("relayed_by_asn", None),
                "is_best": False,
                "bgp_update": {
                    "type": "WITHDRAWAL",
                    "withdrawn_routes": [prefix],
                    "path_attributes": {},
                    "nlri": [],
                },
                "communities": [],
                "is_withdrawal": True,
            }

            all_as_observations[asn].append(withdraw_obs)
            withdrawal_count += 1

    return withdrawal_count


# ── Route Flapping Oscillation Injection ───────────────────────────
# Generates actual announce/withdraw/announce cycles for flapping attacks.
# Citation: Mao et al. 2002, RFC 2439

def inject_flapping_oscillations(
    all_as_observations: dict[int, list[dict]],
    all_flap_metadata: list[list[dict]],
) -> int:
    """Inject route flapping oscillation observations into the dataset.

    For each flapping attack, generates announce/withdraw cycles based
    on the flap_metadata from _build_attack_announcements.

    Args:
        all_as_observations: Current observations dict (modified in-place).
        all_flap_metadata: List of flap_metadata lists from each flapping attack.

    Returns:
        Number of flapping observations added.
    """
    flap_count = 0

    for flap_sequence in all_flap_metadata:
        if not flap_sequence:
            continue

        prefix = flap_sequence[0]["prefix"]
        attacker_asn = flap_sequence[0]["attacker_asn"]

        # Find all ASes that observed the original flapping attack announcement
        observer_asns = []
        for asn, observations in all_as_observations.items():
            for obs in observations:
                if (obs.get("label") == "ROUTE_FLAPPING"
                        and obs["prefix"] == prefix
                        and obs["origin_asn"] == attacker_asn):
                    observer_asns.append(asn)
                    break

        # Generate oscillation observations for each observer
        for flap_event in flap_sequence:
            for asn in observer_asns:
                # Find original observation for this AS
                original = None
                for obs in all_as_observations.get(asn, []):
                    if (obs.get("label") == "ROUTE_FLAPPING"
                            and obs["prefix"] == prefix
                            and obs["origin_asn"] == attacker_asn
                            and not obs.get("is_withdrawal", False)):
                        original = obs
                        break

                if original is None:
                    continue

                flap_obs = {
                    "prefix": prefix,
                    "origin_asn": attacker_asn,
                    "as_path": original.get("as_path", [attacker_asn]),
                    "as_path_length": original.get("as_path_length", 1),
                    "next_hop_asn": original.get("next_hop_asn", attacker_asn),
                    "timestamp": flap_event["timestamp"] + random.randint(0, 15),
                    "timestamp_readable": datetime.fromtimestamp(
                        flap_event["timestamp"]
                    ).strftime('%Y-%m-%d %H:%M:%S'),
                    "recv_relationship": original.get("recv_relationship", "UNKNOWN"),
                    "origin_type": "ATTACKER",
                    "label": "ROUTE_FLAPPING",
                    "is_attack": True,
                    "observed_by_asn": asn,
                    "observer_is_rpki": original.get("observer_is_rpki", False),
                    "hop_distance": original.get("hop_distance", 0),
                    "relayed_by_asn": original.get("relayed_by_asn", None),
                    "is_best": False,
                    "flap_sequence": flap_event["flap_sequence"],
                    "is_withdrawal": flap_event["is_withdrawal"],
                    "bgp_update": {
                        "type": "WITHDRAWAL" if flap_event["is_withdrawal"] else "UPDATE",
                        "withdrawn_routes": [prefix] if flap_event["is_withdrawal"] else [],
                        "path_attributes": {} if flap_event["is_withdrawal"] else original.get("bgp_update", {}).get("path_attributes", {}),
                        "nlri": [] if flap_event["is_withdrawal"] else [prefix],
                    },
                    "communities": [] if flap_event["is_withdrawal"] else original.get("communities", []),
                }

                all_as_observations[asn].append(flap_obs)
                flap_count += 1

    return flap_count


# ── Route Leak Scenario Runner ──────────────────────────────────────
# AccidentalRouteLeak requires special handling: 2 propagation rounds
# with a post_propagation_hook that re-seeds the attacker's announcement.
# Citation: RFC 7908, bgpy AccidentalRouteLeak implementation

def run_route_leak_scenario(
    victim_asn: int,
    attacker_asn: int,
    victim_prefix: str,
    as_graph_info: ASGraphInfo,
    fixed_rpki_asns: frozenset[int],
    timeline: "RealisticTimeline",
    scenario_cls=None,
    scenario_type: str = "accidental_route_leak",
) -> tuple[dict[int, list[dict]], dict]:
    """Run a route leak scenario with bgpy's 2-round mechanism.

    Route leak scenarios work differently from other attacks:
    - Round 0: Victim's prefix propagates normally
    - post_propagation_hook: Attacker's local_rib entry is re-seeded as ORIGIN
    - Round 1: Attacker re-propagates the route to all neighbors (leak)

    Args:
        victim_asn: ASN of the victim.
        attacker_asn: ASN of the leaking AS.
        victim_prefix: The prefix being leaked.
        as_graph_info: ASGraphInfo for the subgraph.
        fixed_rpki_asns: Set of RPKI-enabled ASNs.
        timeline: RealisticTimeline for timestamps.
        scenario_cls: Scenario class (default: AccidentalRouteLeak).
        scenario_type: Label for the scenario type.

    Returns:
        (observations_dict, metadata)
    """
    if scenario_cls is None:
        scenario_cls = AccidentalRouteLeak
    print(f"\n  Running {scenario_type.upper()} scenario (2-round)")
    print(f"    Victim: AS{victim_asn}, Leaker: AS{attacker_asn}, Prefix: {victim_prefix}")

    victim_ts = timeline.get_attack_timestamp()

    victim_ann = Announcement(
        prefix=victim_prefix,
        as_path=(victim_asn,),
        next_hop_asn=victim_asn,
        seed_asn=victim_asn,
        timestamp=victim_ts,
        recv_relationship=Relationships.ORIGIN,
    )
    victim_roa = ROA(ip_network(victim_prefix, strict=False), victim_asn)

    # Use ScenarioConfig with the specified route leak scenario class
    config = ScenarioConfig(
        ScenarioCls=scenario_cls,
        AdoptPolicyCls=BGP,
        BasePolicyCls=BGP,
        override_announcements=(victim_ann,),
        override_roas=(victim_roa,),
        override_victim_asns=frozenset({victim_asn}),
        override_attacker_asns=frozenset({attacker_asn}),
        num_victims=1,
        num_attackers=1,
        attacker_subcategory_attr=ASGroups.ETC.value,
    )

    as_graph = ASGraph(as_graph_info)
    engine = SimulationEngine(as_graph)

    scenario = config.ScenarioCls(
        scenario_config=config,
        percent_adoption=0.0,
        engine=engine,
    )

    all_asns = set(engine.as_graph.as_dict.keys())
    rpki_asns = fixed_rpki_asns & all_asns

    engine.setup(scenario)
    adj_rib_in = install_ann_interceptors(engine)

    # Run 2 rounds with post_propagation_hook
    for round_num in range(2):
        engine.run(propagation_round=round_num, scenario=scenario)
        scenario.post_propagation_hook(
            engine=engine,
            percent_adopt=0.0,
            trial=0,
            propagation_round=round_num,
        )

    # Extract observations — the attacker's leaked announcement will have
    # the attacker as seed_asn, making it identifiable as attack
    observations, _, _ = extract_all_node_observations(
        engine=engine,
        rpki_asns=rpki_asns,
        attacker_asns=frozenset({attacker_asn}),
        victim_asns=frozenset({victim_asn}),
        scenario_type=scenario_type,
        sample_size=None,
        adj_rib_in=adj_rib_in,
    )

    # BGPy's AccidentalRouteLeak.post_propagation_hook re-seeds the attacker's
    # announcement with Timestamps.ATTACKER.value (=1), a symbolic sentinel
    # value. Our downstream filter drops anything with timestamp < 1e9 (to
    # eliminate BGPy's default-zero timestamps), which would delete all
    # leaked observations. Rewrite sentinel timestamps to real Unix epochs
    # sourced from the timeline so they survive the filter.
    leak_fixed_count = 0
    for asn, anns in observations.items():
        for ann in anns:
            ts = ann.get("timestamp", 0)
            if ts < 1_000_000_000:
                new_ts = timeline.get_attack_timestamp()
                ann["timestamp"] = new_ts
                try:
                    ann["timestamp_readable"] = datetime.fromtimestamp(new_ts).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                except (OSError, OverflowError, ValueError):
                    pass
                leak_fixed_count += 1

    total_anns = sum(len(anns) for anns in observations.values())
    attack_anns = sum(
        sum(1 for ann in anns if ann['is_attack'])
        for anns in observations.values()
    )
    print(f"    Route leak observations: {total_anns} total, {attack_anns} attack "
          f"({leak_fixed_count} timestamps rewritten from BGPy sentinel)")

    metadata = {
        "scenario_type": "accidental_route_leak",
        "scenario_class": "AccidentalRouteLeak",
        "victim_asns": [victim_asn],
        "attacker_asns": [attacker_asn],
        "prefix": victim_prefix,
        "total_announcements": total_anns,
        "attack_announcements": attack_anns,
    }

    return observations, metadata


# ── Visibility Diversity Stats ──────────────────────────────────────

def compute_visibility_stats(all_as_observations: dict[int, list[dict]]) -> dict:
    """Compute and print diversity metrics for the dataset."""
    prefixes_per_as = []
    origins_per_as = []
    labels_per_as = []

    for asn, observations in all_as_observations.items():
        unique_prefixes = set(obs["prefix"] for obs in observations)
        unique_origins = set(obs["origin_asn"] for obs in observations)
        unique_labels = set(obs["label"] for obs in observations)
        prefixes_per_as.append(len(unique_prefixes))
        origins_per_as.append(len(unique_origins))
        labels_per_as.append(len(unique_labels))

    import statistics
    stats = {
        "total_ases": len(all_as_observations),
        "prefixes_per_as": {
            "min": min(prefixes_per_as) if prefixes_per_as else 0,
            "max": max(prefixes_per_as) if prefixes_per_as else 0,
            "mean": statistics.mean(prefixes_per_as) if prefixes_per_as else 0,
            "stdev": statistics.stdev(prefixes_per_as) if len(prefixes_per_as) > 1 else 0,
        },
        "origins_per_as": {
            "min": min(origins_per_as) if origins_per_as else 0,
            "max": max(origins_per_as) if origins_per_as else 0,
            "mean": statistics.mean(origins_per_as) if origins_per_as else 0,
            "stdev": statistics.stdev(origins_per_as) if len(origins_per_as) > 1 else 0,
        },
    }

    print(f"\n[VISIBILITY] Diversity metrics:")
    print(f"    Prefixes per AS: min={stats['prefixes_per_as']['min']}, "
          f"max={stats['prefixes_per_as']['max']}, "
          f"mean={stats['prefixes_per_as']['mean']:.1f}, "
          f"stdev={stats['prefixes_per_as']['stdev']:.1f}")
    print(f"    Origins per AS:  min={stats['origins_per_as']['min']}, "
          f"max={stats['origins_per_as']['max']}, "
          f"mean={stats['origins_per_as']['mean']:.1f}, "
          f"stdev={stats['origins_per_as']['stdev']:.1f}")

    return stats


# ── Adj-RIB-In Interceptor ─────────────────────────────────────────
# In real BGP, every router's Adj-RIB-In stores ALL announcements
# received from ALL neighbors (not just the best route).  bgpy's
# recv_q is cleared after each propagation round, so we monkey-patch
# receive_ann() to capture every incoming announcement in a persistent
# side-buffer keyed by (observer_asn, prefix, neighbor_asn).
#
# This gives each node a complete view of what it heard — exactly
# like a real router's RIB — which is critical for blockchain
# consensus (every validator must be able to report what it saw).

def install_ann_interceptors(engine: SimulationEngine) -> dict:
    """Patch every AS's receive_ann to capture ALL incoming announcements.

    Returns adj_rib_in: dict[int, list[Announcement]]
        Maps ASN -> list of every announcement received (unfiltered).
    """
    adj_rib_in: dict[int, list] = defaultdict(list)

    for asn, as_obj in engine.as_graph.as_dict.items():
        original_receive = as_obj.policy.receive_ann.__func__

        def make_interceptor(orig, _asn):
            def interceptor(self, ann):
                adj_rib_in[_asn].append(ann)
                return orig(self, ann)
            return interceptor

        import types
        as_obj.policy.receive_ann = types.MethodType(
            make_interceptor(original_receive, asn), as_obj.policy
        )

    return adj_rib_in


# ── Zoo Topology Helpers (legacy) ────────────────────────────────────

def parse_gml(gml_path: Path) -> tuple[list[int], list[tuple[int, int]]]:
    """
    Parse a GML file and extract node IDs and edges.

    Returns:
        (node_ids, edges) where edges are (source_id, target_id) tuples
    """
    content = gml_path.read_text()

    # Extract node IDs
    node_ids = [int(m) for m in re.findall(r'node\s*\[\s*id\s+(\d+)', content)]

    # Extract edges
    edges = []
    for m in re.finditer(r'edge\s*\[\s*source\s+(\d+)\s*target\s+(\d+)', content):
        edges.append((int(m.group(1)), int(m.group(2))))

    return node_ids, edges


def gml_to_as_graph_info(gml_path: Path) -> ASGraphInfo:
    """
    Convert a Topology Zoo GML file to an ASGraphInfo with inferred hierarchy.

    Hierarchy inference (degree-based):
    1. Sort nodes by degree (descending)
    2. Nodes with degree >= 75th percentile -> core (PeerLinks between them)
    3. Core-to-non-core edges -> CPLink (core=provider)
    4. Non-core-to-non-core edges -> CPLink (higher degree=provider)
    5. Top ~10% by degree -> input_clique_asns
    """
    node_ids, edges = parse_gml(gml_path)

    # Offset node IDs by 1 to use as ASNs (GML IDs start at 0, avoid ASN 0)
    asn_map = {nid: nid + 1 for nid in node_ids}

    # Compute degree for each node
    degree: dict[int, int] = {nid: 0 for nid in node_ids}
    for src, tgt in edges:
        degree[src] += 1
        degree[tgt] += 1

    # Sort degrees to find percentile thresholds
    degrees_sorted = sorted(degree.values())
    n = len(degrees_sorted)
    max_degree = max(degree.values())

    # Core threshold: 75th percentile, but adjust for flat topologies
    core_threshold = degrees_sorted[int(n * 0.75)]
    core_nodes = {nid for nid, d in degree.items() if d >= core_threshold}

    # If too many nodes are core (flat topology), increase threshold
    while len(core_nodes) > n * 0.50 and core_threshold < max_degree:
        core_threshold += 1
        core_nodes = {nid for nid, d in degree.items() if d >= core_threshold}

    # Fallback: if still > 50% or < 2, pick top 25% by degree
    if len(core_nodes) > n * 0.50 or len(core_nodes) < 2:
        sorted_by_degree = sorted(degree, key=lambda x: (-degree[x], x))
        top_n = max(2, n // 4)
        core_nodes = set(sorted_by_degree[:top_n])

    # Input clique: top ~10% by degree, with same flat-topology guard
    clique_threshold = degrees_sorted[int(n * 0.90)]
    clique_nids = {nid for nid, d in degree.items() if d >= clique_threshold}

    while len(clique_nids) > n * 0.20 and clique_threshold < max_degree:
        clique_threshold += 1
        clique_nids = {nid for nid, d in degree.items() if d >= clique_threshold}

    if len(clique_nids) > n * 0.20 or len(clique_nids) < 2:
        sorted_by_degree = sorted(degree, key=lambda x: (-degree[x], x))
        top_n = max(2, n // 10)
        clique_nids = set(sorted_by_degree[:top_n])

    input_clique = {asn_map[nid] for nid in clique_nids}

    # Classify edges into CPLinks and PeerLinks
    cp_links: set[CPLink] = set()
    peer_links: set[PeerLink] = set()

    for src, tgt in edges:
        src_asn, tgt_asn = asn_map[src], asn_map[tgt]

        if src in core_nodes and tgt in core_nodes:
            # Both core -> PeerLink
            peer_links.add(PeerLink(src_asn, tgt_asn))
        elif src in core_nodes:
            # Core=provider, non-core=customer
            cp_links.add(CPLink(customer_asn=tgt_asn, provider_asn=src_asn))
        elif tgt in core_nodes:
            # Core=provider, non-core=customer
            cp_links.add(CPLink(customer_asn=src_asn, provider_asn=tgt_asn))
        else:
            # Both non-core: higher degree is provider
            if degree[src] > degree[tgt]:
                cp_links.add(CPLink(customer_asn=tgt_asn, provider_asn=src_asn))
            elif degree[tgt] > degree[src]:
                cp_links.add(CPLink(customer_asn=src_asn, provider_asn=tgt_asn))
            else:
                # Equal degree: lower ASN is provider (deterministic tiebreak)
                if src_asn < tgt_asn:
                    cp_links.add(CPLink(customer_asn=tgt_asn, provider_asn=src_asn))
                else:
                    cp_links.add(CPLink(customer_asn=src_asn, provider_asn=tgt_asn))

    # Ensure input clique is fully connected (add synthetic PeerLinks).
    # In sparse/tree-like topologies, core nodes may not share GML edges.
    # Without top-level peering, announcements can't cross subtrees.
    existing_link_pairs = {frozenset(link.asns) for link in cp_links | peer_links}
    clique_list = sorted(input_clique)
    synthetic_peers = 0
    for i in range(len(clique_list)):
        for j in range(i + 1, len(clique_list)):
            pair = frozenset((clique_list[i], clique_list[j]))
            if pair not in existing_link_pairs:
                peer_links.add(PeerLink(clique_list[i], clique_list[j]))
                existing_link_pairs.add(pair)
                synthetic_peers += 1

    print(f"    Topology: {gml_path.stem}")
    print(f"    Nodes: {len(node_ids)}, Edges: {len(edges)}")
    print(f"    Core nodes (>= 75th pctl degree): {len(core_nodes)}")
    print(f"    Input clique (top ~10%): {len(input_clique)}")
    print(f"    PeerLinks: {len(peer_links)} ({synthetic_peers} synthetic), CPLinks: {len(cp_links)}")

    return ASGraphInfo(
        customer_provider_links=frozenset(cp_links),
        peer_links=frozenset(peer_links),
        input_clique_asns=frozenset(input_clique),
    )


def compute_rpki_adopters(
    gml_path: Path,
    adoption_rate: float = 0.37,
) -> frozenset[int]:
    """
    Compute a fixed set of RPKI-adopting ASNs based on node degree.

    Higher-degree (core) nodes adopt first, matching the real-world observation
    that large transit providers were early RPKI adopters (RoVista, Li et al.,
    IMC 2023).

    Args:
        gml_path: Path to the Topology Zoo GML file.
        adoption_rate: Fraction of nodes that adopt RPKI (default 0.37 = 37%).

    Returns:
        Frozen set of 1-indexed ASNs that are RPKI adopters.
    """
    node_ids, edges = parse_gml(gml_path)

    # Compute degree for each node (0-indexed GML IDs)
    degree: dict[int, int] = {nid: 0 for nid in node_ids}
    for src, tgt in edges:
        degree[src] += 1
        degree[tgt] += 1

    # Sort by degree descending; tiebreak by lower ASN (= lower GML ID + 1) first
    sorted_nodes = sorted(node_ids, key=lambda nid: (-degree[nid], nid))

    # Select top ceil(n * rate) nodes
    k = math.ceil(len(sorted_nodes) * adoption_rate)
    adopters_gml = sorted_nodes[:k]

    # Convert to 1-indexed ASNs (same offset as gml_to_as_graph_info)
    return frozenset(nid + 1 for nid in adopters_gml)


def announcement_to_dict(
    ann: Announcement,
    attacker_asns: FrozenSet[int],
    victim_asns: FrozenSet[int],
    scenario_type: str,
) -> Dict:
    """Convert announcement to labeled dictionary"""
    origin = ann.origin

    # Determine whether this announcement traces back to the attacker.
    # For most scenarios the origin IS the attacker. For post-ROV attacks
    # (forged-origin, route leak), the attacker SPOOFS the victim's origin
    # but still appears elsewhere in the as_path. BGPy's _copy_and_process
    # sets seed_asn=None on every propagation hop, so we cannot rely on
    # seed_asn — we must scan the as_path instead.
    attacker_is_origin = origin in attacker_asns
    attacker_in_path = (
        attacker_is_origin
        or any(asn in attacker_asns for asn in ann.as_path)
    )

    # Determine the label based on scenario type and origin
    if attacker_in_path:
        if scenario_type == "prefix_hijack":
            label = "PREFIX_HIJACK"
        elif scenario_type == "subprefix_hijack":
            label = "SUBPREFIX_HIJACK"
        elif scenario_type == "bogon_injection":
            label = "BOGON_INJECTION"
        elif scenario_type == "route_flapping":
            label = "ROUTE_FLAPPING"
        elif scenario_type == "accidental_route_leak" or scenario_type == "valley_free_route_leak":
            label = "ROUTE_LEAK"
        elif scenario_type == "path_poisoning":
            label = "PATH_POISONING"
        else:
            label = "ATTACK"
        is_attack = True
        origin_type = "ATTACKER" if attacker_is_origin else "TRANSIT_VIA_ATTACKER"
    elif origin in victim_asns:
        label = "LEGITIMATE"
        is_attack = False
        origin_type = "VICTIM"
    else:
        label = "LEGITIMATE"
        is_attack = False
        origin_type = "TRANSIT"

    communities = _generate_communities(ann, ann.recv_relationship)

    # Realistic LOCAL_PREF by recv_relationship (Gao-Rexford model)
    # Citation: Gao-Rexford model, operational best practice
    rel_name = ann.recv_relationship.name if hasattr(ann.recv_relationship, 'name') else str(ann.recv_relationship)
    if rel_name == "CUSTOMERS":
        local_pref = 150   # Prefer customer routes (revenue-generating)
    elif rel_name == "PEERS":
        local_pref = 100   # Standard for peer routes
    elif rel_name == "PROVIDERS":
        local_pref = 80    # Least preferred (costs money)
    else:
        local_pref = 100   # ORIGIN / default

    # Realistic MED: transit/clique ASes sometimes set MED
    # Stubs typically don't set MED (remains 0)
    path_len = len(ann.as_path)
    if path_len > 1 and random.random() < 0.3:
        med = random.choice([0, 10, 20, 50, 100])
    else:
        med = 0

    # ORIGIN attribute: 85% IGP, 15% INCOMPLETE (RFC 4271)
    origin_attr = "IGP" if random.random() < 0.85 else "INCOMPLETE"

    bgp_update = {
        "type": "UPDATE",
        "withdrawn_routes": [],
        "path_attributes": {
            "ORIGIN": origin_attr,
            "AS_PATH": list(ann.as_path),
            "NEXT_HOP": ann.next_hop_asn,
            "LOCAL_PREF": local_pref,
            "MED": med,
            "COMMUNITIES": communities,
        },
        "nlri": [ann.prefix],
    }

    return {
        "prefix": ann.prefix,
        "origin_asn": origin,
        "as_path": list(ann.as_path),
        "as_path_length": len(ann.as_path),
        "next_hop_asn": ann.next_hop_asn,
        "timestamp": ann.timestamp,
        "timestamp_readable": datetime.fromtimestamp(ann.timestamp).strftime('%Y-%m-%d %H:%M:%S') if ann.timestamp > 0 else "N/A",
        "recv_relationship": ann.recv_relationship.name if hasattr(ann.recv_relationship, 'name') else str(ann.recv_relationship),
        "origin_type": origin_type,
        "label": label,
        "is_attack": is_attack,
        "bgp_update": bgp_update,
        "communities": communities,
        "is_withdrawal": False,
    }


def extract_all_node_observations(
    engine: SimulationEngine,
    rpki_asns: FrozenSet[int],
    attacker_asns: FrozenSet[int],
    victim_asns: FrozenSet[int],
    scenario_type: str,
    sample_size: Optional[int] = None,
    adj_rib_in: Optional[dict] = None,
) -> tuple[Dict[int, List[Dict]], set, set]:
    """
    Extract announcements heard by each AS.

    Uses two data sources (mirroring real BGP routers):
      1. adj_rib_in  — ALL announcements received from ALL neighbors
                        (captured by our interceptor during propagation).
                        These are raw, unprocessed announcements.
      2. local_rib   — The BEST route per prefix after Gao-Rexford
                        selection (like the FIB).

    Each observation is tagged with:
      - "is_best": True if this announcement was the one selected
                   into the Local RIB (i.e. the preferred/FIB route).
      - "is_best": False if it was received but a better route was
                   chosen (still in Adj-RIB-In, not in FIB).

    This distinction is critical for blockchain consensus: validators
    should know EVERYTHING a node heard, not just the route it picked.

    Returns:
        (observations_dict, sampled_rpki_asns, sampled_non_rpki_asns)
    """
    observations = {}
    all_asns = set(engine.as_graph.as_dict.keys())
    non_rpki_asns = all_asns - rpki_asns

    # Sample nodes if requested
    if sample_size and sample_size < len(all_asns):
        rpki_sample_size = min(sample_size // 2, len(rpki_asns))
        non_rpki_sample_size = min(sample_size - rpki_sample_size, len(non_rpki_asns))
        sampled_rpki = set(random.sample(list(rpki_asns), rpki_sample_size))
        sampled_non_rpki = set(random.sample(list(non_rpki_asns), non_rpki_sample_size))
        sampled_asns = sampled_rpki | sampled_non_rpki
    else:
        sampled_rpki = rpki_asns
        sampled_non_rpki = non_rpki_asns
        sampled_asns = all_asns

    for asn in sampled_asns:
        if asn not in engine.as_graph.as_dict:
            continue

        as_obj = engine.as_graph.as_dict[asn]
        node_observations = []

        # Build a set of (prefix, origin) pairs that are in the local_rib
        # (i.e. the "best" selected route = what goes into FIB)
        best_routes = set()
        for prefix, ann in as_obj.policy.local_rib.items():
            if ann is not None:
                best_routes.add((ann.prefix, ann.origin))

        # Source 1: Adj-RIB-In — every announcement this node received
        if adj_rib_in and asn in adj_rib_in:
            seen = set()  # deduplicate (prefix, origin, neighbor)
            for ann in adj_rib_in[asn]:
                # The intercepted ann has the SENDER's as_path (not yet
                # prepended with our ASN). The sender is ann.as_path[0].
                sender_asn = ann.as_path[0] if ann.as_path else None
                dedup_key = (ann.prefix, ann.origin, sender_asn)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                ann_dict = announcement_to_dict(
                    ann, attacker_asns, victim_asns, scenario_type
                )
                # Override as_path to include this node (as it would in RIB)
                ann_dict["as_path"] = [asn] + list(ann.as_path)
                ann_dict["as_path_length"] = len(ann_dict["as_path"])
                ann_dict["observed_by_asn"] = asn
                ann_dict["observer_is_rpki"] = asn in rpki_asns
                ann_dict["hop_distance"] = 0
                ann_dict["relayed_by_asn"] = None
                ann_dict["is_best"] = (ann.prefix, ann.origin) in best_routes
                node_observations.append(ann_dict)

        # Source 2: Seeded announcements (attacker/victim seeds go directly
        # into local_rib, NOT through receive_ann, so they won't be in
        # adj_rib_in). Add them from local_rib.
        for prefix, ann in as_obj.policy.local_rib.items():
            if ann is not None and ann.seed_asn == asn:
                ann_dict = announcement_to_dict(
                    ann, attacker_asns, victim_asns, scenario_type
                )
                ann_dict["observed_by_asn"] = asn
                ann_dict["observer_is_rpki"] = asn in rpki_asns
                ann_dict["hop_distance"] = 0
                ann_dict["relayed_by_asn"] = None
                ann_dict["is_best"] = True
                node_observations.append(ann_dict)

        # Fallback: if no adj_rib_in interceptor, use local_rib
        if not adj_rib_in:
            for prefix, ann in as_obj.policy.local_rib.items():
                if ann is not None:
                    ann_dict = announcement_to_dict(
                        ann, attacker_asns, victim_asns, scenario_type
                    )
                    ann_dict["observed_by_asn"] = asn
                    ann_dict["observer_is_rpki"] = asn in rpki_asns
                    ann_dict["hop_distance"] = 0
                    ann_dict["relayed_by_asn"] = None
                    ann_dict["is_best"] = True
                    node_observations.append(ann_dict)

        if node_observations:
            observations[asn] = node_observations

    # --- Relay pass: nodes with no observations at all ---
    # In sparse topologies, some nodes may not receive ANY announcement
    # (BGP propagation didn't reach them). For blockchain consensus,
    # these nodes relay what their nearest neighbor heard (hop 1-2).
    empty_asns = [asn for asn in sampled_asns
                  if asn in engine.as_graph.as_dict and asn not in observations]
    still_empty = list(empty_asns)
    for hop in (1, 2):
        next_empty = []
        for asn in still_empty:
            if asn in observations:
                continue
            as_obj = engine.as_graph.as_dict[asn]
            relayed = []
            seen_prefixes = set()

            sources = as_obj.neighbors if hop == 1 else [
                n2 for n1 in as_obj.neighbors
                for n2 in n1.neighbors if n2.asn != asn
            ]
            for neighbor in sources:
                for prefix, ann in neighbor.policy.local_rib.items():
                    if ann is not None and prefix not in seen_prefixes:
                        seen_prefixes.add(prefix)
                        ann_dict = announcement_to_dict(
                            ann, attacker_asns, victim_asns, scenario_type
                        )
                        ann_dict["observed_by_asn"] = asn
                        ann_dict["observer_is_rpki"] = asn in rpki_asns
                        ann_dict["hop_distance"] = hop
                        ann_dict["relayed_by_asn"] = neighbor.asn
                        ann_dict["is_best"] = False
                        relayed.append(ann_dict)

            if relayed:
                observations[asn] = relayed
            else:
                next_empty.append(asn)
        still_empty = next_empty

    return observations, sampled_rpki, sampled_non_rpki


def run_scenario_and_extract(
    scenario_cls,
    scenario_type: str,
    num_nodes: int,
    percent_adoption: float = 0.37,
    as_graph_info: Optional[ASGraphInfo] = None,
    fixed_rpki_asns: Optional[FrozenSet[int]] = None,
    override_announcements: Optional[tuple] = None,
    override_roas: Optional[tuple] = None,
    override_victim_asns: Optional[FrozenSet[int]] = None,
    override_attacker_asns: Optional[FrozenSet[int]] = None,
) -> tuple:
    """
    Run a scenario and extract observations from all nodes.

    If override_announcements/roas/victim_asns/attacker_asns are provided,
    they are passed through ScenarioConfig to bypass default scenario logic.
    """
    print(f"\n  Running {scenario_type.upper()} scenario")

    Timestamps.set_base_timestamp()
    base_time = Timestamps.get_base_timestamp()

    if as_graph_info is not None:
        as_graph = ASGraph(as_graph_info)
    else:
        as_graph = CAIDAASGraphConstructor().run()
    engine = SimulationEngine(as_graph)

    # Build ScenarioConfig with overrides
    config_kwargs: dict = {
        "ScenarioCls": scenario_cls,
        "AdoptPolicyCls": BGP,
        "BasePolicyCls": BGP,
    }
    if override_announcements is not None:
        config_kwargs["override_announcements"] = override_announcements
    if override_roas is not None:
        config_kwargs["override_roas"] = override_roas
    if override_victim_asns is not None:
        config_kwargs["override_victim_asns"] = override_victim_asns
        config_kwargs["num_victims"] = len(override_victim_asns)
    if override_attacker_asns is not None:
        config_kwargs["override_attacker_asns"] = override_attacker_asns
        config_kwargs["num_attackers"] = len(override_attacker_asns)

    config = ScenarioConfig(**config_kwargs)

    scenario = config.ScenarioCls(
        scenario_config=config,
        percent_adoption=percent_adoption,
        engine=engine,
    )

    all_asns = set(engine.as_graph.as_dict.keys())
    if fixed_rpki_asns is not None:
        rpki_asns = fixed_rpki_asns & all_asns
        non_rpki_asns = all_asns - rpki_asns
    else:
        rpki_asns = scenario.adopting_asns
        non_rpki_asns = all_asns - rpki_asns

    print(f"    Victim ASes: {sorted(scenario.victim_asns)}")
    print(f"    Attacker ASes: {sorted(scenario.attacker_asns)}")

    # For fixed topologies, export ALL nodes
    effective_sample = None if as_graph_info is not None else num_nodes

    engine.setup(scenario)
    adj_rib_in = install_ann_interceptors(engine)

    num_rounds = max(3, getattr(scenario, 'propagation_rounds', 1) or scenario.min_propagation_rounds)
    for round_num in range(num_rounds):
        engine.run(propagation_round=round_num, scenario=scenario)

    observations, sampled_rpki, sampled_non_rpki = extract_all_node_observations(
        engine=engine,
        rpki_asns=rpki_asns,
        attacker_asns=scenario.attacker_asns,
        victim_asns=scenario.victim_asns,
        scenario_type=scenario_type,
        sample_size=effective_sample,
        adj_rib_in=adj_rib_in,
    )

    total_anns = sum(len(anns) for anns in observations.values())
    attack_anns = sum(
        sum(1 for ann in anns if ann['is_attack'])
        for anns in observations.values()
    )
    print(f"    Observations from {len(observations)} nodes: "
          f"{total_anns} total, {attack_anns} attack")

    metadata = {
        "scenario_type": scenario_type,
        "scenario_class": scenario_cls.__name__,
        "base_timestamp": base_time,
        "base_time_readable": datetime.fromtimestamp(base_time).strftime('%Y-%m-%d %H:%M:%S'),
        "victim_asns": sorted(scenario.victim_asns),
        "attacker_asns": sorted(scenario.attacker_asns),
        "total_ases": len(engine.as_graph.as_dict),
        "rpki_adoption_rate": percent_adoption,
        "total_rpki_nodes": len(rpki_asns),
        "total_non_rpki_nodes": len(non_rpki_asns),
        "sampled_rpki_nodes": len(sampled_rpki),
        "sampled_non_rpki_nodes": len(sampled_non_rpki),
        "total_announcements": total_anns,
        "attack_announcements": attack_anns,
        "legitimate_announcements": total_anns - attack_anns,
        "propagation_rounds": num_rounds,
    }

    Timestamps.reset_base_timestamp()

    return observations, rpki_asns, non_rpki_asns, sampled_rpki, sampled_non_rpki, metadata


# ═══════════════════════════════════════════════════════════════════════════════
# Incremental Attack Injection (--inject-only mode)
# ═══════════════════════════════════════════════════════════════════════════════

def recover_prefix_assignments(dataset_path: Path) -> dict[int, list[str]]:
    """Scan existing observation files to recover prefix-to-ASN assignments.

    Reads each AS observation file and collects the unique prefixes originated
    by that ASN (where origin_asn == asn and label == LEGITIMATE).

    Args:
        dataset_path: Path to the existing dataset directory.

    Returns:
        dict[asn] -> list of prefix strings.
    """
    observations_dir = dataset_path / "observations"
    if not observations_dir.exists():
        raise FileNotFoundError(f"No observations directory at {observations_dir}")

    prefix_assignments: dict[int, list[str]] = {}

    obs_files = sorted(observations_dir.glob("AS*.json")) + sorted(observations_dir.glob("AS*.json.gz"))
    for as_file in obs_files:
        try:
            as_data = _read_json(as_file)
        except (json.JSONDecodeError, IOError):
            continue

        asn = as_data.get("asn")
        if asn is None:
            continue

        # Collect prefixes where this ASN is the origin in legitimate announcements
        prefixes = set()
        for obs in as_data.get("observations", []):
            if (obs.get("origin_asn") == asn
                    and obs.get("label") == "LEGITIMATE"
                    and not obs.get("is_withdrawal", False)):
                prefixes.add(obs["prefix"])

        if prefixes:
            prefix_assignments[asn] = sorted(prefixes)

    total = sum(len(v) for v in prefix_assignments.values())
    print(f"[RECOVER] Recovered {total} prefixes from {len(prefix_assignments)} ASes")
    return prefix_assignments


def load_existing_dataset(dataset_path: Path) -> tuple[
    dict[int, list[dict]],  # all_as_observations
    dict,                    # as_classification
    set[int],                # rpki_asns
    set[int],                # non_rpki_asns
]:
    """Load an existing dataset's observations and classification.

    Args:
        dataset_path: Path to the dataset directory.

    Returns:
        (all_as_observations, as_classification, rpki_asns, non_rpki_asns)
    """
    observations_dir = dataset_path / "observations"
    classification_file = dataset_path / "as_classification.json"

    if not observations_dir.exists():
        raise FileNotFoundError(f"No observations directory at {observations_dir}")
    if not classification_file.exists():
        raise FileNotFoundError(f"No classification file at {classification_file}")

    # Load classification
    as_classification = _read_json(classification_file)

    rpki_asns = set(as_classification.get("rpki_asns", []))
    non_rpki_asns = set(as_classification.get("non_rpki_asns", []))

    # Load all observations (support both .json and .json.gz)
    all_as_observations: dict[int, list[dict]] = {}
    obs_files = sorted(observations_dir.glob("AS*.json")) + sorted(observations_dir.glob("AS*.json.gz"))
    for as_file in obs_files:
        try:
            as_data = _read_json(as_file)
        except (json.JSONDecodeError, IOError):
            continue

        asn = as_data.get("asn")
        if asn is None:
            continue
        all_as_observations[asn] = as_data.get("observations", [])

    total_obs = sum(len(v) for v in all_as_observations.values())
    print(f"[LOAD] Loaded {total_obs} observations from {len(all_as_observations)} ASes")

    return all_as_observations, as_classification, rpki_asns, non_rpki_asns


def inject_new_attacks(
    dataset_path: Path,
    attacks_per_type: int = 5,
    seed: int | None = None,
):
    """Inject new attack types into an existing dataset without regenerating.

    Currently injects:
    - forged_origin_prefix_hijack
    - accidental_route_leak

    Uses the existing topology (rebuilt from AS classification) and prefix
    assignments (recovered from observation files).

    Args:
        dataset_path: Path to the existing dataset directory.
        attacks_per_type: Number of attack instances per new attack type.
        seed: Random seed for reproducibility.
    """
    if seed is not None:
        random.seed(seed)
        print(f"[SEED] Random seed set to {seed}")

    dataset_path = Path(dataset_path)
    print(f"\n{'='*60}")
    print(f"INCREMENTAL ATTACK INJECTION")
    print(f"Dataset: {dataset_path}")
    print(f"Attacks per type: {attacks_per_type}")
    print(f"{'='*60}")

    # Step 1: Load existing dataset
    print(f"\n[1] Loading existing dataset...")
    all_as_observations, as_classification, rpki_asns, non_rpki_asns = \
        load_existing_dataset(dataset_path)

    # Step 2: Recover prefix assignments
    print(f"\n[2] Recovering prefix assignments from observations...")
    prefix_assignments = recover_prefix_assignments(dataset_path)

    if not prefix_assignments:
        raise ValueError("No prefix assignments found. Cannot inject attacks.")

    candidate_asns = sorted(asn for asn in prefix_assignments if prefix_assignments[asn])
    print(f"[2] {len(candidate_asns)} candidate ASes with prefixes")

    # Step 3: Rebuild topology
    print(f"\n[3] Rebuilding CAIDA topology for simulation...")
    all_asns = set(all_as_observations.keys())

    # We need the full CAIDA graph to rebuild ASGraphInfo
    full_graph = CAIDAASGraphConstructor().run()
    subgraph_asns = frozenset(all_asns & set(full_graph.as_dict.keys()))

    # Reconstruct links
    cp_links: set[CPLink] = set()
    peer_links_set: set[PeerLink] = set()
    for asn in subgraph_asns:
        if asn not in full_graph.as_dict:
            continue
        as_obj = full_graph.as_dict[asn]
        for provider in as_obj.providers:
            if provider.asn in subgraph_asns:
                cp_links.add(CPLink(customer_asn=asn, provider_asn=provider.asn))
        for customer in as_obj.customers:
            if customer.asn in subgraph_asns:
                cp_links.add(CPLink(customer_asn=customer.asn, provider_asn=asn))
        for peer in as_obj.peers:
            if peer.asn in subgraph_asns:
                peer_links_set.add(PeerLink(as_obj.asn, peer.asn))

    input_clique_asns = frozenset(
        asn for asn in subgraph_asns if full_graph.as_dict[asn].input_clique
    )
    ixp_asns = frozenset(
        asn for asn in subgraph_asns if full_graph.as_dict[asn].ixp
    )
    linked_asns: set[int] = set()
    for link in cp_links:
        linked_asns.add(link.customer_asn)
        linked_asns.add(link.provider_asn)
    for link in peer_links_set:
        linked_asns.update(link.asns)
    unlinked = frozenset(subgraph_asns - linked_asns)

    as_graph_info = ASGraphInfo(
        customer_provider_links=frozenset(cp_links),
        peer_links=frozenset(peer_links_set),
        input_clique_asns=input_clique_asns,
        ixp_asns=ixp_asns,
        unlinked_asns=unlinked,
    )
    del full_graph

    fixed_rpki_asns = frozenset(rpki_asns)
    print(f"[3] Rebuilt topology: {len(subgraph_asns)} ASes, "
          f"{len(cp_links)} CP + {len(peer_links_set)} peer links")

    # Step 4: Initialize timeline
    timeline = RealisticTimeline(total_duration=1800, seed=seed, expected_events=50)

    # Step 5: Inject forged-origin prefix hijacks
    new_attack_types = [
        (ForgedOriginPrefixHijack, "forged_origin_prefix_hijack"),
    ]

    print(f"\n{'='*60}")
    print(f"INJECTING NEW ATTACK TYPES")
    print(f"{'='*60}")

    all_flap_metadata: list[list[dict]] = []

    for scenario_cls, attack_type in new_attack_types:
        for attack_round in range(attacks_per_type):
            print(f"\n--- {attack_type} round {attack_round+1}/{attacks_per_type} ---")

            victim_asn = random.choice(candidate_asns)
            attacker_candidates = [a for a in candidate_asns if a != victim_asn]
            if not attacker_candidates:
                attacker_candidates = candidate_asns
            attacker_asn = random.choice(attacker_candidates)
            victim_prefix = random.choice(prefix_assignments[victim_asn])

            anns, roas, _, flap_meta = _build_attack_announcements(
                attack_type=attack_type,
                victim_asn=victim_asn,
                attacker_asn=attacker_asn,
                victim_prefix=victim_prefix,
                prefix_assignments=prefix_assignments,
                timeline=timeline,
            )

            observations, _, _, sampled_rpki, sampled_non_rpki, metadata = run_scenario_and_extract(
                scenario_cls=scenario_cls,
                scenario_type=attack_type,
                num_nodes=len(all_asns),
                percent_adoption=0.0,
                as_graph_info=as_graph_info,
                fixed_rpki_asns=fixed_rpki_asns,
                override_announcements=tuple(anns),
                override_roas=tuple(roas),
                override_victim_asns=frozenset({victim_asn}),
                override_attacker_asns=frozenset({attacker_asn}),
            )

            # Accumulate new observations
            for asn, obs_list in observations.items():
                if asn not in all_as_observations:
                    all_as_observations[asn] = []
                all_as_observations[asn].extend(obs_list)

    # Step 6: Inject route leaks
    for leak_round in range(attacks_per_type):
        print(f"\n--- accidental_route_leak round {leak_round+1}/{attacks_per_type} ---")

        victim_asn = random.choice(candidate_asns)
        transit_candidates = [a for a in candidate_asns if a != victim_asn and a not in fixed_rpki_asns]
        if not transit_candidates:
            transit_candidates = [a for a in candidate_asns if a != victim_asn]
        attacker_asn = random.choice(transit_candidates)
        victim_prefix = random.choice(prefix_assignments[victim_asn])

        try:
            leak_obs, leak_meta = run_route_leak_scenario(
                victim_asn=victim_asn,
                attacker_asn=attacker_asn,
                victim_prefix=victim_prefix,
                as_graph_info=as_graph_info,
                fixed_rpki_asns=fixed_rpki_asns,
                timeline=timeline,
            )
            for asn, obs_list in leak_obs.items():
                if asn not in all_as_observations:
                    all_as_observations[asn] = []
                all_as_observations[asn].extend(obs_list)
        except Exception as e:
            print(f"    [WARN] Route leak scenario failed: {e}")

    # Step 7: Apply post-processing to new observations
    print(f"\n[POST] Applying convergence jitter to new observations...")
    apply_convergence_jitter(all_as_observations)

    # Step 8: Save updated dataset
    print(f"\n[SAVE] Saving updated dataset...")
    observations_path = dataset_path / "observations"
    ground_truth_path = dataset_path / "ground_truth"
    ground_truth_path.mkdir(exist_ok=True)

    total_anns = 0
    total_attacks = 0
    attack_counts: dict[str, int] = {}

    for asn, anns in all_as_observations.items():
        is_rpki = asn in rpki_asns

        # Drop observations with invalid timestamps (BGPy default=0 + jitter)
        anns = [a for a in anns if a.get("timestamp", 0) > 1_000_000_000]

        total_anns += len(anns)
        for ann in anns:
            if ann.get('is_attack', False):
                total_attacks += 1
            label = ann.get('label', 'UNKNOWN')
            attack_counts[label] = attack_counts.get(label, 0) + 1

        best_obs = [a for a in anns if a.get('is_best', True)]
        non_best_obs = [a for a in anns if not a.get('is_best', True)]
        as_data = {
            "asn": asn,
            "is_rpki_node": is_rpki,
            "total_observations": len(anns),
            "best_route_observations": len(best_obs),
            "alternative_route_observations": len(non_best_obs),
            "attack_observations": sum(1 for a in anns if a.get('is_attack', False)),
            "legitimate_observations": sum(1 for a in anns if not a.get('is_attack', False)),
            "observations": anns
        }

        as_file = observations_path / f"AS{asn}.json"
        with open(as_file, 'w') as f:
            json.dump(as_data, f, indent=2)

    # Update ground truth
    all_attacks = []
    for asn, anns in all_as_observations.items():
        for ann in anns:
            if ann.get('is_attack', False):
                all_attacks.append(ann)
    all_attacks.sort(key=lambda x: x.get('timestamp', 0))

    with open(ground_truth_path / "ground_truth.csv", 'w') as f:
        f.write("observer_asn,observer_is_rpki,timestamp,attack_type,attacker_asn,prefix,as_path_length\n")
        for att in all_attacks:
            f.write(f"{att.get('observed_by_asn','')},{att.get('observer_is_rpki','')},{att.get('timestamp','')},{att.get('label','')},{att.get('origin_asn','')},{att.get('prefix','')},{att.get('as_path_length','')}\n")

    ground_truth_data = {
        "description": "Ground truth labels for all attack announcements (updated with injected attacks)",
        "total_attacks": len(all_attacks),
        "attack_types": {k: v for k, v in attack_counts.items() if k != "LEGITIMATE"},
        "attacks": all_attacks,
    }
    with open(ground_truth_path / "ground_truth.json", 'w') as f:
        json.dump(ground_truth_data, f, indent=2)

    # Update classification with new attack types
    as_classification["injected_attacks"] = {
        "forged_origin_prefix_hijack": attacks_per_type,
        "accidental_route_leak": attacks_per_type,
    }
    with open(dataset_path / "as_classification.json", 'w') as f:
        json.dump(as_classification, f, indent=2)
    with open(ground_truth_path / "as_classification.json", 'w') as f:
        json.dump(as_classification, f, indent=2)

    # Print summary
    print(f"\n{'='*60}")
    print(f"Incremental Injection Complete")
    print(f"{'='*60}")
    print(f"Total observations: {total_anns}")
    print(f"Total attacks: {total_attacks}")
    print(f"Attack breakdown:")
    for label in sorted(attack_counts.keys()):
        if label != "LEGITIMATE":
            print(f"  - {label}: {attack_counts[label]}")
    print(f"Updated {len(all_as_observations)} AS observation files")
    print(f"Output: {dataset_path}")



def generate_dataset(
    num_nodes: int,
    output_dir: str = "dataset",
    percent_adoption: float = 0.37,
    num_legitimate_scenarios: int = 60,
    topology: Optional[str] = None,
    seed_asn: Optional[int] = None,
    attacks_per_type: int = 5,
    seed: Optional[int] = None,
    small: bool = False,
    rank_threshold: Optional[int] = None,
    compress: bool = False,
    timeline_duration: int = 600,
    bfs: bool = False,
    bfs_seed: int = 174,
    from_topology: Optional[str] = None,
    victims_per_scenario: Optional[int] = None,
    prefixes_per_victim: Optional[int] = None,
    target_rate: Optional[float] = None,
    attack_mode: Optional[str] = None,
):
    """
    Generate CAIDA-anchored dataset with individual AS observation files.

    Args:
        num_nodes: Number of nodes for CAIDA subgraph (ignored for Zoo topologies).
        output_dir: Output directory path.
        percent_adoption: RPKI adoption rate (only used for Zoo fallback).
        num_legitimate_scenarios: Number of legitimate warm-up scenarios.
        topology: 'caida' (default), 'ASN', 'Vlt', or 'Tiscali'.
        seed_asn: Optional seed ASN for CAIDA subgraph (ignored, kept for compat).
        attacks_per_type: Number of attack instances per attack type (default: 5).
        seed: Random seed for reproducibility.
        small: Use small topology mode (internally uses rank-threshold 50, ~25 ASes).
        rank_threshold: If set, use propagation rank threshold instead of max_size.
            Includes ALL ASes with propagation_rank >= rank_threshold. Deterministic.
        compress: Write .json.gz files (no indent, gzip level 6) instead of .json.
        timeline_duration: Duration of the timeline in seconds (default 1800 = 30 min).
        bfs: If True, use BFS expansion from bfs_seed instead of stratified sampling.
        bfs_seed: Seed ASN for BFS expansion (default: 174 = Cogent).
        attack_mode: If 'campaign', use campaign-based PREFIX_HIJACK/SUBPREFIX_HIJACK
            injection with ROA/no-ROA variants spread across the timeline.
    """
    # Set random seed if provided
    if seed is not None:
        random.seed(seed)
        print(f"[SEED] Random seed set to {seed}")

    # Track whether we're using CAIDA subgraph mode (for metadata)
    is_caida_subgraph = False
    is_small_mode = small
    full_graph_ref = None  # Keep full graph reference for prefix assignment
    topology_data = None  # For small mode topology graph

    # Small mode → internally use rank-threshold 50 (~25 ASes)
    if is_small_mode and rank_threshold is None:
        rank_threshold = 50
        print(f"[SMALL] Small mode: using --rank-threshold {rank_threshold} (~25 ASes)")

    # Initialize realistic timeline (Poisson inter-arrival times)
    expected_events = num_legitimate_scenarios + attacks_per_type * 5  # legit + attack scenarios
    timeline = RealisticTimeline(
        total_duration=timeline_duration,
        seed=seed,
        expected_events=expected_events,
    )
    print(f"[TIMELINE] Initialized {timeline_duration}s ({timeline_duration/3600:.0f}-hour) Poisson timeline "
          f"(avg_gap={timeline._avg_gap:.0f}s, expected_events={expected_events}, base={timeline.base_timestamp})")

    # Initialize pyasn for real prefix mapping
    asndb = None
    try:
        asndb = download_real_prefix_mapping()
    except Exception as e:
        print(f"[PYASN] Warning: Could not load real prefix data: {e}")
        print(f"[PYASN] Falling back to synthetic prefix allocation")

    # Track flapping metadata for post-processing
    all_flap_metadata: list[list[dict]] = []

    # Resolve topology
    as_graph_info = None
    fixed_rpki_asns = None
    prefix_assignments: dict[int, list[str]] = {}
    roa_db: dict[str, dict] = {}
    subgraph_asns: set[int] = set()

    if topology and topology in ZOO_TOPOLOGIES:
        # ── Zoo Topology Mode (legacy) ──
        gml_rel = ZOO_TOPOLOGIES[topology]
        gml_path = TOPOLOGY_DIR / gml_rel
        if not gml_path.exists():
            raise FileNotFoundError(f"GML file not found: {gml_path}")

        print("=" * 60)
        print(f"BGPSentry Dataset Generator (Topology Zoo: {topology})")
        print(f"GML file: {gml_path}")
        print(f"NOTE: Zoo topologies use synthetic ASNs and degree-based RPKI heuristic.")
        print(f"      For real ASNs and real RPKI data, use --topology caida")
        print("=" * 60)

        print(f"\nParsing GML and inferring hierarchy...")
        as_graph_info = gml_to_as_graph_info(gml_path)
        total_as_count = len(as_graph_info.asns)

        # Compute RPKI adopters ONCE — same set for every scenario
        fixed_rpki_asns = compute_rpki_adopters(gml_path, percent_adoption)
        print(f"\n    RPKI adoption (degree heuristic): {len(fixed_rpki_asns)}/{total_as_count} "
              f"({len(fixed_rpki_asns)/total_as_count*100:.1f}%) — fixed across all scenarios")

        # Folder name: {topology}_{node_count}
        folder_name = f"{topology}_{total_as_count}"

    elif from_topology is not None:
        # ── Pre-extracted Regional Topology Mode ──
        is_caida_subgraph = True

        print("=" * 60)
        print(f"BGPSentry Dataset Generator (Pre-extracted Topology)")
        print(f"Topology dir: {from_topology}")
        print(f"Attacks per type: {attacks_per_type}")
        print(f"Legitimate scenarios: {num_legitimate_scenarios}")
        print("=" * 60)

        as_graph_info, subgraph_asns, rpki_asns_from_topo = load_pre_extracted_topology(
            from_topology
        )
        total_as_count = len(subgraph_asns)

        # Use natural RPKI labels from the topology — no normalization
        fixed_rpki_asns = rpki_asns_from_topo

        # Build prefix assignments: VRP for RPKI, RouteViews for non-RPKI
        vrp_by_asn = load_vrp_prefixes()
        if vrp_by_asn:
            print(f"\n[PREFIX] Generating prefix assignments (VRP + RouteViews)...")
            prefix_assignments, roa_db = generate_prefix_assignments_from_vrp(
                subgraph_asns, fixed_rpki_asns, vrp_by_asn, asndb,
            )
        else:
            # Fallback: all from RouteViews
            print(f"\n[PREFIX] VRP not available, using RouteViews for all...")
            temp_graph = ASGraph(as_graph_info)
            if asndb is not None:
                prefix_assignments = generate_real_prefix_assignments(
                    temp_graph, subgraph_asns, asndb,
                )
            else:
                prefix_assignments = generate_prefix_assignments(temp_graph, subgraph_asns)
            del temp_graph
            roa_db = {}

        # Folder name: basename of topology directory (no duration suffix)
        # For campaign attack mode, use a distinct folder name
        if attack_mode == "campaign":
            base_topo_name = Path(from_topology).name
            # e.g., 904_afrinic_transit_mh -> 904_afrinic_attack
            parts = base_topo_name.split("_")
            folder_name = f"{parts[0]}_{parts[1]}_attack" if len(parts) >= 2 else f"{base_topo_name}_attack"
        else:
            folder_name = Path(from_topology).name

    elif topology is None or topology == "caida":
        # ── CAIDA Subgraph Mode (recommended, trace-driven) ──
        is_caida_subgraph = True

        if is_small_mode:
            # Override defaults for small mode
            if num_legitimate_scenarios == 60:
                num_legitimate_scenarios = 15
            if attacks_per_type == 5:
                attacks_per_type = 2

        if bfs:
            sampling_method = f"BFS from AS{bfs_seed}"
        elif rank_threshold is not None:
            sampling_method = f"rank-threshold >= {rank_threshold} (deterministic)"
        else:
            sampling_method = "stratified hierarchical sampling"

        print("=" * 60)
        print(f"BGPSentry Dataset Generator (CAIDA Subgraph, Trace-Driven)")
        if bfs:
            print(f"BFS expansion from AS{bfs_seed}, target {num_nodes} nodes")
        elif is_small_mode:
            print(f"SMALL MODE: rank-threshold >= {rank_threshold} (deterministic)")
        elif rank_threshold is not None:
            print(f"Extracting subgraph via {sampling_method}")
        else:
            print(f"Extracting {num_nodes}-node subgraph via {sampling_method}")
        print(f"RPKI data: {RPKI_CLIENT_VRPS_SNAPSHOT}")
        print(f"RPKI target ratio: {RPKI_TARGET_RATIO*100:.1f}% (label normalization applied)")
        print(f"Attacks per type: {attacks_per_type}")
        print(f"Legitimate scenarios: {num_legitimate_scenarios}")
        print("=" * 60)

        # Step 1: Extract connected subgraph
        if bfs:
            as_graph_info, subgraph_asns, full_graph_ref = extract_caida_subgraph_bfs(
                seed_asn=bfs_seed,
                target_size=num_nodes,
            )
        elif rank_threshold is not None:
            as_graph_info, subgraph_asns, full_graph_ref = extract_caida_subgraph_by_rank(
                rank_threshold=rank_threshold,
            )
        else:
            as_graph_info, subgraph_asns, full_graph_ref = extract_caida_subgraph(
                max_size=num_nodes,
                seed_asn=seed_asn,
            )
        total_as_count = len(subgraph_asns)

        # Step 2: Get natural RPKI signing set from rpki-client 2022-06 VRPs,
        # then normalize to the global 36.3% rate via uniform random demotion.
        # See get_rpki_signing_asns_from_rpki_client and normalize_rpki_labels
        # for the full rationale.
        natural_rpki_asns = get_rpki_signing_asns_from_rpki_client(subgraph_asns)
        rpki_natural_count = len(natural_rpki_asns)

        fixed_rpki_asns, rpki_demoted_count = normalize_rpki_labels(
            subgraph_asns=subgraph_asns,
            natural_rpki_asns=natural_rpki_asns,
            target_ratio=RPKI_TARGET_RATIO,
            seed=seed,
        )

        # Ensure at least 1 RPKI and 1 non-RPKI AS for small mode
        if is_small_mode and len(fixed_rpki_asns) == 0:
            # Force-add a clique AS as RPKI (Tier-1s are typically RPKI)
            fallback_rpki = next(iter(as_graph_info.input_clique_asns), None)
            if fallback_rpki:
                fixed_rpki_asns = frozenset({fallback_rpki})
                print(f"[RPKI] Forced AS{fallback_rpki} as RPKI (small mode needs >= 1)")
        if is_small_mode and len(fixed_rpki_asns) >= len(subgraph_asns):
            # Ensure at least 1 non-RPKI
            to_remove = next(
                (asn for asn in subgraph_asns if asn not in as_graph_info.input_clique_asns),
                None,
            )
            if to_remove:
                fixed_rpki_asns = frozenset(fixed_rpki_asns - {to_remove})
                print(f"[RPKI] Forced AS{to_remove} as non-RPKI (small mode needs >= 1)")

        # Step 3: Build ASGraph for prefix assignment (real prefixes via pyasn)
        temp_graph = ASGraph(as_graph_info)
        small_type_caps = {"clique": 10, "transit": 8, "multihomed": 3, "stub": 2}
        if asndb is not None:
            print(f"\n[PREFIX] Generating real prefix assignments (pyasn)...")
            prefix_assignments = generate_real_prefix_assignments(
                temp_graph, subgraph_asns, asndb,
                type_caps=small_type_caps if is_small_mode else None,
            )
        else:
            print(f"\n[PREFIX] Generating synthetic prefix assignments (fallback)...")
            prefix_assignments = generate_prefix_assignments(temp_graph, subgraph_asns)
        del temp_graph

        # Folder name: caida_bfs_{seed}_{count}, caida_rank{threshold}_{count}, or caida_{count}
        # Append timeline duration suffix only if NOT the default 10 min (600s)
        duration_suffix = f"_{timeline_duration}s" if timeline_duration != 600 else ""
        if bfs:
            folder_name = f"caida_bfs_{bfs_seed}_{total_as_count}{duration_suffix}"
        elif rank_threshold is not None:
            folder_name = f"caida_rank{rank_threshold}_{total_as_count}{duration_suffix}"
        else:
            folder_name = f"caida_{total_as_count}{duration_suffix}"

    else:
        raise ValueError(
            f"Unknown topology '{topology}'. "
            f"Choose from: caida, {', '.join(ZOO_TOPOLOGIES)}"
        )

    # Create folder structure
    base_path = Path(output_dir) / folder_name
    observations_path = base_path / "observations"
    ground_truth_path = base_path / "ground_truth"

    # Clean and create directories
    # For --from-topology mode, only clean observations/ and ground_truth/
    # to preserve topology files (as_classification.json, as_relationships.json)
    if from_topology and base_path.exists():
        if observations_path.exists():
            shutil.rmtree(observations_path)
        if ground_truth_path.exists():
            shutil.rmtree(ground_truth_path)
    elif base_path.exists():
        shutil.rmtree(base_path)

    base_path.mkdir(parents=True, exist_ok=True)
    observations_path.mkdir(exist_ok=True)
    ground_truth_path.mkdir(exist_ok=True)

    print(f"\nDataset folder: {base_path}")

    # Generate topology graph for small mode
    if is_small_mode and is_caida_subgraph and fixed_rpki_asns is not None:
        topology_data = generate_topology_graph(
            as_graph_info=as_graph_info,
            subgraph_asns=subgraph_asns,
            rpki_asns=fixed_rpki_asns,
            full_graph=full_graph_ref,
            output_dir=base_path,
        )

    # Free full graph now (after topology graph is generated)
    if full_graph_ref is not None:
        del full_graph_ref
        full_graph_ref = None

    # Collect all observations per AS
    all_as_observations: dict[int, list] = {}
    scenario_metadata = {}

    # Pre-compute classification
    if fixed_rpki_asns is not None:
        all_rpki_asns = set(fixed_rpki_asns)
        all_non_rpki_asns = set(as_graph_info.asns) - all_rpki_asns
    else:
        all_rpki_asns = set()
        all_non_rpki_asns = set()

    # Helper to accumulate observations
    def _accumulate(observations: dict, sampled_rpki=None, sampled_non_rpki=None):
        for asn, anns in observations.items():
            if asn not in all_as_observations:
                all_as_observations[asn] = []
            all_as_observations[asn].extend(anns)
        if fixed_rpki_asns is None and sampled_rpki is not None:
            all_rpki_asns.update(sampled_rpki)
            all_non_rpki_asns.update(sampled_non_rpki)

    # Identify candidate victim/attacker ASNs for CAIDA mode
    if is_caida_subgraph and prefix_assignments:
        # Candidates: ASes with prefixes assigned
        candidate_asns = sorted(asn for asn in prefix_assignments if prefix_assignments[asn])
    else:
        candidate_asns = []

    # ── PHASE 1: LEGITIMATE ANNOUNCEMENTS ─────────────────────
    # Every AS announces its prefix 2-4 times over the simulation window.
    # Batched into rounds of ~100 ASes each for BGPy propagation.
    if is_caida_subgraph and prefix_assignments:
        # Compute announces per AS based on target rate or default 2-4.
        # Formula: target_rate = (num_nodes × announces_per_node × reach) / duration
        #   → announces_per_node = (target_rate × duration) / (num_nodes × reach)
        reach = 0.92  # ~92% propagation reach from empirical testing
        if target_rate is not None:
            computed_ann = (target_rate * timeline_duration) / (len(candidate_asns) * reach)
            # Clamp to at least 2, at most 20; use ceil to stay at or above target
            import math
            announces_per_node = max(2, min(20, math.ceil(computed_ann)))
            # Per-AS randomization: ±1 around target for realistic variance
            lo = max(1, announces_per_node - 1)
            hi = announces_per_node + 1
            print(f"[RATE] Target rate: {target_rate} ev/sec/node")
            print(f"[RATE] Computed announces/node: {computed_ann:.2f} → using {lo}-{hi} (avg ~{announces_per_node})")
            n_rounds_per_as = {asn: random.randint(lo, hi) for asn in candidate_asns}
        else:
            n_rounds_per_as = {asn: random.randint(2, 4) for asn in candidate_asns}
        max_rounds = max(n_rounds_per_as.values())
        total_events = sum(n_rounds_per_as.values())

        # Build rounds: round i contains all ASes that announce at least i+1 times
        rounds: list[list[int]] = []
        for r in range(max_rounds):
            round_asns = [asn for asn in candidate_asns if n_rounds_per_as[asn] > r]
            random.shuffle(round_asns)
            rounds.append(round_asns)

        # Recalibrate timeline to spread timestamps across full duration
        timeline.recalibrate(total_events + attacks_per_type * 5)

        # Split each round into batches of ~100 for BGPy
        batch_size = min(100, len(candidate_asns))
        all_batches: list[list[int]] = []
        for round_asns in rounds:
            for b_start in range(0, len(round_asns), batch_size):
                all_batches.append(round_asns[b_start:b_start + batch_size])

        print(f"\n{'='*60}")
        print(f"PHASE 1: LEGITIMATE ANNOUNCEMENTS")
        print(f"  {len(candidate_asns)} ASes × 2-4 announcements = {total_events} total events")
        print(f"  {max_rounds} announcement rounds, {len(all_batches)} BGPy batches")
        print(f"{'='*60}")

        for batch_idx, batch_asns in enumerate(all_batches):
            print(f"\n--- Legitimate batch {batch_idx+1}/{len(all_batches)} ({len(batch_asns)} announcements) ---")

            legit_anns = []
            legit_roas = []
            for vasn in batch_asns:
                pfx = prefix_assignments[vasn][0]
                legit_anns.append(Announcement(
                    prefix=pfx,
                    as_path=(vasn,),
                    next_hop_asn=vasn,
                    seed_asn=vasn,
                    timestamp=timeline.get_legitimate_timestamp(),
                    recv_relationship=Relationships.ORIGIN,
                ))
                legit_roas.append(ROA(ip_network(pfx, strict=False), vasn))

            observations, rpki_asns, non_rpki_asns, sampled_rpki, sampled_non_rpki, metadata = run_scenario_and_extract(
                scenario_cls=VictimsPrefix,
                scenario_type="legitimate",
                num_nodes=num_nodes,
                percent_adoption=percent_adoption,
                as_graph_info=as_graph_info,
                fixed_rpki_asns=fixed_rpki_asns,
                override_announcements=tuple(legit_anns),
                override_roas=tuple(legit_roas),
                override_victim_asns=frozenset(batch_asns),
                override_attacker_asns=frozenset(),
            )
            _accumulate(observations, sampled_rpki, sampled_non_rpki)
    else:
        # Fallback: old random-pick mode
        print(f"\n{'='*60}")
        print(f"PHASE 1: LEGITIMATE WARM-UP ({num_legitimate_scenarios} scenarios)")
        print(f"{'='*60}")

        for i in range(num_legitimate_scenarios):
            print(f"\n--- Legitimate scenario {i+1}/{num_legitimate_scenarios} ---")
            observations, rpki_asns, non_rpki_asns, sampled_rpki, sampled_non_rpki, metadata = run_scenario_and_extract(
                scenario_cls=VictimsPrefix,
                scenario_type="legitimate",
                num_nodes=num_nodes,
                percent_adoption=percent_adoption,
                as_graph_info=as_graph_info,
                fixed_rpki_asns=fixed_rpki_asns,
            )
            _accumulate(observations, sampled_rpki, sampled_non_rpki)

    # ── PHASE 2: ATTACK INJECTION ─────────────────────────────

    if attack_mode == "campaign" and is_caida_subgraph and prefix_assignments:
        # ── Campaign-based attack injection ──
        # PREFIX_HIJACK and SUBPREFIX_HIJACK with/without ROA,
        # spread across 8 natural campaigns throughout the timeline.
        print(f"\n{'='*60}")
        print(f"PHASE 2: CAMPAIGN-BASED ATTACK INJECTION")
        print(f"{'='*60}")

        # Identify prefixes that have ROA vs those that don't
        roa_prefixes = set(roa_db.keys()) if roa_db else set()
        all_prefixes_by_asn = {}
        for asn, prefixes in prefix_assignments.items():
            has_roa = [p for p in prefixes if p in roa_prefixes]
            no_roa = [p for p in prefixes if p not in roa_prefixes]
            if has_roa or no_roa:
                all_prefixes_by_asn[asn] = {"roa": has_roa, "no_roa": no_roa}

        # Build candidate victim ASes (must have both ROA and non-ROA prefixes ideally)
        roa_victim_candidates = [a for a in candidate_asns if all_prefixes_by_asn.get(a, {}).get("roa")]
        no_roa_victim_candidates = [a for a in candidate_asns if all_prefixes_by_asn.get(a, {}).get("no_roa")]
        non_rpki_attackers = [a for a in candidate_asns if a not in fixed_rpki_asns]

        if not no_roa_victim_candidates:
            # If all prefixes have ROA, create no-ROA variants by picking prefixes
            # whose ROA entries we'll exclude from the final roa_db
            print("    [INFO] All victim prefixes have ROA — will selectively remove ROA for no-ROA attacks")
            no_roa_victim_candidates = roa_victim_candidates[:]
            force_remove_roa = True
        else:
            force_remove_roa = False

        # Define 8 campaigns with natural timing and randomness
        # Campaign structure: (approx_hour, num_prefixes, attack_mix)
        # attack_mix: list of (attack_type_str, scenario_cls, has_roa)
        campaign_templates = [
            (1.2,  4),   # C1: early, small
            (2.8,  3),   # C2: early
            (4.1,  5),   # C3: mid
            (5.5,  6),   # C4: mid, larger (repeat attacker possible)
            (6.9,  4),   # C5: mid-late
            (8.3,  7),   # C6: late, largest
            (9.7,  5),   # C7: late
            (11.1, 6),   # C8: near end
        ]

        # Track prefixes whose ROA entries should be removed for no-ROA attacks
        roa_entries_to_remove = []
        campaign_attack_count = 0

        for c_idx, (approx_hour, num_attacks_in_campaign) in enumerate(campaign_templates):
            # Add timing jitter: +/- 20 minutes
            jitter_sec = random.uniform(-1200, 1200)
            campaign_base_ts = timeline.base_timestamp + int(approx_hour * 3600 + jitter_sec)
            # Clamp within timeline
            campaign_base_ts = max(timeline.base_timestamp + 600,
                                   min(campaign_base_ts, timeline.base_timestamp + timeline.total_duration - 600))

            # Pick attacker for this campaign (occasionally reuse from earlier)
            if c_idx in (3,) and campaign_attack_count > 0:
                # C4 reuses C1's attacker (natural repeat offender)
                attacker_asn = campaign_attackers[0]
            elif c_idx in (6,) and len(campaign_attackers) > 1:
                # C7 reuses C2's attacker
                attacker_asn = campaign_attackers[1]
            else:
                if non_rpki_attackers:
                    attacker_asn = random.choice(non_rpki_attackers)
                else:
                    attacker_asn = random.choice([a for a in candidate_asns if a not in fixed_rpki_asns][:1] or candidate_asns)

            if c_idx == 0:
                campaign_attackers = [attacker_asn]
            elif c_idx <= 1:
                campaign_attackers.append(attacker_asn)

            print(f"\n--- Campaign {c_idx+1}/8 | ~{approx_hour:.1f}h | "
                  f"attacker=AS{attacker_asn} | {num_attacks_in_campaign} attacks ---")

            # Generate individual attacks within campaign
            for atk_idx in range(num_attacks_in_campaign):
                # Randomize attack type and ROA presence
                attack_type_str = random.choice(["prefix_hijack", "subprefix_hijack"])
                has_roa_for_attack = random.random() < 0.48  # ~48% ROA, ~52% no-ROA

                scenario_cls = PrefixHijack if attack_type_str == "prefix_hijack" else SubprefixHijack

                # Pick victim based on ROA availability
                if has_roa_for_attack:
                    if roa_victim_candidates:
                        victim_asn = random.choice(roa_victim_candidates)
                        victim_prefix = random.choice(all_prefixes_by_asn[victim_asn]["roa"])
                    else:
                        victim_asn = random.choice(candidate_asns)
                        victim_prefix = random.choice(prefix_assignments[victim_asn])
                else:
                    if no_roa_victim_candidates and not force_remove_roa:
                        victim_asn = random.choice(no_roa_victim_candidates)
                        victim_prefix = random.choice(all_prefixes_by_asn[victim_asn]["no_roa"])
                    else:
                        # Force no-ROA: pick a ROA prefix and mark for ROA removal
                        victim_asn = random.choice(roa_victim_candidates)
                        victim_prefix = random.choice(all_prefixes_by_asn[victim_asn]["roa"])
                        roa_entries_to_remove.append(victim_prefix)
                        has_roa_for_attack = False

                # Ensure attacker != victim
                if attacker_asn == victim_asn:
                    alt_attackers = [a for a in non_rpki_attackers if a != victim_asn]
                    if alt_attackers:
                        attacker_asn = random.choice(alt_attackers)

                # Timing within campaign: spread over 5-20 minutes with random gaps
                intra_gap = random.uniform(30, 300)  # 30s to 5min between attacks
                attack_ts = campaign_base_ts + int(atk_idx * intra_gap + random.uniform(-15, 15))

                # Build attack announcements with controlled timestamp
                anns, roas, _, _ = _build_attack_announcements(
                    attack_type=attack_type_str,
                    victim_asn=victim_asn,
                    attacker_asn=attacker_asn,
                    victim_prefix=victim_prefix,
                    prefix_assignments=prefix_assignments,
                    timeline=timeline,
                    override_timestamp=attack_ts,
                )

                # For no-ROA attacks, don't include victim ROA
                if not has_roa_for_attack:
                    roas = tuple()  # No ROA for this attack

                # Deduplicate
                seen_keys: set[tuple[str, int]] = set()
                deduped_anns: list[Announcement] = []
                for ann in anns:
                    key = (ann.prefix, ann.seed_asn)
                    if key not in seen_keys:
                        seen_keys.add(key)
                        deduped_anns.append(ann)

                roa_tag = "ROA" if has_roa_for_attack else "NO-ROA"
                label_str = "PREFIX_HIJACK" if attack_type_str == "prefix_hijack" else "SUBPREFIX_HIJACK"
                print(f"    [{atk_idx+1}/{num_attacks_in_campaign}] {label_str} ({roa_tag}) "
                      f"victim=AS{victim_asn} prefix={victim_prefix}")

                try:
                    observations, rpki_asns, non_rpki_asns, sampled_rpki, sampled_non_rpki, metadata = run_scenario_and_extract(
                        scenario_cls=scenario_cls,
                        scenario_type=attack_type_str,
                        num_nodes=num_nodes,
                        percent_adoption=percent_adoption,
                        as_graph_info=as_graph_info,
                        fixed_rpki_asns=fixed_rpki_asns,
                        override_announcements=tuple(deduped_anns),
                        override_roas=tuple(roas),
                        override_victim_asns=frozenset({victim_asn}),
                        override_attacker_asns=frozenset({attacker_asn}),
                    )

                    # Annotate attack observations with campaign metadata
                    for asn_obs_list in observations.values():
                        for obs in asn_obs_list:
                            if obs.get("is_attack", False):
                                obs["campaign"] = c_idx + 1
                                obs["has_roa"] = has_roa_for_attack
                                obs["roa_tag"] = roa_tag

                    _accumulate(observations, sampled_rpki, sampled_non_rpki)

                    # Store metadata with campaign and ROA info
                    meta_key = f"campaign{c_idx+1}_{attack_type_str}_{atk_idx}"
                    metadata["campaign"] = c_idx + 1
                    metadata["has_roa"] = has_roa_for_attack
                    metadata["roa_tag"] = roa_tag
                    scenario_metadata[meta_key] = metadata
                    campaign_attack_count += 1
                except Exception as e:
                    print(f"    [WARN] Attack scenario failed: {e}")
                    import traceback; traceback.print_exc()

        # Remove ROA entries for no-ROA attack victims
        if roa_entries_to_remove and roa_db:
            for prefix in set(roa_entries_to_remove):
                if prefix in roa_db:
                    del roa_db[prefix]
                    print(f"    [ROA] Removed ROA for {prefix} (no-ROA attack victim)")

        print(f"\n    Campaign summary: {campaign_attack_count} total attacks injected across 8 campaigns")

    elif attacks_per_type > 0:
        # ── Original attack injection (non-campaign mode) ──
        # Standard attack types (handled via _build_attack_announcements)
        attack_types = [
            (PrefixHijack, "prefix_hijack"),
            (BogonInjection, "bogon_injection"),
            (RouteFlapping, "route_flapping"),
        ]
        # Scenario-based attacks (require BGPy engine, not _build_attack_announcements)
        has_route_leak = False  # disabled — using ValleyFreeRouteLeak instead
        has_valley_free_leak = is_caida_subgraph and prefix_assignments
        has_path_poisoning = is_caida_subgraph and prefix_assignments

        n_scenario_attacks = len(attack_types) + (1 if has_valley_free_leak else 0) + (1 if has_path_poisoning else 0)
        total_attack_rounds = n_scenario_attacks * attacks_per_type
        print(f"\n{'='*60}")
        n_types = n_scenario_attacks
        print(f"PHASE 2: ATTACK INJECTION ({n_types} types x {attacks_per_type} each = {total_attack_rounds} scenarios)")
        print(f"{'='*60}")

        for scenario_cls, attack_type in attack_types:
            for attack_round in range(attacks_per_type):
                print(f"\n--- {attack_type} round {attack_round+1}/{attacks_per_type} ---")

                if is_caida_subgraph and prefix_assignments:
                    # Pick a random victim and attacker (different ASes)
                    # Attacker must be non-RPKI (RPKI ASes have ROA = traceable identity)
                    victim_asn = random.choice(candidate_asns)
                    non_rpki_candidates = [a for a in candidate_asns if a != victim_asn and a not in fixed_rpki_asns]
                    if not non_rpki_candidates:
                        # Fallback: allow any non-victim if no non-RPKI available
                        non_rpki_candidates = [a for a in candidate_asns if a != victim_asn]
                    attacker_asn = random.choice(non_rpki_candidates)

                    # For small topologies, pick 2-3 victim prefixes per round
                    if is_small_mode:
                        num_victim_prefixes = min(
                            random.randint(2, 3),
                            len(prefix_assignments[victim_asn]),
                        )
                        victim_prefixes = random.sample(
                            prefix_assignments[victim_asn], num_victim_prefixes
                        )
                    else:
                        victim_prefixes = [random.choice(prefix_assignments[victim_asn])]

                    # Build attack announcements for each victim prefix
                    all_anns: list[Announcement] = []
                    all_roas: list[ROA] = []
                    round_flap_metadata: list[dict] = []
                    for victim_prefix in victim_prefixes:
                        anns, roas, _, flap_meta = _build_attack_announcements(
                            attack_type=attack_type,
                            victim_asn=victim_asn,
                            attacker_asn=attacker_asn,
                            victim_prefix=victim_prefix,
                            prefix_assignments=prefix_assignments,
                            timeline=timeline,
                        )
                        all_anns.extend(anns)
                        all_roas.extend(roas)
                        round_flap_metadata.extend(flap_meta)
                    if round_flap_metadata:
                        all_flap_metadata.append(round_flap_metadata)

                    # Deduplicate announcements by (prefix, seed_asn) to avoid seeding conflicts
                    seen_keys: set[tuple[str, int]] = set()
                    deduped_anns: list[Announcement] = []
                    for ann in all_anns:
                        key = (ann.prefix, ann.seed_asn)
                        if key not in seen_keys:
                            seen_keys.add(key)
                            deduped_anns.append(ann)

                    observations, rpki_asns, non_rpki_asns, sampled_rpki, sampled_non_rpki, metadata = run_scenario_and_extract(
                        scenario_cls=scenario_cls,
                        scenario_type=attack_type,
                        num_nodes=num_nodes,
                        percent_adoption=percent_adoption,
                        as_graph_info=as_graph_info,
                        fixed_rpki_asns=fixed_rpki_asns,
                        override_announcements=tuple(deduped_anns),
                        override_roas=tuple(all_roas),
                        override_victim_asns=frozenset({victim_asn}),
                        override_attacker_asns=frozenset({attacker_asn}),
                    )
                else:
                    # Legacy: let bgpy pick victim/attacker randomly
                    observations, rpki_asns, non_rpki_asns, sampled_rpki, sampled_non_rpki, metadata = run_scenario_and_extract(
                        scenario_cls=scenario_cls,
                        scenario_type=attack_type,
                        num_nodes=num_nodes,
                        percent_adoption=percent_adoption,
                        as_graph_info=as_graph_info,
                        fixed_rpki_asns=fixed_rpki_asns,
                    )

                _accumulate(observations, sampled_rpki, sampled_non_rpki)
                scenario_metadata[f"{attack_type}_{attack_round}"] = metadata

        # ── Route Leak Attacks (separate handling, 2-round propagation) ──
        if has_route_leak:
            for leak_round in range(attacks_per_type):
                print(f"\n--- accidental_route_leak round {leak_round+1}/{attacks_per_type} ---")

                # Pick victim and attacker (leaker must be non-RPKI transit)
                victim_asn = random.choice(candidate_asns)
                transit_candidates = [
                    a for a in candidate_asns
                    if a != victim_asn and a not in fixed_rpki_asns
                ]
                if not transit_candidates:
                    transit_candidates = [a for a in candidate_asns if a != victim_asn]
                attacker_asn = random.choice(transit_candidates)

                victim_prefix = random.choice(prefix_assignments[victim_asn])

                try:
                    leak_obs, leak_meta = run_route_leak_scenario(
                        victim_asn=victim_asn,
                        attacker_asn=attacker_asn,
                        victim_prefix=victim_prefix,
                        as_graph_info=as_graph_info,
                        fixed_rpki_asns=fixed_rpki_asns,
                        timeline=timeline,
                    )
                    _accumulate(leak_obs)
                    scenario_metadata[f"accidental_route_leak_{leak_round}"] = leak_meta
                except Exception as e:
                    print(f"    [WARN] Route leak scenario failed: {e}")
                    print(f"    Skipping this round (attacker may not be able to leak)")

        # ── Valley-Free Route Leak (2-round propagation, like AccidentalRouteLeak) ──
        if has_valley_free_leak:
            for leak_round in range(attacks_per_type):
                print(f"\n--- valley_free_route_leak round {leak_round+1}/{attacks_per_type} ---")

                victim_asn = random.choice(candidate_asns)
                transit_candidates = [
                    a for a in candidate_asns
                    if a != victim_asn and a not in fixed_rpki_asns
                ]
                if not transit_candidates:
                    transit_candidates = [a for a in candidate_asns if a != victim_asn]
                attacker_asn = random.choice(transit_candidates)

                victim_prefix = random.choice(prefix_assignments[victim_asn])

                try:
                    leak_obs, leak_meta = run_route_leak_scenario(
                        victim_asn=victim_asn,
                        attacker_asn=attacker_asn,
                        victim_prefix=victim_prefix,
                        as_graph_info=as_graph_info,
                        fixed_rpki_asns=fixed_rpki_asns,
                        timeline=timeline,
                        scenario_cls=ValleyFreeRouteLeak,
                        scenario_type="valley_free_route_leak",
                    )
                    _accumulate(leak_obs)
                    scenario_metadata[f"valley_free_route_leak_{leak_round}"] = leak_meta
                except Exception as e:
                    print(f"    [WARN] Valley-free route leak scenario failed: {e}")
                    print(f"    Skipping this round (attacker may not be able to leak)")

        # ── Path Poisoning (1-round, BGPy scenario with crafted AS-path) ──
        if has_path_poisoning:
            for pp_round in range(attacks_per_type):
                print(f"\n--- path_poisoning round {pp_round+1}/{attacks_per_type} ---")

                victim_asn = random.choice(candidate_asns)
                attacker_candidates = [a for a in candidate_asns if a != victim_asn and a not in fixed_rpki_asns]
                if not attacker_candidates:
                    attacker_candidates = [a for a in candidate_asns if a != victim_asn]
                attacker_asn = random.choice(attacker_candidates)

                victim_prefix = random.choice(prefix_assignments[victim_asn])

                try:
                    pp_ts = timeline.get_attack_timestamp()
                    victim_ann = Announcement(
                        prefix=victim_prefix,
                        as_path=(victim_asn,),
                        next_hop_asn=victim_asn,
                        seed_asn=victim_asn,
                        timestamp=pp_ts,
                        recv_relationship=Relationships.ORIGIN,
                    )
                    victim_roa = ROA(ip_network(victim_prefix, strict=False), victim_asn)

                    # Don't use override_announcements — PathPoisoning needs
                    # _get_announcements() to run so it can craft the poisoned path.
                    # Use Prefixes.PREFIX.value (BGPy default) for both victim and attacker.
                    config = ScenarioConfig(
                        ScenarioCls=PathPoisoning,
                        AdoptPolicyCls=BGP,
                        BasePolicyCls=BGP,
                        override_victim_asns=frozenset({victim_asn}),
                        override_attacker_asns=frozenset({attacker_asn}),
                        num_victims=1,
                        num_attackers=1,
                    )

                    as_graph = ASGraph(as_graph_info)
                    engine = SimulationEngine(as_graph)

                    scenario = config.ScenarioCls(
                        scenario_config=config,
                        percent_adoption=0.0,
                        engine=engine,
                    )

                    all_asns_set = set(engine.as_graph.as_dict.keys())
                    rpki_set = fixed_rpki_asns & all_asns_set

                    engine.setup(scenario)
                    adj_rib_in = install_ann_interceptors(engine)
                    engine.run(propagation_round=0, scenario=scenario)

                    observations, _, _ = extract_all_node_observations(
                        engine=engine,
                        rpki_asns=rpki_set,
                        attacker_asns=frozenset({attacker_asn}),
                        victim_asns=frozenset({victim_asn}),
                        scenario_type="path_poisoning",
                        sample_size=None,
                        adj_rib_in=adj_rib_in,
                    )
                    _accumulate(observations)

                    pp_meta = {
                        "scenario_type": "path_poisoning",
                        "victim_asn": victim_asn,
                        "attacker_asn": attacker_asn,
                        "victim_prefix": victim_prefix,
                    }
                    scenario_metadata[f"path_poisoning_{pp_round}"] = pp_meta

                    total_pp_obs = sum(len(v) for v in observations.values())
                    attack_pp_obs = sum(1 for v in observations.values() for o in v if o.get("is_attack"))
                    print(f"    Observations from {len(observations)} nodes: {total_pp_obs} total, {attack_pp_obs} attack")

                except Exception as e:
                    print(f"    [WARN] Path poisoning scenario failed: {e}")
                    import traceback; traceback.print_exc()

    # ── PHASE 3: POST-PROCESSING ──────────────────────────────
    print(f"\n{'='*60}")
    print(f"PHASE 3: POST-PROCESSING")
    print(f"{'='*60}")

    # Apply convergence jitter
    print(f"\n[JITTER] Applying per-hop convergence jitter (MRAI 1-30s per hop)...")
    apply_convergence_jitter(all_as_observations)

    # Generate WITHDRAW messages (~10-12% of observations)
    print(f"\n[WITHDRAW] Generating realistic withdrawal observations...")
    withdrawal_count = generate_withdrawal_observations(all_as_observations, timeline)
    total_obs_before_withdraw = sum(len(v) for v in all_as_observations.values())
    withdraw_pct = (withdrawal_count / total_obs_before_withdraw * 100) if total_obs_before_withdraw > 0 else 0
    print(f"[WITHDRAW] Added {withdrawal_count} withdrawal observations ({withdraw_pct:.1f}%)")

    # Inject route flapping oscillations
    if all_flap_metadata:
        print(f"\n[FLAPPING] Injecting route flapping oscillation cycles...")
        flap_count = inject_flapping_oscillations(all_as_observations, all_flap_metadata)
        print(f"[FLAPPING] Added {flap_count} flapping oscillation observations "
              f"from {len(all_flap_metadata)} attack rounds")
    else:
        flap_count = 0

    # Sort observations by timestamp per node (jitter may have disordered them)
    # then deduplicate: same (prefix, origin, path, timestamp) kept once (prefer is_best=True)
    print(f"\n[SORT+DEDUP] Sorting and deduplicating observations per node...")
    total_deduped = 0
    for asn in all_as_observations:
        obs = sorted(
            all_as_observations[asn],
            key=lambda o: (o.get("timestamp", 0), -int(o.get("is_best", False))),
        )
        seen = set()
        deduped = []
        for o in obs:
            key = (o.get("prefix"), o.get("origin_asn"), o.get("timestamp"), tuple(o.get("as_path", [])))
            if key not in seen:
                seen.add(key)
                deduped.append(o)
            else:
                total_deduped += 1
        all_as_observations[asn] = deduped
    if total_deduped:
        print(f"[SORT+DEDUP] Removed {total_deduped} exact duplicates (same prefix/origin/path/timestamp)")

    # Compute visibility stats
    visibility_stats = compute_visibility_stats(all_as_observations)

    # Save individual AS files
    print(f"\n[6] Saving individual AS observation files...")
    total_anns = 0
    total_attacks = 0
    attack_counts = {"PREFIX_HIJACK": 0, "SUBPREFIX_HIJACK": 0, "BOGON_INJECTION": 0, "ROUTE_FLAPPING": 0, "ROUTE_LEAK": 0, "PATH_POISONING": 0, "LEGITIMATE": 0}

    for asn, anns in all_as_observations.items():
        is_rpki = asn in all_rpki_asns

        # Drop observations with invalid timestamps (BGPy default=0 + jitter)
        anns = [a for a in anns if a.get("timestamp", 0) > 1_000_000_000]

        # Count statistics
        total_anns += len(anns)
        for ann in anns:
            if ann['is_attack']:
                total_attacks += 1
            attack_counts[ann['label']] = attack_counts.get(ann['label'], 0) + 1

        # Create AS file
        best_obs = [a for a in anns if a.get('is_best', True)]
        non_best_obs = [a for a in anns if not a.get('is_best', True)]
        as_data = {
            "asn": asn,
            "is_rpki_node": is_rpki,
            "total_observations": len(anns),
            "best_route_observations": len(best_obs),
            "alternative_route_observations": len(non_best_obs),
            "attack_observations": sum(1 for a in anns if a['is_attack']),
            "legitimate_observations": sum(1 for a in anns if not a['is_attack']),
            "observations": anns
        }

        ext = ".json.gz" if compress else ".json"
        as_file = observations_path / f"AS{asn}{ext}"
        _write_json(as_file, as_data, compress=compress)

    print(f"    Saved {len(all_as_observations)} individual AS files"
          + (" (gzip compressed)" if compress else ""))

    # Save AS classification
    print(f"\n[7] Saving AS classification...")
    as_classification = {
        "description": "Classification of ASes as RPKI or non-RPKI",
        "total_ases": len(all_as_observations),
        "rpki_count": len(all_rpki_asns),
        "non_rpki_count": len(all_non_rpki_asns),
        "rpki_asns": sorted(list(all_rpki_asns)),
        "non_rpki_asns": sorted(list(all_non_rpki_asns)),
        "classification": {
            str(asn): "RPKI" if asn in all_rpki_asns else "NON_RPKI"
            for asn in sorted(all_as_observations.keys())
        }
    }

    # Add CAIDA-specific metadata for real RPKI data
    if is_caida_subgraph:
        as_classification["rpki_source"] = RPKI_CLIENT_VRPS_SNAPSHOT
        as_classification["rpki_source_url"] = (
            "https://web.archive.org/web/20220618163743/"
            "https://console.rpki-client.org/vrps.json"
        )
        as_classification["rpki_metric"] = (
            "ROA signing (has >=1 registered ROA) — NOT ROV enforcement. "
            "This is the property required for RPKI-anchored cryptographic "
            "identity used by BGP-Sentry validators."
        )
        if 'rpki_demoted_count' in locals() and 'rpki_natural_count' in locals():
            as_classification["rpki_natural_count"] = int(rpki_natural_count)
            as_classification["rpki_demoted_count"] = int(rpki_demoted_count)
            as_classification["rpki_target_ratio"] = RPKI_TARGET_RATIO
            as_classification["rpki_normalization"] = (
                f"Natural sample RPKI rate inflated above global 36.3% due to "
                f"backbone-bias of connected CAIDA subgraphs. {rpki_demoted_count} "
                f"ASes uniformly downsampled from RPKI to non-RPKI (deterministic, "
                f"seeded) to match global deployment density."
            )
        as_classification["rpki_role"] = {
            str(asn): "blockchain_validator" if asn in all_rpki_asns else "observer"
            for asn in sorted(all_as_observations.keys())
        }
        as_classification["topology_source"] = "CAIDA AS Relationships Dataset (2022-01-01)"
        if is_small_mode:
            as_classification["subgraph_method"] = f"Rank-threshold >= {rank_threshold} (small mode, deterministic)"
        elif bfs:
            as_classification["subgraph_method"] = f"BFS expansion from AS{bfs_seed}"
        else:
            as_classification["subgraph_method"] = (
                "v3 stratified sampling (scaled clique floor, realistic tier quotas, "
                "unlimited bridge reconnection for connectivity)"
            )
        as_classification["visibility_stats"] = visibility_stats
    else:
        as_classification["rpki_source"] = (
            f"Degree-based heuristic ({percent_adoption*100:.0f}% adoption rate)"
        )
        as_classification["topology_source"] = f"Internet Topology Zoo ({topology})"

    _write_json(base_path / "as_classification.json", as_classification, compress=compress)

    # Save ROA database (prefix -> authorized_as) for Rust detection
    if not roa_db and prefix_assignments and all_rpki_asns:
        # Fallback: derive ROA from prefix assignments
        for asn in sorted(all_rpki_asns):
            if asn in prefix_assignments:
                for prefix in prefix_assignments[asn]:
                    prefix_len = int(prefix.split('/')[1])
                    roa_db[prefix] = {
                        "authorized_as": asn,
                        "max_length": prefix_len,
                    }
    if roa_db:
        _write_json(base_path / "roa_database.json", roa_db, compress=False)
        print(f"    Saved ROA database: {len(roa_db)} entries")

    # Save ground truth
    print(f"\n[8] Saving ground truth...")
    all_attacks = []
    for asn, anns in all_as_observations.items():
        for ann in anns:
            if ann['is_attack']:
                all_attacks.append(ann)

    all_attacks.sort(key=lambda x: x['timestamp'])

    # CSV format (never compressed — small and useful as-is)
    with open(ground_truth_path / "ground_truth.csv", 'w') as f:
        f.write("observer_asn,observer_is_rpki,timestamp,attack_type,attacker_asn,prefix,as_path_length,campaign,has_roa,roa_tag\n")
        for att in all_attacks:
            campaign = att.get('campaign', '')
            has_roa = att.get('has_roa', '')
            roa_tag = att.get('roa_tag', '')
            f.write(f"{att['observed_by_asn']},{att['observer_is_rpki']},{att['timestamp']},{att['label']},{att['origin_asn']},{att['prefix']},{att['as_path_length']},{campaign},{has_roa},{roa_tag}\n")

    # JSON format
    ground_truth_data = {
        "description": "Ground truth labels for all attack announcements",
        "total_attacks": len(all_attacks),
        "attack_types": {k: v for k, v in attack_counts.items() if k != "LEGITIMATE"},
        "attacks": all_attacks
    }

    gt_ext = ".json.gz" if compress else ".json"
    _write_json(ground_truth_path / f"ground_truth{gt_ext}", ground_truth_data, compress=compress)

    # Save AS classification in ground truth folder too
    _write_json(ground_truth_path / "as_classification.json", as_classification, compress=compress)

    print(f"    Saved {len(all_attacks)} attacks to ground_truth folder")

    # Generate README
    if is_caida_subgraph:
        readme_content = _generate_caida_readme(
            num_nodes, total_as_count, folder_name,
            all_as_observations, all_rpki_asns, all_non_rpki_asns,
            total_anns, total_attacks, attack_counts,
            attacks_per_type=attacks_per_type,
            visibility_stats=visibility_stats,
            topology_data=topology_data,
        )
    elif topology and topology in ZOO_TOPOLOGIES:
        readme_content = _generate_zoo_readme(
            topology, total_as_count, folder_name,
            all_as_observations, all_rpki_asns, all_non_rpki_asns,
            total_anns, total_attacks, attack_counts,
            percent_adoption,
        )
    else:
        readme_content = _generate_caida_readme(
            num_nodes, total_as_count, folder_name,
            all_as_observations, all_rpki_asns, all_non_rpki_asns,
            total_anns, total_attacks, attack_counts,
            attacks_per_type=attacks_per_type,
            visibility_stats=visibility_stats,
            topology_data=topology_data,
        )

    with open(base_path / "README.md", 'w') as f:
        f.write(readme_content)

    # Compute coverage stats
    total_best = sum(
        sum(1 for a in anns if a.get('is_best', True))
        for anns in all_as_observations.values()
    )
    total_alt = sum(
        sum(1 for a in anns if not a.get('is_best', True))
        for anns in all_as_observations.values()
    )

    print(f"\n{'='*60}")
    print(f"Dataset Statistics")
    print(f"{'='*60}")
    print(f"Total ASes: {len(all_as_observations)}")
    print(f"  - RPKI: {len(all_rpki_asns)} "
          f"({100*len(all_rpki_asns)/max(1,len(all_as_observations)):.2f}%)")
    print(f"  - Non-RPKI: {len(all_non_rpki_asns)}")
    if is_caida_subgraph:
        print(f"  - RPKI source: {RPKI_CLIENT_VRPS_SNAPSHOT}")
        if 'rpki_natural_count' in locals() and 'rpki_demoted_count' in locals():
            print(f"  - Natural RPKI count: {rpki_natural_count} "
                  f"(before normalization)")
            print(f"  - Demoted: {rpki_demoted_count} "
                  f"(to match global {RPKI_TARGET_RATIO*100:.1f}% rate)")
        print(f"  - RPKI role: {len(all_rpki_asns)} validators, {len(all_non_rpki_asns)} observers")
    print(f"Total announcements: {total_anns}")
    print(f"  - Best routes (FIB/selected): {total_best}")
    print(f"  - Alternative routes (Adj-RIB-In only): {total_alt}")
    if total_anns > 0:
        print(f"Attack announcements: {total_attacks} ({total_attacks/total_anns*100:.2f}%)")
    else:
        print(f"Attack announcements: {total_attacks}")
    # Count withdrawals and flapping
    total_withdrawals = sum(
        sum(1 for a in anns if a.get('is_withdrawal', False))
        for anns in all_as_observations.values()
    )
    if total_anns > 0:
        print(f"Withdrawal observations: {total_withdrawals} ({total_withdrawals/total_anns*100:.1f}%)")
    if flap_count > 0:
        print(f"Flapping oscillation observations: {flap_count}")
    print(f"\nAttack breakdown:")
    for attack_type in ["PREFIX_HIJACK", "SUBPREFIX_HIJACK", "BOGON_INJECTION", "ROUTE_FLAPPING", "ROUTE_LEAK", "PATH_POISONING"]:
        count = attack_counts.get(attack_type, 0)
        print(f"  - {attack_type}: {count}")
    print(f"Timeline: {timeline.total_duration}s ({timeline.total_duration/3600:.0f}h), "
          f"avg_gap={timeline._avg_gap:.0f}s")

    print(f"\n{'='*60}")
    print(f"Dataset generation complete!")
    print(f"{'='*60}")
    print(f"Output: {base_path}")
    print(f"\nFolder structure:")
    print(f"  {base_path}/")
    print(f"  ├── observations/         # {len(all_as_observations)} individual AS observation files")
    print(f"  ├── ground_truth/")
    print(f"  │   ├── ground_truth.csv")
    print(f"  │   ├── ground_truth.json")
    print(f"  │   └── as_classification.json")
    print(f"  ├── as_classification.json")
    if is_small_mode and topology_data:
        print(f"  ├── topology.json          # Topology graph (nodes, edges, DOT)")
        print(f"  ├── topology.dot           # Graphviz DOT file")
    print(f"  └── README.md")

    return base_path


def _generate_zoo_readme(
    topology_name, node_count, folder_name,
    all_as_observations, all_rpki_asns, all_non_rpki_asns,
    total_anns, total_attacks, attack_counts,
    percent_adoption=0.37,
):
    """Generate README for a Topology Zoo dataset."""
    attack_pct = (total_attacks / total_anns * 100) if total_anns > 0 else 0
    return f"""# BGPSentry Dataset - {topology_name} Topology ({node_count} Nodes)

> **Note:** This dataset uses a **Zoo topology** with synthetic ASNs and degree-based
> RPKI heuristic. For datasets with real ASNs and real RPKI data, use `--topology caida`.
> See `DATASET_METHODOLOGY.md` for why this approach was tried and ultimately superseded.

## Overview
This dataset contains **realistic BGP observations** generated using the **bgpy** simulation framework
on the **{topology_name}** topology from the **Internet Topology Zoo**.

**All {node_count} nodes** in the topology export observations (no sampling).

## Data Source: Internet Topology Zoo

The topology comes from the **Internet Topology Zoo** project:
- **Topology**: {topology_name}
- **Nodes**: {node_count}
- **Source**: [The Internet Topology Zoo](http://www.topology-zoo.org/)
- **Citation**: Knight et al., "The Internet Topology Zoo," IEEE JSAC, 2011

### Hierarchy Inference
The original Topology Zoo data provides flat connectivity (no BGP hierarchy).
We infer customer-provider and peer relationships using **node degree**:
- **Core nodes** (degree >= 75th percentile): peer with each other (PeerLinks)
- **Core-to-edge edges**: customer-provider (core = provider)
- **Edge-to-edge edges**: higher-degree node is provider

### RPKI Adoption Model
RPKI adoption is assigned **once** before any scenario runs using a **degree-based
role model**: nodes are sorted by degree (descending) and the top {percent_adoption*100:.0f}% are
designated as RPKI adopters. This mirrors real-world deployment where large transit
providers adopted RPKI first (RoVista, Li et al., IMC 2023).

### Limitations of This Approach
- **Synthetic ASNs**: Nodes are offset GML IDs (1, 2, 3...), not real Internet ASNs
- **Intra-AS topology**: Zoo networks are router-level, not AS-level
- **Heuristic RPKI**: Degree-based adoption doesn't reflect real-world ROV deployment

## Dataset Statistics

| Metric | Value |
|--------|-------|
| **Total ASes** | {len(all_as_observations):,} |
| **RPKI ASes** | {len(all_rpki_asns):,} |
| **Non-RPKI ASes** | {len(all_non_rpki_asns):,} |
| **Total Announcements** | {total_anns:,} |
| **Total Attacks** | {total_attacks:,} ({attack_pct:.2f}%) |
| **Legitimate** | {attack_counts.get('LEGITIMATE', 0):,} |

### Attack Breakdown
| Attack Type | Count |
|-------------|-------|
| PREFIX_HIJACK | {attack_counts.get('PREFIX_HIJACK', 0):,} |
| SUBPREFIX_HIJACK | {attack_counts.get('SUBPREFIX_HIJACK', 0):,} |
| BOGON_INJECTION | {attack_counts.get('BOGON_INJECTION', 0):,} |
| ROUTE_FLAPPING | {attack_counts.get('ROUTE_FLAPPING', 0):,} |

## Folder Structure

```
{folder_name}/
├── README.md
├── as_classification.json
├── observations/               # {len(all_as_observations)} individual AS files (ALL nodes)
│   ├── AS1.json
│   ├── AS2.json
│   └── ...
└── ground_truth/
    ├── ground_truth.csv
    ├── ground_truth.json
    └── as_classification.json
```

## Citation

If you use this dataset in your research, please cite:

```bibtex
@misc{{bgpsentry_dataset_{topology_name.lower()},
  title = {{BGPSentry BGP Dataset ({topology_name} Topology)}},
  author = {{BGPSentry Team}},
  year = {{2025}},
  note = {{Generated using bgpy with {topology_name} topology from Internet Topology Zoo}}
}}

@article{{knight2011internet,
  title = {{The Internet Topology Zoo}},
  author = {{Knight, Simon and Nguyen, Hung X. and Falkner, Nick and Bowden, Rhys and Roughan, Matthew}},
  journal = {{IEEE Journal on Selected Areas in Communications}},
  volume = {{29}},
  number = {{9}},
  pages = {{1765--1775}},
  year = {{2011}}
}}
```

## Generated

- **Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **Generator**: BGPSentry Dataset Generator
- **Topology**: {topology_name} (Internet Topology Zoo)
- **Status**: Legacy (superseded by CAIDA subgraph mode)
"""


def _generate_caida_readme(
    num_nodes, total_as_count, folder_name,
    all_as_observations, all_rpki_asns, all_non_rpki_asns,
    total_anns, total_attacks, attack_counts,
    attacks_per_type=5, visibility_stats=None, topology_data=None,
):
    """Generate README for a CAIDA subgraph dataset (trace-driven)."""
    attack_pct = (total_attacks / total_anns * 100) if total_anns > 0 else 0
    rpki_pct = (len(all_rpki_asns) / len(all_as_observations) * 100) if all_as_observations else 0

    vis_section = ""
    if visibility_stats:
        ps = visibility_stats.get("prefixes_per_as", {})
        os_ = visibility_stats.get("origins_per_as", {})
        vis_section = (
            "\n### Visibility Diversity\n"
            "| Metric | Min | Max | Mean | Stdev |\n"
            "|--------|-----|-----|------|-------|\n"
            f"| Prefixes per AS | {ps.get('min', 0)} | {ps.get('max', 0)} "
            f"| {ps.get('mean', 0):.1f} | {ps.get('stdev', 0):.1f} |\n"
            f"| Origins per AS | {os_.get('min', 0)} | {os_.get('max', 0)} "
            f"| {os_.get('mean', 0):.1f} | {os_.get('stdev', 0):.1f} |\n"
        )

    topo_section = ""
    if topology_data:
        nodes = topology_data.get("nodes", [])
        edges = topology_data.get("edges", [])
        dot_str = topology_data.get("dot", "")

        # Node table
        node_rows = ""
        for n in nodes:
            rpki_str = "Yes" if n["rpki"] else "No"
            node_rows += f"| AS{n['asn']} | {n['type']} | {rpki_str} | {n['degree']} |\n"

        # Edge table
        edge_rows = ""
        for e in edges:
            if e["relationship"] == "customer-provider":
                edge_rows += f"| AS{e['provider']} | AS{e['customer']} | customer-provider |\n"
            else:
                edge_rows += f"| AS{e['source']} | AS{e['target']} | peer-peer |\n"

        topo_section = f"""
## Topology Graph

> This section is generated for small topology mode. Files: `topology.json`, `topology.dot`

### Nodes ({len(nodes)})

| ASN | Type | RPKI | Degree |
|-----|------|------|--------|
{node_rows}
### Edges ({len(edges)})

| Source | Target | Relationship |
|--------|--------|-------------|
{edge_rows}
### DOT Format (Graphviz)

Paste into [graphviz.org](https://dreampuf.github.io/GraphvizOnline/) to visualize:

```dot
{dot_str}
```
"""

    return f"""# BGPSentry Dataset - CAIDA Subgraph ({total_as_count} Nodes, Trace-Driven)

## Overview

This dataset contains **trace-driven BGP observations** generated using the **bgpy** simulation
framework on a **connected subgraph** extracted from the real **CAIDA AS-level Internet topology**.

**Trace-driven design**: Topology from CAIDA, RPKI from rov-collector, prefix counts proportional
to real AS sizes, propagation via Gao-Rexford — only attack *injection* is simulated, as real BGP
feeds lack ground truth labels.

Key properties:
- **Real ASNs** from the actual Internet (e.g., AS7018 AT&T, AS13335 Cloudflare)
- **Real customer-provider and peer relationships** from CAIDA
- **Real RPKI/ROV deployment data** from rov-collector (6 measurement sources)
- **Stratified hierarchical sampling** preserving Internet tier structure
- **Dynamic per-AS prefix counts** proportional to AS type
- **Multiple attack instances** ({attacks_per_type} per type) with different victim/attacker pairs
- **Per-hop convergence jitter** modeling BGP MRAI timer dynamics
- **All {total_as_count} nodes** exported (no sampling) for blockchain consensus integrity

## Data Sources

### Topology: CAIDA AS Relationships Dataset

- **Source**: [CAIDA AS Relationships](https://www.caida.org/catalog/datasets/as-relationships/)
- **Method**: Stratified hierarchical sampling (all input_clique + proportional transit/multihomed/stubs)
- **Full topology**: ~73,000 ASes with real customer-provider and peer links
- **Connectivity**: Union-find component detection + BFS shortest-path bridge reconnection

> CAIDA infers AS relationships from BGP routing data collected by RouteViews and RIPE RIS.
> Subgraph preserves the Internet's hierarchical tier structure via stratified sampling from CAIDA AS groups.

### RPKI Data: rov-collector (6 Sources)

RPKI/ROV deployment status is determined by **real measurement data**, not heuristics:

| Source | Method | Reference |
|--------|--------|-----------|
| **RoVista** | Active measurement of ROV filtering | Li et al., IMC 2023 |
| **APNIC** | ROV measurement via APNIC labs | APNIC Research |
| **TMA** | Traffic and routing analysis | TMA Research |
| **FRIENDS** | Collaborative ROV measurement | FRIENDS Project |
| **IsBGPSafeYet** | Community-maintained ROV status | Cloudflare |
| **rpki.net** | RPKI repository monitoring | rpki.net |

### Prefix Assignment

Per-AS prefix counts proportional to AS type, consistent with observed Internet prefix distribution
where large transit providers originate orders of magnitude more prefixes than stub ASes (Huston, APNIC):
- **Input clique**: 20-50 prefixes (/16-/20)
- **Transit**: 5-20 prefixes (/18-/24)
- **Multihomed**: 2-5 prefixes (/22-/24)
- **Stubs**: 1-3 prefixes (/24)

### Timestamp Model

Per-hop convergence delay follows the BGP MRAI timer (RFC 4271, default 30s) with jitter,
consistent with measured convergence dynamics (Labovitz et al., 2001):
- Path length 1: +0.5-15s
- Path length 3: +1.5-45s
- Path length 6: +3-90s

### Blockchain Role Assignment

In BGPSentry's **Proof of Population** consensus:
- **RPKI-enabled ASes** = **Blockchain validators** (can vote in consensus)
- **Non-RPKI ASes** = **Observers** (submit data but cannot vote)

This mapping is stored in `as_classification.json` under the `rpki_role` field.

## Simulation Framework: bgpy

1. **Subgraph extraction**: Stratified hierarchical sampling from CAIDA (preserves tier ratios)
2. **RPKI assignment**: Real ROV data from rov-collector (not degree heuristic)
3. **Prefix assignment**: Dynamic per-AS counts proportional to type
4. **BGP Engine**: `SimulationEngine` with Gao-Rexford propagation model
5. **Scenarios**: Legitimate warm-ups + {attacks_per_type} attack instances per type (4 types)
6. **Post-processing**: Per-hop convergence jitter on timestamps
7. **Extraction**: Full Adj-RIB-In capture from every AS (ALL nodes, no sampling)

## Dataset Statistics

| Metric | Value |
|--------|-------|
| **Total ASes** | {len(all_as_observations):,} |
| **RPKI ASes (validators)** | {len(all_rpki_asns):,} ({rpki_pct:.1f}%) |
| **Non-RPKI ASes (observers)** | {len(all_non_rpki_asns):,} ({100-rpki_pct:.1f}%) |
| **Total Announcements** | {total_anns:,} |
| **Total Attacks** | {total_attacks:,} ({attack_pct:.2f}%) |
| **Legitimate** | {attack_counts.get('LEGITIMATE', 0):,} |
| **Attacks per type** | {attacks_per_type} |
| **RPKI Source** | rov-collector (6 real measurement sources) |
| **Topology Source** | CAIDA AS Relationships (stratified sampling) |

### Attack Breakdown
| Attack Type | Count |
|-------------|-------|
| PREFIX_HIJACK | {attack_counts.get('PREFIX_HIJACK', 0):,} |
| SUBPREFIX_HIJACK | {attack_counts.get('SUBPREFIX_HIJACK', 0):,} |
| BOGON_INJECTION | {attack_counts.get('BOGON_INJECTION', 0):,} |
| ROUTE_FLAPPING | {attack_counts.get('ROUTE_FLAPPING', 0):,} |
{vis_section}{topo_section}
## Folder Structure

```
{folder_name}/
├── README.md
├── as_classification.json        # Real RPKI data + blockchain roles + visibility stats
{"├── topology.json                 # Topology graph (nodes, edges, DOT)" if topology_data else ""}
{"├── topology.dot                  # Graphviz DOT file for visualization" if topology_data else ""}
├── observations/                  # {len(all_as_observations)} individual AS files (ALL nodes, real ASNs)
│   ├── AS<real_asn>.json
│   └── ...
└── ground_truth/
    ├── ground_truth.csv
    ├── ground_truth.json
    └── as_classification.json
```

## Citation

If you use this dataset in your research, please cite:

```bibtex
@misc{{bgpsentry_dataset_caida,
  title = {{BGPSentry BGP Dataset (CAIDA Subgraph, {total_as_count} Nodes)}},
  author = {{BGPSentry Team}},
  year = {{2025}},
  note = {{Trace-driven dataset using bgpy with CAIDA topology, real RPKI data, and stratified sampling}}
}}

@misc{{caida_as_relationships,
  title = {{CAIDA AS Relationships Dataset}},
  author = {{Center for Applied Internet Data Analysis (CAIDA)}},
  howpublished = {{\\url{{https://www.caida.org/catalog/datasets/as-relationships/}}}},
  year = {{2024}}
}}

@inproceedings{{li2023rovista,
  title = {{RoVista: Measuring and Analyzing the Route Origin Validation (ROV) in RPKI}},
  author = {{Li, Weitong and Chunhui, Liang and Testart, Cecilia and Calder, Matt and Claffy, KC}},
  booktitle = {{ACM Internet Measurement Conference (IMC)}},
  year = {{2023}}
}}
```

## Generated

- **Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **Generator**: BGPSentry Dataset Generator (Trace-Driven Edition)
- **Mode**: CAIDA Subgraph (stratified sampling, real RPKI, dynamic prefixes)
"""


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate BGPSentry dataset with individual AS observations"
    )
    parser.add_argument(
        "--nodes",
        type=int,
        default=200,
        help="Number of nodes in CAIDA subgraph (default: 200). Ignored for Zoo topologies."
    )
    parser.add_argument(
        "--output",
        type=str,
        default="dataset",
        help="Output directory (default: dataset)"
    )
    parser.add_argument(
        "--adoption",
        type=float,
        default=0.37,
        help="RPKI adoption rate for Zoo topologies (default: 0.37). Ignored for CAIDA mode (uses real data)."
    )
    parser.add_argument(
        "--legitimate-scenarios",
        type=int,
        default=60,
        help="Number of legitimate scenarios (default: 60, targets ~6%% attack ratio)"
    )
    parser.add_argument(
        "--topology",
        type=str,
        default="caida",
        choices=["caida", "ASN", "Vlt", "Tiscali"],
        help="Topology: caida (default, real ASNs + real RPKI) or Zoo network (ASN=18, Vlt=92, Tiscali=161)"
    )
    parser.add_argument(
        "--seed-asn",
        type=int,
        default=None,
        help="Seed ASN for CAIDA subgraph (kept for compat, ignored in stratified mode)."
    )
    parser.add_argument(
        "--attacks-per-type",
        type=int,
        default=5,
        help="Number of attack instances per attack type (default: 5)"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for reproducibility (default: None)"
    )
    parser.add_argument(
        "--small",
        action="store_true",
        default=False,
        help="Use small topology mode (rank-threshold 50, ~25 ASes). "
             "Reduces prefix caps, legitimate scenarios (15), and attacks per type (2). "
             "Deterministic subset of all larger datasets."
    )
    parser.add_argument(
        "--rank-threshold",
        type=int,
        default=None,
        help="Use propagation rank threshold instead of --nodes for CAIDA subgraph. "
             "Includes ALL ASes with propagation_rank >= threshold (deterministic). "
             "Natural boundaries: 50 (~25 ASes), 40 (~250), 10 (~434), 5 (~950), 3 (~2156)."
    )
    parser.add_argument(
        "--compress",
        action="store_true",
        default=False,
        help="Write observation and ground truth files as gzip (.json.gz) with no "
             "indentation. Estimated 85%% size reduction for large datasets."
    )
    parser.add_argument(
        "--timeline-duration",
        type=int,
        default=1800,
        help="Duration of the BGP timeline in seconds (default: 1800 = 30 min). "
             "Matches the 300-second trust-evolution figure in the paper with "
             "a conservative 2x margin for scalability-metric stability."
    )
    parser.add_argument(
        "--inject-only",
        type=str,
        default=None,
        metavar="PATH",
        help="Inject new attack types (forged_origin, route_leak) into an existing "
             "dataset at PATH without regenerating. Reads existing observations, "
             "rebuilds topology, runs new attack scenarios, and updates files in-place."
    )
    parser.add_argument(
        "--bfs",
        action="store_true",
        default=False,
        help="Use BFS expansion from a seed AS instead of stratified sampling. "
             "Produces a naturally connected subgraph — no bridge reconnection needed."
    )
    parser.add_argument(
        "--bfs-seed",
        type=int,
        default=174,
        help="Seed ASN for BFS expansion (default: 174 = Cogent, Tier-1). "
             "Only used when --bfs is set."
    )
    parser.add_argument(
        "--from-topology",
        type=str,
        default=None,
        metavar="DIR",
        help="Use pre-extracted topology from DIR (must contain as_classification.json "
             "and as_relationships.json from extract_regional_topology.py). "
             "Skips CAIDA subgraph extraction and RPKI normalization."
    )
    parser.add_argument(
        "--no-attacks",
        action="store_true",
        default=False,
        help="Generate only legitimate BGP announcements (no attack injection). "
             "Useful when you only need the BGP observation data without attacks."
    )
    parser.add_argument(
        "--attack-mode",
        type=str,
        default=None,
        choices=["campaign"],
        help="Attack injection mode. 'campaign' uses campaign-based injection "
             "with PREFIX_HIJACK and SUBPREFIX_HIJACK (with/without ROA) spread "
             "across the timeline in natural bursts."
    )
    parser.add_argument(
        "--target-rate",
        type=float,
        default=None,
        help="Target observation rate in events/sec/node. Auto-computes announces "
             "per AS to achieve this rate. RIPE RIS baseline: 0.005 ev/sec/peer. "
             "If not set, defaults to 2-4 announces per AS."
    )
    parser.add_argument(
        "--victims-per-scenario",
        type=int,
        default=None,
        help="Number of victim ASes per legitimate scenario (default: 5-10 random). "
             "Set to 1 for controlled observation rate."
    )
    parser.add_argument(
        "--prefixes-per-victim",
        type=int,
        default=None,
        help="Number of prefixes per victim AS (default: all assigned prefixes). "
             "Set to 1 for controlled observation rate."
    )

    args = parser.parse_args()

    # BFS datasets go directly into BGP-Sentry dataset/bfsTopology/
    if args.bfs and args.output == "dataset":
        args.output = str(Path(__file__).resolve().parent / "dataset" / "bfsTopology")

    if args.inject_only:
        # Incremental injection mode
        inject_new_attacks(
            dataset_path=Path(args.inject_only),
            attacks_per_type=args.attacks_per_type,
            seed=args.seed,
        )
    else:
        # Full generation mode
        generate_dataset(
            num_nodes=args.nodes,
            output_dir=args.output,
            percent_adoption=args.adoption,
            num_legitimate_scenarios=args.legitimate_scenarios,
            topology=args.topology,
            seed_asn=args.seed_asn,
            attacks_per_type=0 if args.no_attacks else args.attacks_per_type,
            seed=args.seed,
            small=args.small,
            rank_threshold=args.rank_threshold,
            compress=args.compress,
            timeline_duration=args.timeline_duration,
            bfs=args.bfs,
            bfs_seed=args.bfs_seed,
            from_topology=args.from_topology,
            victims_per_scenario=args.victims_per_scenario,
            prefixes_per_victim=args.prefixes_per_victim,
            target_rate=args.target_rate,
            attack_mode=args.attack_mode,
        )
