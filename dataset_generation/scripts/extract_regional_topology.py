#!/usr/bin/env python3
"""Extract regional transit subgraphs from the CAIDA AS-relationship dataset.

Downloads RIR delegation files to map ASNs to regions (RIPE, ARIN, APNIC),
then filters the CAIDA topology to transit ASes in the selected region(s)
with a minimum customer count threshold.  Outputs as_classification.json
and as_relationships.json compatible with BGP-Sentry evaluation datasets.

Usage:
    python3 scripts/extract_regional_topology.py arin_3plus --output dataset/arin_3plus/
    python3 scripts/extract_regional_topology.py all --output dataset/
"""

import argparse
import json
import os
import sys
import urllib.request
from collections import defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Presets
# ---------------------------------------------------------------------------

PRESETS = {
    "afrinic_transit_mh":      {"regions": ["AFRINIC"],            "min_customers": 1, "include_multihomed": True},
    "arin_transit":            {"regions": ["ARIN"],               "min_customers": 1, "include_multihomed": False},
    "lacnic_afrinic_transit":  {"regions": ["LACNIC", "AFRINIC"],  "min_customers": 1, "include_multihomed": False},
    "lacnic_5plus_mh":         {"regions": ["LACNIC"],             "min_customers": 5, "include_multihomed": True},
}

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CAIDA_TOPOLOGY = os.path.join(
    os.path.dirname(__file__), "..",
    "dataset", "source_data", "downloaded_caida_as_relationships_20260401.txt",
)
RPKI_FILE = os.path.join(
    os.path.dirname(__file__), "..",
    "dataset", "source_data", "computed_from_downloaded_rpki_vrps_unique_asns_20260418.json",
)
RIR_CACHE_DIR = "/tmp/rir_cache"

RIR_URLS = {
    "RIPE":    "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest",
    "ARIN":    "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "APNIC":   "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest",
    "LACNIC":  "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest",
    "AFRINIC": "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest",
}

RIR_NAME_MAP = {
    "ripencc": "RIPE",
    "arin":    "ARIN",
    "apnic":   "APNIC",
    "lacnic":  "LACNIC",
    "afrinic": "AFRINIC",
}


# ---------------------------------------------------------------------------
# Download / cache RIR delegation files
# ---------------------------------------------------------------------------

def _download_cached(url: str, cache_dir: str) -> str:
    """Download *url* to *cache_dir* if not already cached; return local path."""
    os.makedirs(cache_dir, exist_ok=True)
    fname = url.rsplit("/", 1)[-1]
    local = os.path.join(cache_dir, fname)
    if os.path.exists(local):
        print(f"  [cache hit] {local}")
        return local
    print(f"  Downloading {url} ...")
    urllib.request.urlretrieve(url, local)
    print(f"  Saved to {local}")
    return local


def load_rir_asn_allocations(regions: list[str]) -> dict[int, str]:
    """Return {ASN: region_name} for all ASN allocations in *regions*.

    Only rows with type ``asn`` and status ``allocated`` or ``assigned``
    are included.
    """
    needed_rirs = set(r.upper() for r in regions)
    asn_region: dict[int, str] = {}

    for rir_label, url in RIR_URLS.items():
        if rir_label not in needed_rirs:
            continue
        path = _download_cached(url, RIR_CACHE_DIR)
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("|")
                if len(parts) < 7:
                    continue
                # registry|cc|type|start|value|date|status[|...]
                rec_type = parts[2]
                if rec_type != "asn":
                    continue
                status = parts[6].lower()
                if status not in ("allocated", "assigned"):
                    continue
                start_asn = int(parts[3])
                count = int(parts[4])
                registry = parts[0].lower()
                region = RIR_NAME_MAP.get(registry, registry.upper())
                if region not in needed_rirs:
                    continue
                for asn in range(start_asn, start_asn + count):
                    asn_region[asn] = region

    return asn_region


# ---------------------------------------------------------------------------
# Load CAIDA topology
# ---------------------------------------------------------------------------

def load_caida_topology(path: str):
    """Parse CAIDA AS-relationship file.

    Returns
    -------
    cp_links : list of (provider, customer)
    peer_links : list of (a, b)  with a < b
    tier1_asns : set of int
    """
    cp_links: list[tuple[int, int]] = []
    peer_links: list[tuple[int, int]] = []
    tier1_asns: set[int] = set()

    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line.startswith("# input clique:"):
                tier1_asns = {int(x) for x in line.split(":")[1].split()}
                continue
            if line.startswith("#") or not line:
                continue
            parts = line.split("|")
            if len(parts) < 3:
                continue
            a, b, rel = int(parts[0]), int(parts[1]), int(parts[2])
            if rel == -1:
                # provider a -> customer b
                cp_links.append((a, b))
            elif rel == 0:
                peer_links.append((min(a, b), max(a, b)))

    return cp_links, peer_links, tier1_asns


# ---------------------------------------------------------------------------
# Load RPKI ASNs
# ---------------------------------------------------------------------------

def load_rpki_asns(path: str) -> set[int]:
    asns: set[int] = set()
    if path.endswith(".json"):
        import json as _json
        with open(path) as fh:
            data = _json.load(fh)
        if isinstance(data, dict) and "rpki_asns" in data:
            asns = {int(a) for a in data["rpki_asns"]}
        elif isinstance(data, list):
            asns = {int(a) for a in data}
    else:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        asns.add(int(line))
                    except ValueError:
                        pass
    return asns


# ---------------------------------------------------------------------------
# Build filtered subgraph
# ---------------------------------------------------------------------------

def _connected_components(adj: dict[int, set[int]], nodes: set[int]):
    """Yield sets of connected components."""
    visited: set[int] = set()
    for start in sorted(nodes):
        if start in visited:
            continue
        comp: set[int] = set()
        stack = [start]
        while stack:
            n = stack.pop()
            if n in visited:
                continue
            visited.add(n)
            comp.add(n)
            for nb in adj.get(n, set()):
                if nb not in visited and nb in nodes:
                    stack.append(nb)
        yield comp


def build_subgraph(
    cp_links: list[tuple[int, int]],
    peer_links: list[tuple[int, int]],
    tier1_asns: set[int],
    rpki_asns: set[int],
    region_asns: dict[int, str],
    min_customers: int,
    include_multihomed: bool = False,
):
    """Filter to regional transit ASes and extract internal links.

    Returns a dict with all the data needed to write output files.
    """
    # Step 1: count customers per AS (within the region)
    regional_set = set(region_asns.keys())
    customers_of: dict[int, set[int]] = defaultdict(set)
    providers_of: dict[int, set[int]] = defaultdict(set)
    for prov, cust in cp_links:
        if prov in regional_set and cust in regional_set:
            customers_of[prov].add(cust)
        if cust in regional_set and prov in regional_set:
            providers_of[cust].add(prov)

    # Step 2: identify transit ASes (those with >= min_customers regional customers)
    if min_customers <= 0:
        # "all_transit" — any AS with at least 1 customer
        transit = {asn for asn, custs in customers_of.items() if len(custs) >= 1}
    else:
        transit = {asn for asn, custs in customers_of.items() if len(custs) >= min_customers}

    # Also include Tier-1 ASes in the region even if customer count is low
    transit |= (tier1_asns & regional_set)

    # Step 2b: optionally include multihomed ASes (multiple providers, no customers)
    if include_multihomed:
        has_customers = set(customers_of.keys())
        multihomed = {
            asn for asn in regional_set
            if asn not in has_customers and len(providers_of.get(asn, set())) > 1
        }
        transit = transit | multihomed

    # Step 3: filter links — BOTH endpoints must be in the selected set
    filtered_cp: list[tuple[int, int]] = []
    filtered_peer: list[tuple[int, int]] = []
    adj: dict[int, set[int]] = defaultdict(set)

    for prov, cust in cp_links:
        if prov in transit and cust in transit:
            filtered_cp.append((prov, cust))
            adj[prov].add(cust)
            adj[cust].add(prov)

    seen_peers: set[tuple[int, int]] = set()
    for a, b in peer_links:
        key = (min(a, b), max(a, b))
        if a in transit and b in transit and key not in seen_peers:
            filtered_peer.append(key)
            seen_peers.add(key)
            adj[a].add(b)
            adj[b].add(a)

    # Step 4: compute degree and drop isolated nodes
    degree: dict[int, int] = {}
    for asn in transit:
        degree[asn] = len(adj.get(asn, set()) & transit)

    isolated = {asn for asn, d in degree.items() if d == 0}
    active = transit - isolated

    # Re-filter links (removing isolated should not change anything but be safe)
    filtered_cp = [(p, c) for p, c in filtered_cp if p in active and c in active]
    filtered_peer = [(a, b) for a, b in filtered_peer if a in active and b in active]

    # Rebuild adj for active
    adj_active: dict[int, set[int]] = defaultdict(set)
    for p, c in filtered_cp:
        adj_active[p].add(c)
        adj_active[c].add(p)
    for a, b in filtered_peer:
        adj_active[a].add(b)
        adj_active[b].add(a)

    # Step 5: connectivity
    components = list(_connected_components(adj_active, active))
    components.sort(key=len, reverse=True)
    largest_pct = len(components[0]) / len(active) * 100 if components else 0.0

    # Step 6: RPKI classification
    rpki_in_set = sorted(asn for asn in active if asn in rpki_asns)
    non_rpki_in_set = sorted(asn for asn in active if asn not in rpki_asns)
    classification = {}
    for asn in sorted(active):
        classification[str(asn)] = "RPKI" if asn in rpki_asns else "NON_RPKI"

    # Step 7: relationships dict
    rels: dict[str, dict] = {}
    for asn in sorted(active):
        rels[str(asn)] = {"customers": [], "providers": [], "peers": []}
    for prov, cust in filtered_cp:
        rels[str(prov)]["customers"].append(cust)
        rels[str(cust)]["providers"].append(prov)
    for a, b in filtered_peer:
        rels[str(a)]["peers"].append(b)
        rels[str(b)]["peers"].append(a)
    # Sort for determinism
    for asn_str in rels:
        for k in ("customers", "providers", "peers"):
            rels[asn_str][k] = sorted(rels[asn_str][k])

    tier1_in_set = sorted(tier1_asns & active)

    return {
        "active": active,
        "rpki_in_set": rpki_in_set,
        "non_rpki_in_set": non_rpki_in_set,
        "classification": classification,
        "relationships": rels,
        "cp_count": len(filtered_cp),
        "peer_count": len(filtered_peer),
        "components": components,
        "largest_pct": largest_pct,
        "isolated_dropped": len(isolated),
        "tier1_in_set": tier1_in_set,
    }


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_outputs(
    result: dict,
    output_dir: str,
    preset_name: str,
    preset_cfg: dict,
    rpki_file: str,
):
    os.makedirs(output_dir, exist_ok=True)

    rpki_natural = len(result["rpki_in_set"])
    total = len(result["active"])
    rpki_rate = rpki_natural / total if total else 0.0

    regions_str = "+".join(sorted(preset_cfg["regions"]))
    min_cust = preset_cfg["min_customers"]

    cls_data = {
        "description": (
            f"Regional transit subgraph: {regions_str} ASes with "
            f"{min_cust}+ customers (preset: {preset_name})"
        ),
        "total_ases": total,
        "rpki_count": rpki_natural,
        "non_rpki_count": total - rpki_natural,
        "rpki_asns": result["rpki_in_set"],
        "non_rpki_asns": result["non_rpki_in_set"],
        "classification": result["classification"],
        "rpki_source": "rpki-client VRP snapshot (2022-06-18)",
        "rpki_source_url": (
            "https://web.archive.org/web/20220618163743/"
            "https://console.rpki-client.org/vrps.json"
        ),
        "topology_source": "CAIDA AS Relationships Dataset (2026-04-01)",
        "subgraph_method": (
            f"Regional filter ({regions_str}), transit ASes with "
            f"{min_cust}+ customers, isolated nodes dropped"
        ),
        "rpki_natural_count": rpki_natural,
        "rpki_target_ratio": round(rpki_rate, 6),
    }

    cls_path = os.path.join(output_dir, "as_classification.json")
    with open(cls_path, "w") as fh:
        json.dump(cls_data, fh, indent=2)
        fh.write("\n")

    rel_path = os.path.join(output_dir, "as_relationships.json")
    with open(rel_path, "w") as fh:
        json.dump(result["relationships"], fh, indent=2)
        fh.write("\n")

    return cls_path, rel_path


def print_summary(result: dict, preset_name: str, preset_cfg: dict):
    total = len(result["active"])
    rpki_n = len(result["rpki_in_set"])
    rpki_rate = rpki_n / total * 100 if total else 0.0
    regions_str = "+".join(sorted(preset_cfg["regions"]))

    print(f"\n{'='*60}")
    print(f"  Preset: {preset_name}  ({regions_str}, min_customers={preset_cfg['min_customers']})")
    print(f"{'='*60}")
    print(f"  Total ASes:         {total}")
    print(f"  RPKI ASes:          {rpki_n}  ({rpki_rate:.1f}%)")
    print(f"  Non-RPKI ASes:      {total - rpki_n}")
    print(f"  CP links:           {result['cp_count']}")
    print(f"  Peer links:         {result['peer_count']}")
    print(f"  Tier-1 in set:      {len(result['tier1_in_set'])}  {result['tier1_in_set']}")
    print(f"  Connected comps:    {len(result['components'])}")
    print(f"  Largest comp:       {len(result['components'][0]) if result['components'] else 0}"
          f"  ({result['largest_pct']:.1f}%)")
    print(f"  Isolated dropped:   {result['isolated_dropped']}")
    print(f"{'='*60}\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_preset(
    preset_name: str,
    preset_cfg: dict,
    cp_links,
    peer_links,
    tier1_asns,
    rpki_asns,
    region_asns: dict[int, str],
    output_dir: str,
):
    result = build_subgraph(
        cp_links, peer_links, tier1_asns, rpki_asns,
        region_asns, preset_cfg["min_customers"],
        include_multihomed=preset_cfg.get("include_multihomed", False),
    )
    if not result["active"]:
        print(f"[WARN] Preset {preset_name}: no ASes matched — skipping.")
        return

    cls_path, rel_path = write_outputs(
        result, output_dir, preset_name, preset_cfg, RPKI_FILE,
    )
    print_summary(result, preset_name, preset_cfg)
    print(f"  Wrote: {cls_path}")
    print(f"  Wrote: {rel_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Extract regional transit subgraphs from CAIDA topology.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Available presets:\n"
            + "\n".join(
                f"  {name:20s}  regions={cfg['regions']}, min_customers={cfg['min_customers']}"
                for name, cfg in PRESETS.items()
            )
            + "\n\nUse 'all' to generate every preset."
        ),
    )
    parser.add_argument(
        "preset",
        choices=list(PRESETS.keys()) + ["all"],
        help="Preset name or 'all' to generate every preset.",
    )
    parser.add_argument(
        "--output", "-o",
        required=True,
        help=(
            "Output directory.  For a single preset, files are written here. "
            "For 'all', each preset gets a subdirectory."
        ),
    )
    parser.add_argument(
        "--caida-file",
        default=CAIDA_TOPOLOGY,
        help="Path to CAIDA AS-relationship file.",
    )
    parser.add_argument(
        "--rpki-file",
        default=RPKI_FILE,
        help="Path to RPKI ASN list (one ASN per line).",
    )
    args = parser.parse_args()

    # Resolve paths
    caida_path = os.path.abspath(args.caida_file)
    rpki_path = os.path.abspath(args.rpki_file)

    if not os.path.exists(caida_path):
        print(f"ERROR: CAIDA file not found: {caida_path}", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(rpki_path):
        print(f"ERROR: RPKI file not found: {rpki_path}", file=sys.stderr)
        sys.exit(1)

    # Determine which presets to run
    if args.preset == "all":
        presets_to_run = list(PRESETS.items())
    else:
        presets_to_run = [(args.preset, PRESETS[args.preset])]

    # Collect all needed regions across presets
    all_regions: set[str] = set()
    for _, cfg in presets_to_run:
        all_regions.update(cfg["regions"])

    # Load data
    print("Loading CAIDA topology ...")
    cp_links, peer_links, tier1_asns = load_caida_topology(caida_path)
    print(f"  {len(cp_links)} CP links, {len(peer_links)} peer links, "
          f"{len(tier1_asns)} Tier-1 ASes")

    print("Loading RPKI ASNs ...")
    rpki_asns = load_rpki_asns(rpki_path)
    print(f"  {len(rpki_asns)} RPKI ASes")

    print("Loading RIR delegation files ...")
    region_asns = load_rir_asn_allocations(sorted(all_regions))
    for r in sorted(all_regions):
        count = sum(1 for v in region_asns.values() if v == r)
        print(f"  {r}: {count} ASN allocations")

    # Run presets
    for preset_name, preset_cfg in presets_to_run:
        # Filter region_asns to only the regions needed by this preset
        needed = set(preset_cfg["regions"])
        filtered_region = {asn: reg for asn, reg in region_asns.items() if reg in needed}

        if args.preset == "all":
            out_dir = os.path.join(args.output, preset_name)
        else:
            out_dir = args.output

        run_preset(
            preset_name, preset_cfg,
            cp_links, peer_links, tier1_asns, rpki_asns,
            filtered_region, out_dir,
        )

    print("Done.")


if __name__ == "__main__":
    main()
