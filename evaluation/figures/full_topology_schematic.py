#!/usr/bin/env python3
"""Figure: Full CAIDA BGP topology — k-core decomposition for clarity."""

import matplotlib
matplotlib.use("pdf")
matplotlib.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Linux Libertine", "Libertine", "Times New Roman", "Times", "DejaVu Serif"],
    "font.size": 18,
    "axes.linewidth": 0.6,
})

import matplotlib.pyplot as plt
import numpy as np
import networkx as nx
import json
import random
from matplotlib.collections import LineCollection
from matplotlib.lines import Line2D

random.seed(42)

# --- Load full CAIDA topology ---
print("Loading CAIDA AS relationships...")
G = nx.Graph()
with open("dataset/source_data/downloaded_caida_as_relationships_20260401.txt") as f:
    for line in f:
        if line.startswith("#"):
            continue
        parts = line.strip().split("|")
        if len(parts) >= 3:
            a, b = int(parts[0]), int(parts[1])
            G.add_edge(a, b)

print(f"Full topology: {G.number_of_nodes():,} ASes, {G.number_of_edges():,} links")

# --- Load RPKI ASes ---
with open("dataset/source_data/computed_from_downloaded_rpki_vrps_unique_asns_20260418.json") as f:
    rpki_data = json.load(f)
rpki_set = set(rpki_data["rpki_asns"])

# --- K-core decomposition ---
K = 10
print(f"Extracting {K}-core...")
H = nx.k_core(G, k=K)
print(f"  {K}-core: {H.number_of_nodes():,} ASes, {H.number_of_edges():,} links")

# --- Stats ---
full_degrees = dict(G.degree())
core_degrees = dict(H.degree())
max_deg = max(core_degrees.values())
avg_deg = sum(core_degrees.values()) / len(core_degrees)

# --- Layout ---
print("Computing spring layout...")
# Thin edges for layout: max 12 per node
H_layout = nx.Graph()
H_layout.add_nodes_from(H.nodes())
for n in H.nodes():
    neighbors = list(H.neighbors(n))
    if len(neighbors) > 12:
        neighbors = random.sample(neighbors, 12)
    for nb in neighbors:
        H_layout.add_edge(n, nb)

pos = nx.spring_layout(H_layout, k=0.15, iterations=80, seed=42)

# --- Classify ---
rpki_nodes = [n for n in H.nodes() if n in rpki_set]
non_rpki_nodes = [n for n in H.nodes() if n not in rpki_set]

rpki_sizes = [0.5 + 10 * (core_degrees[n] / max_deg) for n in rpki_nodes]
non_rpki_sizes = [0.5 + 6 * (core_degrees[n] / max_deg) for n in non_rpki_nodes]

# --- Sample edges for drawing ---
all_edges = list(H.edges())
edge_sample = random.sample(all_edges, min(20000, len(all_edges)))
print(f"Drawing {len(edge_sample):,} of {H.number_of_edges():,} edges")

# --- Plot ---
print("Plotting...")
fig, ax = plt.subplots(figsize=(4.2, 3.0))

# Edges
edge_coords = [(pos[u], pos[v]) for u, v in edge_sample if u in pos and v in pos]
lc = LineCollection(edge_coords, colors="#aaaaaa", linewidths=0.06, alpha=0.12)
ax.add_collection(lc)

# RPKI (green, background)
if rpki_nodes:
    rpki_xy = np.array([pos[n] for n in rpki_nodes])
    ax.scatter(rpki_xy[:, 0], rpki_xy[:, 1], s=rpki_sizes,
               c="#CC0000", edgecolors="#990000", linewidths=0.1,
               zorder=2, alpha=0.7)

# Non-RPKI (black, foreground — drawn on top)
if non_rpki_nodes:
    non_rpki_xy = np.array([pos[n] for n in non_rpki_nodes])
    non_rpki_sizes = [0.5 + 6 * (core_degrees[n] / max_deg) for n in non_rpki_nodes]
    ax.scatter(non_rpki_xy[:, 0], non_rpki_xy[:, 1], s=non_rpki_sizes,
               c="#1a1a1a", edgecolors="black", linewidths=0.1,
               zorder=3, alpha=0.9)


# Print stats for caption use
print(f"\n--- For caption ---")
print(f"Full topology: {G.number_of_nodes():,} ASes, {G.number_of_edges():,} links")
print(f"{K}-core: {H.number_of_nodes():,} ASes, {H.number_of_edges():,} links")
print(f"RPKI in core: {len(rpki_nodes):,} ({len(rpki_nodes)/H.number_of_nodes()*100:.1f}%)")
print(f"Non-RPKI in core: {len(non_rpki_nodes):,} ({len(non_rpki_nodes)/H.number_of_nodes()*100:.1f}%)")
print(f"Max degree: {max_deg:,}  |  Avg: {avg_deg:.1f}")

# Legend
legend_elements = [
    Line2D([0], [0], marker='o', color='w', markerfacecolor='#CC0000',
           markeredgecolor='#990000', markersize=10,
           label=f'RPKI AS'),
    Line2D([0], [0], marker='o', color='w', markerfacecolor='#1a1a1a',
           markeredgecolor='black', markersize=10,
           label=f'Non-RPKI AS'),
]
ax.legend(handles=legend_elements, loc='upper center', ncol=2,
          fontsize=14, frameon=False, bbox_to_anchor=(0.5, 1.14),
          handletextpad=0.3, columnspacing=0.8)

ax.axis("off")

fig.patch.set_visible(False)

fig.tight_layout()
fig.savefig("output/figures/full_topology_schematic.pdf",
            bbox_inches="tight", pad_inches=0.05)
            bbox_inches="tight", pad_inches=0.05)
print("Saved: output/figures/full_topology_schematic.pdf")
