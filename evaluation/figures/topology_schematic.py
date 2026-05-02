#!/usr/bin/env python3
"""
Schematic CAIDA AS-level topology grid (2x2) for ACM CCS paper.

Uses Barabasi-Albert model to generate schematic graphs that scale
with real topology stats. RPKI assignment biased toward high-degree nodes.

Encoding:
  - Schematic node count scales with real |V|
  - BA `m` parameter scales with real avg degree
  - Node size reflects local degree
  - Filled (dark gray) = RPKI AS
  - Hollow (white) = non-RPKI AS

Usage:
    python3 evaluation/figures/topology_schematic.py
"""

import matplotlib.pyplot as plt
import matplotlib as mpl
from matplotlib.lines import Line2D
import networkx as nx
import numpy as np
import random

# ─── Real topology stats from datasets ───────────────────────────────────────
TOPOLOGIES = [
    {"label": "(a) AFRINIC Transit-MH",
     "real_n": 904, "real_e": 6676, "rpki": 445, "non_rpki": 459,
     "schem_n": 25, "m": 2, "seed": 3},
    {"label": "(b) ARIN Transit",
     "real_n": 2030, "real_e": 11098, "rpki": 1371, "non_rpki": 659,
     "schem_n": 35, "m": 2, "seed": 7},
    {"label": "(c) LACNIC-AFRINIC Transit",
     "real_n": 3152, "real_e": 24260, "rpki": 1930, "non_rpki": 1222,
     "schem_n": 50, "m": 3, "seed": 11},
    {"label": "(d) LACNIC 5+ MH",
     "real_n": 5008, "real_e": 22544, "rpki": 2671, "non_rpki": 2337,
     "schem_n": 65, "m": 2, "seed": 17},
]

OUT_DIR = "output/figures"

# ─── Style ───────────────────────────────────────────────────────────────────
mpl.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": ["Arial", "Helvetica", "DejaVu Sans"],
    "font.size": 8,
    "axes.linewidth": 0.5,
    "figure.dpi": 300,
})


def build_schematic(n, m, seed):
    random.seed(seed)
    np.random.seed(seed)
    return nx.barabasi_albert_graph(n=n, m=m, seed=seed)


def draw_panel(ax, G, seed, topo):
    rng = np.random.default_rng(seed)

    # Layout — spring with tuned spacing
    pos = nx.spring_layout(G, k=1.8/np.sqrt(len(G)), iterations=500, seed=seed)

    degs = dict(G.degree())
    nodes = list(G.nodes)
    dvals = np.array([degs[n] for n in nodes])

    # Node sizes — degree-modulated
    base = 18
    deg_norm = (dvals - dvals.min()) / max(dvals.max() - dvals.min(), 1)
    sizes = base + deg_norm * 30

    # RPKI assignment — biased toward high degree
    rpki_ratio = topo["rpki"] / topo["real_n"]
    k_rpki = int(round(rpki_ratio * len(nodes)))
    probs = dvals / dvals.sum()
    rpki_set = set(rng.choice(nodes, size=k_rpki, replace=False, p=probs))
    non_rpki = [n for n in nodes if n not in rpki_set]

    # Edges — lighter for less clutter
    nx.draw_networkx_edges(G, pos, ax=ax,
                           edge_color="#999999", width=0.25, alpha=0.5)

    # Non-RPKI: white fill, thin black stroke
    nx.draw_networkx_nodes(G, pos, nodelist=non_rpki, ax=ax,
                           node_size=[sizes[nodes.index(n)] for n in non_rpki],
                           node_color="white", edgecolors="black",
                           linewidths=0.5)

    # RPKI: black fill
    nx.draw_networkx_nodes(G, pos, nodelist=list(rpki_set), ax=ax,
                           node_size=[sizes[nodes.index(n)] for n in rpki_set],
                           node_color="black", edgecolors="black",
                           linewidths=0.3)

    ax.set_axis_off()
    ax.margins(0.05)

    # Label below the panel — single line
    label = f"{topo['label']} ({topo['real_n']:,} ASes)"
    ax.text(0.5, -0.05, label, transform=ax.transAxes,
            ha='center', va='top', fontsize=6)


def main():
    fig, axes = plt.subplots(2, 2, figsize=(3.45, 2.8), facecolor="white")

    for ax, topo in zip(axes.flat, TOPOLOGIES):
        print(f"Generating {topo['label']}...")
        G = build_schematic(topo["schem_n"], topo["m"], topo["seed"])
        draw_panel(ax, G, topo["seed"], topo)

    # Shared legend
    handles = [
        Line2D([0], [0], marker="o", color="none",
               markerfacecolor="black", markeredgecolor="black",
               markeredgewidth=0.3, markersize=5, label="RPKI AS"),
        Line2D([0], [0], marker="o", color="none",
               markerfacecolor="white", markeredgecolor="black",
               markeredgewidth=0.5, markersize=5, label="Non-RPKI AS"),
    ]
    fig.legend(handles=handles, loc="lower center", ncol=2,
               frameon=False, fontsize=6, bbox_to_anchor=(0.5, 0.0),
               handletextpad=0.3, columnspacing=1.0)

    plt.subplots_adjust(left=0.02, right=0.98, top=0.99, bottom=0.14,
                        wspace=0.05, hspace=0.30)
    plt.savefig(f"{OUT_DIR}/topology_schematic.pdf",
                bbox_inches="tight", facecolor="white")
    plt.savefig(f"{OUT_DIR}/topology_schematic.png",
                dpi=300, bbox_inches="tight", facecolor="white")
                bbox_inches="tight", facecolor="white")
    print("Saved: topology_schematic.pdf / .png")


if __name__ == "__main__":
    main()
