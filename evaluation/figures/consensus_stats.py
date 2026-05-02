#!/usr/bin/env python3
"""Figure: Consensus status distribution (single y-axis, 3 bars per topology).
Updated with origin_neighbors voter selection results."""

import matplotlib
matplotlib.use("pdf")
matplotlib.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": ["Arial", "Helvetica", "DejaVu Sans"],
    "font.size": 12,
    "axes.labelsize": 12,
    "xtick.labelsize": 11,
    "ytick.labelsize": 11,
    "legend.fontsize": 9,
    "axes.linewidth": 0.5,
})

import matplotlib.pyplot as plt
import numpy as np

# --- Data from consensus_origin_neighbors_comparison.json ---
topologies = [904, 2030, 3152, 5008]
topo_names = ["AFRINIC", "ARIN", "LAC+AFR", "LACNIC"]

raw = {
    904:  {"CONFIRMED": 885444, "INSUFFICIENT_CONSENSUS": 50105, "SINGLE_WITNESS": 4342},
    2030: {"CONFIRMED": 8539410, "INSUFFICIENT_CONSENSUS": 336705, "SINGLE_WITNESS": 32987},
    3152: {"CONFIRMED": 16243148, "INSUFFICIENT_CONSENSUS": 526902, "SINGLE_WITNESS": 36893},
    5008: {"CONFIRMED": 24037610, "INSUFFICIENT_CONSENSUS": 1698510, "SINGLE_WITNESS": 134407},
}

confirmed_pct, endorsed_pct, observed_pct = [], [], []
for t in topologies:
    d = raw[t]
    total = d["CONFIRMED"] + d["INSUFFICIENT_CONSENSUS"] + d["SINGLE_WITNESS"]
    confirmed_pct.append(d["CONFIRMED"] / total * 100)
    endorsed_pct.append(d["INSUFFICIENT_CONSENSUS"] / total * 100)
    observed_pct.append(d["SINGLE_WITNESS"] / total * 100)

# --- Plot: single y-axis, 3 bars per topology ---
fig, ax = plt.subplots(figsize=(3.33, 1.84))

x = np.arange(len(topologies)) * 0.8
width = 0.20
gap = 0.03

bars1 = ax.bar(x - width - gap, confirmed_pct, width,
               color='#cce0f0', edgecolor='#444444', linewidth=0.5,
               label=u'\u22653 votes')
scale = 2
bars2 = ax.bar(x, [v * scale for v in endorsed_pct], width,
               color='#7bafd4', edgecolor='#444444', linewidth=0.5,
               label=u'1\u20132 votes')
bars3 = ax.bar(x + width + gap, [v * scale for v in observed_pct], width,
               color='#336699', edgecolor='#444444', linewidth=0.5,
               label='0 votes')

ax.set_ylabel('Transaction (%)', fontsize=10)
ax.set_ylim(0, 120)
ax.set_yticks([0, 25, 50, 75, 100])

ax.set_xticks(x)
ax.set_xticklabels(topo_names, fontsize=9)

ax.grid(False)

for spine in ax.spines.values():
    spine.set_linewidth(0.3)
ax.tick_params(width=0, length=0)

# Legend horizontal across x-axis
ax.legend(loc='upper center', frameon=False, fontsize=8,
          ncol=3, handletextpad=0.3, columnspacing=0.8)

fig.patch.set_visible(False)

fig.tight_layout(pad=0.4)
fig.savefig("output/figures/consensus_distribution.pdf",
            bbox_inches="tight", transparent=True)
            bbox_inches="tight", transparent=True)
print("Saved: consensus_distribution.pdf")

for i, t in enumerate(topologies):
    print(f"  {t}: Confirmed={confirmed_pct[i]:.1f}%  "
          f"Insufficient={endorsed_pct[i]:.1f}%  SingleWitness={observed_pct[i]:.1f}%")
