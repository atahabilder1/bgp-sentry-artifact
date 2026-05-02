#!/usr/bin/env python3
"""
Figure: TPS Scalability — Measured BGP-Sentry throughput across topologies.
Bars: RPKI validators + avg degree, Line: aggregate TPS.
Single-column ACM CCS format.

Usage:
    python3 evaluation/figures/tps_scalability.py
"""

import matplotlib
matplotlib.rcParams.update({
    'font.family': 'serif',
    'font.serif': ['Times New Roman', 'Times', 'DejaVu Serif'],
    'font.size': 8,
    'axes.labelsize': 9,
    'xtick.labelsize': 8,
    'ytick.labelsize': 8,
    'figure.dpi': 300,
})
import matplotlib.pyplot as plt
import numpy as np

# ─── Actual BGP-Sentry data (hop=1, Apr 21-22 runs) ─────────────────────────
topo_order = [
    {"name": "AFRINIC",  "rpki": 445,  "avg_deg": 14.8, "mean_bpn": 1597.3, "elapsed": 2396, "committed": 37591},
    {"name": "LACNIC",   "rpki": 2671, "avg_deg": 9.0,  "mean_bpn": 747.7,  "elapsed": 3700, "committed": 63905},
    {"name": "ARIN",     "rpki": 1371, "avg_deg": 10.9, "mean_bpn": 1682.5, "elapsed": 2873, "committed": 70974},
    {"name": "LAC+AFR",  "rpki": 1930, "avg_deg": 15.4, "mean_bpn": 1921.2, "elapsed": 3276, "committed": 111510},
]

rpki_counts = np.array([t["rpki"] for t in topo_order])
avg_degs = np.array([t["avg_deg"] for t in topo_order])
agg_bps = np.array([t["mean_bpn"] * t["rpki"] / t["elapsed"] for t in topo_order])
x_labels = [t['name'] for t in topo_order]
x_pos = np.arange(len(topo_order)) * 0.8
width = 0.17
gap = 0.02

fig, ax1 = plt.subplots(figsize=(3.45, 1.98))

# Bars: RPKI validators
bars1 = ax1.bar(x_pos - width/2 - gap, rpki_counts, width,
                color='#cccccc', edgecolor='#999999', linewidth=0.4,
                label='RPKI Validators', zorder=2)
ax1.set_ylabel('RPKI Validators')
ax1.set_ylim(0, max(rpki_counts) * 1.4)
ax1.set_yticks([0, 500, 1000, 1500, 2000, 2500])

# Bars: avg degree (second left axis via scaling)
ax3 = ax1.twinx()
ax3.spines['right'].set_position(('axes', -0.0))
bars2 = ax3.bar(x_pos + width/2 + gap, avg_degs, width,
                color='#888888', edgecolor='#666666', linewidth=0.4,
                label='Avg. Degree', zorder=2)
ax3.set_ylabel('Avg. Degree')
ax3.set_ylim(0, max(avg_degs) * 2.5)
ax3.set_yticks([0, 5, 10, 15, 20])
ax3.spines['right'].set_visible(False)
ax3.yaxis.set_visible(False)

# Line: aggregate TPS (right y-axis)
ax2 = ax1.twinx()
ax2.plot(x_pos, agg_bps, color='black', linewidth=0.6,
         marker='o', markersize=4, linestyle='solid',
         markerfacecolor='black', label='Throughput (TPS)', zorder=5)

for i, v in enumerate(agg_bps):
    ax2.annotate(f'{v:.0f}', (x_pos[i], v), textcoords="offset points",
                 xytext=(0, 8), ha='center', fontsize=7, fontweight='bold')

ax2.set_ylabel('Throughput (TPS)')
ax2.set_ylim(0, 1500)
ax2.set_yticks([0, 300, 600, 900, 1200, 1500])

ax1.set_xticks(x_pos)
ax1.set_xticklabels(x_labels, fontsize=8)

for ax in [ax1, ax2]:
    for spine in ax.spines.values():
        spine.set_linewidth(0.3)
    ax.tick_params(width=0, length=0)
ax3.tick_params(width=0, length=0)

# Legend
lines = [bars1, bars2, ax2.get_lines()[0]]
labs = ['RPKI Validators', 'Avg. Degree', 'Throughput (TPS)']
ax1.legend(lines, labs, loc='upper center',
           frameon=False, fontsize=6.5, ncol=3, handletextpad=0.3,
           columnspacing=0.6)

fig.patch.set_visible(False)

plt.tight_layout(pad=0.4)
plt.savefig('output/figures/tps_scalability.png',
            dpi=300, bbox_inches='tight', transparent=True)
plt.savefig('output/figures/tps_scalability.pdf',
            bbox_inches='tight', transparent=True)
print("Saved: tps_scalability.png / .pdf")
