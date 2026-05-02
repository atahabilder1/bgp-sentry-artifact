#!/usr/bin/env python3
"""
Figure: Announcement Coverage across topologies.

Single-axis bar chart showing coverage (%) per topology.

Usage:
    python3 evaluation/figures/announcement_coverage.py
"""

import matplotlib
matplotlib.rcParams.update({
    'font.family': 'serif',
    'font.serif': ['Linux Libertine', 'Libertine', 'Times New Roman', 'Times', 'DejaVu Serif'],
    'font.size': 11,
    'axes.labelsize': 12,
    'axes.titlesize': 13,
    'legend.fontsize': 10,
    'xtick.labelsize': 10,
    'ytick.labelsize': 11,
    'figure.dpi': 300,
})
import matplotlib.pyplot as plt
import numpy as np
import json

RESULTS_DIR = "results"
OUT_DIR = "output/figures"

with open(f'{RESULTS_DIR}/observation_completeness.json') as f:
    data = json.load(f)

topos = data["topologies"]
labels = ["AFRINIC", "ARIN", "LAC+AFR", "LACNIC"]
coverage = [t["coverage_pct"] for t in topos]

fig, ax = plt.subplots(figsize=(3.45, 1.78))

x = np.arange(len(labels)) * 0.8
width = 0.30

bars = ax.bar(x, coverage, width,
              color='#555555', edgecolor='#333333', linewidth=0.4)
ax.set_ylabel('Ann. Recorded (%)')
ax.set_ylim(94, 100)
ax.set_yticks([94, 95.5, 97, 98.5, 100])

ax.set_xticks(x)
ax.set_xticklabels(labels, fontsize=10)
ax.set_xlabel('')

ax.grid(True, axis='y', alpha=0.2, linewidth=0.3, linestyle='--')
ax.set_axisbelow(True)

for spine in ax.spines.values():
    spine.set_linewidth(0.5)
ax.tick_params(width=0, length=0)


fig.patch.set_visible(False)

plt.tight_layout(pad=0.4)
plt.savefig(f'{OUT_DIR}/announcement_coverage.png', dpi=300, bbox_inches='tight',
            transparent=True)
plt.savefig(f'{OUT_DIR}/announcement_coverage.pdf', bbox_inches='tight',
            transparent=True)
print("Saved: announcement_coverage.png / .pdf")
