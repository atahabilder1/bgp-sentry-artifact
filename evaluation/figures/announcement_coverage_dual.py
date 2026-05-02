#!/usr/bin/env python3
"""
Figure: Announcement Coverage + RPKI Adoption (dual bar chart).

Usage:
    python3 evaluation/figures/announcement_coverage_dual.py
"""

import matplotlib
matplotlib.rcParams.update({
    'font.family': 'sans-serif',
    'font.sans-serif': ['Arial', 'Helvetica', 'DejaVu Sans'],
    'font.size': 10.5,
    'axes.labelsize': 11.5,
    'xtick.labelsize': 10.5,
    'ytick.labelsize': 10.5,
    'figure.dpi': 300,
    'pdf.fonttype': 42,
    'ps.fonttype': 42,
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
rpki_pct = [49.2, 67.5, 61.2, 53.3]

fig, ax = plt.subplots(figsize=(3.33, 2.0))

x = np.arange(len(labels))
width = 0.27
gap = 0.03

bars1 = ax.bar(x - width/2 - gap/2, coverage, width,
               color='#cce0f0', edgecolor='#444444', linewidth=0.5,
               label='Event Coverage')
bars2 = ax.bar(x + width/2 + gap/2, rpki_pct, width,
               color='#336699', edgecolor='#444444', linewidth=0.5,
               label='RPKI Adoption')

ax.set_ylabel('Percentage (%)', fontsize=10)
ax.set_ylim(0, 120)
ax.set_yticks([0, 25, 50, 75, 100])

ax.set_xlim(-0.6, 3.6)
ax.set_xticks(x)
ax.set_xticklabels(labels)
ax.set_xlabel('')

for spine in ax.spines.values():
    spine.set_linewidth(0.4)
    spine.set_visible(True)
ax.tick_params(width=0, length=0)

ax.legend(loc='upper center', frameon=False, fontsize=8,
          ncol=2, handletextpad=0.3, columnspacing=0.8,
          bbox_to_anchor=(0.5, 1.0))

ax.set_axisbelow(True)

plt.tight_layout(pad=0.4)
plt.savefig(f'{OUT_DIR}/announcement_coverage.png', dpi=300, bbox_inches='tight')
plt.savefig(f'{OUT_DIR}/announcement_coverage.pdf', bbox_inches='tight')
print("Saved: announcement_coverage.png / .pdf")
