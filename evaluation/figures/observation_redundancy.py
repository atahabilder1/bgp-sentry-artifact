#!/usr/bin/env python3
"""
Figure: Observation Redundancy across topologies (appendix).

Single-axis bar chart showing redundancy (obs per unique event per hour).

Usage:
    python3 evaluation/figures/observation_redundancy.py
"""

import matplotlib
matplotlib.rcParams.update({
    'font.family': 'serif',
    'font.serif': ['Times New Roman', 'Times', 'DejaVu Serif'],
    'font.size': 8,
    'axes.labelsize': 9,
    'axes.titlesize': 10,
    'legend.fontsize': 7,
    'xtick.labelsize': 7,
    'ytick.labelsize': 8,
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
labels = [t["name"] for t in topos]
SIM_HOURS = 12
redundancy = [t["obs_per_unique"] / SIM_HOURS for t in topos]

fig, ax = plt.subplots(figsize=(3.45, 1.8))

x = np.arange(len(labels))
width = 0.45

bars = ax.bar(x, redundancy, width,
              color='#bbbbbb', edgecolor='#888888', linewidth=0.4)
ax.set_ylabel('Obs. per Unique Event per Hour')
ax.set_ylim(0, 160)

ax.set_xticks(x)
ax.set_xticklabels(labels, fontsize=7)
ax.set_xlabel('Topology Size (ASes)')

ax.grid(True, axis='y', alpha=0.2, linewidth=0.3, linestyle='--')
ax.set_axisbelow(True)

for spine in ax.spines.values():
    spine.set_linewidth(0.5)
ax.tick_params(width=0.5, length=3)

for bar in bars:
    height = bar.get_height()
    ax.text(bar.get_x() + bar.get_width()/2., height + 2,
            f'{height:.1f}\u00d7', ha='center', va='bottom', fontsize=6, fontweight='bold')

fig.patch.set_visible(False)

plt.tight_layout(pad=0.4)
plt.savefig(f'{OUT_DIR}/observation_redundancy.png', dpi=300, bbox_inches='tight',
            transparent=True)
plt.savefig(f'{OUT_DIR}/observation_redundancy.pdf', bbox_inches='tight',
            transparent=True)
print("Saved: observation_redundancy.png / .pdf")
