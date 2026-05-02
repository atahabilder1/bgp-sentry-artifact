#!/usr/bin/env python3
"""
Figure: Observation Completeness across topologies.

Dual-axis grouped bar chart showing:
  - Coverage (%) on left y-axis
  - Observation redundancy (×) on right y-axis

Usage:
    python3 evaluation/figures/observation_completeness.py
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
labels = ["AFRINIC", "ARIN", "LAC+AFR", "LACNIC"]
coverage = [t["coverage_pct"] for t in topos]
SIM_HOURS = 12
redundancy = [t["obs_per_unique"] / SIM_HOURS for t in topos]

# ─── Plot: Dual-axis grouped bar chart ──────────────────────────────────────
fig, ax1 = plt.subplots(figsize=(3.45, 1.8))

x = np.arange(len(labels))
width = 0.30

gap = 0.07
bars1 = ax1.bar(x - width/2 - gap/2, coverage, width,
                color='#555555', edgecolor='#333333', linewidth=0.4,
                label='Coverage (%)')
ax1.set_ylabel('Announcements Recorded (%)')
ax1.set_ylim(94, 102)
ax1.yaxis.set_major_locator(plt.MultipleLocator(2))

ax2 = ax1.twinx()
bars2 = ax2.bar(x + width/2 + gap/2, redundancy, width,
                color='#bbbbbb', edgecolor='#888888', linewidth=0.4,
                label=u'Redundancy (\u00d7/hr)')
ax2.set_ylabel('Obs. per Unique Event per Hour')
ax2.set_ylim(0, 250)

ax1.set_xticks(x)
ax1.set_xticklabels(labels, fontsize=7)

ax1.grid(True, axis='y', alpha=0.2, linewidth=0.3, linestyle='--')
ax1.set_axisbelow(True)

# Spines
for ax in [ax1, ax2]:
    ax.spines['top'].set_linewidth(0.5)
    ax.spines['left'].set_linewidth(0.5)
    ax.spines['right'].set_linewidth(0.5)
    ax.spines['bottom'].set_linewidth(0.5)
    ax.tick_params(width=0.5, length=3)

# Combined legend
lines1, labels1 = ax1.get_legend_handles_labels()
lines2, labels2 = ax2.get_legend_handles_labels()
ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper center', frameon=False,
           fontsize=6, ncol=2)

# Value labels on bars
for bar in bars1:
    height = bar.get_height()
    ax1.text(bar.get_x() + bar.get_width()/2., height + 0.15,
             f'{height:.1f}%', ha='center', va='bottom', fontsize=6, fontweight='bold')

for bar in bars2:
    height = bar.get_height()
    ax2.text(bar.get_x() + bar.get_width()/2., height + 15,
             f'{height:.1f}\u00d7', ha='center', va='bottom', fontsize=6, fontweight='bold')

fig.patch.set_visible(False)

plt.tight_layout(pad=0.4)
plt.savefig(f'{OUT_DIR}/observation_completeness.png', dpi=300, bbox_inches='tight',
            transparent=True)
plt.savefig(f'{OUT_DIR}/observation_completeness.pdf', bbox_inches='tight',
            transparent=True)
print("Saved: observation_completeness.png / .pdf")
