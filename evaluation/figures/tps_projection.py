#!/usr/bin/env python3
"""
Figure: Capacity vs Demand line plot with headroom ratio.
Two y-axes: left = throughput (log), right = headroom ratio.
Shows both capacity and demand growing with N, headroom stable/improving.

Usage:
    python3 evaluation/figures/tps_projection.py
"""

import matplotlib
matplotlib.rcParams.update({
    'font.family': 'serif',
    'font.serif': ['Times New Roman', 'Times', 'DejaVu Serif'],
    'font.size': 8,
    'axes.labelsize': 9,
    'axes.titlesize': 9,
    'legend.fontsize': 6.5,
    'xtick.labelsize': 7.5,
    'ytick.labelsize': 7.5,
    'figure.dpi': 300,
})
import matplotlib.pyplot as plt
import numpy as np

# ─── Data ─────────────────────────────────────────────────────────────────────
topo_order = [
    {"name": "AFRINIC",     "nodes": 904,  "rpki": 445,  "elapsed": 2396,
     "committed": 37591,  "mean_bpn": 1597.3},
    {"name": "ARIN",        "nodes": 2030, "rpki": 1371, "elapsed": 2873,
     "committed": 70974,  "mean_bpn": 1682.5},
    {"name": "LACNIC-AFR.", "nodes": 3152, "rpki": 1930, "elapsed": 3276,
     "committed": 111510, "mean_bpn": 1921.2},
    {"name": "LACNIC",      "nodes": 5008, "rpki": 2671, "elapsed": 3700,
     "committed": 63905,  "mean_bpn": 747.7},
]

# Sort by total nodes
topo_order.sort(key=lambda t: t["nodes"])

names     = [t["name"] for t in topo_order]
nodes     = np.array([t["nodes"] for t in topo_order])
rpki      = np.array([t["rpki"] for t in topo_order])
elapsed   = np.array([t["elapsed"] for t in topo_order])
committed = np.array([t["committed"] for t in topo_order])
mean_bpn  = np.array([t["mean_bpn"] for t in topo_order])

# Capacity (blk/s) and Demand (TX/s)
capacity = mean_bpn * rpki / elapsed
demand   = committed / elapsed
headroom = capacity / demand

# ─── Plot ─────────────────────────────────────────────────────────────────────
fig, ax1 = plt.subplots(figsize=(3.45, 2.4))

# Left axis: capacity and demand (log scale)
ln1 = ax1.plot(nodes, capacity, 'ko-', markersize=5, linewidth=1.2,
               label='Capacity (blk/s)', zorder=5)
ln2 = ax1.plot(nodes, demand, 's--', color='#777777', markersize=4.5,
               linewidth=1.0, label='Demand (TX/s)', zorder=5,
               markerfacecolor='#999999')

# Fill between to highlight the gap
ax1.fill_between(nodes, demand, capacity, alpha=0.08, color='black')

# Annotate capacity values
for i in range(len(nodes)):
    ax1.annotate(f'{capacity[i]:.0f}', (nodes[i], capacity[i]),
                 textcoords="offset points", xytext=(0, 7),
                 ha='center', fontsize=5.5, fontweight='bold')
    ax1.annotate(f'{demand[i]:.0f}', (nodes[i], demand[i]),
                 textcoords="offset points", xytext=(0, -10),
                 ha='center', fontsize=5.5, color='#555555')

ax1.set_yscale('log')
ax1.set_xlabel('Topology Size (ASes)')
ax1.set_ylabel('Throughput (log scale)')
ax1.set_ylim(5, max(capacity) * 3)
ax1.set_xlim(nodes[0] - 200, nodes[-1] + 300)

# Right axis: headroom ratio
ax2 = ax1.twinx()
ln3 = ax2.plot(nodes, headroom, 'D-', color='black', markersize=4,
               linewidth=0.8, label='Headroom ratio (H)',
               markerfacecolor='white', markeredgewidth=1.0, zorder=4)

for i in range(len(nodes)):
    ax2.annotate(f'{headroom[i]:.0f}x', (nodes[i], headroom[i]),
                 textcoords="offset points", xytext=(8, 0),
                 ha='left', fontsize=6, fontweight='bold')

ax2.set_ylabel('Headroom Ratio (H)', fontsize=8)
ax2.set_ylim(0, max(headroom) * 1.8)
for spine in ax2.spines.values():
    spine.set_linewidth(0.5)
    spine.set_visible(True)

# X-axis: topology names
ax1.set_xticks(nodes)
ax1.set_xticklabels([f'{n}\n({nodes[i]:,})' for i, n in enumerate(names)],
                     fontsize=6)

# Combined legend
lns = ln1 + ln2 + ln3
labs = [l.get_label() for l in lns]
ax1.legend(lns, labs, loc='center left', fontsize=5.5, frameon=True,
           framealpha=0.9, edgecolor='lightgray')

for spine in ax1.spines.values():
    spine.set_linewidth(0.5)
    spine.set_visible(True)
ax1.tick_params(width=0.5, length=3)
ax1.grid(True, axis='y', alpha=0.12, linewidth=0.3, linestyle='--')
ax1.set_axisbelow(True)
ax1.yaxis.set_minor_locator(plt.NullLocator())

plt.tight_layout(pad=0.4)
plt.savefig('output/figures/tps_projection.png',
            dpi=300, bbox_inches='tight')
plt.savefig('output/figures/tps_projection.pdf',
            bbox_inches='tight')
print("Saved: tps_projection.png / .pdf")

for i in range(len(nodes)):
    print(f"  {names[i]}: capacity={capacity[i]:.0f}, demand={demand[i]:.1f}, H={headroom[i]:.0f}x")
