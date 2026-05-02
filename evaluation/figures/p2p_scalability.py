#!/usr/bin/env python3
"""
Figure: P2P Communication Scalability — BGP-Sentry vs Conventional Blockchain Models.

Shows actual BGP-Sentry P2P message counts alongside theoretical message counts
for conventional consensus models (PBFT O(n²), Gossip O(n·log(n)), Full Flood O(n²))
to demonstrate that BGP-Sentry's per-node chain architecture scales sublinearly.

Usage:
    python3 evaluation/figures/p2p_scalability.py
"""

import matplotlib
matplotlib.rcParams.update({
    'font.family': 'sans-serif',
    'font.sans-serif': ['Arial', 'Helvetica', 'DejaVu Sans'],
    'font.size': 9,
    'axes.labelsize': 9,
    'axes.titlesize': 9,
    'legend.fontsize': 9,
    'xtick.labelsize': 9,
    'ytick.labelsize': 9,
    'figure.dpi': 300,
})
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np

# ─── Actual BGP-Sentry data (hop=1, Apr 21-22 modified code runs) ───────────
# (nodes = RPKI validators, since only they participate in consensus)
data = {
    "904":  {"rpki": 445,  "p2p_total": 732_455,   "elapsed": 2396, "committed": 37_591},
    "2030": {"rpki": 1371, "p2p_total": 2_367_724, "elapsed": 2873, "committed": 70_974},
    "3152": {"rpki": 1930, "p2p_total": 4_126_130, "elapsed": 3276, "committed": 111_510},
    "5008": {"rpki": 2671, "p2p_total": 2_478_275, "elapsed": 3700, "committed": 63_905},
}

# Sort by RPKI node count
sorted_keys = sorted(data.keys(), key=lambda k: data[k]["rpki"])
n_nodes = np.array([data[k]["rpki"] for k in sorted_keys])
p2p_total = np.array([data[k]["p2p_total"] for k in sorted_keys])
p2p_per_sec = np.array([data[k]["p2p_total"] / data[k]["elapsed"] for k in sorted_keys])
committed = np.array([data[k]["committed"] for k in sorted_keys])

# ─── Theoretical models (per consensus round × number of rounds) ────────────
# We normalize so that conventional models produce the same number of committed
# transactions as BGP-Sentry did, but with their own message complexity.
#
# For each topology, we compute: messages = committed_tx × msg_per_round(n)
#
# PBFT:          O(n²) messages per consensus round (all-to-all)
# Gossip flood:  O(n·log(n)) per round (epidemic protocol)
# Full broadcast: O(n) per round but every node broadcasts → O(n²) total

# Use the smallest topology as the normalization anchor:
# At n=445, BGP-Sentry used 732,455 messages for 37,591 txs → ~19.5 msg/tx
# We scale conventional models relative to this baseline.
n_range = np.linspace(n_nodes[0], n_nodes[-1], 200)

# Theoretical per-tx message costs
def pbft_messages(n, tx_count):
    """PBFT: 3 phases × n² messages per round (pre-prepare, prepare, commit)."""
    return tx_count * 3 * n * n

def gossip_messages(n, tx_count):
    """Gossip/epidemic: each tx propagated to O(n·log(n)) peers."""
    return tx_count * n * np.log2(n)

def raft_messages(n, tx_count):
    """Raft/leader-based: leader sends to all followers + ACKs → O(n) per tx."""
    return tx_count * 2 * n

# Average committed txs across topologies for theoretical curves
avg_tx_per_node = np.mean(committed / n_nodes)  # tx per node ratio

# ─── Single Plot: Messages per Committed Transaction ─────────────────────────
# ACM CCS single-column
fig, ax = plt.subplots(figsize=(3.33, 2.5))

msg_per_tx_bgp = p2p_total / committed
msg_per_tx_pbft = 3 * n_nodes * n_nodes  # per tx
msg_per_tx_gossip = n_nodes * np.log2(n_nodes)
msg_per_tx_raft = 2 * n_nodes

x_pos = np.arange(len(n_nodes))
ax.plot(x_pos, msg_per_tx_pbft, color='black', linewidth=0.8,
        marker='s', markersize=4.5, label='PBFT  O(n²)', linestyle='-',
        markerfacecolor='black')
ax.plot(x_pos, msg_per_tx_gossip, color='#555555', linewidth=0.8,
        marker='^', markersize=5, label='Gossip  O(n log n)',
        linestyle='--', markerfacecolor='#555555')
ax.plot(x_pos, msg_per_tx_raft, color='#888888', linewidth=0.8,
        marker='D', markersize=4, label='Raft  O(n)',
        linestyle=':', markerfacecolor='#888888')
ax.plot(x_pos, msg_per_tx_bgp, color='#aaaaaa', linewidth=0.8,
        marker='o', markersize=4.5, label='BGP-Sentry', zorder=5,
        linestyle='-', markerfacecolor='white', markeredgecolor='#666666',
        markeredgewidth=1.0)

topo_labels = ["AFRINIC", "ARIN", "LAC+AFR", "LACNIC"]

x_pos = np.arange(len(n_nodes))
ax.set_xticks(x_pos)
ax.set_xticklabels(topo_labels)
ax.set_ylabel('P2P Messages / Tx')
ax.set_yscale('log')
ax.set_ylim(1, 10**10.5)
ax.set_yticks([10, 100, 10000, 1000000, 100000000])
ax.set_yticklabels(['10', '100', '10K', '1M', '100M'])
ax.yaxis.set_minor_locator(plt.NullLocator())
ax.set_xlim(-0.5, len(n_nodes) - 0.5)
ax.legend(loc='upper center', ncol=2, handletextpad=0.3, framealpha=0.9,
          handlelength=2.0,
          columnspacing=0.8, frameon=False)
ax.grid(True, alpha=0.2, linewidth=0.3)
for spine in ax.spines.values():
    spine.set_linewidth(0.3)
ax.tick_params(width=0, length=0)

plt.subplots_adjust(left=0.16, right=0.92, top=0.90, bottom=0.30)
plt.savefig('output/figures/p2p_scalability.png', dpi=300, bbox_inches='tight')
plt.savefig('output/figures/p2p_scalability.pdf', bbox_inches='tight')
print("Saved: p2p_scalability.png / .pdf")
