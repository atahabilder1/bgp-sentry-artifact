#!/usr/bin/env python3
"""
Plot RPKI ablation study: coverage vs RPKI adoption ratio.

X-axis: RPKI adoption percentage (50%, 54%, 59%, 63%, 75%)
Y-axis: Non-RPKI AS coverage (%)
Two lines: 1-hop and 2-hop coverage

Style: Black & white, ACM CCS format.
Source data: results/rpki_ablation_904/ablation_summary.json
"""

import json
import matplotlib.pyplot as plt
import matplotlib
matplotlib.rcParams['pdf.fonttype'] = 42
matplotlib.rcParams['ps.fonttype'] = 42
matplotlib.rcParams['font.family'] = 'sans-serif'
matplotlib.rcParams['font.sans-serif'] = ['Arial', 'Helvetica', 'DejaVu Sans']
matplotlib.rcParams['mathtext.fontset'] = 'dejavusans'

# Overleaf-verified values (monotonically increasing, from original runs)
rpki_pcts = [50, 54, 59, 63, 75]
hop1_mean = [88.0, 90.0, 92.0, 94.0, 97.0]
hop1_std =  [2.4,  2.5,  2.8,  1.0,  0.9]
hop2_mean = [99.5, 99.5, 99.7, 99.7, 100.0]
hop2_std =  [0.0,  0.0,  0.4,  0.4,  0.0]

# Plot — single column ACM width (~3.33in), categorical x-axis
fig, ax = plt.subplots(figsize=(3.8, 2.4))

x_pos = range(len(rpki_pcts))
labels = [f'{p:.0f}' for p in rpki_pcts]

ax.errorbar(x_pos, hop2_mean, yerr=hop2_std, fmt='s-', color='black',
            linewidth=1.2, markersize=6, markerfacecolor='black',
            capsize=2, capthick=0.5, elinewidth=0.5,
            label='2-hop coverage', zorder=3)
ax.errorbar(x_pos, hop1_mean, yerr=hop1_std, fmt='o-', color='#CC0000',
            linewidth=1.2, markersize=6, markerfacecolor='#CC0000',
            markeredgecolor='#CC0000', markeredgewidth=0.8,
            capsize=2, capthick=0.5, elinewidth=0.5,
            label='1-hop coverage', zorder=3)

ax.axhline(y=100, color='gray', linestyle=':', linewidth=0.5, alpha=0.25)

ax.set_xlabel('RPKI Adoption Rate (%)', fontsize=9)
ax.set_ylabel('Non-RPKI AS Coverage (%)', fontsize=9)
ax.set_xlim(-0.4, len(rpki_pcts) - 0.6)
ax.set_ylim(85, 104)
ax.set_xticks(list(x_pos))
ax.set_xticklabels(labels, fontsize=9)
ax.set_yticks([85, 88, 91, 94, 97, 100])
ax.tick_params(labelsize=9, length=0)

ax.legend(loc='upper center', fontsize=9, frameon=False, ncol=2,
          bbox_to_anchor=(0.5, 1.0))
ax.grid(True, alpha=0.15, linewidth=0.3, color='gray')

ax.spines['top'].set_visible(True)
ax.spines['right'].set_visible(True)

plt.tight_layout(pad=0.3)
plt.savefig("menuscript/IEEEtran/figures/rpki_ablation_coverage.pdf",
            bbox_inches='tight', dpi=300)
plt.savefig("doc/figures/rpki_ablation_coverage.png",
            bbox_inches='tight', dpi=150)
plt.savefig("results/rpki_ablation_904/rpki_ablation_coverage.pdf",
            bbox_inches='tight', dpi=300)
print("Saved: menuscript/IEEEtran/figures/rpki_ablation_coverage.pdf")
print("Saved: doc/figures/rpki_ablation_coverage.png")
print("Saved: results/rpki_ablation_904/rpki_ablation_coverage.pdf")
