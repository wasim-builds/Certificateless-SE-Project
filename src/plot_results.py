import matplotlib.pyplot as plt
import numpy as np
import os

# Estimated times in milliseconds based on standard ECC vs Pairing benchmarks
# Tp (Pairing) ~ 5.4 ms
# Tm (Scalar Mult) ~ 2.1 ms
# Th (Map to point) ~ 0.01 ms (negligible, but we'll add a tiny bit)

# Lu et al: Encrypt(2Tp+4Tm) = 19.2, Trapdoor(1Tp+3Tm) = 11.7, Test(2Tp+1Tm) = 12.9
# Elhabob et al: Encrypt(5Tm) = 10.5, Trapdoor(0) = 0, Test(4Tp) = 21.6
# Liu et al: Encrypt(4Tm) = 8.4, Trapdoor(3Tm) = 6.3, Test(6Tm) = 12.6
# Ours: Encrypt(2Tm) = 4.2, Trapdoor(2Tm) = 4.2, Search(2Tm) = 4.2

labels = ['Lu et al. [1]', 'Elhabob et al. [2]', 'Liu et al. [3]', 'Proposed Scheme X']
encrypt_times = [19.2, 10.5, 8.4, 4.2]
trapdoor_times = [11.7, 0.0, 6.3, 4.2]
search_times = [12.9, 21.6, 12.6, 4.2]

x = np.arange(len(labels))
width = 0.25

fig, ax = plt.subplots(figsize=(8, 5))
rects1 = ax.bar(x - width, encrypt_times, width, label='Encrypt', color='#3498db', edgecolor='black')
rects2 = ax.bar(x, trapdoor_times, width, label='Trapdoor', color='#2ecc71', edgecolor='black')
rects3 = ax.bar(x + width, search_times, width, label='Search/Test', color='#e74c3c', edgecolor='black')

ax.set_ylabel('Execution Time (ms)', fontsize=12, fontweight='bold')
ax.set_title('Computational Overhead Comparison (128-bit security)', fontsize=14, fontweight='bold')
ax.set_xticks(x)
ax.set_xticklabels(labels, fontsize=11)
ax.legend(fontsize=11)
ax.grid(axis='y', linestyle='--', alpha=0.7)

fig.tight_layout()

# Save the figure to the paper directory
out_path = '/run/media/wasim/2ADE-F06D/research/Certificateless-SE-Project/paper/performance_comparison.eps'
plt.savefig(out_path, format='eps', dpi=300)
print(f"[*] Successfully saved graph to {out_path}")
