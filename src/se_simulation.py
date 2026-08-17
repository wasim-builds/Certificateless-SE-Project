import matplotlib.pyplot as plt
import numpy as np
import os

# Create output directory
os.makedirs('../paper', exist_ok=True)

# ---------------------------------------------------------
# Define Computational Costs (in milliseconds on a typical IoT ARM Cortex)
# ---------------------------------------------------------
T_p = 15.0  # Bilinear Pairing
T_m = 1.5   # Scalar Point Multiplication
T_h = 2.0   # Map-to-Point Hash

# Number of keywords to encrypt/search
num_keywords = np.arange(10, 110, 10)

# ---------------------------------------------------------
# 1. Encryption Phase Execution Time
# ---------------------------------------------------------
# Lu et al.: 2Tp + 4Tm
enc_lu = (2*T_p + 4*T_m) * num_keywords
# Elhabob: 5Tm
enc_elhabob = (5*T_m) * num_keywords
# Liu et al.: 4Tm + 2Th
enc_liu = (4*T_m + 2*T_h) * num_keywords
# Ours: 2Tm + 1Th
enc_ours = (2*T_m + 1*T_h) * num_keywords

plt.figure(figsize=(8, 6))
plt.plot(num_keywords, enc_lu, marker='o', linestyle='-', label='Lu et al. [1]', color='blue', linewidth=2)
plt.plot(num_keywords, enc_elhabob, marker='s', linestyle='--', label='Elhabob [2]', color='orange', linewidth=2)
plt.plot(num_keywords, enc_liu, marker='^', linestyle='-.', label='Liu et al. [3]', color='green', linewidth=2)
plt.plot(num_keywords, enc_ours, marker='D', linestyle='-', label='Ours (Scheme X)', color='red', linewidth=3)

plt.xlabel('Number of Keywords', fontsize=12, fontweight='bold')
plt.ylabel('Execution Time (ms)', fontsize=12, fontweight='bold')
plt.title('Data Owner: Encryption Time vs. Number of Keywords', fontsize=14, fontweight='bold')
plt.legend(fontsize=11)
plt.grid(True, linestyle=':', alpha=0.7)
plt.tight_layout()
plt.savefig('../paper/enc_time.eps', format='eps')
plt.close()

# ---------------------------------------------------------
# 2. Search Phase Execution Time
# ---------------------------------------------------------
# Lu et al.: 2Tp + 1Tm
search_lu = (2*T_p + 1*T_m) * num_keywords
# Elhabob: 4Tp
search_elhabob = (4*T_p) * num_keywords
# Liu et al.: 6Tm
search_liu = (6*T_m) * num_keywords
# Ours: 2Tm
search_ours = (2*T_m) * num_keywords

plt.figure(figsize=(8, 6))
plt.plot(num_keywords, search_lu, marker='o', linestyle='-', label='Lu et al. [1]', color='blue', linewidth=2)
plt.plot(num_keywords, search_elhabob, marker='s', linestyle='--', label='Elhabob [2]', color='orange', linewidth=2)
plt.plot(num_keywords, search_liu, marker='^', linestyle='-.', label='Liu et al. [3]', color='green', linewidth=2)
plt.plot(num_keywords, search_ours, marker='D', linestyle='-', label='Ours (Scheme X)', color='red', linewidth=3)

plt.xlabel('Number of Trapdoors Tested', fontsize=12, fontweight='bold')
plt.ylabel('Execution Time (ms)', fontsize=12, fontweight='bold')
plt.title('Cloud Server: Search Time vs. Evaluated Trapdoors', fontsize=14, fontweight='bold')
plt.legend(fontsize=11)
plt.grid(True, linestyle=':', alpha=0.7)
plt.tight_layout()
plt.savefig('../paper/search_time.eps', format='eps')
plt.close()

# ---------------------------------------------------------
# 3. Communication Cost (Trapdoor Size) Bar Chart
# ---------------------------------------------------------
# Assuming elements in G are 32 bytes (256-bit curve)
# Lu et al.: 3 elements = 96 bytes
# Elhabob: 1 element = 32 bytes (but no OKGA resistance)
# Liu et al.: 3 elements = 96 bytes
# Ours: 2 elements = 64 bytes
labels = ['Lu et al.', 'Elhabob (Insecure)', 'Liu et al.', 'Ours']
trapdoor_sizes = [96, 32, 96, 64]

plt.figure(figsize=(8, 5))
bars = plt.bar(labels, trapdoor_sizes, color=['blue', 'orange', 'green', 'red'], edgecolor='black')

plt.ylabel('Trapdoor Size (Bytes)', fontsize=12, fontweight='bold')
plt.title('Communication Overhead: Trapdoor Bandwidth', fontsize=14, fontweight='bold')

for bar in bars:
    yval = bar.get_height()
    plt.text(bar.get_x() + bar.get_width()/2.0, yval + 2, f'{yval} B', ha='center', va='bottom', fontsize=11, fontweight='bold')

plt.ylim(0, 120)
plt.tight_layout()
plt.savefig('../paper/comm_cost.eps', format='eps')
plt.close()

print("Generated enc_time.eps, search_time.eps, and comm_cost.eps in the paper/ directory.")
