import os
import shutil
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

# Ensure scratch directory exists
os.makedirs('/workspace/scratch', exist_ok=True)

# Set random seed for reproducibility
np.random.seed(1337)

# -----------------------------------------------------------------------------
# 1. GENERATE BASELINE AND POISONED TRAINING DATA
# -----------------------------------------------------------------------------
# Normal traffic rate: Mean of 100 packets/sec, std dev of 12
n_clean = 100
clean_data = np.random.normal(loc=100, scale=12, size=n_clean)

# Poisoned training data (the "Boiling Frog" simulation)
# An attacker slowly injects chaff over 15 days to drift the baseline
poison_chaff = np.array([12, 18, 25, 35, 48, 62, 78, 95, 115, 138, 160, 185, 210, 235, 260])
# The poisoned dataset contains 85 normal days and 15 poisoned days
poisoned_days = clean_data[:85] + np.random.normal(loc=0, scale=8, size=85) # base
poisoned_days = np.concatenate([poisoned_days, clean_data[85:] + poison_chaff])

# Let's verify the size
assert len(poisoned_days) == 100

# -----------------------------------------------------------------------------
# 2. DEFINE DEFENSIVE STATISTICAL DETECTORS
# -----------------------------------------------------------------------------
# Classical Z-score components (Clean vs Poisoned)
mean_clean = np.mean(clean_data)
std_clean = np.std(clean_data)
thresh_z_clean = mean_clean + 3.0 * std_clean

mean_poison = np.mean(poisoned_days)
std_poison = np.std(poisoned_days)
thresh_z_poison = mean_poison + 3.0 * std_poison

# Robust Z-score components (Clean vs Poisoned) using MAD
median_clean = np.median(clean_data)
mad_clean = np.median(np.abs(clean_data - median_clean))
# scale factor b = 1.4826 to align MAD with standard deviation for normal distribution
sigma_mad_clean = 1.4826 * mad_clean
thresh_robust_clean = median_clean + 3.0 * sigma_mad_clean

median_poison = np.median(poisoned_days)
mad_poison = np.median(np.abs(poisoned_days - median_poison))
sigma_mad_poison = 1.4826 * mad_poison
thresh_robust_poison = median_poison + 3.0 * sigma_mad_poison

# Print results to stdout for verification
print(f"--- CLASSICAL ESTIMATORS ---")
print(f"Clean Mean: {mean_clean:.2f} | Clean Std Dev: {std_clean:.2f} | Threshold (3-sigma): {thresh_z_clean:.2f}")
print(f"Poisoned Mean: {mean_poison:.2f} | Poisoned Std Dev: {std_poison:.2f} | Threshold (3-sigma): {thresh_z_poison:.2f}")
print(f"Result: Traditional Threshold bloated by {((thresh_z_poison - thresh_z_clean) / thresh_z_clean) * 100:.1f}%\n")

print(f"--- ROBUST ESTIMATORS (MAD) ---")
print(f"Clean Median: {median_clean:.2f} | Clean MAD-Sigma: {sigma_mad_clean:.2f} | Threshold: {thresh_robust_clean:.2f}")
print(f"Poisoned Median: {median_poison:.2f} | Poisoned MAD-Sigma: {sigma_mad_poison:.2f} | Threshold: {thresh_robust_poison:.2f}")
print(f"Result: Robust Threshold changed by only {((thresh_robust_poison - thresh_robust_clean) / thresh_robust_clean) * 100:.1f}%")

# -----------------------------------------------------------------------------
# 3. TEST SET PERFORMANCE EVALUATION
# -----------------------------------------------------------------------------
# Standard test set: 30 days of clean traffic + 5 days of attack (size = ~350, i.e., total ~450 packets)
test_clean = np.random.normal(loc=100, scale=12, size=30)
test_attack = np.array([450.0, 442.0, 458.0, 435.0, 460.0]) # Massive DoS / Exfil attack
test_data = np.concatenate([test_clean, test_attack])

# Evaluate classical Z-score under poisoned baseline
z_scores_traditional = (test_data - mean_poison) / std_poison
detected_traditional = z_scores_traditional > 3.0

# Evaluate robust Z-score under poisoned baseline
z_scores_robust = (test_data - median_poison) / sigma_mad_poison
detected_robust = z_scores_robust > 3.0

# Export confusion summary
eval_df = pd.DataFrame({
    'Day': range(1, len(test_data) + 1),
    'Actual Traffic': test_data,
    'Is Attack': [False]*30 + [True]*5,
    'Traditional Z-score': z_scores_traditional,
    'Traditional Flagged': detected_traditional,
    'Robust Z-score': z_scores_robust,
    'Robust Flagged': detected_robust
})

# -----------------------------------------------------------------------------
# 4. PLOT SIDE-BY-SIDE VISUALIZATION
# -----------------------------------------------------------------------------
sns.set_theme(style='whitegrid', palette='colorblind', font='DejaVu Sans')

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))

# Plot 1: The Training Phase (How the baseline got poisoned)
ax1.plot(clean_data, label='Clean Normal Baseline', color='#2b5c8f', alpha=0.5, linestyle=':')
ax1.plot(poisoned_days, label='Injected Boiling Frog Traffic (Poisoned)', color='#e7298a', linewidth=1.5)
ax1.axhline(y=thresh_z_poison, color='#d95f02', linestyle='--', label=f'Poisoned Traditional Thresh ({thresh_z_poison:.1f})')
ax1.axhline(y=thresh_robust_poison, color='#1b9e77', linestyle='-.', label=f'Poisoned Robust Thresh ({thresh_robust_poison:.1f})')
ax1.set_title('Training Phase: Classical Threshold Bloats (Drifts Up) Under Slow Poisoning', fontsize=12, fontweight='bold')
ax1.set_xlabel('Days of Training Phase')
ax1.set_ylabel('Traffic Rate (Packets/Sec)')
ax1.legend(loc='upper left', frameon=True, fontsize=9)

# Plot 2: Test Phase (Evasion Success vs Robust Detection)
ax2.plot(test_data, label='Test Data', color='#7570b3', linewidth=1.5)
ax2.scatter(range(30, 35), test_attack, color='red', marker='X', s=80, label='Actual Massive Attacks')

# Threshold lines from poisoned baseline
ax2.axhline(y=thresh_z_poison, color='#d95f02', linestyle='--', label='Poisoned Traditional Limit')
ax2.axhline(y=thresh_robust_poison, color='#1b9e77', linestyle='-.', label='Poisoned Robust Limit (MAD)')

ax2.set_title('Test Phase: Attack Evades Poisoned Traditional Baseline but is Caught by Robust MAD', fontsize=12, fontweight='bold')
ax2.set_xlabel('Days of Test Phase')
ax2.set_ylabel('Traffic Rate (Packets/Sec)')
ax2.legend(loc='upper left', frameon=True, fontsize=9)

# Highlight evasion region
ax2.fill_between(range(len(test_data)), thresh_robust_poison, thresh_z_poison, color='orange', alpha=0.15, label='Evasion Zone (Slipped Under Standard Threshold)')

sns.despine()
plt.tight_layout(pad=1.5)

chart_path = '/workspace/scratch/baseline_poisoning_chart.png'
fig.savefig(chart_path, dpi=150, bbox_inches='tight')
plt.close()

# Save CSV summaries
eval_df.to_csv('/workspace/scratch/baseline_poisoning_evaluation.csv', index=False)

print("Baseline Poisoning Simulation ran successfully!")
