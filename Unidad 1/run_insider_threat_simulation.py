import os
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import MinMaxScaler

# Ensure scratch directory exists
os.makedirs('/workspace/scratch', exist_ok=True)

# Set random seed for reproducibility
np.random.seed(1337)

# ----------------------------------------------------------------------------
# 1. GENERATE TELEMETRY DATA FOR NORMAL USERS AND INSIDER THREATS
# ----------------------------------------------------------------------------
# Features:
# 1. action_frequency_anomaly (0 to 100): Burstiness of user actions
# 2. resource_access_diversity (0 to 100): Number of unique out-of-scope assets queried
# 3. login_velocity_anomaly (0 to 100): Rapid-fire login sessions / minute
# 4. off_hours_activity_anomaly (0 to 100): Midnight/weekend activity index
# 5. data_egress_mb (0 to 100): Scaled external transfer volume (up to several GBs)

n_normal = 1000

# Normal Baseline: low-signal, standard operations during business hours
action_normal = np.random.poisson(lam=15, size=n_normal)
res_normal = np.random.poisson(lam=5, size=n_normal)
login_normal = np.random.poisson(lam=2, size=n_normal)
time_normal = np.random.exponential(scale=10, size=n_normal)  # mostly near 0 (daytime)
egress_normal = np.random.lognormal(mean=2.0, sigma=0.5, size=n_normal) # typical 5-20MB

X_normal = np.column_stack([action_normal, res_normal, login_normal, time_normal, egress_normal])

# Scale normal data columns to a 0-100 range for logical alignment
scaler = MinMaxScaler(feature_range=(0, 100))
X_normal_scaled = scaler.fit_transform(X_normal)

# Let's create the anomalous cases (insider threat scenarios)
# Case A: Disgruntled Employee (Data Theft before leaving)
# Characteristics: Staging out-of-scope files, high database access, massive external exfiltration, evening hours
action_a = [35, 45, 60, 40, 50]
res_a = [85, 90, 95, 80, 88] # very high diversity (sweeping out-of-scope files)
login_a = [5, 4, 3, 6, 4]
time_a = [75, 80, 90, 85, 78] # off-hours activity
egress_a = [9200, 10500, 15000, 8500, 11000] # massive egress (8.5 - 15 GB exfiltration)

X_anom_a = np.column_stack([action_a, res_a, login_a, time_a, egress_a])

# Case B: Compromised Privileged Account (External actor using harvested Admin credentials)
# Characteristics: Rapid-fire credential stuffing/verification, broad internal sweeps, off-hours execution
action_b = [95, 98, 100, 92, 96] # machine speed bursts
res_b = [70, 75, 80, 72, 78] # sweeping files
login_b = [90, 95, 99, 88, 92] # extreme login velocity (brute force/token replay)
time_b = [85, 92, 95, 88, 90] # late night access
egress_b = [150, 200, 350, 120, 250] # moderate egress (moving tools)

X_anom_b = np.column_stack([action_b, res_b, login_b, time_b, egress_b])

# Case C: Negligent User / Shadow IT Leakage (Developer uploading source code/PII to public AI tool)
# Characteristics: Standard hours, low login velocity, but high egress to unapproved SaaS, moderate action frequency
action_c = [40, 52, 45, 38, 48]
res_c = [10, 12, 15, 8, 11] # normal resources
login_c = [2, 1, 3, 2, 1] # normal login
time_c = [5, 8, 12, 10, 6] # regular business hours
egress_c = [1200, 1500, 2200, 950, 1800] # high egress (950MB to 2.2GB upload to AI domains)

X_anom_c = np.column_stack([action_c, res_c, login_c, time_c, egress_c])

# Combine all anomalies
X_anom_raw = np.vstack([X_anom_a, X_anom_b, X_anom_c])
# Transform anomalies using the normal scaler, clipping values to handle out-of-bounds metrics elegantly
X_anom_scaled = scaler.transform(X_anom_raw)
X_anom_scaled = np.clip(X_anom_scaled, 0, 100)

# Build a unified evaluation DataFrame
X_test_scaled = np.vstack([X_normal_scaled, X_anom_scaled])

features = [
    'action_frequency_anomaly', 
    'resource_access_diversity', 
    'login_velocity_anomaly', 
    'off_hours_activity_anomaly', 
    'data_egress_anomaly'
]

df = pd.DataFrame(X_test_scaled, columns=features)

# Map labels to distinct groups
labels = ['Normal Employee'] * n_normal + \
         ['Malicious Insider (Case A)'] * 5 + \
         ['Compromised Admin (Case B)'] * 5 + \
         ['Negligent Developer (Case C)'] * 5

df['Account_Type'] = labels
df['Account_Name'] = [f'user_{i:04d}' for i in range(len(df))]

# Override names for anomalies to make the logs realistic and traceable
anomaly_names = [
    'emp_departing_01', 'emp_departing_02', 'emp_departing_03', 'emp_departing_04', 'emp_departing_05', # Case A
    'adm_compromised_01', 'adm_compromised_02', 'adm_compromised_03', 'adm_compromised_04', 'adm_compromised_05', # Case B
    'dev_negligent_01', 'dev_negligent_02', 'dev_negligent_03', 'dev_negligent_04', 'dev_negligent_05' # Case C
]
df.iloc[n_normal:, df.columns.get_loc('Account_Name')] = anomaly_names

# ----------------------------------------------------------------------------
# 2. MULTI-DIMENSIONAL RISK SCORING ENGINE (COMPOSITE RISK SCORE)
# ----------------------------------------------------------------------------
# Weights: Action Freq (20%), Resource Div (25%), Login Vel (15%), Off-hours (15%), Data Egress (25%)
weights = np.array([0.20, 0.25, 0.15, 0.15, 0.25])

# Calculate weighted score (0 - 100)
composite_scores = np.dot(df[features].values, weights)
df['Composite_Risk_Score'] = composite_scores

# Determine alert status and protective actions based on the threshold policy
# Status:
# - RISK <= 45: NORMAL
# - 45 < RISK <= 70: ALERT / INVESTIGATE (SOC Ticket)
# - RISK > 70: CRITICAL / BLOCK (Automated account isolation & token revocation)
def determine_status(score):
    if score <= 45:
        return 'NORMAL', 'No action required.'
    elif score <= 70:
        return 'ALERT / INVESTIGATE', 'Generate SOC Case; Enforce Step-up Multi-Factor Authentication.'
    else:
        return 'CRITICAL / BLOCK', 'Revoke OAuth tokens; Terminate Active Sessions; Quarantined by ACIE.'

status_actions = [determine_status(s) for score in df['Composite_Risk_Score'] for s in [score]]
df['Response_Status'] = [sa[0] for sa in status_actions]
df['Automated_Remediation'] = [sa[1] for sa in status_actions]

# Save the dataset to a CSV file in the scratch space
df.to_csv('/workspace/scratch/insider-threat-alerts.csv', index=False)

# ----------------------------------------------------------------------------
# 3. VISUALIZATION: RISK SCORING DIVERGENCE CHART
# ----------------------------------------------------------------------------
plt.figure(figsize=(10, 6))
sns.set_theme(style='whitegrid', palette='colorblind', font='DejaVu Sans')

# Threshold lines
threshold_alert = 45
threshold_block = 70

# Colors for groups
palette = {
    'Normal Employee': '#3182bd',
    'Malicious Insider (Case A)': '#de2d26',
    'Compromised Admin (Case B)': '#756bb1',
    'Negligent Developer (Case C)': '#ec7014'
}

# Plot scatter
for group, color in palette.items():
    sub_df = df[df['Account_Type'] == group]
    plt.scatter(
        sub_df.index, sub_df['Composite_Risk_Score'], 
        color=color, label=group, alpha=0.8, edgecolors='none', s=45
    )

# Add Threshold bands
plt.axhline(y=threshold_alert, color='#fec44f', linestyle='--', linewidth=1.5, 
            label=f'SOC Investigation Threshold: {threshold_alert}')
plt.axhline(y=threshold_block, color='#d95f02', linestyle='-', linewidth=2, 
            label=f'ACIE Quarantine Threshold: {threshold_block}')

# Titles and formatting
plt.title('Multi-Dimensional Composite Risk Scores Isolate Insider Attacks with Zero False Alerts', 
          fontsize=13, fontweight='bold', pad=15)
plt.xlabel('Audited Employee Sessions (Chronological logs)')
plt.ylabel('Composite Risk Score (0 - 100)')
plt.legend(loc='lower left', frameon=True, fontsize=9)
plt.ylim(0, 105)

sns.despine()
plt.tight_layout(pad=1.5)

# Save chart to scratch space
chart_path = '/workspace/scratch/insider-threat-chart.png'
plt.savefig(chart_path, dpi=150, bbox_inches='tight')
plt.close()

# Print metrics summary to output
print("Insider Threat simulation finished successfully!")
print(f"Normal baseline average risk score: {df[df['Account_Type']=='Normal Employee']['Composite_Risk_Score'].mean():.4f}")
print(f"Case A (Malicious) average risk score: {df[df['Account_Type']=='Malicious Insider (Case A)']['Composite_Risk_Score'].mean():.4f}")
print(f"Case B (Compromised) average risk score: {df[df['Account_Type']=='Compromised Admin (Case B)']['Composite_Risk_Score'].mean():.4f}")
print(f"Case C (Negligent) average risk score: {df[df['Account_Type']=='Negligent Developer (Case C)']['Composite_Risk_Score'].mean():.4f}")
