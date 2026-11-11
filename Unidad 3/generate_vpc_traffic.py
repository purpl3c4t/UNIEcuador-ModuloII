import pandas as pd
import numpy as np

np.random.seed(42)
n_normal = 1000

normal_data = {
    'flow_id': [f"flow_norm_{i}" for i in range(n_normal)],
    'bytes_out': np.random.exponential(scale=1500, size=n_normal) + 200,
    'packets_out': np.random.poisson(lam=10, size=n_normal) + 2,
    'flow_duration': np.random.uniform(0.1, 5.0, size=n_normal),
    'bytes_in_ratio': np.random.uniform(0.4, 0.9, size=n_normal),
    'dest_port': np.random.choice([80, 443, 8080, 3306, 5432], size=n_normal),
    'label': 0
}
df_normal = pd.DataFrame(normal_data)

n_exfil_s3 = 15
exfil_s3_data = {
    'flow_id': [f"flow_exfil_s3_{i}" for i in range(n_exfil_s3)],
    'bytes_out': np.random.uniform(80000, 250000, size=n_exfil_s3),
    'packets_out': np.random.uniform(500, 1500, size=n_exfil_s3),
    'flow_duration': np.random.uniform(15.0, 60.0, size=n_exfil_s3),
    'bytes_in_ratio': np.random.uniform(0.01, 0.05, size=n_exfil_s3),
    'dest_port': [443] * n_exfil_s3,
    'label': 1
}
df_exfil_s3 = pd.DataFrame(exfil_s3_data)

n_exfil_doh = 10
exfil_doh_data = {
    'flow_id': [f"flow_exfil_doh_{i}" for i in range(n_exfil_doh)],
    'bytes_out': np.random.uniform(12000, 25000, size=n_exfil_doh),
    'packets_out': np.random.uniform(80, 180, size=n_exfil_doh),
    'flow_duration': np.random.uniform(0.5, 2.0, size=n_exfil_doh),
    'bytes_in_ratio': np.random.uniform(0.05, 0.12, size=n_exfil_doh),
    'dest_port': [443] * n_exfil_doh,
    'label': 1
}
df_exfil_doh = pd.DataFrame(exfil_doh_data)

df_all = pd.concat([df_normal, df_exfil_s3, df_exfil_doh], ignore_index=True)
df_all = df_all.sample(frac=1, random_state=42).reset_index(drop=True)
df_all.to_csv("vpc_flows.csv", index=False)
print("[+] Archivo 'vpc_flows.csv' generado exitosamente con 1025 flujos.")
