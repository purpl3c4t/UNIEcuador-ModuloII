import os
import numpy as np
import pandas as pd
import networkx as nx
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

# Ensure scratch directory exists
os.makedirs('/workspace/scratch', exist_ok=True)

# -----------------------------------------------------------------------------
# 1. DEFINE THE IDENTITY RELATIONSHIP GRAPH DATA
# -----------------------------------------------------------------------------
edges_data = [
    {
        "Source": "U_compromised", "Source_Type": "User",
        "Destination": "W_host1", "Destination_Type": "Workstation",
        "Propagation_Score": 0.56, "In_Attack_Path": 1
    },
    {
        "Source": "W_host1", "Source_Type": "Workstation",
        "Destination": "S_database", "Destination_Type": "Server",
        "Propagation_Score": 0.64, "In_Attack_Path": 1
    },
    {
        "Source": "SA_sql_svc", "Source_Type": "ServiceAccount",
        "Destination": "S_database", "Destination_Type": "Server",
        "Propagation_Score": 0.73, "In_Attack_Path": 0
    },
    {
        "Source": "SA_sql_svc", "Source_Type": "ServiceAccount",
        "Destination": "DC_domain_controller", "Destination_Type": "DomainController",
        "Propagation_Score": 0.67, "In_Attack_Path": 0
    },
    {
        "Source": "S_database", "Source_Type": "Server",
        "Destination": "SA_cloud_adm", "Destination_Type": "ServiceAccount",
        "Propagation_Score": 0.71, "In_Attack_Path": 1
    },
    {
        "Source": "SA_cloud_adm", "Source_Type": "ServiceAccount",
        "Destination": "DC_domain_controller", "Destination_Type": "DomainController",
        "Propagation_Score": 0.895, "In_Attack_Path": 1
    }
]

df_edges = pd.DataFrame(edges_data)
df_edges["Path_Resistance"] = 1.0 / df_edges["Propagation_Score"]

# Save the path definition to a local CSV file (v2)
df_edges.to_csv('/workspace/scratch/privilege-escalation-paths-v2.csv', index=False)

# -----------------------------------------------------------------------------
# 2. BUILD THE GRAPH & RUN DIJKSTRA
# -----------------------------------------------------------------------------
G = nx.DiGraph()

node_types = {}
for idx, row in df_edges.iterrows():
    G.add_node(row["Source"], type=row["Source_Type"])
    G.add_node(row["Destination"], type=row["Destination_Type"])
    node_types[row["Source"]] = row["Source_Type"]
    node_types[row["Destination"]] = row["Destination_Type"]

for idx, row in df_edges.iterrows():
    G.add_edge(row["Source"], row["Destination"], 
               weight=row["Path_Resistance"], 
               propagation_score=row["Propagation_Score"],
               in_attack_path=row["In_Attack_Path"])

optimal_path = nx.dijkstra_path(G, source="U_compromised", target="DC_domain_controller", weight="weight")
cumulative_resistance = nx.dijkstra_path_length(G, source="U_compromised", target="DC_domain_controller", weight="weight")

# -----------------------------------------------------------------------------
# 3. PASS-THE-HASH (PtH) HEURISTIC DETECTION ENGINE
# -----------------------------------------------------------------------------
# We simulate logon event streams on the network.
# PtH characteristics: NTLM protocol used for high privilege accounts or abnormal paths.
logon_events = [
    {"EventID": 101, "Source": "U_compromised", "Destination": "W_host1", "Account": "U_compromised", "Protocol": "Kerberos", "LogonType": 2},
    {"EventID": 102, "Source": "SA_sql_svc", "Destination": "S_database", "Account": "SA_sql_svc", "Protocol": "Kerberos", "LogonType": 3},
    # PtH Anomalous Event: SA_cloud_adm logging into W_host1 using NTLM (unusual, highly suspicious)
    {"EventID": 103, "Source": "W_host1", "Destination": "S_database", "Account": "SA_cloud_adm", "Protocol": "NTLM", "LogonType": 3},
    # PtH Anomalous Event: SA_sql_svc logging to DC using NTLM
    {"EventID": 104, "Source": "W_host1", "Destination": "DC_domain_controller", "Account": "SA_sql_svc", "Protocol": "NTLM", "LogonType": 3},
    {"EventID": 105, "Source": "S_database", "Destination": "DC_domain_controller", "Account": "SA_cloud_adm", "Protocol": "Kerberos", "LogonType": 3}
]

df_events = pd.DataFrame(logon_events)

def detect_pass_the_hash(event, graph):
    src = event["Source"]
    dst = event["Destination"]
    acc = event["Account"]
    proto = event["Protocol"]
    
    # Heuristic 1: Protocol is NTLM (high correlation with PtH when abusing service accounts)
    is_ntlm = (proto == "NTLM")
    
    # Heuristic 2: Target node or account is of high privilege (Service Account / DC)
    is_privileged_acc = "SA_" in acc or "adm" in acc
    
    # Heuristic 3: Check if the logon path exists in the normal trust graph
    path_exists = graph.has_edge(src, dst)
    
    # Heuristic 4: Calculate Risk Score (0 to 100)
    risk_score = 10  # Baseline
    reasons = []
    
    if is_ntlm:
        risk_score += 40
        reasons.append("NTLM Protocol Used")
    if is_privileged_acc:
        risk_score += 30
        reasons.append("Privileged Account")
    if not path_exists:
        risk_score += 20
        reasons.append("Anomalous/Untrusted Network Path")
        
    status = "ALERT" if risk_score >= 60 else "NORMAL"
    if risk_score >= 80:
        status = "CRITICAL / BLOCK"
        
    return risk_score, status, ", ".join(reasons) if reasons else "None"

# Apply detection engine
scores = []
statuses = []
triggers = []
for idx, row in df_events.iterrows():
    risk, stat, trig = detect_pass_the_hash(row, G)
    scores.append(risk)
    statuses.append(stat)
    triggers.append(trig)

df_events["Risk_Score"] = scores
df_events["Detection_Status"] = statuses
df_events["Detection_Triggers"] = triggers

# Save detection logs
df_events.to_csv('/workspace/scratch/pass-the-hash-alerts-v2.csv', index=False)

# Print Console Output
print("--- INITIAL ESCALATION PATH ---")
print(f"Optimal Privilege Escalation Path Found: {' -> '.join(optimal_path)}")
print(f"Cumulative Path Resistance Cost: {cumulative_resistance:.4f}\n")

print("--- PASS-THE-HASH DETECTION ALERTS ---")
print(df_events[["EventID", "Account", "Protocol", "Risk_Score", "Detection_Status", "Detection_Triggers"]].to_string(index=False))

# -----------------------------------------------------------------------------
# 4. VISUALIZE GRAPH & PATHS WITH PT-H ALERTS
# -----------------------------------------------------------------------------
plt.figure(figsize=(12, 7))
sns.set_theme(style='white', font='DejaVu Sans')

pos = {
    "U_compromised": (-2, 0),
    "W_host1": (-1, 0.5),
    "SA_sql_svc": (0, -1),
    "S_database": (0, 1),
    "SA_cloud_adm": (1, 0.5),
    "DC_domain_controller": (2, 0)
}

colors_map = {
    "User": "#377eb8",
    "Workstation": "#4daf4a",
    "Server": "#984ea3",
    "ServiceAccount": "#ff7f00",
    "DomainController": "#e41a1c"
}

node_colors = [colors_map[G.nodes[node]["type"]] for node in G.nodes()]

# Draw nodes and background structures
nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=1400, edgecolors='black', linewidths=1.5)

# Highlight standard attack path edges vs. Normal edges
attack_edges = [(u, v) for u, v, d in G.edges(data=True) if d.get('in_attack_path') == 1]
normal_edges = [(u, v) for u, v, d in G.edges(data=True) if d.get('in_attack_path') == 0]

nx.draw_networkx_edges(G, pos, edgelist=attack_edges, edge_color='#e41a1c', width=3, 
                       arrowstyle='-|>', arrowsize=20, connectionstyle='arc3,rad=0.1')
nx.draw_networkx_edges(G, pos, edgelist=normal_edges, edge_color='#cccccc', width=1.5, 
                       arrowstyle='-|>', arrowsize=15, style='dashed', connectionstyle='arc3,rad=0.1')

# Add a visual indicator for where the PtH alert was intercepted (Event 103 and 104)
# Event 103: W_host1 -> S_database (abusing SA_cloud_adm)
# Event 104: W_host1 -> DC_domain_controller (abusing SA_sql_svc, untrusted path)
# We draw glowing red halos around nodes under active alert
alert_nodes = ["W_host1", "S_database", "DC_domain_controller"]
nx.draw_networkx_nodes(G, pos, nodelist=alert_nodes, node_color='none', 
                       edgecolors='#ff0000', node_size=1800, linewidths=3)

# Labels
labels = {node: f"{node}\n({G.nodes[node]['type']})" for node in G.nodes()}
nx.draw_networkx_labels(G, pos, labels=labels, font_size=8, font_weight='bold')

# Edge labels
edge_labels = {
    (u, v): f"P:{d['propagation_score']:.2f}\nR:{d['weight']:.2f}" 
    for u, v, d in G.edges(data=True)
}
nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=7, label_pos=0.5)

plt.title("Identity Graph SEC: Red Path (Lateral Movement) with Red Circle Alert Halos", 
          fontsize=12, fontweight='bold', pad=20)
plt.axis('off')
plt.tight_layout()

# Save the visualization to a local file
chart_path_v2 = '/workspace/scratch/privilege-escalation-chart-v2.png'
plt.savefig(chart_path_v2, dpi=150, bbox_inches='tight')
plt.close()

print("\nPrivilege escalation v2 simulation completed successfully!")
