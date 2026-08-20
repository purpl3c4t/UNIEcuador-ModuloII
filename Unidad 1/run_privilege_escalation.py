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
# The graph represents an Active Directory & Cloud trust environment
# We model nodes with types: User, Workstation, Server, ServiceAccount, DomainController
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

# Path Resistance is the inverse of the Propagation Score (P_ij)
# Representing how difficult or risky a hop is for the attacker (higher score = lower resistance)
df_edges["Path_Resistance"] = 1.0 / df_edges["Propagation_Score"]

# Save the path definition to a local CSV file
csv_path = '/workspace/scratch/privilege-escalation-paths.csv'
df_edges.to_csv(csv_path, index=False)

# -----------------------------------------------------------------------------
# 2. BUILD THE GRAPH & RUN DIJKSTRA (PEPE ALGORITHM)
# -----------------------------------------------------------------------------
G = nx.DiGraph()

# Add nodes with types
node_types = {}
for idx, row in df_edges.iterrows():
    G.add_node(row["Source"], type=row["Source_Type"])
    G.add_node(row["Destination"], type=row["Destination_Type"])
    node_types[row["Source"]] = row["Source_Type"]
    node_types[row["Destination"]] = row["Destination_Type"]

# Add edges with attributes
for idx, row in df_edges.iterrows():
    G.add_edge(row["Source"], row["Destination"], 
               weight=row["Path_Resistance"], 
               propagation_score=row["Propagation_Score"],
               in_attack_path=row["In_Attack_Path"])

# Find the path of least resistance from U_compromised to DC_domain_controller
source_node = "U_compromised"
target_node = "DC_domain_controller"

print(f"--- INITIAL ESCALATION ANALYSIS ---")
try:
    optimal_path = nx.dijkstra_path(G, source=source_node, target=target_node, weight="weight")
    cumulative_resistance = nx.dijkstra_path_length(G, source=source_node, target=target_node, weight="weight")
    
    print(f"Optimal Privilege Escalation Path Found: {' -> '.join(optimal_path)}")
    print(f"Cumulative Path Resistance Cost: {cumulative_resistance:.4f}\n")
except nx.NetworkXNoPath:
    print("No escalation path found from initial compromised node!\n")
    optimal_path = []
    cumulative_resistance = 0.0

# -----------------------------------------------------------------------------
# 3. VISUALIZE GRAPH (PEPE MAP)
# -----------------------------------------------------------------------------
plt.figure(figsize=(10, 6))
sns.set_theme(style='white', font='DejaVu Sans')

# Node positions layout
pos = {
    "U_compromised": (-2, 0),
    "W_host1": (-1, 0.5),
    "SA_sql_svc": (0, -1),
    "S_database": (0, 1),
    "SA_cloud_adm": (1, 0.5),
    "DC_domain_controller": (2, 0)
}

# Node colors by type
colors_map = {
    "User": "#377eb8",             # Blue
    "Workstation": "#4daf4a",      # Green
    "Server": "#984ea3",           # Purple
    "ServiceAccount": "#ff7f00",   # Orange
    "DomainController": "#e41a1c"  # Red
}

node_colors = [colors_map[G.nodes[node]["type"]] for node in G.nodes()]

# Draw Nodes
nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=1200, edgecolors='black', linewidths=1.5)

# Identify edge categories
attack_edges = [(u, v) for u, v, d in G.edges(data=True) if d.get('in_attack_path') == 1]
normal_edges = [(u, v) for u, v, d in G.edges(data=True) if d.get('in_attack_path') == 0]

# Draw Edges
nx.draw_networkx_edges(G, pos, edgelist=attack_edges, edge_color='#e41a1c', width=3, 
                       arrowstyle='-|>', arrowsize=20, connectionstyle='arc3,rad=0.1')
nx.draw_networkx_edges(G, pos, edgelist=normal_edges, edge_color='#cccccc', width=1.5, 
                       arrowstyle='-|>', arrowsize=15, style='dashed', connectionstyle='arc3,rad=0.1')

# Draw Labels
labels = {node: f"{node}\n({G.nodes[node]['type']})" for node in G.nodes()}
nx.draw_networkx_labels(G, pos, labels=labels, font_size=8, font_weight='bold')

# Draw Edge Labels (Propagation Scores and Resistances)
edge_labels = {
    (u, v): f"P:{d['propagation_score']:.2f}\nR:{d['weight']:.2f}" 
    for u, v, d in G.edges(data=True)
}
# Adjust edge label drawing slightly to avoid overlapping
nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=7, label_pos=0.5)

plt.title("Predictive Privilege Escalation Path Mapping (Identity Relationship Graph SEC)", 
          fontsize=12, fontweight='bold', pad=20)
plt.axis('off')
plt.tight_layout()

# Save the visualization to a local file
chart_path = '/workspace/scratch/privilege-escalation-chart.png'
plt.savefig(chart_path, dpi=150, bbox_inches='tight')
plt.close()

print("Privilege escalation simulation ran successfully!")
