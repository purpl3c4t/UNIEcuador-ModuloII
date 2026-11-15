import networkx as nx
import pandas as pd
import numpy as np
import os

def create_corporate_topology():
    G = nx.DiGraph()
    
    # Nodos: Usuarios, Estaciones de Trabajo, Servidores de Salto, Controladores y Bases de Datos
    # tier 3: usuario final / endpoint; tier 2: jumpbox / servidores de gestión; tier 1: base de datos; tier 0: controlador de dominio
    nodes = [
        ("User_Carlos_Finanzas", {"type": "User", "tier": 3, "ip": "10.0.10.15"}),
        ("Host_WS_Finanzas", {"type": "Endpoint", "tier": 3, "ip": "10.0.10.15"}),
        ("Host_WS_Dev", {"type": "Endpoint", "tier": 3, "ip": "10.0.20.45"}),
        ("Srv_Jumpbox_Admin", {"type": "Server", "tier": 2, "ip": "10.0.1.5"}),
        ("User_Svc_Backup", {"type": "ServiceAccount", "tier": 1, "ip": "10.0.1.50"}),
        ("Srv_Database_Prod", {"type": "Database", "tier": 1, "ip": "10.0.2.100"}),
        ("DC_Primary_Core", {"type": "DomainController", "tier": 0, "ip": "10.0.0.1"})
    ]
    G.add_nodes_from(nodes)
    
    # Conexiones legítimas con alta probabilidad y conexiones atípicas con probabilidad muy baja (epsilon)
    # El peso de resistencia se modela como -log(probabilidad + 1e-6)
    transitions = [
        ("User_Carlos_Finanzas", "Host_WS_Finanzas", 0.98),
        ("Host_WS_Finanzas", "Host_WS_Dev", 0.001), # Anomalía lateral
        ("Host_WS_Dev", "Srv_Jumpbox_Admin", 0.05),
        ("Host_WS_Finanzas", "Srv_Jumpbox_Admin", 0.005), # Salto directo sospechoso
        ("Srv_Jumpbox_Admin", "User_Svc_Backup", 0.85),
        ("User_Svc_Backup", "Srv_Database_Prod", 0.90),
        ("Srv_Jumpbox_Admin", "DC_Primary_Core", 0.70)
    ]
    
    edge_records = []
    for u, v, prob in transitions:
        weight = float(-np.log(prob))
        G.add_edge(u, v, probability=prob, weight=weight)
        edge_records.append({'source': u, 'target': v, 'probability': prob, 'weight': round(weight, 4)})
        
    data_dir = os.path.dirname(__file__) + '/data'
    pd.DataFrame(edge_records).to_csv(f'{data_dir}/network_transitions.csv', index=False)
    nx.write_gml(G, f'{data_dir}/corporate_identity_graph.gml')
    print("Lab 3: Topología de grafo de identidad generada en GML y CSV.")

if __name__ == '__main__':
    create_corporate_topology()
