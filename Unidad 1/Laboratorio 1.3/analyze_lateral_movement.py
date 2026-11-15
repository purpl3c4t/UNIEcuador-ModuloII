import networkx as nx
import pandas as pd
import numpy as np
import os

def analyze_lateral_paths():
    data_dir = os.path.dirname(__file__) + '/data'
    graph_path = f'{data_dir}/corporate_identity_graph.gml'
    
    if not os.path.exists(graph_path):
        from create_topology import create_corporate_topology
        create_corporate_topology()
        
    G = nx.read_gml(graph_path)
    
    print("================================================================================")
    print(" ANÁLISIS PREDICTIVO DE MOVIMIENTO LATERAL Y ZERO-PACKET RECON EN GRAFOS (TGAD)")
    print("================================================================================")
    
    # 1. Simulación Zero-Packet Recon (Inspección pasiva de ARP y Netstat en memoria)
    print("\n[FASE 1: Zero-Packet Reconnaissance desde Host_WS_Finanzas]")
    print(" -> Consultando tabla de caché ARP local (arp -a) y conexiones activas (netstat -ano)...")
    recon_entries = [
        {"ip": "10.0.1.5", "mac": "00:1A:2B:3C:4D:5E", "interface": "Srv_Jumpbox_Admin", "source": "ARP_Cache"},
        {"ip": "10.0.20.45", "mac": "00:50:56:A1:B2:C3", "interface": "Host_WS_Dev", "source": "Netstat_Established"},
        {"ip": "10.0.0.1", "mac": "00:0C:29:FE:DC:BA", "interface": "DC_Primary_Core", "source": "DNS_Client_Cache"}
    ]
    df_recon = pd.DataFrame(recon_entries)
    print(df_recon.to_string(index=False))
    print("[+] Descubrimiento completado con 0 paquetes transmitidos hacia la red externa.")
    
    # 2. Análisis de Camino de Mínima Resistencia (Dijkstra)
    print("\n[FASE 2: Modelado de Rutas Críticas hacia el Objetivo de Alto Valor]")
    source_node = "User_Carlos_Finanzas"
    target_node = "Srv_Database_Prod"
    
    try:
        path = nx.shortest_path(G, source=source_node, target=target_node, weight='weight')
        cost = nx.shortest_path_length(G, source=source_node, target=target_node, weight='weight')
        
        print(f"Objetivo: Acceso al activo crítico [{target_node}]")
        print(f"Ruta detectada en Grafo: {' -> '.join(path)}")
        print(f"Costo Total de Resistencia Topológica: {cost:.4f}")
        
        # Evaluar saltos anómalos
        print("\nDetalle de Transiciones del Camino:")
        for i in range(len(path) - 1):
            u, v = path[i], path[i+1]
            prob = G[u][v]['probability']
            w = G[u][v]['weight']
            is_anomaly = prob < 0.01
            print(f" -> Salto {u} ==> {v} | Probabilidad Histórica: {prob:.4f} | Peso: {w:.2f} {'[ALERTA: TRANSICIÓN ANÓMALA]' if is_anomaly else '[NORMAL]'}")
            
    except nx.NetworkXNoPath:
        print(f"[!] No existe camino entre {source_node} y {target_node}.")
        
    # 3. Métrica de Grado de Centralidad y Detección de Abanico (Connection Fan-Out)
    print("\n[FASE 3: Centralidad de Salida y Detección de Saltos Anómalos]")
    out_degree = dict(G.out_degree())
    for node, deg in out_degree.items():
        if "Host_WS" in node:
            print(f" -> Host: {node} - Conexiones salientes hacia segmentos de gestión: {deg}")
            
    print("================================================================================\n")

if __name__ == '__main__':
    analyze_lateral_paths()
