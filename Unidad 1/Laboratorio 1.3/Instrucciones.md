# Zero-Packet Reconnaissance y Predicción de Movimiento Lateral en Grafos
---
## Objetivo:
Simular técnicas de reconocimiento pasivo local en la pila de red (Zero-Packet Recon) para evitar firmas de escaneo perimetral, modelar la red corporativa como un Grafo de Identidades y predecir rutas críticas de escalamiento de privilegios antes de que se consume el acceso al objetivo final.

Reconocimiento pasivo local en memoria (*Zero-Packet Recon* vía ARP y Netstat) y movimiento lateral (*Pass-the-Hash*). Modelado topológico con *NetworkX* utilizando grafos de identidades y cálculo de rutas de mínima resistencia de privilegios mediante el algoritmo de Dijkstra.

### Insumo de Entrada Requerido: 
Criterios de filtrado estadístico y normalización de telemetría del Laboratorio.

### Entregable Requerido para Lab 4: 
Grafo de relaciones de identidad construido (identity_graph.gml) y la matriz de rutas de mínima resistencia de privilegios.

## Marco Teórico y Planteamiento del Escenario
Los atacantes experimentados no ejecutan barridos ruidosos con Nmap ni consultas LDAP masivas hacia el controlador de dominio. En su lugar, aplican Zero-Packet Reconnaissance: interrogan la memoria local, la caché ARP (arp -a), las tablas de enrutamiento (route print) y las conexiones TCP establecidas (netstat -aon). 

Esta recolección pasiva tiene huella cero en la red.Para neutralizar este reconocimiento invisible y el posterior salto lateral (Pass-the-Hash / WinRM), la defensa utiliza Redes de Grafos de Identidades. En un grafo $G=(V, E)$, los nodos $V$ representan cuentas y equipos, y las aristas $E$ representan autenticaciones ponderadas por el algoritmo de Dijkstra: `$$\text{Distancia del Camino} = \sum_{e \in \text{ruta}} -\log(P(e))$$ Donde $P(e)$` es la probabilidad de transición aprendida para el grupo de pares. Un usuario estándar que súbitamente reduce su distancia topológica hacia una cuenta privilegiada activa una alarma predictiva.

## Guía Paso a Paso de Ejecución 

### Paso 3.1: Construcción del Grafo de Identidades con NetworkX
Modelar una infraestructura corporativa con tres áreas (Contabilidad, Desarrollo y Controladores de Dominio) y simula el avance de un intruso que ha obtenido credenciales locales y busca alcanzar el servidor de base de datos financiero: `lab3_graph_lateral_movement.py`

<img width="753" height="454" alt="image" src="https://github.com/user-attachments/assets/79c439a6-6704-43e2-b3b1-ddc5a727804a" />

### Paso 3.2: Detección Predictiva de Anomalía de Abanico (Connection Fan-Out)
Analizar el grado de centralidad de salida (Out-Degree Centrality) de Host_Workstation_04 para verificar el momento exacto en que la estación intenta saltar a recursos fuera de su perfil de pares.

<img width="592" height="52" alt="image" src="https://github.com/user-attachments/assets/43b7b59f-27c3-415b-9145-5c657039577b" />


<img width="748" height="798" alt="image" src="https://github.com/user-attachments/assets/02503e1d-de19-4341-ac26-00d7cb8a5ef3" />

## Preguntas de Control y Validación
* ¿Por qué el reconocimiento de la caché ARP local no puede ser interceptado por un sensor Network Detection and Response (NDR) perimetral?
* ¿Cómo influye el decaimiento temporal exponencial en el cálculo de pesos del grafo si una credencial administrativa no se ha utilizado en más de 90 días?
