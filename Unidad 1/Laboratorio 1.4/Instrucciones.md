# Laboratorio 4 (30 min): Simulación de Insider Threat y Puntuación de Riesgo Compuesta
## Objetivo: 

Ejecutar una simulación IASE (Insider Access Simulation Exercise) utilizando credenciales válidas, modelar las fases de Data Staging en %TEMP% y fuga lenta (Low-and-Slow), calcular la Puntuación de Riesgo Compuesta (Composite Risk Score) e implementar una acción de respuesta automatizada vía API.

### Insumo de Entrada Requerido: 
Anomalías del Autoencoder (Lab 1), umbrales robustos (Lab 2) y pesos topológicos del grafo (Lab 3)

### .Entregable Requerido: 
Motor de evaluación de riesgo integrado (composite_engine.py) y registro de revocación de sesiones.

## Marco Teórico y Planteamiento del Escenario 
El atacante interno no evade la autenticación: es un usuario legítimo. Por tanto, las defensas perimetrales no generan alertas. El modelo del Camino Crítico (Critical Pathway) del CERT y el Servicio Secreto establece que el usuario atraviesa estresores, exploración inusual, empaquetado (staging) y finalmente exfiltración. 

Para detectar esta secuencia sin abrumar al SOC con falsos positivos, el motor analítico combina múltiples micro-señales débiles en una Puntuación de Riesgo Compuesta `($R_t \in [0, 100]$): $$R_t = \sum_{k=1}^{m} w_k \cdot S_k(t)$$` Donde $w_k$ son los pesos de ponderación y $S_k(t)$ son las puntuaciones normalizadas de anomalía de horario, destino atípico, volumen exfiltrado y sensibilidad del recurso accedido. Si `$R_t \ge 85$`, el sistema activa la revocación automática de tokens OAuth de la cuenta.

## Guía Paso a Paso de Ejecución

### Paso 4.1: Modelado de Eventos Forenses de Insider Threat
El estudiante procesa un registro de eventos simulados de Windows (IDs 4624, 4672, 4663 y 4688) correspondientes a una empleada que ha presentado su carta de renuncia y recolecta archivos en %TEMP%:  `lab4_insider_simulation.py`

<img width="769" height="1018" alt="image" src="https://github.com/user-attachments/assets/ac5cb051-bf7d-4c18-8277-0866261636e3" />

### Paso 4.2: Orquestación de la Respuesta Automatizada
Escribir una función simulada de webhook que interactúa con la API de identidad (Microsoft Entra ID / Okta) para invalidar el token de actualización (refresh token) y aislar el host en la red mediante políticas de cuarentena.

## Preguntas de Control y Validación
* ¿Por qué es fundamental que la recolección previa (Data Staging) en carpetas locales temporales como %TEMP% aumente drásticamente el score de riesgo antes de que se inicie la transferencia de red?
* ¿Cuál es la diferencia operativa entre un bloqueo preventivo basado en Step-Up MFA frente a la revocación inmediata de la sesión activa?

  
