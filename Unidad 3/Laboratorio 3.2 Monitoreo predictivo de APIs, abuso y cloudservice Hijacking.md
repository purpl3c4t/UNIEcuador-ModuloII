## Laboratorio 2: Monitoreo Predictivo de APIs y Detección de Secuestro de Servicios

* **Tema vinculado:** 3.2\. Monitoreo predictivo de APIs, abuso y *cloudservice hijacking*.
* **Duración estimada:** 30 minutos.
* **Insumos requeridos:** El dataset de eventos `audit_events.json` exportado en el Laboratorio 1, enriquecido con telemetría de fondo (actividad legítima de desarrollo).

### Objetivos de Aprendizaje

1. Analizar telemetría de registros de auditoría cloud (CloudTrail / Cloud Audit Logs).
2. Extraer vectores de características conductuales: variación de entropía en cadenas *User-Agent*, secuencias anómalas de llamadas a la API y ráfagas de respuestas `AccessDenied`.
3. Detectar intentos de aprovisionamiento no autorizado orientados a *cloudservice hijacking* (despliegue de cómputo para minería o proxies C2).

### Guía Paso a Paso

#### Paso 1: Vectorización y procesamiento de secuencias de API en Python
Cargar la telemetría del Lab 1 y estructura las secuencias temporales de llamadas por entidad:

```python
import pandas as pd
import json

# Cargar eventos de auditoría
with open("audit_events.json", "r") as f:
    events = json.load(f)

df = pd.DataFrame(events)

# Extracción de características temporales y operacionales
df['eventTime'] = pd.to_datetime(df['eventTime'])
df = df.sort_values(by=['userIdentity.arn', 'eventTime'])

# Cálculo de tasa de errores (AccessDenied) en ventanas de 5 minutos
df['is_denied'] = df['errorCode'].apply(lambda x: 1 if x in ['AccessDenied', 'Client.UnauthorizedOperation'] else 0)
df['denied_rolling_5m'] = df.groupby('userIdentity.arn')['is_denied'].rolling('5min', on=df['eventTime']).sum().values

```

#### Paso 2: Análisis de anomalías en cadenas User-Agent y geolocalización
Detección de patrones sintomáticos de herramientas automatizadas de explotación cloud (ej. herramientas de red team o scripts genéricos):

```
import numpy as np

def calculate_entropy(text):
    if not text or pd.isna(text): return 0
    probs = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * np.log2(p) for p in probs)

df['ua_entropy'] = df['userAgent'].apply(calculate_entropy)

# Filtrar eventos con combinación de alta frecuencia de errores y agentes sospechosos
anomalous_api_calls = df[
    (df['denied_rolling_5m'] &gt;= 3) | 
    (df['eventName'].isin(['CreateFunction', 'RunInstances']) &amp; df['userAgent'].str.contains('python-requests|Boto3', case=False))
]
print(f"Llamadas sospechosas identificadas: {len(anomalous_api_calls)}")

```

#### Paso 3: Identificación de vectores de Secuestro de Servicios (*Hijacking*)
Identificar en el registro la llamada donde la credencial comprometida en el Lab 1 intentó instanciar recursos de cómputo no estándar (ej. instancias optimizadas para GPU o contenedores externos en EKS/GKE).

* **Entregable / Enlace con el Lab 3:** Lista de entidades de IAM y direcciones IP identificadas como comprometidas, junto con el archivo de flujos de red (`vpc_flows.csv`) correspondiente a las cargas de trabajo desplegadas por dichas entidades.
