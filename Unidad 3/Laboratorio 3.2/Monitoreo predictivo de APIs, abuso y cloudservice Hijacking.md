# Laboratorio 2: Monitoreo Predictivo de APIs y Detección de Secuestro de Servicios

* **Insumos requeridos:** El dataset de eventos `audit_events.json` exportado en el Laboratorio 1, enriquecido con telemetría de fondo (actividad legítima de desarrollo).

## Objetivos de Aprendizaje

1. Analizar telemetría de registros de auditoría cloud (CloudTrail / Cloud Audit Logs).
2. Extraer vectores de características conductuales: variación de entropía en cadenas *User-Agent*, secuencias anómalas de llamadas a la API y ráfagas de respuestas `AccessDenied`.
3. Detectar intentos de aprovisionamiento no autorizado orientados a *cloudservice hijacking* (despliegue de cómputo para minería o proxies C2).

## Marco teórico
* **Ingesta de Auditoría:** Procesamiento de eventos en formato CloudTrail/Activity Logs sin recurrir a inspección de paquetes TCP.
* **Detección Predictiva:** Identificación de la identidad anómala mediante la combinación de ráfagas de denegación ($\ge 3$ en 5 min) y análisis de entropía de agente.
* **Identificación del Secuestro:** Localización del intento de despliegue de cómputo GPU (p3.8xlarge) y persistencia serverless (BackdoorPrivEsc).

## Guía Paso a Paso

### Paso 1: Vectorización y procesamiento de secuencias de API en Python
Cargar la telemetría del Laboratorio 1 y estructurar las secuencias temporales de llamadas por entidad. Esto es un script para visualizar los datos únicamente:

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
*Interpretación:* _Los primeros cuatro eventos representan tráfico legítimo de administración y servicios de fondo sin errores de autorización._

### Paso 2: Análisis de anomalías en cadenas User-Agent y geolocalización
Detección de patrones sintomáticos de herramientas automatizadas de explotación cloud (ej. herramientas de red team o scripts genéricos):

```python
python3 api_anomaly_detector.py ../lab1_identity_exploitation/audit_events.json
```

#### Paso 3: Identificación de vectores de Secuestro de Servicios (*Hijacking*)
Identificar en el registro la llamada donde la credencial comprometida en el Laboratorio 1 intentó instanciar recursos de cómputo no estándar (ej. instancias optimizadas para GPU o contenedores externos en EKS/GKE).

Verifica el archivo estructurado generado automáticamente por el script, el cual servirá como puente de entrada para el Laboratorio 3:

```
cat compromised_manifest.json
```

## Verificación
## Aislamiento de Ráfagas `AccessDenied` (Cartografía Ofensiva)
* **Qué detectó el script:** El rol `_________________` acumuló 3 __________________ en una ventana menor a 5 minutos.
* **Significado de seguridad:** Cuando una credencial legítima de servicio comienza a emitir peticiones no autorizadas en ráfaga, delata a un adversario que no conoce los privilegios asignados e intenta mapear los límites del grafo IAM.
### Anomalía de Entropía en `User-Agent`
* **Qué detectó el script:** La cadena `python-requests/2.31.0` arrojó una entropía de Shannon de **1.82 bits**, contrastando con los **4.20–4.40 bits** calculados para los navegadores y SDKs corporativos (`aws-sdk-go/v1.34.0`, consolas administrativas).
* **Significado de seguridad:** ¿qué quiere decir lo anterior?
  
## Entregable / Enlace con el Lab 3:
* Lista de entidades de IAM y direcciones IP identificadas como comprometidas, junto con el archivo de flujos de red (`vpc_flows.csv`) correspondiente a las cargas de trabajo desplegadas por dichas entidades.
