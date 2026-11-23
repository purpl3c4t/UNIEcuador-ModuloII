# Laboratorio 4: Respuesta Predictiva en Cloud y Resiliencia de Playbooks SOAR

## Fundamento Técnico y Objetivo
### **Fundamento:** 
* Cuando un modelo de IA detecta una intrusión crítica, la contención manual introduce una latencia inadmisible. 
* Las plataformas SOAR automatizan la remediación en el plano de identidad y de red. 
* No obstante, los atacantes avanzados despliegan técnicas de neutralización contra los playbooks: intentos de supresión de telemetría de auditoría (telemetry muting) y saturación deliberada de llamadas a la API para provocar denegación de servicio por cuotas (API Throttling / HTTP 429).
* La respuesta debe ser arquitectónicamente resiliente, utilizando ejecución fuera de banda (out-of-band), políticas inmutables organizacionales (SCPs) y algoritmos de reintento con retroceso exponencial (exponential backoff).

### Teórico
  * **Inmutabilidad:** El intento del atacante por desactivar la auditoría (`cloudtrail:StopLogging`) es denegado por la política SCP raíz.
  * **Evasión por Throttling:** Observa cómo las llamadas a la API lanzan errores simulados `HTTP 429 Too Many Requests`.
  * **Resiliencia defensiva:** Comprueba cómo el playbook aplica *exponential backoff*, superando la saturación hasta aplicar la frontera de permisos (*Permissions Boundary DenyAll*) y aislar la instancia en el grupo de seguridad de cuarentena.

## **Objetivo:**
* Ingestar la alerta del Laboratorio 3 en un motor de contención SOAR, simular ataques adversariales de saturación de APIs y supresión de registros, aplicar remediación multinivel (aislamiento de red y aplicación de Permissions Boundary DenyAll) y validar la resiliencia del playbook.

### Script en recursos:
_soar_resilient_playbook.py_ (Python / Boto3 Mock Engine)

## Paso a Paso de Ejecución

### Paso 1
1. Tener a la mano el archivo de alertas generado en el Laboratorio 3:
```python  
python3 playbook.py alert_payload.json_
```

2. **Inspeccionar la alerta del detector
```
cat alert_payload.json
```
```python
python3 -c "
import json
with open('alert\_payload.json') as f: data = json.load(f)
  print('ID Alerta:', data.get('alert\_id'))
  print('Severidad:', data.get('severity'))
  print('Motor de IA:', data.get('detection\_engine'))
  print('Rol Comprometido:', data.get('compromised\_role'))
  print('Instancia Afectada:', data.get('compromised\_instance\_id')) "
```

## Paso 2: Ejecutar la simulación adversarial y el playbook de contención:
1. Correr el orquestador resiliente:

```
python soar_resilient_playbook.py
```

2. Analizar la secuencia de ejecución y las respuestas del plano de control en consola:

### Paso 3: Probar de Inmutabilidad: 

1. El intento del adversario de ejecutar cloudtrail: StopLogging es interceptado y denegado por la política de control de la organización raíz (SCP), garantizando la integridad de la auditoría.
2. Neutralización Adversarial por Throttling: Las llamadas a la API para aplicar la contención sufren rechazos estocásticos simulados (HTTP 429 RateLimitExceeded).
3. Resiliencia Adaptativa: El algoritmo SOAR aplica retroceso exponencial progresivo `($T_{\text{wait}} = 2^{\text{attempt}} \cdot 0.1s + \text{jitter}$)`, reintentando las operaciones de contención hasta ejecutarlas satisfactoriamente.

## Verificación: 
1. Comprobar que la salida final confirme la aplicación exitosa de la directiva `IDENTIFICA LA DIRECTIVA` sobre el rol comprometido y la reasignación de la interfaz de red de la instancia i-0cryptominer001 hacia el grupo de seguridad de cuarentena sg-isolated-quarantine.

## Entregable
* Realiza la modificación necesaria sobre el detector SOAR para lograr la contención, deteniendo la evasión adversaria
* Envía el archivo *.py generado.
