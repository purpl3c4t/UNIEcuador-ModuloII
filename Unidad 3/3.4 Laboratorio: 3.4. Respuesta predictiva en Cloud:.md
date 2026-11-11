# Laboratorio 4: Respuesta Predictiva en Cloud y Resiliencia de Playbooks SOAR

## Fundamento Técnico y Objetivo
### **Fundamento:** 
* Cuando un modelo de IA detecta una intrusión crítica, la contención manual introduce una latencia inadmisible. 
* Las plataformas SOAR automatizan la remediación en el plano de identidad y de red. 
* No obstante, los atacantes avanzados despliegan técnicas de neutralización contra los playbooks: intentos de supresión de telemetría de auditoría (telemetry muting) y saturación deliberada de llamadas a la API para provocar denegación de servicio por cuotas (API Throttling / HTTP 429).
* La respuesta debe ser arquitectónicamente resiliente, utilizando ejecución fuera de banda (out-of-band), políticas inmutables organizacionales (SCPs) y algoritmos de reintento con retroceso exponencial (exponential backoff).
**Tiempo objetivo:** 30 minutos
### **Puntos clave a evaluar en la ejecución:**
  * **Inmutabilidad:** El intento del atacante por desactivar la auditoría (`cloudtrail:StopLogging`) es denegado por la política SCP raíz.
  * **Evasión por Throttling:** Observa cómo las llamadas a la API lanzan errores simulados `HTTP 429 Too Many Requests`.
  * **Resiliencia defensiva:** Comprueba cómo el playbook aplica *exponential backoff*, superando la saturación hasta aplicar la frontera de permisos (*Permissions Boundary DenyAll*) y aislar la instancia en el grupo de seguridad de cuarentena.

### **Objetivo:**
* Ingestar la alerta del Laboratorio 3 en un motor de contención SOAR, simular ataques adversariales de saturación de APIs y supresión de registros, aplicar remediación multinivel (aislamiento de red y aplicación de Permissions Boundary DenyAll) y validar la resiliencia del playbook.

### Script en recursos:
_soar_resilient_playbook.py_ (Python / Boto3 Mock Engine)

### Paso a Paso de Ejecución

1. Navega al directorio del laboratorio:cd `../lab4_soar_resilience.py`

2. Ejecuta el playbook de contención automatizada procesando la alerta generada en el Laboratorio 3: _python3 playbook.py alert_payload.json_
a. **Inspeccionar la alerta del detector:**

```
cat alert_payload.json

```
b. **Ejecutar la simulación adversarial y el playbook de contención:** Corre el orquestador resiliente [2, 9, 10]:

```
python recursos/soar_resilient_playbook.py

```

3. Analizar la secuencia de ejecución y las respuestas del plano de control en consola:

4. Probar de Inmutabilidad: 
* El intento del adversario de ejecutar cloudtrail: StopLogging es interceptado y denegado por la política de control de la organización raíz (SCP), garantizando la integridad de la auditoría.
* Neutralización Adversarial por Throttling: Las llamadas a la API para aplicar la contención sufren rechazos estocásticos simulados (HTTP 429 RateLimitExceeded).
* Resiliencia Adaptativa: El algoritmo SOAR aplica retroceso exponencial progresivo ($T_{\text{wait}} = 2^{\text{attempt}} \cdot 0.1s + \text{jitter}$), reintentando las operaciones de contención hasta ejecutarlas satisfactoriamente.

4. **Verificación:** 
Comprueba que la salida final confirme la aplicación exitosa de la directiva `arn:aws:iam::123456789012:policy/DenyAllBoundary` sobre el rol comprometido y la reasignación de la interfaz de red de la instancia i-0cryptominer001 hacia el grupo de seguridad de cuarentena sg-isolated-quarantine.
