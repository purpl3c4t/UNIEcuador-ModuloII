# Tarea integrador de Unidad 3 "Pipeline Autónomo de Emulación Adversarial y Defensa en la Nube"

Como evaluación de cierre de la unidad, los estudiantes deben presentar un informe técnico y demostración en vivo organizados en parejas (Blue Team vs. Red Team):
Despliegue Red Team (Emulación Adversarial):Ejecutar la cadena completa: robo de credenciales vía SSRF sobre IMDSv1 $\rightarrow$ escalada por grafos IAM $\rightarrow$ aprovisionamiento de recursos para secuestro de cómputo $\rightarrow$ exfiltración por canal HTTPS/DoH $\rightarrow$ saturación de APIs para intentar cegar al SOAR.

**Despliegue Blue Team (Defensa Predictiva y Respuesta):**
Ingestar la telemetría en tiempo real, procesar los vectores con el modelo híbrido de Machine Learning y disparar el playbook automatizado fuera de banda para aislar la carga y revocar privilegios.

**Métricas de Evaluación:**
* MTTD (Tiempo Medio de Detección): Debe ser menor a 3 minutos desde la primera llamada anómala a la API.
* MTTR (Tiempo Medio de Respuesta): La contención debe completarse en menos de 30 segundos tras la emisión de la alerta de IA.
* Tasa de Acierto del Modelo: Alcanzar un puntaje `$F_1 \ge 0.95$` en la clasificación de flujos de exfiltración encubierta sin generar falsos positivos sobre el tráfico legítimo de desarrollo.

### Fundamento Técnico y Objetivo
* **Fundamento:**
Las arquitecturas de ciberseguridad asistidas por Inteligencia Artificial deben evaluarse bajo condiciones de operación reales, donde las tácticas ofensivas (Red Team) y las capacidades predictivas de detección y contención (Blue Team) interactúan simultáneamente (Purple Team Assessment).
* **Objetivo:** Diseñar y ejecutar de extremo a extremo un pipeline continuo que integre la cadena completa de intrusión (explotación de IMDSv1, escalada IAM, secuestro de servicios y exfiltración encubierta) contra el pipeline de defensa autónoma (recolección de telemetría, inferencia no supervisada híbrida con Autoencoder + Isolation Forest y contención resiliente en SOAR).
*
### Scripts y Recursos en 
pipeline_orchestrator.py (Python / End-to-End Test Harness)config_assessment.json (Parámetros operacionales y umbrales de evaluación)

### Paso a Paso de Ejecución
1. Descarga desde el directorio de Github: project_pipeline
   
3. Configurar los parámetros de evaluación y umbrales de rendimiento en el archivo de control: `cat config_assessment.json`
(Verifica que los umbrales exijan: MTTD $\le$ 180s, MTTR $\le$ 30s, y $F_1\text{-score} \ge 0.95$).

2. Ejecutar el orquestador del pipeline completo de emulación adversarial y respuesta autónoma:
   `python3 pipeline_orchestrator.py --config config_assessment.json --mode full-assessment`

3. Monitorea las fases secuenciales reportadas en consola:

* Fase I (Red Team - Infiltración): Simulación de petición SSRF, robo de credenciales STS vía IMDSv1 y escalada mediante iam:PassRole.
* Fase II (Blue Team - Telemetría & Detección API): Ingesta de registros de auditoría y cálculo de anomalías por variaciones de entropía en llamadas a APIs.
* Fase III (Red Team - Exfiltración Encubierta): Transmisión de datos simulada hacia cuenta externa S3 y mediante DoH cifrado.
* Fase IV (Blue Team - Clasificación por IA): Activación del Autoencoder y el Isolation Forest para segmentar los flujos de exfiltración.
* Fase V (Blue Team - Respuesta SOAR): Disparo de la contención fuera de banda con mitigación activa contra ráfagas de API Throttling.

### Verificación:
1. Inspecciona el informe consolidado final purple_team_results.json generado automáticamente en el directorio y valida que todas las métricas de efectividad defensiva cumplan los estándares exigidos para la acreditación del módulo:
* MTTD (Mean Time to Detect): Registro temporal inferior a 3 minutos desde el inicio del ataque.
* MTTR (Mean Time to Respond): Contención de identidad y aislamiento de red en menos de 30 segundos tras la alerta.
* Tasa de Resiliencia del Playbook: 100% de éxito en acciones de contención frente a saturación de API inducida.
