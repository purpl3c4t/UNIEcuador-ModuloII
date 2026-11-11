# Unidad 2: Clasificación de Malware (Estático/Dinámico)


## TAREA DEL MÓDULO

### Descripción General

Como proyecto integrador, los estudiantes conformarán parejas asumiendo un rol dual (Red Team / Blue Team) para simular y contener una campaña basada en el paradigma de **Ransomware 3.0** y **Polimorfismo Generativo** (como *BlackMamba* o *PromptLock*)[41].

```
                 CICLO CERRADO DEL PROYECTO INTEGRADOR
┌────────────────────────────────────────────────────────────────────────┐
│ [ FASE RED TEAM ]                                                      │
│  Orquestador base ──► Consulta LLM local (Ollama) ──► Payload Lua      │
│  (Cifrado SPECK-128 in-memory + Execution Guardrails + IAT Oculta)     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Ejecución en Sandbox (120 seg)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ [ FASE BLUE TEAM ]                                                     │
│  Captura de telemetría ──► Extracción n-gramas ──► Scoring PADL / CAPA │
│  Evaluador Conformal (Transcend) ──► Aislamiento y Neutralización      │
└────────────────────────────────────────────────────────────────────────┘

```

### Objetivos y Desafíos del Proyecto

1. **Fase Ofensiva (Red Team):**
  * Estructurar un orquestador que interactúe con un endpoint local de inferencia (ej. API de Ollama o servidor simulado) para solicitar en tiempo de ejecución la generación de un script en Lua que realice una tarea quirúrgica (cifrado con SPECK-128 o recolección de pulsaciones)[44].
  * El ejecutable principal debe incorporar la resolución dinámica de APIs del **Lab 1**, la manipulación de cabeceras para resistir modelos estáticos del **Lab 2**, y salvaguardas que verifiquen el entorno antes de invocar al modelo generativo como en el **Lab 3**[2].
  * La carga devuelta debe interpretarse y ejecutarse **estrictamente en memoria** (mediante el runtime de Lua o primitivas dinámicas) sin generar artefactos persistentes en disco[44].
2. **Fase Defensiva (Blue Team):**
  * Configurar un colector de telemetría que capture la actividad de procesos, archivos y memoria durante la ventana crítica inicial de 120 segundos[29][30].
  * Implementar la capa de detección **PADL**: transformar los n-gramas de comportamiento en etiquetas de política alineadas con MITRE ATT&amp;CK[29][48].
  * Incorporar el filtro de rechazo conformal del **Lab 4** para verificar que, aunque el script generado presente una firma criptográfica única y una sintaxis mutable en cada detonación, el sistema catalogue la anomalía conductual y active la contención automatizada[31].
3. **Criterios de Evaluación y Entrega:**
  * **Dossier de Ingeniería Inversa (40%):** Documentación técnica con desensamblado, grafo de flujo de control (CFG) y análisis de perturbación de cabeceras.
  * **Eficacia de la Capa Defensiva (40%):** Matriz de confusión del clasificador y tasa de abstención de la capa conformal frente a 10 variantes sintéticas generadas por la IA.
  * **Defensa Oral y Análisis Crítico (20%):** Debate técnico sobre la viabilidad económica y táctica del uso de LLMs en malware y las limitaciones de los EDRs actuales frente a la ejecución *fileless*[49]
