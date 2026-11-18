# Unidad 2: Clasificación de Malware (Estático/Dinámico)

## Tarea de Módulo: The AI Cyber Arms Race (Campaña Ofensiva vs. Pipeline Defensivo en Capas)

---

## Objetivos de Aprendizaje

Al completar este proyecto integrador se podrá
* Modelar el ciclo de vida completo de un ataque moderno impulsado por IA (*Living Off the LLM* y polimorfismo generativo en memoria).
* Explicar cuantitativamente por qué las defensas perimetrales y estáticas convencionales (antivirus por firmas y clasificadores de Machine Learning sin protección adversarial) colapsan ante técnicas combinadas de evasión.
* Evaluar e implementar un pipeline de defensa en profundidad que combine **aislamiento estadístico conformal** (para mitigar el *Concept Drift* sin falsos negativos) con **inspección comportamental temprana en Ring -1**.

---

## Arquitectura del Enfrentamiento (Red Team vs. Blue Team)

```text
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                        THE AI CYBER ARMS RACE: CICLO CERRADO DE SIMULACIÓN                             │
├────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                        │
│  [ RED TEAM: Campaña Ofensiva Modular (Ransomware 3.0) ]                                               │
│  ┌───────────────────────┐   ┌───────────────────────┐   ┌──────────────────────────────────────────┐  │
│  │ 1. Loader con IAT     │──►│ 2. Perturbación de    │──►│ 3. Orquestador Generativo (LLM)          │  │
│  │    Oculta (PEB/ROR13) │   │    58 bytes DOS Header│   │    Micro-script mutable con SPECK-128    │  │
│  └───────────────────────┘   └───────────────────────┘   └──────────────────────────────────────────┘  │
│                                                                                 │                      │
│                                                                                 ▼                      │
│  [ BLUE TEAM: Pipeline Defensivo en Capas ]                                                            │
│  ┌─────────────────────────────────┐                                                                   │
│  │ Capa 1: Antivirus Estático (IAT)│ ──► [BYPASS: IAT limpia, Score: 0/100]                            │
│  └────────────────┬────────────────┘                                                                   │
│                   ▼                                                                                    │
│  ┌─────────────────────────────────┐                                                                   │
│  │ Capa 2: Red Neuronal MalConv    │ ──► [BYPASS: Probabilidad maliciosa cae a 0.22 < 0.50]            │
│  └────────────────┬────────────────┘                                                                   │
│                   ▼                                                                                    │
│  ┌─────────────────────────────────┐                                                                   │
│  │ Capa 3: Transcend Conformal     │ ──► [CONTENCIÓN 1: p-value < 0.15 -> CUARENTENA OOD / ZERO-DAY]  │
│  └────────────────┬────────────────┘                                                                   │
│                   ▼                                                                                    │
│  ┌─────────────────────────────────┐                                                                   │
│  │ Capa 4: VMI Ring -1 (DRAKVUF)   │ ──► [TRANSPARENTE: altp2m neutraliza guardrails CPUID/RDTSC]      │
│  └────────────────┬────────────────┘                                                                   │
│                   ▼                                                                                    │
│  ┌─────────────────────────────────┐                                                                   │
│  │ Capa 5: Políticas PADL (120s)   │ ──► [CONTENCIÓN 2: Score 0.89 >= 0.70 -> Regla PADL-08 (T+70s)]   │
│  └─────────────────────────────────┘     [PROCESO AISLADO PROACTIVAMENTE ANTES DE CIFRADO MASIVO]      │
│                                                                                                        │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Instrucciones de Ejecución

El proyecto DEBE ser ejecutado directamente mediante el script unificado `ai_cyber_arms_race.py` con los siguientes argumentos:

```bash
cd proyecto_final
python3 ai_cyber_arms_race.py --rounds 3 --telemetry ../lab3_guardrails/telemetry_120s.json --export proyecto_integrador_report.json
```

### Parámetros Disponibles:
* `--rounds N`: Número de rondas de ataque/defensa a simular (por defecto: `3`). Cada ronda rota algoritmos criptográficos (`SPECK-128`, `ChaCha20-Poly1305`, `XOR-Rolling-Key`) y muta los identificadores sintácticos.
* `--telemetry PATH`: Ruta al archivo de telemetría de 120 segundos extraído del entorno con VMI en el Laboratorio 3.
* `--export PATH`: Ruta donde se guardará el dossier estructurado en formato JSON con la evidencia para la entrega del estudiante (por defecto: `proyecto_integrador_report.json`).

---

## ENTREGABLE
---

###Salida Esperada en Consola

```text
========================================================================================
 PROYECTO FINAL INTEGRADOR: THE AI CYBER ARMS RACE
 Simulación en Ciclo Cerrado: Red Team (Ransomware 3.0) vs. Blue Team (Pipeline Defensivo)
========================================================================================

########################################################################################
 >>> [RONDA 1/3] CAMPAÑA ADVERSARIA EN CURSO (Algoritmo Criptográfico: SPECK-128)
########################################################################################
[*] [RED TEAM] Desplegando artefacto ofensivo multietapa:
    -> Loader PE         : loader_r1.exe (SHA-256: 846031cec8020400...)
    -> Ofuscación IAT    : Dynamic API Resolution (PEB + ROR13) [IAT Size: 0]
    -> Perturbación DOS  : 58 bytes libres modificados (Preserva 'MZ' y e_lfanew en 0x80)
    -> Guardrails        : CPUID (0x40000000), Hardware Check (<=2 vCPUs), Timing (RDTSC)
    -> Payload IA        : Micro-script en memoria generado dinámicamente (SPECK-128)

[*] [BLUE TEAM] Activando Pipeline Defensivo en Capas:
    [1/5] Capa 1: ApexGuard Heuristic AV      -> Veredicto: CLEAN / ALLOWED           | Bypass: True
    [2/5] Capa 2: MalConv Deep Learning Classifier -> Prob: 0.2752 | Veredicto: BENIGN (Falso Negativo)
    [3/5] Capa 3: Transcend Conformal Reject Filter -> p-value: 0.0111 | Acción: QUARANTINE_OOD
          [✓] FILTRO TRANSCEND ACTIVADO: Muestra catalogada como Out-of-Distribution (OOD).
              Enviada a cuarentena preventiva evitando falso negativo.
    [4/5] Capa 4: Sandbox Dinámico            -> Veredicto: MONITOREO TRANSPARENTE (Guardrails neutralizados por hardware EPT)
    [5/5] Capa 5: Motor de Políticas Tempranas PADL (120s) -> Score: 0.8909 (Umbral: 0.7)
          [✓] CONTENCIÓN EN TIEMPO REAL: Regla PADL-08 disparada a los T+70s.
              Aislamiento de proceso efectuado antes de que comience el cifrado quirúrgico.

========================================================================================
 RESUMEN TÉCNICO Y EVALUACIÓN DEL PROYECTO INTEGRADOR
========================================================================================
 [*] Total de Rondas Simuladas                  : 3
 [*] Tasa de Bypass de Capas Estáticas (AV/IA)   : 100.0% (Esperado por diseño ofensivo)
 [*] Tasa de Aislamiento Conformal (Transcend)  : 100.0% (Contención Zero-Day)
 [*] Tasa de Contención Temprana PADL (120s)     : 100.0% (Contención en memoria)
 [✓] EFECTIVIDAD FINAL DE DEFENSA EN PROFUNDIDAD : 100.0% DE AMENAZAS NEUTRALIZADAS

[+] Dossier de evidencia exportado exitosamente: 'proyecto_integrador_report.json'
========================================================================================
```

---

### Verificación

Analizar que los siguientes puntos se respondan en los ejes fundamentales solicitados en el archivo `proyecto_integrador_report.json`:

### 1. Dossier de Evasión Multietapa (Perspectiva Red Team)
* Justifique por qué la combinación de **Dynamic API Resolution** (Lab 1) y la **Perturbación del DOS Header** (Lab 2) logró un 100% de bypass en las Capas 1 y 2.
* Analice cómo la generación de micro-scripts en memoria por LLMs elude las listas de control basadas en hashes criptográficos convencionales (MD5/SHA-256).

### 2. Eficacia de la Predicción Conformal y el Rechazo Estadístico (Perspectiva Blue Team)
* Explique por qué el clasificador MalConv produjo un falso negativo ante la muestra perturbada, mientras que el filtro **Transcend** (Capa 3) logró contener la amenaza.
* Detalle qué significa estadísticamente que el *p-value* sea inferior a $\alpha = 0.15$ y por qué la opción de rechazo previene incidentes catastróficos en el SOC ante amenazas *Zero-Day*.

### 3. Contención Comportamental Temprana y Recomendaciones para SIEM/SOAR
* Analice la traza de telemetría de 120 segundos del Laboratorio 3 y determine en qué momento exacto ($T+70s$) la regla **PADL-08** emitió la orden de aislamiento preventivo.
* Plantee tres recomendaciones operativas concretas para integrar la arquitectura **VMI (Ring -1)** y las políticas **PADL** en un entorno corporativo de detección y respuesta a incidentes (EDR/XDR/SOAR).

