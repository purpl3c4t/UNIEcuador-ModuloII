# Suite de Laboratorios Prácticos: Análisis Binario Asistido por IA, Evasión Ofensiva y Detección Comportamental

Bienvenido al repositorio oficial de materiales prácticos para la suite de laboratorios de la **Unidad 2: Ciclo de Vida del Malware, Evasión de EDR y Ciberdefensa Asistida por Inteligencia Artificial**. Este paquete contiene el código ejecutable en Python y C, scripts de auditoría, implementaciones de modelos en PyTorch/Scikit-learn, generadores de telemetría y guías técnicas para desarrollar 4 laboratorios prácticos acumulativos (30 minutos cada uno, 2 horas en total) y un Proyecto Integrador autónomo en ciclo cerrado.

---
## 🚀 Requisitos y Configuración del Entorno

Los scripts están desarrollados en Python 3.10+ y C (MinGW-w64 / MSVC para compilación nativa en Windows) utilizando bibliotecas estándares de ciencia de datos, aprendizaje profundo y ciberseguridad.

### Instalación de Dependencias (Python)
```bash
pip install torch numpy scikit-learn lightgbm
```

*(Opcional: Compilador cruzado x64 en distribuciones Linux / Debian / Ubuntu):*
```bash
sudo apt-get install gcc-mingw-w64-x86-64
```

---
## ⏱️ Secuencia de Ejecución de los Laboratorios (2 Horas)

Los 4 ejercicios están encadenados de forma acumulativa: cada laboratorio consume el artefacto binario o la telemetría generada en la práctica inmediatamente anterior.

```
[ Lab 1: ~30 min ] ──► Compilación del Loader PEB/API Hashing
         │              (Generación de stage1_loader.exe con IAT oculta)
         ▼
[ Lab 2: ~30 min ] ──► Evasión de MalConv mediante DOS Header Perturbation
         │              (Manipulación de 58 bytes en cabecera PE -> stage2_evasive.exe)
         ▼
[ Lab 3: ~30 min ] ──► Inyección de Execution Guardrails y Evasión Dinámica
         │              (Blindaje anti-análisis y exportación de telemetría de 120s)
         ▼
[ Lab 4: ~30 min ] ──► Detección Adaptativa Temprana (PADL / Transcend)
         │              (Evaluación de telemetría de 120s y mitigación de Concept Drift)
         ▼
[ PROYECTO FINAL ] ──► The AI Cyber Arms Race: Simulación Red Team vs Blue Team
```

---

### Laboratorio 1: Resolución Dinámica de APIs y Evasión de IAT (30 min)
* **Objetivo:** Comprender la técnica MITRE ATT&CK T1027.007 para ocultar dependencias críticas de la Import Address Table (IAT) en memoria virtual mediante el recorrido de `InMemoryOrderModuleList` en el Process Environment Block (PEB) y el algoritmo de API Hashing ROR13.
* **Flujo Acumulativo:** Genera el binario base `stage1_loader.exe` con IAT limpia, que sirve como insumo obligatorio para el Laboratorio 2.
* **Ejecución:**
  ```bash
  cd lab1_dynamic_api
  python3 audit_iat_hashing.py stage1_loader.exe
  ```
  *(Opcional: Compilación nativa en C con MinGW-w64):*
  ```bash
  x86_64-w64-mingw32-gcc stage1_loader.c -o stage1_loader.exe -s
  ```

---

### Laboratorio 2: Auditoría y Evasión Adversaria de MalConv (30 min)
* **Objetivo:** Auditar la robustez del modelo de aprendizaje profundo MalConv (Raff et al.) utilizando *Integrated Gradients*, detectar el sesgo decisorio desproporcionado hacia las cabeceras PE y aplicar un ataque adversario manipulando 58 bytes libres del *DOS Header*.
* **Flujo Acumulativo:** Toma `stage1_loader.exe` del Lab 1, preserva la funcionalidad del ejecutable (`.text`, número mágico `MZ` y puntero `e_lfanew` en `0x3C`) y genera `stage2_evasive.exe`, reduciendo la probabilidad predicha por la IA por debajo del umbral de detección.
* **Ejecución:**
  ```bash
  cd ../lab2_static_evasion
  python3 malconv_adversarial.py ../lab1_dynamic_api/stage1_loader.exe stage2_evasive.exe
  ```

---

### Laboratorio 3: Implementación de Execution Guardrails y Evasión de Sandbox (30 min)
* **Objetivo:** Instrumentar el binario con salvaguardas condicionales en tiempo de ejecución (MITRE ATT&CK T1480 / T1497: sondeo CPUID en hoja `0x40000000`, detección de recursos $\le 2$ vCPUs y anomalías temporales RDTSC). Comparar la efectividad de la evasión frente a sandboxes tradicionales vs. la Introspección de Máquinas Virtuales (VMI en Ring -1 con DRAKVUF / EPT).
* **Flujo Acumulativo:** Detona el artefacto en un entorno con VMI transparente y exporta el archivo de telemetría de eventos de los primeros dos minutos (`telemetry_120s.json`), insumo del Laboratorio 4.
* **Ejecución:**
  ```bash
  cd ../lab3_guardrails
  python3 guardrails_sandbox.py
  ```

---

### Laboratorio 4: Detección Adaptativa Temprana y Clasificación ante Concept Drift (30 min)
* **Objetivo:** Cuantificar la degradación del clasificador estándar evaluado cronológicamente bajo el protocolo TESSERACT ante *Virtual Drift* y *Real Drift*. Implementar una capa de *Predicción Conformal con Opción de Rechazo (marco Transcend / Transcendent)* y evaluar la regla de detección temprana de la arquitectura *PADL (Policy-Adaptive Detection Layer)* en la ventana de 120 segundos.
* **Flujo Acumulativo:** Ingiere `telemetry_120s.json` generado en el Lab 3 y aplica la puntuación de políticas tempranas sobre eventos sospechosos en memoria antes de la fase de propagación o cifrado.
* **Ejecución:**
  ```bash
  cd ../lab4_detection_drift
  python3 concept_drift_padl.py ../lab3_guardrails/telemetry_120s.json
  ```

---

## 🏆 Proyecto Integrador Autónomo: The AI Cyber Arms Race

El estudiante asume un rol dual (Red Team / Blue Team) para simular y contener en ciclo cerrado una campaña inspirada en el paradigma de **Ransomware 3.0** y **Polimorfismo Generativo** (como *BlackMamba*, *PromptLock* o ataques *Living Off the LLM*):

* **Red Team:** Un orquestador genera en memoria scripts mutables en tiempo de ejecución interactuando con un modelo generativo, cifrando archivos con SPECK-128 con hashes criptográficos únicos en cada iteración y sin tocar disco.
* **Blue Team:** El motor defensivo captura la telemetría comportamental de los primeros 120 segundos, correlaciona las llamadas a memoria virtual y evaluación de políticas PADL, y activa el aislamiento preventivo mediante rechazo conformal.

### Ejecución del Proyecto:
```bash
cd ../proyecto_final
python3 ai_cyber_arms_race.py
```

### Reporte a Entregar:
El reporte técnico final a presentar debe incluir:
1. **Dossier de Evasión (Red Team):** Justificación de cómo la resolución dinámica del Lab 1, la perturbación del DOS Header del Lab 2 y los guardrails del Lab 3 se combinan con la orquestación generativa para eludir firmas estáticas e inspectores tradicionales.
2. **Evaluación de Resiliencia (Blue Team):** Análisis de la matriz de degradación por Concept Drift del Lab 4, justificando por qué la opción de rechazo conformal previene falsos negativos críticos al abstenerse ante muestras fuera de distribución (OOD).
3. **Análisis de la Ventana de 120s (PADL):** Evaluación de la puntuación obtenida en runtime y recomendaciones operativas para la integración de políticas tempranas en un SOC o pipeline EDR/XDR moderno.
