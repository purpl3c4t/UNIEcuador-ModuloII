# Laboratorio 4: Detección Adaptativa Temprana y Clasificación ante Concept Drift (30 min)
* **Prerrequisito:** El registro de telemetría de eventos generado en el Laboratorio 3 y un dataset longitudinal de variantes sintéticas de malware.

## 🎯 Objetivo de la Práctica 
1. **Componente Ofensivo:** Comprender y experimentar con la **Generación Automática de Payloads Asistida por IA** (*Polimorfismo Generativo*, ataques *Living Off the LLM*, *BlackMamba* y *Ransomware 3.0*), sintetizando variantes polimórficas en memoria con mutación continua de hashes y sintaxis.
2. **Componente Defensivo:**
   * Diagnosticar el fenómeno de **Concept Drift** (Deriva Virtual y Real) y medir el envejecimiento del clasificador bajo el protocolo cronológico **TESSERACT**.
   * Implementar la **Predicción Conformal con Opción de Rechazo (marco Transcend / Transcendent)** para aislar amenazas *Zero-Day* fuera de distribución (OOD) y evitar falsos negativos críticos.
   * Procesar la telemetría dinámica de la ventana de **120 segundos** (`telemetry_120s.json` proveniente del **Laboratorio 3**) mediante la arquitectura **PADL (Policy-Adaptive Detection Layer)** para neutralizar la amenaza antes de su propagación.

---

## 🛠️ Paso a Paso Técnico para el Estudiante

### Paso 1: Generación y Experimentación de Payloads Asistidos por IA
El estudiante puede ejecutar el generador en **modo interactivo** o mediante **argumentos de terminal** para experimentar con la mutación polimórfica:

#### Opción A: Modo Interactivo
```bash
python3 payload_generator_ai.py --interactive
```
*El asistente solicitará:*
1. Tipo de Payload:
   * `[1]` **Ransomware 3.0** (Cifrado quirúrgico selectivo con SPECK-128 / ChaCha20 sin ráfagas masivas de I/O).
   * `[2]` **In-Memory Credential Stealer** (Técnica BlackMamba: extracción en heap y exfiltración directa).
   * `[3]` **Reflective Syscall Loader** (Resolución de SSN y lectura de PEB sin tocar disco).
2. Número de variantes a sintetizar (ej. 3 a 5).

#### Opción B: Modo por Línea de Comandos (CLI)
```bash
python3 payload_generator_ai.py --type ransomware_speck --iterations 3 --mutation high --export-dir generated_payloads
```

*Salida esperada:*
```text
[*] Generando 3 variantes de tipo 'ransomware_speck' (Mutación: high)...
  [+] Variante 1: SHA-256=b128182186c820de... | Cifrado=ChaCha20   | Entropía=5.0179
  [+] Variante 2: SHA-256=ec19efbec57135e8... | Cifrado=XOR-Rolling | Entropía=5.0050
  [+] Variante 3: SHA-256=aa58ce6d55fedc5e... | Cifrado=SPECK-128   | Entropía=5.0776
[+] Finalizado. Variantes guardadas en 'generated_payloads/' (generated_payloads/payload_metadata.json)
```

*Análisis* Observar cómo cada iteración produce un hash SHA-256 completamente distinto, nombres de variables mutados y algoritmos criptográficos rotativos, haciendo inservibles las firmas estáticas tradicionales.

---

### Paso 2: Evaluación Defensiva con Telemetría de Lab 3 (TESSERACT, Transcend y PADL)
Ejecute el motor de evaluación consumiendo el archivo de telemetría de 120 segundos generado en el **Laboratorio 3** (`../lab3_guardrails/telemetry_120s.json`) y vinculando los payloads recién generados:

```bash
python3 concept_drift_padl.py ../lab3_guardrails/telemetry_120s.json --eval-payload generated_payloads/payload_metadata.json
```

*Salida esperada del reporte defensivo:*
```text
==========================================================================
 LABORATORIO 4: CONCEPT DRIFT, CONFORMAL PREDICTION Y DEFENSA TEMPRANA PADL
 Tema 2.4: Modelos Predictivos y AI para Generación Automática de Payloads
==========================================================================

[FASE 1] Evaluación de Concept Drift Temporal (Protocolo TESSERACT):
  -> Periodo T0 (Entrenamiento inicial / Línea Base)   : F1 = 1.0000
  -> Periodo T1 (Drift Virtual - Hashing & Obfuscation) : F1 = 0.9950
  -> Periodo T2 (Drift Real - Polimorfismo & AI Payloads): F1 = 0.4733
  [!] Caída de rendimiento por envejecimiento de modelo : -52.7%

[FASE 2] Capa de Predicción Conformal (Transcend Framework, umbral p=0.15):
  -> Tasa Global de Muestras Rechazadas (Cuarentena/SOC)  : 52.5%
  -> Tasa de Aislamiento de Malware Zero-Day (OOD)        : 100.0%
  -> Precisión en Muestras Aceptadas con Certidumbre     : 100.00%
  [✓] Diagnóstico: Las amenazas Zero-Day son aisladas estadísticamente en lugar de generar falsos negativos.

==========================================================================
 EVALUACIÓN DEL COMPONENTE DE GENERACIÓN AUTOMÁTICA DE PAYLOADS (AI)
 Insumo: generated_payloads/payload_metadata.json (3 variantes detectadas)
==========================================================================
[*] Variante 1 [ransomware_speck | ChaCha20 | Entropía: 5.0179]:
    - Hash SHA-256               : b128182186c820de...
    - Clasificador Estándar      : Predicción = MALWARE (Confianza: 0.700)
    - Capa Conformal (Transcend) : p-value = 0.0000 (Umbral de Rechazo: 0.15)
    - Decisión Final de Defensa  : RECHAZADA -> CUARENTENA / SOC (OOD)
      [✓] Éxito Defensivo: Variedad Zero-Day detectada y aislada mediante rechazo estadístico.

==========================================================================
[FASE 3] Detección Temprana PADL en la Ventana Crítica de 120 Segundos
  -> Archivo de telemetría analizado: '../lab3_guardrails/telemetry_120s.json'
==========================================================================
[*] Puntuación de Telemetría Temprana PADL: 0.8909 (Umbral de bloqueo: 0.70)
[*] Reglas de Política Temprana Activadas en Memoria:
    -> [ACTIVADA] PADL-01 [T+5s]: Asignación y protección RWX en memoria virtual (NtAllocateVirtualMemory)
    -> [ACTIVADA] PADL-01 [T+12s]: Asignación y protección RWX en memoria virtual (NtWriteVirtualMemory)
    -> [ACTIVADA] PADL-01 [T+25s]: Asignación y protección RWX en memoria virtual (NtProtectVirtualMemory)
    -> [ACTIVADA] PADL-08 [T+70s]: Creación de hilo remoto tras reserva de memoria (NtCreateThreadEx)
    -> [ACTIVADA] PADL-03 [T+105s]: Detección de retardo o manipulación de ejecución (NtDelayExecution)

[✓] DECISIÓN DEFENSA PADL: AMENAZA BLOQUEADA Y AISLADA PROACTIVAMENTE.
    Causa: Encadenamiento de operaciones en memoria en los primeros 120s.
    Efectividad: Neutralizada antes de propagación o ejecución del cifrado masivo.

[+] Reporte de evaluación exportado para entrega: 'lab4_evaluation_report.json'
==========================================================================
```

---

## Verificación
1. **Polimorfismo Generativo:** Comparar los archivos `.lua` generados en `generated_payloads/`. ¿Por qué ningún antivirus basado en firmas (hashes) puede bloquear la segunda variante a partir de la firma de la primera?
2. **Concept Drift:** ¿Cuál es la diferencia matemática entre el deterioro leve observado en T1 (Drift Virtual) y el colapso abrupto en T2 (Drift Real)?
3. **Opción de Rechazo Conformal:** ¿Por qué un p-value cercano a 0.0000 en el marco Transcend permite enviar una muestra a cuarentena sin necesidad de que el modelo adivine si es benigna o maliciosa?
4. **Ventana de 120s de PADL:** Observe la regla `PADL-08` en el segundo T+70s. ¿Por qué es crucial que el EDR/SIEM bloquee la muestra en ese momento y no espere a los 300 segundos tradicionales?

