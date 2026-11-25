# Laboratorio 2: Detección Avanzada y Creación Sintética de Spear Phishing con LLMs

## Objetivo de Aprendizaje:
Capacitar al estudiante en la comprensión del vector de armamento de Modelos de Lenguaje (LLM Weaponization) para la generación automatizada a escala de campañas de Spear Phishing lateral altamente contextualizadas, y en el diseño y evaluación de canalizaciones defensivas basadas en arquitecturas Transformer (BERT vs. RoBERTa), analizando el impacto de los algoritmos de tokenización de subpalabras (WordPiece vs. Byte-Pair Encoding) y priorizando la minimización operativa del False Negative Rate (FNR) en el SOC.

---

## Contexto y Escenario Práctico
Un actor hostil avanzado (*Advanced Persistent Threat - APT*) aprovecha la inteligencia técnica obtenida en fuentes públicas y foros clandestinos (generada en el Laboratorio 1) para alimentar un modelo de lenguaje generativo. En lugar de redactar correos genéricos de spam con errores ortográficos, el LLM sintetiza comunicaciones internas hiperrealistas que suplantan al departamento de TI y a la dirección de seguridad, instruyendo a los colaboradores a acceder a portales de autenticación simulados para "parchear de urgencia" las vulnerabilidades reales detectadas.

Desde la perspectiva del Blue Team, la pasarela de seguridad tradicional basada en listas negras estáticas y reglas YARA es incapaz de detectar estas comunicaciones sintéticas. El equipo de ciberdefensa debe evaluar modelos de Procesamiento del Lenguaje Natural para identificar los correos maliciosos, analizando cómo la tokenización BPE a nivel de bytes en RoBERTa ofrece mayor resiliencia ante variaciones adversarias que la tokenización WordPiece en BERT.

---

## Recursos Involucrados:
* **Entorno de Ejecución:** Python 3.12 con bibliotecas `pandas`, `numpy`, `scikit-learn`.
* **Datos de Entrada:** `lab1_cti_ner/stix_cti_graph.json` (inteligencia CTI estructurada del Laboratorio 1).
* **Scripts de Procesamiento:**
  * `lab2_phishing/generate_dataset.py` (Módulo Ofensivo / Red Team: Generador contextual).
  * `lab2_phishing/train_eval_phish_detector.py` (Módulo Defensivo / Blue Team: Evaluador de tokenizadores y clasificadores).
* **Artefacto de Salida:** `lab2_phishing/synthetic_phish_eval.csv` (Corpus de evaluación balanceado con etiquetas de seguridad).

---

## Metodología Paso a Paso

### Paso 1: Ingesta y Preprocesamiento
1. Verifica que el grafo de inteligencia del Laboratorio 1 esté presente:
   ```bash
   ls -l lab1_cti_ner/stix_cti_graph.json
   ```
2. Ejecuta el generador ofensivo contextual:
   ```bash
   python3 lab2_phishing/generate_dataset.py
   ```
3. El script ingesta el grafo STIX 2.1, identifica los actores de amenazas activos (`TA505`, `Scattered Spider`) y los identificadores de vulnerabilidades (`CVE-2023-34362`, `CVE-2024-1709`), y sintetiza comunicaciones legítimas corporativas (estilo *Enron*) intercaladas con ataques dirigidos de Spear Phishing lateral.

### Paso 2: Exportación Estructurada:
1. Inspecciona el archivo de evaluación generado:
   ```bash
   head -n 10 lab2_phishing/synthetic_phish_eval.csv
   ```
2. Constata que el archivo contiene las columnas `subject`, `body`, `label` ($0$ para benigno, $1$ para malicioso) y `category` (`benign_ham` vs `deceptive_spear`).
3. Comprueba el volumen total de registros generados (29 muestras balanceadas).

### Paso 3: Benchmark Comparativo de Tokenización y Clasificación Defensiva
1. Ejecuta el módulo de evaluación defensiva:
   ```bash
   python3 lab2_phishing/train_eval_phish_detector.py
   ```
2. **Análisis de Tokenización (WordPiece vs. BPE):**
   * Observa en consola cómo WordPiece (BERT) fragmenta agresivamente términos técnicos (`CVE-2023-34362` se divide en `['CVE-', '##2023-', '##34362']`), mientras que BPE (RoBERTa) opera a nivel de bytes, manteniendo la coherencia de URLs ofuscadas y hashes criptográficos.
3. **Evaluación de Métricas SOC:**
   * Examina la tabla comparativa de desempeño:
     * **Precisión:** Proporción de alertas de phishing que corresponden a ataques reales (~82.76%).
     * **Recall:** Capacidad de capturar el 100% de los incidentes hostiles ($1.0$).
     * **False Negative Rate (FNR):** Tasa de correos maliciosos que logran infiltrarse inadvertidos en la bandeja del usuario ($0.0$).
   * Justifica operativamente por qué un Falso Positivo solo requiere triage menor por un analista L1 (~$15 USD), mientras que un Falso Negativo desencadena una intrusión de ransomware multimillonaria.

---

## Verificación

Para certificar la correcta ejecución del laboratorio:

1. **Confirmar la existencia del dataset sintetizado:**
   ```bash
   wc -l lab2_phishing/synthetic_phish_eval.csv
   ```
   *(Debe reportar 30 líneas, correspondientes al encabezado y los 29 registros).*

2. **Validar las métricas defensivas en consola:**
   ```text
                  Modelo  Precision  Recall  F1-Score  Falsos Negativos (FN)  Tasa Falsos Negativos (FNR)
      BERT-base Pipeline     0.8276     1.0    0.9057                      0                          0.0
   RoBERTa-base Pipeline     0.8276     1.0    0.9057                      0                          0.0
   ```

---

### Entregable Técnico Requerido
1. Archivo `lab2_phishing/synthetic_phish_eval.csv` debidamente generado con base en el grafo del Lab 1.
2. Informe técnico breve o captura de consola que detalle:
   * La demostración de fragmentación de tokens entre WordPiece y BPE.
   * La tabla de métricas (Precision, Recall, F1, FNR) y la justificación económica de por qué el SOC prioriza minimizar el FNR ante ataques de Spear Phishing.
