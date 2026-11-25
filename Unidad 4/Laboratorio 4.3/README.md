# Laboratorio 3: Prevención de Fraude Corporativo: Detección de Ataques BEC y Fraude del CEO con CatBoost

## Objetivo de Aprendizaje:
Capacitar al estudiante en la implementación de canalizaciones analíticas de baja latencia y alta precisión para la detección en tiempo real de ataques de Compromiso de Correo Corporativo (Business Email Compromise - BEC) y Fraude del CEO desprovistos de cargas técnicas (sin malware ni enlaces), mediante la formulación de características psicolingüísticas avanzadas (entropía de Shannon, legibilidad Flesch-Kincaid, asimetría de autoridad), el entrenamiento de modelos de Gradient Boosting optimizados (*Ordered Boosting* con CatBoost) y la generación de explicabilidad forense interpretable para analistas del SOC a través de valores SHAP (*SHapley Additive exPlanations*).

---

## Contexto y Escenario Práctico
El fraude corporativo BEC genera pérdidas superiores a los $2,700M–$2,900M anuales a nivel global. A diferencia del phishing tradicional, los correos de fraude del CEO no contienen ejecutables maliciosos, exploits ni enlaces a páginas clonadas: son mensajes de texto plano enviados desde dominios tipográficamente similares (*display name spoofing*) o desde cuentas legítimas comprometidas (*Account Takeover - ATO*). 
El atacante manipula psicológicamente al personal de tesorería o contabilidad simulando una orden urgente, confidencial y fuera de procedimiento del Director General para transferir fondos a cuentas bajo control del adversario.

Las pasarelas de seguridad perimetrales convencionales (antivirus y gateways de correo basados en firmas) son completamente ciegas ante este vector. En este laboratorio, el estudiante construye un detector de inspección profunda que procesa correos entrantes en menos de un milisegundo (requisito de inline mail-flow), clasificando el riesgo con base en la estructura lingüística y generando una justificación forense transparente para que los analistas del SOC puedan congelar pagos sospechosos con total certeza.

---

## Recursos Involucrados:
* **Entorno de Ejecución:** Python 3.12 con bibliotecas `catboost`, `pandas`, `numpy`, `scikit-learn`.
* **Datos de Entrada:** `data/bec_fraud_dataset.csv` (18 muestras balanceadas de flujos legítimos y correos de fraude BEC del CEO).
* **Scripts de Procesamiento:**
  * `lab3_bec_catboost/feature_extraction.py` (Módulo extractor de 12 dimensiones psicolingüísticas y de cabecera).
  * `lab3_bec_catboost/train_catboost_bec.py` (Módulo de entrenamiento, medición de latencia y cálculo de SHAP).
* **Artefactos de Salida:**
  * `lab3_bec_catboost/bec_catboost.cbm` (Binario serializado del modelo CatBoost).
  * `lab3_bec_catboost/shap_importance_report.json` (Informe estructurado de importancia de características).

---

## Metodología Paso a Paso

### Paso 1: Ingesta y Preprocesamiento
1. Inspecciona el conjunto de datos de comunicaciones corporativas:
   ```bash
   head -n 6 data/bec_fraud_dataset.csv
   ```
2. Observa que las muestras maliciosas carecen de enlaces y archivos adjuntos; su anomalía radica en la manipulación discursiva y discrepancias en los encabezados RFC 5322.
3. El módulo `feature_extraction.py` transforma el texto y metadatos en un vector de 12 características continuas y binarias:
   * **Entropía de Shannon del Texto:** Cuantifica la concentración de vocabulario y la simplificación sintáctica forzada:
     $$H(S) = -\sum_{i=1}^{K} p(x_i) \log_2 p(x_i)$$
   * **Grado Escolar Flesch-Kincaid ($GL$):** Evalúa la longitud media de oraciones y sílabas:
     $$GL = 0.39 \left(\frac{\text{palabras}}{\text{oraciones}}\right) + 11.8 \left(\frac{\text{sílabas}}{\text{palabras}}\right) - 15.59$$
   * **Marcadores Psicológicos y de Cabecera:** Conteo de términos de urgencia, secreto/confidencialidad, transacciones financieras y la bandera booleana `display_name_spoofed`.

### Paso 2: Exportación Estructurada:
1. Ejecuta el pipeline completo de entrenamiento y extracción:
   ```bash
   python3 lab3_bec_catboost/train_catboost_bec.py
   ```
2. El script procesa las muestras, compila la matriz de características ($18 \times 12$) y entrena un `CatBoostClassifier` con *Ordered Boosting* para prevenir el sobreajuste y la fuga de información (*target leakage*).
3. El modelo entrenado se exporta como un archivo binario liviano en `lab3_bec_catboost/bec_catboost.cbm`.
4. El análisis forense se exporta automáticamente en `lab3_bec_catboost/shap_importance_report.json`.

### Paso 3: Benchmark de Latencia en Tiempo Real y Explicabilidad Forense
1. **Validación de Latencia Operativa:**
   * Revisa la salida del benchmark en consola. CatBoost evalúa cada correo individual en aproximadamente **0.36 ms** en un solo núcleo de CPU (~2,773 correos por segundo).
   * Comprende por qué este enfoque es drásticamente superior a desplegar un LLM masivo en el flujo de correo perimetral (que añadiría demoras inaceptables de 500 a 2,000 ms y costos millonarios en computación).
2. **Interpretación del Ranking SHAP:**
   * Analiza el orden de contribución marginal a la decisión del modelo:
     1. `display_name_spoofed` (Impacto SHAP $\approx 1.037$)
     2. `shannon_entropy` (Impacto SHAP $\approx 0.708$)
     3. `psychological_pressure_score` (Impacto SHAP $\approx 0.688$)
     4. `financial_term_count` (Impacto SHAP $\approx 0.211$)
   * Comprueba que el analista del SOC cuenta con la evidencia forense necesaria para responder a los incidentes y justificar el bloqueo preventivo ante la dirección general.

---

## Verificación

Para constatar la correcta ejecución del laboratorio:

1. **Comprobar la existencia del modelo binario compilado:**
   ```bash
   ls -lh lab3_bec_catboost/bec_catboost.cbm
   ```
2. **Inspeccionar el reporte JSON de explicabilidad SHAP:**
   ```bash
   cat lab3_bec_catboost/shap_importance_report.json
   ```

**Salida esperada:**
```json
{
    "latency_ms": 0.361,
    "feature_importance": [
        {
            "feature": "display_name_spoofed",
            "mean_abs_shap": 1.03705
        },
        {
            "feature": "shannon_entropy",
            "mean_abs_shap": 0.70787
        },
        {
            "feature": "psychological_pressure_score",
            "mean_abs_shap": 0.68811
        }
    ]
}
```

---

### Entregable Técnico Requerido
1. Archivo de modelo serializado `lab3_bec_catboost/bec_catboost.cbm`.
2. Archivo `lab3_bec_catboost/shap_importance_report.json` con la descomposición de valores SHAP y latencia registrada.
3. Resumen analítico que explique por qué la combinación de `display_name_spoofed` y `shannon_entropy` es determinante para neutralizar ataques de Fraude del CEO sin generar interrupciones al negocio.
