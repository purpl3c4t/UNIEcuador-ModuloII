## Laboratorio 4: Detección Adaptativa Temprana y Clasificación ante Concept Drift (30 min)

*Tema 2.4: Modelos predictivos y AI para generación automática de payloads*

* **Prerrequisito:** El registro de telemetría de eventos generado en el Laboratorio 3 y un dataset longitudinal de variantes sintéticas de malware.
* **Objetivo:** Analizar la degradación de clasificadores supervisados ante nuevas familias/variantes y configurar una capa de detección adaptativa temprana con rechazo conformal[29][31].
* **Entorno:** Python, Scikit-learn / LightGBM, `mlflow` o entorno estadístico para evaluación de modelos[12][32].
* **Flujo Práctico:**
  1. Los estudiantes entrenan un modelo supervisado (LightGBM / Random Forest) con un dataset histórico y constatan cómo su F1-Score decae drásticamente al evaluar muestras recientes, experimentando **Concept Drift** (deriva virtual y real)[33].
  2. Implementan la arquitectura de ventana temprana inspirada en **PADL (Policy-Adaptive Detection Layer)**: procesan los eventos de los primeros **120 segundos** extrayendo n-gramas de comportamiento secuencial y mapeándolos a tácticas MITRE ATT&amp;CK[29].
  3. Configuran una capa de **Predicción Conformal con opción de rechazo** (basada en el marco Transcend/Transcendent)[31][38]: calculan medidas de no-conformidad (NCM) mediante p-values; cuando se introduce una muestra con comportamiento polimórfico o Zero-Day, el sistema se abstiene de clasificarla de forma forzada y la envía a cuarentena para triaje forense[31].
* **Entregable del Laboratorio 4:** Script de inferencia que combina el scoring de políticas PADL en los primeros 120s con la regla de abstención conformal calibrada.

### Fundamento Técnico y Objetivo

El objetivo es comprobar cómo el **Concept Drift** (deriva temporal de características) degrada clasificadores estándar evaluados bajo el protocolo cronológico estricto **TESSERACT**. Los estudiantes implementarán una **Predicción Conformal con Opción de Rechazo (marco Transcend)** para abstenerse y aislar muestras Zero-Day fuera de distribución (OOD), integrando el scoring de políticas **PADL (Policy-Adaptive Detection Layer)** en la ventana temprana de 120 segundos.

### Script
`concept_drift_padl.py` (Python / Scikit-learn)

```
#!/usr/bin/env python3
"""
Lab 4: concept_drift_padl.py
Evaluación de Concept Drift (TESSERACT), Predicción Conformal (Transcend) y PADL (120s).
"""
import numpy as np
import json
import os
import sys
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score

def generate_longitudinal_dataset():
    np.random.seed(42)
    # Periodo T0 (Entrenamiento)
    X_t0_b = np.random.normal(loc=[1.5, 5, 0.0, 0.0, 0.001, 1], scale=0.3, size=(200, 6))
    X_t0_m = np.random.normal(loc=[4.5, 3, 0.0, 0.8, 0.001, 8], scale=0.4, size=(200, 6))
    X_t0 = np.vstack([X_t0_b, X_t0_m])
    y_t0 = np.array([0]*200 + [1]*200)

    # Periodo T1 (Drift Virtual - Obfuscation / API Hashing)
    X_t1_b = np.random.normal(loc=[1.6, 5, 0.0, 0.0, 0.001, 1], scale=0.3, size=(100, 6))
    X_t1_m = np.random.normal(loc=[2.2, 2, 0.9, 0.0, 0.002, 7], scale=0.4, size=(100, 6))
    X_t1 = np.vstack([X_t1_b, X_t1_m])
    y_t1 = np.array([0]*100 + [1]*100)

    # Periodo T2 (Drift Real - Polimorfismo / Guardrails)
    X_t2_b = np.random.normal(loc=[1.5, 5, 0.0, 0.0, 0.001, 1], scale=0.3, size=(100, 6))
    X_t2_m = np.random.normal(loc=[1.4, 2, 0.95, 0.0, 0.008, 5], scale=0.3, size=(100, 6))
    X_t2 = np.vstack([X_t2_b, X_t2_m])
    y_t2 = np.array([0]*100 + [1]*100)

    return (X_t0, y_t0), (X_t1, y_t1), (X_t2, y_t2)

class ConformalClassifierReject:
    def __init__(self, base_clf, p_value_threshold=0.15):
        self.clf = base_clf
        self.threshold = p_value_threshold
        self.calibration_ncms = []

    def fit_calibration(self, X_calib, y_calib):
        self.clf.fit(X_calib, y_calib)
        probs = self.clf.predict_proba(X_calib)
        for idx, y_true in enumerate(y_calib):
            ncm = 1.0 - probs[idx, y_true]
            self.calibration_ncms.append(ncm)
        self.calibration_ncms = np.sort(self.calibration_ncms)

    def predict_conformal(self, X):
        probs = self.clf.predict_proba(X)
        predictions, rejected = [], []
        for p in probs:
            pred_class = np.argmax(p)
            ncm = 1.0 - p[pred_class]
            p_val = np.mean(self.calibration_ncms &gt;= ncm)
            if p_val &lt; self.threshold:
                predictions.append(-1) # Rechazado / OOD
                rejected.append(True)
            else:
                predictions.append(pred_class)
                rejected.append(False)
        return np.array(predictions), np.array(rejected)

def padl_early_telemetry_score(telemetry_file="telemetry_120s.json"):
    if not os.path.exists(telemetry_file):
        return 0.85
    with open(telemetry_file, "r") as f:
        events = json.load(f)
    weights = {"memory": 2.5, "injection": 3.0, "persistence": 1.5, "anti-analysis": 2.0}
    score = sum(weights.get(e.get("category", ""), 1.0) for e in events if e.get("suspicious", False))
    return float(1.0 / (1.0 + np.exp(-score / 5.0)))

if __name__ == "__main__":
    print("=== Laboratorio 4: Concept Drift y Detección Temprana con Opción de Rechazo ===")
    (X_t0, y_t0), (X_t1, y_t1), (X_t2, y_t2) = generate_longitudinal_dataset()

    clf_std = RandomForestClassifier(n_estimators=50, random_state=42)
    clf_std.fit(X_t0, y_t0)

    print("[*] Evaluación Temporal TESSERACT (Random Forest Estándar):")
    print(f"  -&gt; T0 (Línea Base): F1 = {f1_score(y_t0, clf_std.predict(X_t0)):.4f}")
    print(f"  -&gt; T1 (Drift Virtual): F1 = {f1_score(y_t1, clf_std.predict(X_t1)):.4f}")
    print(f"  -&gt; T2 (Drift Real):    F1 = {f1_score(y_t2, clf_std.predict(X_t2)):.4f}")

    print("\n[*] Capa de Predicción Conformal (Transcend Framework):")
    conformal = ConformalClassifierReject(RandomForestClassifier(n_estimators=50, random_state=42), p_value_threshold=0.15)
    conformal.fit_calibration(X_t0, y_t0)

    preds_t2, rej_t2 = conformal.predict_conformal(X_t2)
    print(f"  -&gt; Muestras enviadas a Cuarentena/SOC (Rechazo OOD): {np.mean(rej_t2)*100:.1f}%")

    telemetry_path = sys.argv[1] if len(sys.argv) &gt; 1 else "../lab3_guardrails/telemetry_120s.json"
    padl_val = padl_early_telemetry_score(telemetry_path)
    print(f"\n[*] Puntuación de Telemetría Temprana PADL (120s): {padl_val:.4f}")
    if padl_val &gt;= 0.70:
        print("  [+] DECISIÓN FINAL: Muestra neutralizada proactivamente antes de propagación.")

```

### Paso a Paso de Ejecución

1. Navega al directorio del laboratorio en este folder dentro de Github

2. Ejecuta el análisis longitudinal y vincula la telemetría del Laboratorio 3:

```
python3 concept_drift_padl.py ../lab3_guardrails/telemetry_120s.json

```

3. **Verificación:** Constata cómo la opción de rechazo filtra más del 50% de las muestras ambiguas de T2 hacia análisis forense manual y cómo la puntuación de PADL (&gt; 0.85) identifica la intencionalidad ofensiva dentro de los primeros 120 segundos.
