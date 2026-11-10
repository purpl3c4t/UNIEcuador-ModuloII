#!/usr/bin/env python3
"""
Lab 4: concept_drift_padl.py
Evaluación de Concept Drift temporal (Protocolo TESSERACT),
Capa de Detección Adaptativa Temprana (PADL - 120s)
y Clasificación con Opción de Rechazo Conformal (Transcend Framework).
"""
import numpy as np
import json
import os
import sys
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score

def generate_longitudinal_dataset():
    """
    Genera un conjunto de datos sintético estructurado en 3 periodos temporales (T0, T1, T2):
    T0: Malware tradicional (familias conocidas)
    T1: Malware con evasión estática y API Hashing (Concept Drift virtual)
    T2: Malware polimórfico generativo con Execution Guardrails (Concept Drift real / Zero-Day)
    """
    np.random.seed(42)
    # Características: [iat_entropy, n_sections, has_dos_perturb, api_alloc_rva, timing_delta, memory_ops_120s]
    
    # Periodo T0 (Entrenamiento)
    n_t0 = 400
    X_t0_benign = np.random.normal(loc=[1.5, 5, 0.0, 0.0, 0.001, 1], scale=0.3, size=(n_t0 // 2, 6))
    X_t0_malware = np.random.normal(loc=[4.5, 3, 0.0, 0.8, 0.001, 8], scale=0.4, size=(n_t0 // 2, 6))
    X_t0 = np.vstack([X_t0_benign, X_t0_malware])
    y_t0 = np.array([0] * (n_t0 // 2) + [1] * (n_t0 // 2))

    # Periodo T1 (Drift Virtual: Cambios de ofuscación y hashing)
    n_t1 = 200
    X_t1_benign = np.random.normal(loc=[1.6, 5, 0.0, 0.0, 0.001, 1], scale=0.3, size=(n_t1 // 2, 6))
    X_t1_malware = np.random.normal(loc=[2.2, 2, 0.9, 0.0, 0.002, 7], scale=0.4, size=(n_t1 // 2, 6))
    X_t1 = np.vstack([X_t1_benign, X_t1_malware])
    y_t1 = np.array([0] * (n_t1 // 2) + [1] * (n_t1 // 2))

    # Periodo T2 (Drift Real: Polimorfismo y guardrails)
    n_t2 = 200
    X_t2_benign = np.random.normal(loc=[1.5, 5, 0.0, 0.0, 0.001, 1], scale=0.3, size=(n_t2 // 2, 6))
    X_t2_malware = np.random.normal(loc=[1.4, 2, 0.95, 0.0, 0.008, 5], scale=0.3, size=(n_t2 // 2, 6))
    X_t2 = np.vstack([X_t2_benign, X_t2_malware])
    y_t2 = np.array([0] * (n_t2 // 2) + [1] * (n_t2 // 2))

    return (X_t0, y_t0), (X_t1, y_t1), (X_t2, y_t2)

class ConformalClassifierReject:
    """
    Marco Transcend: Predicción Conformal con Opción de Rechazo.
    Calcula la medida de no-conformidad (NCM) y rechaza muestras Out-of-Distribution (OOD).
    """
    def __init__(self, base_clf, p_value_threshold=0.10):
        self.clf = base_clf
        self.threshold = p_value_threshold
        self.calibration_ncms = []

    def fit_calibration(self, X_calib, y_calib):
        self.clf.fit(X_calib, y_calib)
        probs = self.clf.predict_proba(X_calib)
        # NCM: 1 - probabilidad predicha de la clase verdadera
        for idx, y_true in enumerate(y_calib):
            ncm = 1.0 - probs[idx, y_true]
            self.calibration_ncms.append(ncm)
        self.calibration_ncms = np.sort(self.calibration_ncms)

    def predict_conformal(self, X):
        probs = self.clf.predict_proba(X)
        predictions = []
        rejected = []

        for p in probs:
            pred_class = np.argmax(p)
            ncm_sample = 1.0 - p[pred_class]
            # p-value: Proporción de valores de calibración mayores o iguales a la muestra
            p_val = np.mean(self.calibration_ncms >= ncm_sample)
            if p_val < self.threshold:
                predictions.append(-1) # RECHAZADA / OOD (Envío a Cuarentena)
                rejected.append(True)
            else:
                predictions.append(pred_class)
                rejected.append(False)

        return np.array(predictions), np.array(rejected)

def padl_early_telemetry_score(telemetry_file="telemetry_120s.json"):
    """
    Procesa las trazas dinámicas de la ventana de 120s según la arquitectura PADL.
    """
    if not os.path.exists(telemetry_file):
        # Valores por defecto si se ejecuta sin Lab 3 previo
        return 0.85
    with open(telemetry_file, "r") as f:
        events = json.load(f)
    
    # Ponderación basada en tácticas MITRE ATT&CK tempranas
    weights = {"memory": 2.5, "injection": 3.0, "persistence": 1.5, "anti-analysis": 2.0}
    score = 0.0
    for ev in events:
        cat = ev.get("category", "")
        if ev.get("suspicious", False):
            score += weights.get(cat, 1.0)
    # Normalización sigmoidal
    padl_score = 1.0 / (1.0 + np.exp(-score / 5.0))
    return padl_score

if __name__ == "__main__":
    print("=== Laboratorio 4: Concept Drift y Detección Temprana con Opción de Rechazo ===")
    (X_t0, y_t0), (X_t1, y_t1), (X_t2, y_t2) = generate_longitudinal_dataset()

    # 1. Entrenamiento tradicional sin adaptación temporal
    clf_standard = RandomForestClassifier(n_estimators=50, random_state=42)
    clf_standard.fit(X_t0, y_t0)

    # 2. Evaluación temporal estricta (Protocolo TESSERACT)
    f1_t0 = f1_score(y_t0, clf_standard.predict(X_t0))
    f1_t1 = f1_score(y_t1, clf_standard.predict(X_t1))
    f1_t2 = f1_score(y_t2, clf_standard.predict(X_t2))

    print("[*] Degradación Temporal del Clasificador Estándar:")
    print(f"  -> T0 (Línea Base / Entrenamiento): F1 = {f1_t0:.4f}")
    print(f"  -> T1 (Drift Virtual - Obfuscation): F1 = {f1_t1:.4f}")
    print(f"  -> T2 (Drift Real - Polymorphic):   F1 = {f1_t2:.4f}")
    print(f"  [!] Caída de rendimiento por Concept Drift: {(f1_t0 - f1_t2)*100:.1f}%")

    # 3. Predicción Conformal con Opción de Rechazo (Transcend)
    print("\n[*] Evaluando con Capa de Predicción Conformal (Rechazo OOD)...")
    conformal = ConformalClassifierReject(RandomForestClassifier(n_estimators=50, random_state=42), p_value_threshold=0.15)
    conformal.fit_calibration(X_t0, y_t0)

    preds_t2, rejections_t2 = conformal.predict_conformal(X_t2)
    valid_mask = ~rejections_t2
    f1_t2_filtered = f1_score(y_t2[valid_mask], preds_t2[valid_mask])
    rejection_rate = np.mean(rejections_t2) * 100

    print(f"  -> Tasa de muestras rechazadas (enviadas a Cuarentena/SOC): {rejection_rate:.1f}%")
    print(f"  -> F1 en muestras aceptadas con alta certidumbre: {f1_t2_filtered:.4f}")

    # 4. Integración PADL de 120s
    telemetry_path = sys.argv[1] if len(sys.argv) > 1 else "../lab3_guardrails/telemetry_120s.json"
    padl_score = padl_early_telemetry_score(telemetry_path)
    print(f"\n[*] Puntuación de Telemetría Temprana PADL (Ventana 120s): {padl_score:.4f}")
    if padl_score >= 0.70:
        print("  [+] DECISIÓN FINAL: Muestra neutralizada proactivamente antes de propagación.")
    else:
        print("  [-] DECISIÓN FINAL: Requiere mayor tiempo de observación.")
