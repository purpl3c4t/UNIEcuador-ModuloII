#!/usr/bin/env python3
"""
Laboratorio 3 - Script 2: Entrenamiento y Evaluacion de CatBoost para Fraude BEC
Mide latencia de inferencia en tiempo real (<3 ms) y calcula explicabilidad SHAP.
"""

import os
import time
import json
import pandas as pd
import numpy as np
import catboost as cb
from feature_extraction import extract_bec_features

def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_file = os.path.join(base_dir, "data", "bec_fraud_dataset.csv")
    model_output = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bec_catboost.cbm")
    report_output = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shap_importance_report.json")

    print("[*] Laboratorio 3: Cargando dataset de fraude BEC y extrayendo caracteristicas...")
    df = pd.read_csv(data_file)

    feature_matrix = []
    feature_names = None
    y = df["is_bec"].values

    for idx, row in df.iterrows():
        feats, names = extract_bec_features(
            row["text"],
            display_name_spoofed=row.get("display_name_spoofed", 0),
            off_hours=row.get("off_hours", 0)
        )
        feature_matrix.append(feats)
        if feature_names is None:
            feature_names = names

    X = np.array(feature_matrix)
    print(f" [+] Matriz de caracteristicas generada: {X.shape[0]} muestras, {X.shape[1]} atributos.")

    # Configuracion de CatBoost optimizado para inferencia rapida y baja varianza
    model = cb.CatBoostClassifier(
        iterations=150,
        learning_rate=0.08,
        depth=5,
        loss_function="Logloss",
        eval_metric="F1",
        verbose=0,
        random_seed=42
    )

    print("[*] Entrenando modelo CatBoost (Ordered Boosting)...")
    start_train = time.time()
    model.fit(X, y)
    train_time = time.time() - start_train
    print(f" [+] Entrenamiento finalizado en {train_time:.3f} segundos.")

    # Evaluacion de latencia de inferencia por mensaje individual (requisito de gateway en tiempo real)
    num_eval_runs = 50
    start_inf = time.time()
    for _ in range(num_eval_runs):
        for sample_vec in X:
            _ = model.predict_proba(sample_vec.reshape(1, -1))
    total_samples = num_eval_runs * len(X)
    avg_latency_ms = ((time.time() - start_inf) / total_samples) * 1000.0

    print(f"\n[+] Benchmark de Despliegue en Tiempo Real:")
    print(f"    Latencia promedio de inferencia: {avg_latency_ms:.3f} ms por correo")
    print(f"    Rendimiento estimado: {int(1000.0 / avg_latency_ms)} correos evaluados por segundo (Single CPU)")

    # Calculo de Valores SHAP para explicabilidad en el SOC
    pool = cb.Pool(X, y, feature_names=feature_names)
    shap_values = model.get_feature_importance(pool, type="ShapValues")
    
    # shap_values tiene dimension (N, M + 1), donde la ultima columna es el valor base (expected value)
    mean_abs_shap = np.mean(np.abs(shap_values[:, :-1]), axis=0)
    importance_ranking = sorted(
        [{"feature": f_name, "mean_abs_shap": round(float(val), 5)} 
         for f_name, val in zip(feature_names, mean_abs_shap)],
        key=lambda x: x["mean_abs_shap"],
        reverse=True
    )

    print("\n--- Ranking de Importancia SHAP (Top Factores de Decision para Analistas SOC) ---")
    for rank, item in enumerate(importance_ranking[:6], 1):
        print(f" {rank}. {item['feature']:<30} | Impacto SHAP: {item['mean_abs_shap']}")

    # Guardar modelo y reporte
    model.save_model(model_output)
    with open(report_output, "w") as f:
        json.dump({
            "latency_ms": round(avg_latency_ms, 3),
            "feature_importance": importance_ranking
        }, f, indent=4)

    print(f"\n[+] Modelo CatBoost serializado en: {model_output}")
    print(f"[+] Reporte forense SHAP exportado en: {report_output}")

if __name__ == "__main__":
    main()
