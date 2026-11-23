import json
import sys
import warnings
from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

warnings.filterwarnings("ignore", category=UserWarning)

# Categorías defensivas de eventos de alto riesgo (extensible)
DENIED_ERROR_CODES = {
    "AccessDenied",
    "UnauthorizedOperation",
    "Client.UnauthorizedOperation",
    "AccessDeniedException",
}

PROVISIONING_AND_HIJACK_EVENTS = {
    "RunInstances",
    "StartInstances",
    "CreateFunction",
    "UpdateFunctionCode",
    "CreateCluster",
    "RunTask",
}

PRIV_ESC_AND_PERSISTENCE_EVENTS = {
    "AttachRolePolicy",
    "AttachUserPolicy",
    "PutRolePolicy",
    "PutUserPolicy",
    "CreateAccessKey",
    "CreateUser",
    "PassRole",
    "UpdateAssumeRolePolicy",
}

HIGH_RISK_EVENTS = PROVISIONING_AND_HIJACK_EVENTS | PRIV_ESC_AND_PERSISTENCE_EVENTS


def calculate_shannon_entropy(text: Any) -> float:
    """Calcula la entropía de Shannon sobre una cadena de texto."""
    if not text or pd.isna(text):
        return 0.0
    text_str = str(text)
    length = len(text_str)
    if length == 0:
        return 0.0
    probs = [text_str.count(c) / length for c in set(text_str)]
    return float(-sum(p * np.log2(p) for p in probs))


def extract_request_params(row: pd.Series) -> Dict[str, Any]:
    """Extrae requestParameters de forma robusta sin importar el aplanamiento de pandas."""
    raw_params = row.get("requestParameters")
    if isinstance(raw_params, dict):
        return raw_params
    return {
        k.replace("requestParameters.", ""): v
        for k, v in row.items()
        if str(k).startswith("requestParameters.") and pd.notna(v)
    }


def extract_instance_ids(params: Dict[str, Any]) -> List[str]:
    """Extrae identificadores de instancias EC2 u otros recursos de cómputo."""
    found = []
    if not params:
        return found

    if "instanceId" in params and params["instanceId"]:
        found.append(str(params["instanceId"]))

    if "instancesSet" in params and isinstance(params["instancesSet"], dict):
        items = params["instancesSet"].get("items", [])
        for item in items:
            if isinstance(item, dict) and "instanceId" in item:
                found.append(str(item["instanceId"]))

    return found


def build_entity_features(df: pd.DataFrame, user_col: str) -> pd.DataFrame:
    """
    Construye una matriz de características conductuales por identidad (UEBA)
    para alimentar el modelo predictivo de anomalías.
    """
    features = []

    for entity, group in df.groupby(user_col):
        group = group.sort_values("eventTime")
        total_events = len(group)

        # 1. Errores de autorización (reconocimiento / fuerza bruta de permisos)
        denied_count = int(group["is_denied"].sum())
        denied_ratio = denied_count / total_events if total_events > 0 else 0.0

        # 2. Cambios de contexto (IP y User-Agent distintos en la misma sesión/ventana)
        unique_ips = group["sourceIPAddress"].nunique(dropna=True) if "sourceIPAddress" in group else 1
        unique_uas = group["userAgent"].nunique(dropna=True) if "userAgent" in group else 1

        # 3. Entropía del User-Agent (variabilidad y desviación)
        ua_entropy_std = float(group["ua_entropy"].std(ddof=0)) if total_events > 1 else 0.0
        ua_entropy_mean = float(group["ua_entropy"].mean())

        # 4. Llamadas a APIs sensibles (aprovisionamiento / escalada de privilegios)
        high_risk_count = int(group["is_high_risk"].sum())

        # 5. Velocidad de eventos (ráfagas temporales)
        if total_events > 1:
            duration_sec = (group["eventTime"].max() - group["eventTime"].min()).total_seconds()
            events_per_min = total_events / max(duration_sec / 60.0, 1.0)
        else:
            events_per_min = 0.0

        features.append({
            "entity": entity,
            "total_events": total_events,
            "denied_count": denied_count,
            "denied_ratio": denied_ratio,
            "unique_ips": unique_ips,
            "unique_uas": unique_uas,
            "ua_entropy_mean": ua_entropy_mean,
            "ua_entropy_std": ua_entropy_std,
            "high_risk_count": high_risk_count,
            "events_per_min": events_per_min,
        })

    return pd.DataFrame(features)


def compute_robust_z_scores(feature_matrix: pd.DataFrame) -> np.ndarray:
    """
    Calcula una puntuación estadística robusta (Z-Score) por entidad.
    Funciona de forma confiable incluso con pocos usuarios/roles en el log.
    """
    numeric_cols = [
        "denied_count",
        "denied_ratio",
        "unique_ips",
        "unique_uas",
        "high_risk_count",
        "events_per_min",
    ]
    X = feature_matrix[numeric_cols].astype(float).values
    means = np.mean(X, axis=0)
    stds = np.std(X, axis=0)

    # Evitar división por cero cuando una característica es constante
    stds_safe = np.where(stds == 0, 1.0, stds)
    z_scores = (X - means) / stds_safe

    # Solo penalizamos desviaciones positivas (más errores, más IPs, más APIs críticas)
    positive_z = np.maximum(z_scores, 0.0)
    return np.mean(positive_z, axis=1)


def predict_anomalous_entities(feature_df: pd.DataFrame) -> pd.DataFrame:
    """
    Aplica detección predictiva híbrida:
    - Isolation Forest (aprendizaje no supervisado) cuando hay suficientes muestras.
    - Puntuación estadística Z-Score robusta para datasets pequeños o refuerzo de señal.
    """
    feature_cols = [
        "total_events",
        "denied_count",
        "denied_ratio",
        "unique_ips",
        "unique_uas",
        "ua_entropy_std",
        "high_risk_count",
        "events_per_min",
    ]

    result = feature_df.copy()
    result["stat_score"] = compute_robust_z_scores(result)
    result["ml_anomaly"] = False
    result["ml_score"] = 0.0

    # Ejecutar Isolation Forest si scikit-learn está disponible y hay al menos 3 entidades
    if SKLEARN_AVAILABLE and len(result) >= 3:
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(result[feature_cols].fillna(0.0))

        # Contaminación adaptativa conservadora para evitar falsos positivos masivos
        contamination = min(0.35, max(0.05, 1.0 / len(result)))
        iso_forest = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42,
        )
        preds = iso_forest.fit_predict(X_scaled)
        # decision_function: valores más bajos indican mayor anomalía
        raw_scores = iso_forest.decision_function(X_scaled)

        result["ml_anomaly"] = preds == -1
        result["ml_score"] = -raw_scores  # Invertir para que mayor = más anómalo

    # Decisión defensiva combinada:
    # Una entidad es sospechosa si el modelo ML la marca como anomalía Y/O supera el umbral estadístico,
    # siempre que presente al menos una señal de riesgo real (evita falsos positivos en logs limpios).
    has_risk_signal = (
        (result["denied_count"] > 0)
        | (result["high_risk_count"] > 0)
        | (result["unique_ips"] > 1)
    )
    result["is_anomalous"] = has_risk_signal & (
        result["ml_anomaly"] | (result["stat_score"] >= 1.0)
    )

    return result


def analyze_cloud_telemetry(file_path: str, output_manifest: str = "compromised_manifest.json") -> None:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            events = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"[!] Error al leer el archivo de telemetría '{file_path}': {exc}")
        sys.exit(1)

    if not events:
        print("[*] El archivo de telemetría está vacío. No se detectaron anomalías.")
        manifest = {"compromised_role": [], "compromised_instances": []}
        with open(output_manifest, "w", encoding="utf-8") as out:
            json.dump(manifest, out, indent=2)
        return

    df = pd.json_normalize(events)

    # Identificación robusta de la columna de identidad
    user_col = "userIdentity.arn" if "userIdentity.arn" in df.columns else "userIdentity"
    if user_col not in df.columns:
        raise ValueError("El archivo JSON no contiene un campo 'userIdentity' válido.")

    df["eventTime"] = pd.to_datetime(df["eventTime"], errors="coerce")
    df = df.sort_values(by=[user_col, "eventTime"])

    # Enriquecimiento de telemetría a nivel de evento
    df["errorCode"] = df.get("errorCode", pd.Series([None] * len(df)))
    df["userAgent"] = df.get("userAgent", pd.Series([""] * len(df)))
    df["is_denied"] = df["errorCode"].apply(lambda x: 1 if str(x) in DENIED_ERROR_CODES else 0)
    df["is_high_risk"] = df["eventName"].apply(lambda x: 1 if str(x) in HIGH_RISK_EVENTS else 0)
    df["ua_entropy"] = df["userAgent"].apply(calculate_shannon_entropy)

    # Ingeniería de características por entidad y predicción de anomalías
    entity_features = build_entity_features(df, user_col)
    scored_entities = predict_anomalous_entities(entity_features)

    suspicious_entities = scored_entities.loc[
        scored_entities["is_anomalous"], "entity"
    ].tolist()

    compromised_instances = set()

    print("=" * 65)
    print("INFORME DE MONITOREO PREDICTIVO DE APIS (DEFENSIVO / UEBA)")
    print("=" * 65)
    engine_label = "IsolationForest + Z-Score Robusto" if SKLEARN_AVAILABLE else "Z-Score Robusto (fallback)"
    print(f"[*] Motor predictivo activo: {engine_label}")
    print(f"[*] Entidades analizadas: {len(scored_entities)}")
    print(f"[*] Entidades anómalas detectadas: {suspicious_entities}\n")

    # Inspección de eventos críticos asociados a entidades anómalas
    flagged_events = df[
        df[user_col].isin(suspicious_entities)
        & df["eventName"].isin(HIGH_RISK_EVENTS)
    ]

    for _, row in flagged_events.iterrows():
        user = row[user_col]
        ua = str(row.get("userAgent", ""))
        entropy = float(row.get("ua_entropy", 0.0))
        ip = row.get("sourceIPAddress", "N/A")
        params = extract_request_params(row)

        for inst_id in extract_instance_ids(params):
            compromised_instances.add(inst_id)

        print(f"[!] ALERTA CRÍTICA: Comportamiento anómalo y uso de API sensible por {user}")
        print(f"    - Acción: {row['eventName']}")
        print(f"    - IP Origen: {ip}")
        print(f"    - User-Agent: {ua} (Entropía: {entropy:.2f})")
        print(f"    - Parámetros: {params}")

    # Generar manifiesto de salida sin valores hardcodeados
    manifest = {
        "compromised_role": suspicious_entities,
        "compromised_instances": sorted(compromised_instances),
    }

    with open(output_manifest, "w", encoding="utf-8") as out:
        json.dump(manifest, out, indent=2)

    print(f"\n[+] Manifiesto guardado con éxito en '{output_manifest}'.")


if __name__ == "__main__":
    target_file = sys.argv[1] if len(sys.argv) > 1 else "audit_events.json"
    analyze_cloud_telemetry(target_file)
