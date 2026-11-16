import pandas as pd
import numpy as np
import os

def calculate_composite_risk_and_respond():
    data_path = os.path.dirname(__file__) + '/data/insider_audit_events.csv'
    df = pd.read_csv(data_path)
    
    print("================================================================================")
    print(" MOTOR DE PUNTUACIÓN DE RIESGO COMPUESTO Y MITIGACIÓN AUTOMATIZADA (UEBA)")
    print("================================================================================")
    
    # Pesos de correlación multidimensional (Definidos por la política de seguridad del SOC)
    # Total = 1.0 (100 puntos máx)
    w_horario = 0.20        # Anomalía temporal (fuera de horario de oficina)
    w_sensibilidad = 0.30   # Acceso a activos críticos o carpetas protegidas
    w_staging = 0.30        # Empaquetado/compresión en carpetas temporales (%TEMP%)
    w_volumen = 0.20        # Volumen inusual de datos transferidos
    
    risk_history = []
    
    print("\n--- PROCESAMIENTO SECUENCIAL DE TELEMETRÍA FORENSE ---")
    for idx, row in df.iterrows():
        # Normalización de variables a escala [0.0 - 1.0]
        s_horario = 1.0 if row['is_off_hours'] == 1 else 0.0
        s_sens = 1.0 if row['is_sensitive'] == 1 else 0.0
        s_staging = 1.0 if row['staging_detected'] == 1 else 0.0
        
        # Volumen escalado (mayor a 5 MB satura a 1.0)
        s_vol = min(1.0, row['bytes_transferred'] / 5000000.0)
        
        # Puntuación compuesta instantánea
        score_instant = (w_horario * s_horario + 
                         w_sensibilidad * s_sens + 
                         w_staging * s_staging + 
                         w_volumen * s_vol) * 100.0
                         
        risk_history.append(round(score_instant, 2))
        
        print(f"[{row['timestamp']}] Evento: {row['event_id']} | Acción: {row['action']}")
        print(f"  -> Recurso: {row['resource']}")
        print(f"  -> Score Parcial: {score_instant:.2f} / 100.0")
        
        # Reglas de respuesta automatizada vía API de Identidad (Microsoft Entra ID / Okta)
        if score_instant >= 85.0:
            print("  [!] UMBRAL CRÍTICO SUPERADO (>= 85.0/100):")
            print("      * ACCIÓN AUTOMATIZADA 1: Revocación inmediata de tokens OAuth / Refresh Tokens.")
            print("      * ACCIÓN AUTOMATIZADA 2: Cierre forzado de sesiones activas RDP.")
            print("      * ACCIÓN AUTOMATIZADA 3: Aislamiento preventivo del endpoint en la red.")
        elif score_instant >= 50.0:
            print("  [*] UMBRAL DE ADVERTENCIA (>= 50.0/100):")
            print("      * ACCIÓN PREVENTIVA: Exigir Step-Up MFA para autorizar la acción.")
        else:
            print("  [✓] Tráfico y actividad dentro de los márgenes normales.")
        print("-" * 75)
        
    df['risk_score'] = risk_history
    out_scored = os.path.dirname(__file__) + '/data/insider_risk_evaluation.csv'
    df.to_csv(out_scored, index=False)
    print(f"\nEvaluación completa exportada a: {out_scored}")
    print("================================================================================\n")

if __name__ == '__main__':
    calculate_composite_risk_and_respond()
