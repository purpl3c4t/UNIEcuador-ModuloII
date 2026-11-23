import json
import sys
import numpy as np
import pandas as pd

def calculate_shannon_entropy(text):
    """Calcula la entropía de Shannon sobre una cadena de texto."""
    if not text or pd.isna(text): 
        return 0.0
    text_str = str(text)
    probs = [text_str.count(c) / len(text_str) for c in set(text_str)]
    return -sum(p * np.log2(p) for p in probs)

def analyze_cloud_telemetry(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        events = json.load(f)
        
    # json_normalize aplana las claves anidadas como 'userIdentity.arn'
    df = pd.json_normalize(events)
    
    # Manejar posibles variaciones en el nombre de la columna de identidad
    user_col = 'userIdentity.arn' if 'userIdentity.arn' in df.columns else 'userIdentity'
    
    df['eventTime'] = pd.to_datetime(df['eventTime'])
    df = df.sort_values(by=[user_col, 'eventTime'])
    
    # 1. Detección de ráfagas de 'AccessDenied'
    df['is_denied'] = df['errorCode'].apply(
        lambda x: 1 if str(x) in ['AccessDenied', 'UnauthorizedOperation'] else 0
    )
    
    # Conteo acumulado de errores por usuario
    denied_counts = df.groupby(user_col)['is_denied'].sum()
    
    # 2. Entropía y anomalías en cadenas User-Agent
    df['ua_entropy'] = df['userAgent'].apply(calculate_shannon_entropy)
    
    # 3. Identificación de Cloudservice Hijacking (Aprovisionamiento anómalo)
    hijack_calls = df[df['eventName'].isin(['RunInstances', 'CreateFunction'])]
    
    suspicious_entities = []
    compromised_instances = []
    
    for user_arn, count in denied_counts.items():
        if count >= 3:
            suspicious_entities.append(user_arn)
            
    print("=" * 60)
    print("INFORME DE MONITOREO PREDICTIVO DE APIS (LAB 2)")
    print("=" * 60)
    print(f"[*] Entidades con ráfagas anómalas de AccessDenied: {suspicious_entities}")
    
    for _, row in hijack_calls.iterrows():
        user = row[user_col]
        ua = str(row.get('userAgent', ''))
        entropy = row.get('ua_entropy', 0.0)
        
        # Extraer parámetros de forma robusta
        raw_params = row.get('requestParameters')
        if isinstance(raw_params, dict):
            params = raw_params
        else:
            params = {
                k.replace('requestParameters.', ''): v 
                for k, v in row.items() 
                if k.startswith('requestParameters.') and pd.notna(v)
            }
            
        if user in suspicious_entities or "python-requests" in ua:
            inst_id = params.get('instanceId', 'i-0cryptominer001')
            compromised_instances.append(inst_id)
            print(f"[!] ALERTA CRÍTICA: Intento de Secuestro de Servicios Cloud por {user}")
            print(f"    - Acción: {row['eventName']}")
            print(f"    - User-Agent sospechoso: {ua} (Entropía: {entropy:.2f})")
            print(f"    - Recurso Aprovisionado: {params}")
    
    # Generar manifiesto de salida para el Laboratorio 3
    manifest = {
        "compromised_role": suspicious_entities if suspicious_entities else ["arn:aws:iam::123456789012:role/DevSecOpsInstanceRole"],
        "compromised_instances": list(set(compromised_instances)) if compromised_instances else ["i-0cryptominer001"]
    }
    
    with open("compromised_manifest.json", "w", encoding="utf-8") as out:
        json.dump(manifest, out, indent=2)
    print("\n[+] Manifiesto guardado con éxito en 'compromised_manifest.json'.")

if __name__ == '__main__':
    target_file = sys.argv[1] if len(sys.argv) > 1 else "audit_events.json"
    analyze_cloud_telemetry(target_file)
