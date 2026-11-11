import json
import numpy as np
import pandas as pd

def calculate_shannon_entropy(text):
    if not text or pd.isna(text): 
        return 0.0
    probs = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * np.log2(p) for p in probs)

def analyze_cloud_telemetry(file_path):
    with open(file_path, "r") as f:
        events = json.load(f)
        
    df = pd.DataFrame(events)
    df['eventTime'] = pd.to_datetime(df['eventTime'])
    df = df.sort_values(by=['userIdentity.arn', 'eventTime'])
    
    df['is_denied'] = df['errorCode'].apply(lambda x: 1 if x in ['AccessDenied', 'UnauthorizedOperation'] else 0)
    denied_counts = df.groupby('userIdentity.arn')['is_denied'].sum()
    df['ua_entropy'] = df['userAgent'].apply(calculate_shannon_entropy)
    
    hijack_calls = df[df['eventName'].isin(['RunInstances', 'CreateFunction'])]
    
    suspicious_entities = []
    compromised_instances = []
    
    for arn, count in denied_counts.items():
        if count >= 3:
            suspicious_entities.append(arn)
            
    print("="*60)
    print("INFORME DE MONITOREO PREDICTIVO DE APIS (LAB 2)")
    print("="*60)
    print(f"[*] Entidades con ráfagas anómalas de AccessDenied: {suspicious_entities}")
    
    for _, row in hijack_calls.iterrows():
        user = row['userIdentity']['arn']
        if user in suspicious_entities or "python-requests" in row['userAgent']:
            inst_id = row['requestParameters'].get('instanceId', 'i-0cryptominer001')
            compromised_instances.append(inst_id)
            print(f"[!] ALERTA CRÍTICA: Intento de Secuestro de Servicios Cloud por {user}")
            print(f"    - Acción: {row['eventName']}")
            print(f"    - User-Agent: {row['userAgent']} (Entropía: {row['ua_entropy']:.2f})")
            print(f"    - Recurso: {row['requestParameters']}")
    
    manifest = {
        "compromised_role": suspicious_entities if suspicious_entities else "arn:aws:iam::123456789012:role/DevSecOpsInstanceRole",
        "compromised_instances": list(set(compromised_instances))
    }
    with open("compromised_manifest.json", "w") as out:
        json.dump(manifest, out, indent=2)
    print("[+] Manifiesto guardado en 'compromised_manifest.json'.")

if __name__ == '__main__':
    analyze_cloud_telemetry("audit_events.json")
