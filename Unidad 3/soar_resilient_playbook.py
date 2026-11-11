import json
import time
import random

class CloudControlPlaneMock:
    def __init__(self, throttle_intensity=0.7):
        self.throttle_intensity = throttle_intensity
        self.audit_logging_active = True
        self.permissions_boundary_applied = None
        self.instance_quarantined = None

    def put_role_permissions_boundary(self, role_name, boundary_arn):
        if random.random() < self.throttle_intensity:
            raise Exception("ClientError: HTTP 429 Too Many Requests (RateLimitExceeded)")
        self.permissions_boundary_applied = boundary_arn
        return {"status": "SUCCESS", "role": role_name, "boundary": boundary_arn}

    def modify_instance_security_groups(self, instance_id, group_id):
        if random.random() < self.throttle_intensity:
            raise Exception("ClientError: HTTP 429 Too Many Requests (RateLimitExceeded)")
        self.instance_quarantined = group_id
        return {"status": "SUCCESS", "instance": instance_id, "group": group_id}

    def stop_audit_logging(self):
        raise Exception("AccessDeniedException: Operation 'cloudtrail:StopLogging' is denied by Root Organization SCP.")

def execute_playbook_with_backoff(cloud_api, alert, max_retries=6):
    role = alert["compromised_role"]
    instance = alert["compromised_instance_id"]
    
    print(f"\n[*] INICIANDO PLAYBOOK SOAR PARA INCIDENTE: {alert['alert_id']}")
    print(f"[*] Severidad: {alert['severity']} | Motor: {alert['detection_engine']}")
    
    # 1. Contención de Identidad
    boundary_applied = False
    for attempt in range(1, max_retries + 1):
        try:
            print(f" -> Intento {attempt}: Aplicando 'DenyAll' Permissions Boundary a {role}...")
            cloud_api.put_role_permissions_boundary(role, "arn:aws:iam::123456789012:policy/DenyAllBoundary")
            print("    [✓] Identidad neutralizada exitosamente.")
            boundary_applied = True
            break
        except Exception as e:
            wait_time = (2 ** attempt) * 0.1 + random.uniform(0.05, 0.1)
            print(f"    [!] Error en API: {e}. Aplicando retroceso exponencial ({wait_time:.2f}s)...")
            time.sleep(wait_time)
            
    if not boundary_applied:
        print("    [X] Fallo crítico: No se pudo contener la identidad.")
        return False

    # 2. Aislamiento de Red
    network_contained = False
    for attempt in range(1, max_retries + 1):
        try:
            print(f" -> Intento {attempt}: Aislando instancia {instance} en Security Group 'sg-quarantine'...")
            cloud_api.modify_instance_security_groups(instance, "sg-isolated-quarantine")
            print("    [✓] Interfaz de red de la instancia puesta en cuarentena.")
            network_contained = True
            break
        except Exception as e:
            wait_time = (2 ** attempt) * 0.1 + random.uniform(0.05, 0.1)
            print(f"    [!] Error en API: {e}. Esperando ({wait_time:.2f}s)...")
            time.sleep(wait_time)

    return boundary_applied and network_contained

def main():
    try:
        with open("alert_payload.json", "r") as f:
            alert = json.load(f)
    except Exception:
        alert = {
            "alert_id": "ALT-AI-2026-9921",
            "severity": "CRITICAL",
            "detection_engine": "Hybrid_Autoencoder_IsolationForest",
            "compromised_role": "arn:aws:iam::123456789012:role/DevSecOpsInstanceRole",
            "compromised_instance_id": "i-0cryptominer001"
        }
        
    cloud_api = CloudControlPlaneMock(throttle_intensity=0.6)
    
    print("="*60)
    print("SIMULACIÓN DE NEUTRALIZACIÓN ADVERSARIAL (ATTACKER VIEW)")
    print("="*60)
    print("[*] Atacante intenta cegar telemetría ('cloudtrail:StopLogging')...")
    try:
        cloud_api.stop_audit_logging()
    except Exception as e:
        print(f"[!] ATAQUE BLOQUEADO: {e}")
        
    print("\n[*] Atacante inyecta ráfaga de tráfico para provocar 'API Throttling'...")
    success = execute_playbook_with_backoff(cloud_api, alert)
    
    print("\n" + "="*60)
    if success:
        print("[+] RESULTADO: Contención autónoma completada con éxito. Resiliencia validada.")
    else:
        print("[-] RESULTADO: La contención falló debido a la evasión adversarial.")
    print("="*60)

if __name__ == '__main__':
    main()
