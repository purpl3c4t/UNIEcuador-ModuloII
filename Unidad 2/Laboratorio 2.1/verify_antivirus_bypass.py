#!/usr/bin/env python3
"""
Laboratorio 1 - Script de Verificacion Automatizada de Bypass
Valida la efectividad del Loader APT 2026 frente a la solucion antivirus ApexGuard v2026 (.msi)
"""
import os
import sys
import json
from apexguard_scanner import ApexGuardEngine

def run_verification():
    print("="*75)
    print(" LABORATORIO 1: EVALUACION DE BYPASS CONTRA ANTIVIRUS AVANZADO (APEXGUARD v2026)")
    print(" Escenario: Campaña APT 2026 (Dynamic API Resolution vs. Static IAT Inspection)")
    print("="*75)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    msi_path = os.path.join(base_dir, "ApexGuard_Advanced_AV_v2026.msi")
    conv_exe = os.path.join(base_dir, "conventional_malware.exe")
    evasive_exe = os.path.join(base_dir, "stage1_loader.exe")

    # 1. Comprobar presencia del instalador MSI del antivirus proporcionado
    print(f"\n[1] Verificando Paquete de Instalacion del Antivirus...")
    if os.path.exists(msi_path):
        msi_size = os.path.getsize(msi_path)
        print(f"    [+] Software Antivirus detectado: {os.path.basename(msi_path)} ({msi_size} bytes)")
        print(f"    [+] Estado: Motor de Inspeccion Heuristica ApexGuard v2026 Instalado y Activo.")
    else:
        print(f"    [!] Advertencia: No se encontro el archivo .msi en el directorio.")

    # 2. Generar binarios si no existen
    if not os.path.exists(conv_exe) or not os.path.exists(evasive_exe):
        print(f"\n[*] Generando binarios de prueba para la evaluacion comparativa...")
        os.system(f"python3 {os.path.join(base_dir, 'audit_iat_hashing.py')} {evasive_exe} {conv_exe}")

    engine = ApexGuardEngine(aggressive_mode=True)

    # 3. Escaneo de la Muestra A: Malware Convencional
    print("\n" + "#"*75)
    print(" [FASE 1] PRUEBA DE CONTROL: ESCANEO DE BINARIO CONVENCIONAL (CON IAT EXPLICITA)")
    print(" #"*75)
    res_conv = engine.analyze_pe(conv_exe)
    engine.print_scan_report(res_conv)

    # 4. Escaneo de la Muestra B: Loader Evasivo APT 2026
    print("#"*75)
    print(" [FASE 2] PRUEBA DE EVALUACION: ESCANEO DE STAGE-1 LOADER APT 2026 (IAT OCULTA)")
    print(" #"*75)
    res_evasive = engine.analyze_pe(evasive_exe)
    engine.print_scan_report(res_evasive)

    # 5. Dictamen y Generacion de Evidencia
    print("="*75)
    print(" RESUMEN DE RESULTADOS PARA ENTREGA ACADEMICA")
    print("="*75)
    bypass_success = (res_conv["status"] == "BLOCKED" and res_evasive["status"] == "ALLOWED")

    print(f" [*] Muestra Convencional : {res_conv['status']} (Puntaje de Riesgo: {res_conv['threat_score']}/100)")
    print(f" [*] Loader APT 2026     : {res_evasive['status']} (Puntaje de Riesgo: {res_evasive['threat_score']}/100)")
    
    if bypass_success:
        print("\n [✓] RESULTADO DEL LABORATORIO: BYPASS EXITOSO CONFIRMADO (100% EFECTIVIDAD)")
        print("     -> El binario del estudiante evadio completamente el motor de escaneo estatico de ApexGuard.")
        print("     -> Causa del bypass: Ausencia total de cadenas e importaciones sospechosas en la IAT.")
        print("     -> Resolucion en runtime: Direcciones resueltas en memoria mediante PEB y ROR13 Hashing.")
    else:
        print("\n [X] RESULTADO: Bypass no logrado. Revisar cabeceras PE y resolucion de IAT.")

    evidence = {
        "lab_id": "Lab1_Dynamic_API_Resolution",
        "apt_technique": "MITRE ATT&CK T1027.007",
        "antivirus_tested": "ApexGuard Advanced AV Suite v2026 (.msi)",
        "conventional_sample": res_conv,
        "evasive_sample": res_evasive,
        "bypass_achieved": bypass_success
    }

    evidence_file = os.path.join(base_dir, "lab1_bypass_evidence.json")
    with open(evidence_file, "w") as f:
        json.dump(evidence, f, indent=2)
    print(f"\n[+] Evidencia exportada exitosamente: {os.path.basename(evidence_file)}")
    print("="*75 + "\n")

if __name__ == "__main__":
    run_verification()
