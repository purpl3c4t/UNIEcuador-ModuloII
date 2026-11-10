#!/usr/bin/env python3
"""
Lab 3: guardrails_sandbox.py
Inyección de Execution Guardrails (Anti-VM, Timing Attacks, Resource Probing)
y simulación del monitoreo dinámico (User-Hooking vs Hypervisor VMI).
"""
import time
import struct
import os
import sys
import json

class ExecutionGuardrails:
    """
    Implementa salvaguardas condicionales en el ejecutable.
    """
    def __init__(self, is_sandbox_env: bool = False, vcpu_count: int = 1):
        self.is_sandbox_env = is_sandbox_env
        self.vcpu_count = vcpu_count

    def check_hypervisor_cpuid(self) -> bool:
        """
        Simula la instrucción CPUID con EAX=0x40000000.
        En hypervisores típicos devuelve firmas como 'VMwareVMware', 'KVMKVMKVM'.
        """
        if self.is_sandbox_env:
            vendor = "VMwareVMware"
            print(f"  [!] CPUID check: Detectado hypervisor vendor string '{vendor}'")
            return True
        return False

    def check_hardware_resources(self) -> bool:
        """
        Verifica si el sistema cuenta con recursos reducidos típicos de sandboxes automáticos (<= 2 vCPUs).
        """
        if self.vcpu_count <= 2:
            print(f"  [!] Resource check: Entorno sospechoso con solo {self.vcpu_count} vCPUs.")
            return True
        return False

    def timing_evasion_rdtsc(self, simulated_hook_latency: bool = False) -> bool:
        """
        Simula la medición de ciclos con RDTSC. Si el EDR intercepta llamadas
        mediante hooks o VMI sin hardware-assist, la sobrecarga temporal activa la evasión.
        """
        start = time.perf_counter()
        if simulated_hook_latency:
            # Latencia artificial provocada por breakpoints INT3 o inspección de API hooks
            time.sleep(0.01)
        elapsed = time.perf_counter() - start
        if elapsed > 0.005:
            print(f"  [!] RDTSC check: Latencia de CPU anómala detectada ({elapsed*1000:.2f} ms).")
            return True
        return False

def simulate_detonation(guardrails: ExecutionGuardrails, use_hypervisor_vmi: bool = False):
    """
    Ejecuta el ciclo de detonación durante una ventana de 120 segundos (escalada para la simulación).
    """
    print(f"\n[*] Detonando implante... (Modo VMI Transparente: {use_hypervisor_vmi})")
    telemetry_events = []

    # 1. Evaluación de Guardrails
    is_vm = guardrails.check_hypervisor_cpuid()
    is_low_res = guardrails.check_hardware_resources()
    timing_anomaly = guardrails.timing_evasion_rdtsc(simulated_hook_latency=(not use_hypervisor_vmi))

    if is_vm or is_low_res or timing_anomaly:
        print("  [X] Execution Guardrails activados: Entorno de análisis detectado.")
        print("  [>] Desviando flujo hacia comportamiento inofensivo (exit(0))...")
        telemetry_events.append({"timestamp": 1, "api": "ExitProcess", "category": "termination", "suspicious": False})
        return telemetry_events, False

    # 2. Si no detecta sandbox, despliega el comportamiento en memoria
    print("  [+] Guardrails superados: Desplegando capacidades ofensivas en memoria...")
    actions = [
        (5, "NtAllocateVirtualMemory", "memory", True),
        (12, "NtWriteVirtualMemory", "memory", True),
        (25, "NtProtectVirtualMemory", "memory", True),
        (45, "RegQueryValueExW", "persistence", False),
        (70, "NtCreateThreadEx", "injection", True),
        (105, "NtDelayExecution", "anti-analysis", False),
        (120, "NtTerminateProcess", "process", False)
    ]

    for t_sec, api_name, cat, is_susp in actions:
        telemetry_events.append({
            "timestamp": t_sec,
            "api": api_name,
            "category": cat,
            "suspicious": is_susp
        })
        print(f"    [T+{t_sec:03d}s] Telemetría registrada: {api_name:25} [{cat.upper()}]")

    return telemetry_events, True

if __name__ == "__main__":
    print("=== Laboratorio 3: Simulación de Guardrails y Evasión Dinámica ===")
    
    # Caso A: Sandbox convencional con hooks en espacio de usuario
    print("\n--- Caso A: Entorno Sandbox Tradicional (2 vCPUs + Hooking EDR) ---")
    g_sandbox = ExecutionGuardrails(is_sandbox_env=True, vcpu_count=2)
    events_a, executed_a = simulate_detonation(g_sandbox, use_hypervisor_vmi=False)
    print(f"Resultado Caso A: {'Payload Ejecutado' if executed_a else 'Evasión Exitosa (Payload Oculto)'}")

    # Caso B: Sandbox con Hypervisor VMI (DRAKVUF / EPT) donde se ocultan los artefactos
    print("\n--- Caso B: Análisis con VMI Transparente (Hypervisor DRAKVUF / 8 vCPUs) ---")
    g_target = ExecutionGuardrails(is_sandbox_env=False, vcpu_count=8)
    events_b, executed_b = simulate_detonation(g_target, use_hypervisor_vmi=True)
    print(f"Resultado Caso B: {'Payload Ejecutado' if executed_b else 'Evasión Exitosa'}")

    # Guardar traza de telemetría de 120s para el Laboratorio 4
    output_log = "telemetry_120s.json"
    with open(output_log, "w") as f:
        json.dump(events_b, f, indent=2)
    print(f"\n[+] Telemetría de 120s exportada para Lab 4: {output_log}")
