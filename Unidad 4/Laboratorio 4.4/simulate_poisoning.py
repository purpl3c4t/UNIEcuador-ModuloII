#!/usr/bin/env python3
"""
Laboratorio 4 - Script 2: Simulador de Impacto de Envenenamiento de Feeds de CTI
Demuestra la diferencia entre ingesta ingenua vs ingesta sanitizada en el SOC.
"""

import os
import json

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(os.path.dirname(base_dir), "data")
    feed_file = os.path.join(data_dir, "poisoned_feed_sample.json")
    sanitized_file = os.path.join(base_dir, "sanitized_firewall_rules.json")
    audit_file = os.path.join(base_dir, "sanitizer_drop_audit.json")

    if not os.path.exists(sanitized_file):
        raise FileNotFoundError(f"No se encontro {sanitized_file}. Ejecuta feed_sanitizer.py primero.")

    with open(feed_file, "r") as f:
        raw_feed = json.load(f)
    with open(sanitized_file, "r") as f:
        rules = json.load(f)
    with open(audit_file, "r") as f:
        audit = json.load(f)

    print("======================================================================")
    print("   SIMULACION SOC: IMPACTO DE CONTAMINACION DE FEEDS DE INTELIGENCIA")
    print("======================================================================")

    # 1. Escenario Ingesta Ingenua
    print("\n[ESCENARIO 1: INGESTA INGENUA (Sin Sanitizador)]")
    naive_blocks = len(raw_feed)
    critical_self_dos = [i for i in raw_feed if i["indicator"] in ["1.1.1.1", "8.8.8.8", "7029517178345711e64a4b4947477b63f2334f59088730b200b848039c9f0bcf"]]
    print(f" -> Total reglas perimetrales aplicadas ciegamente: {naive_blocks}")
    print(f" -> ALERTA CRITICA: Se bloquearon {len(critical_self_dos)} servicios indispensables:")
    for c in critical_self_dos:
        print(f"    [X] {c['indicator']} ({c['type']}) -> Motivo simulado: {c['description']}")
    print(" -> CONSECUENCIA: Perdida total de resolucion DNS corporativa y falla en binarios del SO.")

    # 2. Escenario con Sanitizador Defensivo
    print("\n[ESCENARIO 2: INGESTA SANITIZADA (Defensa en 3 Capas)]")
    print(f" -> Reglas perimetrales legitimas aprobadas: {len(rules)}")
    for r in rules:
        print(f"    [OK] Bloqueando {r['indicator']} (Consenso: {len(r['corroborating_sources'])} fuentes | Confianza: {r['confidence_score']})")

    print(f"\n -> Amenazas de envenenamiento neutralizadas por el Sanitizador: {len(audit)}")
    for a in audit:
        print(f"    [ESCUDO ACTIVADO] Descartado: {a['indicator']} | Motivo: {a['reason']}")

    print("\n======================================================================")
    print(" [CONCLUSION]: La plataforma ha prevenido con exito el ataque de")
    print(" Denegacion de Servicio Autoinfligido sin comprometer la deteccion real.")
    print("======================================================================")

if __name__ == "__main__":
    main()
