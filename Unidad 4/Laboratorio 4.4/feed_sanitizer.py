#!/usr/bin/env python3
"""
Laboratorio 4 - Script 1: Sanitizador de Feeds de CTI contra Envenenamiento de Indicadores
Implementa defensa en 3 capas:
 1. Puntuacion dinamica de confianza (Reputacion de fuente)
 2. Validacion cruzada multi-fuente (Consenso >= 2)
 3. Escudo contra Denegacion de Servicio Autoinfligida (Lista blanca de infraestructura esencial)
"""

import os
import json
from collections import defaultdict

def sanitize_cti_feed(raw_indicators, config):
    """
    Filtra indicadores adversarios para prevenir envenenamiento de feeds y DoS autoinfligido.
    """
    sanitizer_cfg = config.get("cti_sanitizer", {})
    min_consensus = sanitizer_cfg.get("min_source_consensus", 2)
    min_confidence = sanitizer_cfg.get("confidence_threshold", 0.70)
    whitelist_ips = set(sanitizer_cfg.get("whitelist_ips", []))
    known_benign_hashes = set(sanitizer_cfg.get("known_benign_hashes", []))

    # Reputacion heuristica de fuentes
    source_reputation = {
        "ThreatIntel_Consortium_Partner": 0.95,
        "DarkWeb_Scraper_Alpha": 0.75,
        "Unverified_Paste_Feed": 0.20,
        "Unverified_Community_Submissions": 0.15
    }

    # Agrupar reportes por indicador
    grouped = defaultdict(list)
    for item in raw_indicators:
        grouped[item["indicator"]].append(item)

    sanitized_rules = []
    dropped_audit_log = []

    for indicator, reports in grouped.items():
        # Capa 3: Escudo de Denegacion de Servicio (Whitelist preventiva)
        if indicator in whitelist_ips or indicator in known_benign_hashes:
            dropped_audit_log.append({
                "indicator": indicator,
                "reason": "CRITICAL_SELF_DOS_PREVENTED (Infraestructura legitima o binario critico)",
                "sources": [r["feed_source"] for r in reports]
            })
            continue

        # Capa 1: Evaluacion probabilistica de reputacion
        sources = list(set(r["feed_source"] for r in reports))
        avg_confidence = sum(source_reputation.get(s, 0.3) for s in sources) / len(sources)

        # Capa 2: Validacion cruzada multi-fuente
        if len(sources) < min_consensus and avg_confidence < 0.90:
            dropped_audit_log.append({
                "indicator": indicator,
                "reason": f"INSUFFICIENT_CONSENSUS ({len(sources)}/{min_consensus} fuentes, Confianza: {avg_confidence:.2f})",
                "sources": sources
            })
            continue

        # Indicador validado para emision de reglas perimetrales
        sanitized_rules.append({
            "indicator": indicator,
            "type": reports[0]["type"],
            "action": "BLOCK",
            "enforcement": "FIREWALL_AND_EDR",
            "confidence_score": round(avg_confidence, 2),
            "corroborating_sources": sources,
            "description": reports[0]["description"]
        })

    return sanitized_rules, dropped_audit_log

def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    feed_file = os.path.join(base_dir, "data", "poisoned_feed_sample.json")
    config_file = os.path.join(base_dir, "config.json")
    output_rules = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sanitized_firewall_rules.json")
    audit_output = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sanitizer_drop_audit.json")

    with open(config_file, "r") as f:
        cfg = json.load(f)
    with open(feed_file, "r") as f:
        raw_feed = json.load(f)

    print("[*] Laboratorio 4: Iniciando Sanitizacion de Feeds de CTI...")
    print(f" [+] Total de indicadores sin procesar recibidos: {len(raw_feed)}")

    rules, dropped = sanitize_cti_feed(raw_feed, cfg)

    with open(output_rules, "w") as f:
        json.dump(rules, f, indent=4)
    with open(audit_output, "w") as f:
        json.dump(dropped, f, indent=4)

    print(f"\n[+] Resultados del Sanitizador:")
    print(f"    Reglas validas generadas para firewall: {len(rules)}")
    print(f"    Indicadores maliciosos/envenenados bloqueados preventivamente: {len(dropped)}")
    print(f"\n[+] Reglas exportadas a: {output_rules}")
    print(f"[+] Registro de auditoria exportado a: {audit_output}")

if __name__ == "__main__":
    main()
