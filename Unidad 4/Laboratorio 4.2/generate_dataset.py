#!/usr/bin/env python3
"""
Laboratorio 2 - Script 1: Construccion de Dataset para Evaluacion de Modelos NLP
Consume los metadatos estructurados del Laboratorio 1 (stix_cti_graph.json)
"""

import os
import json
import csv

def load_stix_context(stix_file):
    if not os.path.exists(stix_file):
        raise FileNotFoundError(f"No se encontro el archivo del Lab 1: {stix_file}.")

    with open(stix_file, "r") as f:
        bundle = json.load(f)

    actors = []
    cves = []
    for obj in bundle.get("objects", []):
        if obj.get("type") == "threat-actor":
            actors.append(obj.get("name"))
        elif obj.get("type") == "vulnerability":
            cves.append(obj.get("name"))

    return {
        "actors": list(set(actors)) if actors else ["ThreatGroup-A"],
        "cves": list(set(cves)) if cves else ["CVE-2024-0001"]
    }

def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    stix_file = os.path.join(base_dir, "lab1_cti_ner", "stix_cti_graph.json")
    output_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "synthetic_phish_eval.csv")

    cti = load_stix_context(stix_file)
    print(f"[*] Lab 2: Integrando contexto CTI del Lab 1: {cti}")

    samples = [
        # Benign corporate communications (estilo Enron)
        ("Project Review Sync", "Please review the attached project milestone timeline for Q4 planning.", 0, "benign_ham"),
        ("Weekly Operations Report", "Operations metrics and telemetry reports are now updated on the internal portal.", 0, "benign_ham"),
        ("Engineering Sync Agenda", "Agenda for tomorrow morning architecture session is shared in the workspace.", 0, "benign_ham"),
        ("System Maintenance Notice", "Scheduled maintenance on internal database clusters will take place this Saturday evening.", 0, "benign_ham"),
        ("Quarterly Budget Allocation", "Finance has published the updated department budget guidelines for review.", 0, "benign_ham"),
    ]

    # Deceptive / Social Engineering communications grounded in CTI findings
    for actor in cti["actors"]:
        for cve in cti["cves"]:
            samples.append((
                f"Urgent Security Remediation regarding {cve}",
                f"Security notice: Automated telemetry indicates required configuration updates for {cve} attributed to {actor} activity. Verify system profile immediately via corporate link.",
                1,
                "deceptive_spear"
            ))
            samples.append((
                f"Administrative Policy Alert: {actor} threat mitigation",
                f"Mandatory employee verification requirement regarding recent security bulletin {cve}. Complete compliance steps before end of day.",
                1,
                "deceptive_spear"
            ))

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["subject", "body", "label", "category"])
        for s in samples:
            writer.writerow(s)

    print(f"[+] Dataset de evaluacion generado en: {output_file} con {len(samples)} registros.")

if __name__ == "__main__":
    main()
