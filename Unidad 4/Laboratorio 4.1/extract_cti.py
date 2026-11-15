#!/usr/bin/env python3
"""
Laboratorio 1: Mineria de CTI en la Dark Web y Extraccion de IoCs bajo Ontologia STIX 2.1
Framework: EventHunter & CyberNER (STIX 2.1 standard)
"""

import os
import re
import json
import math
import uuid
from datetime import datetime

def extract_entities_from_text(text):
    """
    Simula la capa de extraccion NER basada en Transformers especializados (SecureBERT/CyberNER/DNRTI)
    extrayendo entidades estandarizadas bajo STIX 2.1.
    """
    entities = []

    # 1. Vulnerabilidades (CVEs)
    cve_matches = re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
    for cve in set(cve_matches):
        entities.append({"type": "vulnerability", "value": cve.upper()})

    # 2. Threat Actors
    actors_known = ["TA505", "Scattered Spider", "BlackCat", "ALPHV", "RedLine"]
    for actor in actors_known:
        if re.search(r"\b" + re.escape(actor) + r"\b", text, re.IGNORECASE):
            entities.append({"type": "threat-actor", "value": actor})

    # 3. Malware / Herramientas
    malware_known = ["MOVEit", "ScreenConnect", "BlackCat", "RedLine Stealer", "FortiOS"]
    for mal in malware_known:
        if re.search(r"\b" + re.escape(mal) + r"\b", text, re.IGNORECASE):
            entities.append({"type": "malware", "value": mal})

    # 4. Direcciones IPv4
    ip_matches = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text)
    for ip in set(ip_matches):
        # Filtrar IPs no enrutables genericas si aplica
        entities.append({"type": "ipv4-addr", "value": ip})

    # 5. Hashes criptograficos (SHA256, MD5)
    sha256_matches = re.findall(r"\b[a-fA-F0-9]{64}\b", text)
    for h in set(sha256_matches):
        entities.append({"type": "file-hash-sha256", "value": h.lower()})

    md5_matches = re.findall(r"\b[a-fA-F0-9]{32}\b", text)
    for h in set(md5_matches):
        entities.append({"type": "file-hash-md5", "value": h.lower()})

    # 6. Dominios
    domain_matches = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+(?:net|org|com|io|info|xyz|internal-auth\.net)\b", text)
    for d in set(domain_matches):
        entities.append({"type": "domain-name", "value": d.lower()})

    return entities

def compute_eventhunter_score(post, entities, weights):
    """
    Calcula la metrica de completitud y prioridad segun el framework EventHunter:
    C(c_i) = w_alpha * log(1 + |unique_entities|) + w_beta * log(1 + |unique_types|)
    Priority = w_time * T + w_rel * V + w_cred * R + C(c_i)
    """
    unique_entities = set(e["value"] for e in entities)
    unique_types = set(e["type"] for e in entities)

    w_alpha = weights.get("w_alpha", 1.2)
    w_beta = weights.get("w_beta", 0.8)

    completeness = w_alpha * math.log(1 + len(unique_entities)) + w_beta * math.log(1 + len(unique_types))
    
    # Credibilidad basada en la reputacion del autor (normalizada 0 - 1)
    credibility = min(post.get("author_reputation", 1.0) / 5.0, 1.0)

    # Relevancia basada en el impacto de las entidades (e.g., presencia de 0-days o hashes)
    relevance = 1.0 if any(e["type"] in ["vulnerability", "threat-actor"] for e in entities) else 0.4

    # Oportunidad (Timeliness)
    timeliness = 0.90 # Valor estandar para eventos de reciente publicacion

    w_time = weights.get("w_timeliness", 0.35)
    w_rel = weights.get("w_relevance", 0.35)
    w_cred = weights.get("w_credibility", 0.30)

    priority_score = (w_time * timeliness + w_rel * relevance + w_cred * credibility) * (1 + 0.5 * completeness)
    return round(completeness, 4), round(priority_score, 4)

def build_stix21_bundle(clusters):
    """
    Genera un STIX 2.1 Bundle valido que agrupa los indicadores extraidos.
    """
    bundle_id = f"bundle--{uuid.uuid4()}"
    stix_objects = []

    for cluster in clusters:
        post = cluster["post"]
        entities = cluster["entities"]

        threat_actor_id = None
        vulnerability_id = None

        for ent in entities:
            obj_id = f"{ent['type']}--{uuid.uuid4()}"
            if ent["type"] == "threat-actor":
                threat_actor_id = obj_id
                stix_objects.append({
                    "type": "threat-actor",
                    "spec_version": "2.1",
                    "id": obj_id,
                    "name": ent["value"],
                    "created": datetime.utcnow().isoformat() + "Z",
                    "description": f"Extracted from {post['forum']} post {post['post_id']}"
                })
            elif ent["type"] == "vulnerability":
                vulnerability_id = obj_id
                stix_objects.append({
                    "type": "vulnerability",
                    "spec_version": "2.1",
                    "id": obj_id,
                    "name": ent["value"],
                    "created": datetime.utcnow().isoformat() + "Z"
                })
            elif ent["type"] in ["ipv4-addr", "file-hash-sha256", "domain-name"]:
                stix_objects.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{uuid.uuid4()}",
                    "pattern": f"[{ent['type']}:value = '{ent['value']}']",
                    "pattern_type": "stix",
                    "valid_from": datetime.utcnow().isoformat() + "Z",
                    "confidence": int(cluster["priority_score"] * 20),
                    "created": datetime.utcnow().isoformat() + "Z"
                })

        # Relacion STIX entre Threat Actor y Vulnerabilidad
        if threat_actor_id and vulnerability_id:
            stix_objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid.uuid4()}",
                "relationship_type": "targets",
                "source_ref": threat_actor_id,
                "target_ref": vulnerability_id,
                "created": datetime.utcnow().isoformat() + "Z"
            })

    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": stix_objects
    }

def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_file = os.path.join(base_dir, "data", "darkweb_forum_dump.json")
    config_file = os.path.join(base_dir, "config.json")
    output_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "stix_cti_graph.json")

    with open(config_file, "r") as f:
        cfg = json.load(f)
    weights = cfg.get("eventhunter_weights", {})

    with open(data_file, "r") as f:
        posts = json.load(f)

    clusters = []
    print("[*] Iniciando Extraccion de CTI y Named Entity Recognition (NER STIX 2.1)...")
    for post in posts:
        full_text = post["title"] + " " + post["content"]
        entities = extract_entities_from_text(full_text)
        comp, prio = compute_eventhunter_score(post, entities, weights)
        clusters.append({
            "post": post,
            "entities": entities,
            "completeness": comp,
            "priority_score": prio
        })
        print(f" [+] Post ID: {post['post_id']} | Entidades: {len(entities)} | Completitud: {comp} | Prioridad EventHunter: {prio}")

    # Ordenar por prioridad descendente
    clusters.sort(key=lambda x: x["priority_score"], reverse=True)

    # Generar bundle STIX 2.1
    stix_bundle = build_stix21_bundle(clusters)
    with open(output_file, "w") as f:
        json.dump(stix_bundle, f, indent=4)

    print(f"\n[+] Proceso completado exitosamente.")
    print(f"[+] Bundle STIX 2.1 exportado en: {output_file}")
    print(f"[+] Total de objetos STIX generados: {len(stix_bundle['objects'])}")

if __name__ == "__main__":
    main()
