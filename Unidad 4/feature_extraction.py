#!/usr/bin/env python3
"""
Laboratorio 3 - Modulo 1: Extraccion de Caracteristicas Psicolinguisticas y Forenses para BEC
Vector de atributos que captura manipulacion semantica, entropia de Shannon y legibilidad Flesch-Kincaid.
"""

import math
import re
import numpy as np

FINANCIAL_KEYWORDS = [
    "wire", "transfer", "invoice", "payment", "bank", "disbursement",
    "escrow", "funds", "routing", "account", "dollars", "gift card"
]

URGENCY_KEYWORDS = [
    "urgent", "immediately", "confidential", "private", "emergency",
    "cutoff", "asap", "strictly", "today", "now"
]

def shannon_entropy(text):
    """
    Calcula la entropia de Shannon de la cadena para detectar ofuscacion o aleatoriedad:
    H(S) = - sum(p(x) * log2(p(x)))
    """
    if not text:
        return 0.0
    prob_dist = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob_dist)

def count_syllables(word):
    """
    Estimacion heuristica de silabas en una palabra.
    """
    word = word.lower()
    count = len(re.findall(r"[aeiouy]+", word))
    return max(1, count)

def flesch_kincaid_grade_level(text):
    """
    Indice de legibilidad Flesch-Kincaid (GL):
    GL = 0.39 * (words / sentences) + 11.8 * (syllables / words) - 15.59
    """
    sentences = max(1, len(re.split(r"[.!?]+", text)))
    words = re.findall(r"\b\w+\b", text)
    num_words = max(1, len(words))
    num_syllables = sum(count_syllables(w) for w in words)

    gl = 0.39 * (num_words / sentences) + 11.8 * (num_syllables / num_words) - 15.59
    return round(max(0.0, gl), 2)

def extract_bec_features(text, display_name_spoofed=0, off_hours=0):
    """
    Extrae el vector de caracteristicas forenses y linguisticas para la clasificacion BEC.
    """
    text_clean = str(text)
    words = re.findall(r"\b\w+\b", text_clean)
    num_words = max(1, len(words))
    num_chars = len(text_clean)

    # 1. Metricas Estadisticas y de Complejidad Linguistica
    entropy = shannon_entropy(text_clean)
    readability_gl = flesch_kincaid_grade_level(text_clean)
    avg_word_len = sum(len(w) for w in words) / num_words
    uppercase_ratio = sum(1 for c in text_clean if c.isupper()) / max(1, num_chars)
    exclamation_count = text_clean.count("!")
    question_count = text_clean.count("?")
    dollar_count = text_clean.count("$")

    # 2. Metricas Psicolinguisticas y Semanticas
    lower_text = text_clean.lower()
    fin_term_count = sum(lower_text.count(k) for k in FINANCIAL_KEYWORDS)
    urgency_term_count = sum(lower_text.count(k) for k in URGENCY_KEYWORDS)

    # Ratio de presion psicologica
    psychological_pressure = (urgency_term_count * 2.0 + fin_term_count * 1.5) / num_words

    # 3. Metricas Contextuales y de Metadatos
    spoof_flag = float(display_name_spoofed)
    off_hours_flag = float(off_hours)

    feature_dict = {
        "shannon_entropy": entropy,
        "flesch_kincaid_gl": readability_gl,
        "avg_word_length": avg_word_len,
        "uppercase_ratio": uppercase_ratio,
        "exclamation_count": exclamation_count,
        "question_count": question_count,
        "dollar_sign_count": dollar_count,
        "financial_term_count": fin_term_count,
        "urgency_term_count": urgency_term_count,
        "psychological_pressure_score": psychological_pressure,
        "display_name_spoofed": spoof_flag,
        "off_hours": off_hours_flag
    }

    return list(feature_dict.values()), list(feature_dict.keys())

if __name__ == "__main__":
    sample = "URGENT: Initiate wire transfer of $45,000 to vendor escrow account immediately."
    feats, names = extract_bec_features(sample, display_name_spoofed=1, off_hours=1)
    print("Vector de Caracteristicas de Prueba:")
    for n, f in zip(names, feats):
        print(f"  {n}: {f:.4f}")
