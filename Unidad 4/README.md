# Recursos de Laboratorio - Módulo 4: NLP en Ciberseguridad, Phishing/BEC y CTI

Este paquete contiene todos los scripts, datasets, esquemas de configuración y orquestadores para la ejecución de los 4 laboratorios prácticos acumulativos y el Proyecto Integrador de Unidad.

---

## Estructura del Directorio

```text
recursos/
├── README.md                          # Guía de referencia y descripción de componentes
├── requirements.txt                   # Dependencias de Python requeridas
├── config.json                        # Parámetros globales (pesos EventHunter, umbrales de consenso)
├── data/                              # Conjuntos de datos y telemetría sintética
│   ├── darkweb_forum_dump.json        # Publicaciones de foros clandestinos (Lab 1)
│   ├── bec_fraud_dataset.csv          # Flujos de correos con etiquetas de fraude BEC (Lab 3)
│   └── poisoned_feed_sample.json      # Feeds con IoCs legítimos y contaminación simulada (Lab 4)
├── lab1_cti_ner/                      # Laboratorio 1
│   ├── extract_cti.py                 # Extractor NER STIX 2.1 y algoritmo EventHunter
│   └── stix_cti_graph.json            # Artefacto generado: Bundle STIX 2.1
├── lab2_phishing/                     # Laboratorio 2
│   ├── generate_dataset.py            # Generador contextual guiado por CTI del Lab 1
│   ├── synthetic_phish_eval.csv       # Artefacto generado: Corpus de evaluación
│   └── train_eval_phish_detector.py   # Benchmark comparativo de tokenización (BPE vs WordPiece) y clasificación
├── lab3_bec_catboost/                 # Laboratorio 3
│   ├── feature_extraction.py          # Extractor de 12 dimensiones psicolingüísticas y estadísticas
│   ├── train_catboost_bec.py          # Entrenamiento CatBoost, medición de latencia y SHAP
│   ├── bec_catboost.cbm               # Artefacto generado: Modelo binario serializado
│   └── shap_importance_report.json    # Artefacto generado: Ranking de explicabilidad forense
├── lab4_feed_poisoning/               # Laboratorio 4
│   ├── feed_sanitizer.py              # Sanitizador de 3 capas (confianza, consenso, whitelist)
│   ├── simulate_poisoning.py          # Demostrador de prevención de DoS autoinfligido
│   ├── sanitized_firewall_rules.json  # Artefacto generado: Reglas perimetrales aprobadas
│   └── sanitizer_drop_audit.json      # Artefacto generado: Registro de amenazas mitigadas
└── project_ccdp/                      # Proyecto Integrador
    ├── ccdp_orchestrator.py           # Orquestador del flujo end-to-end unificado
    └── ccdp_executive_report.json     # Artefacto generado: Reporte ejecutivo de estado
```

---

## Instalación Rápida de Dependencias

```bash
pip install -r requirements.txt
```
