# Laboratorio 1: Minería de CTI en la Dark Web y Extracción de IoCs bajo Ontología STIX 2.1
## Tema Asociado: 4.4. Inteligencia de Amenazas (CTI), Operaciones en la Dark Web y Contra-Inteligencia
### Duración estimada: 30 minutos.
### Objetivo de Aprendizaje: 
* Procesar publicaciones no estructuradas de foros subterráneos de la Dark Web.
* Extraer entidades de ciberseguridad mediante Named Entity Recognition (NER) especializado y estructurar los IoCs resultantes en objetos conformes a STIX 2.11more_horiz.1.

### Contexto y Escenario Práctico
El analista del equipo de Threat Intelligence monitorea publicaciones clandestinas en foros subterráneos (similares a los registros del corpus CrimeBB procedentes de foros como BreachForums o HackForums). 
Debe extraer menciones de actores de amenazas (Threat-Actor), familias de malware (Malware), vulnerabilidades (Vulnerability/CVE) e indicadores técnicos de compromiso (IoCs)7more_horiz.

## Metodología Paso a PasoIngesta y Preprocesamiento
1. Cargar un corpus simulado de 100 discusiones de foros técnicos y filtraciones que contienen jerga criminal ofuscada y menciones a exploits de día cero.
2. Extracción de Entidades con Pipeline de CTI:
   * Utilizar un modelo Transformer preentrenado especializado en ciberseguridad con decodificador estructurado (BERT-CRF o representaciones inspiradas en SecureBERT / DarkBERT) more_horiz.
   * Aplicar el etiquetado BIO (Begin, Inside, Outside) entrenado sobre el corpus armonizado CyberNER (STIX 2.1) more_horiz y DNRTI1617.
   * Puntuación de Prioridad (EventHunter Framework): Computar el índice de completitud del evento: $$C(c_i) = w_\alpha \cdot \log(1 + |\text{unique\_entities}|) + w_\beta \cdot \log(1 + |\text{unique\_entity\_types}|)$$18
3. Calcular la prioridad operativa del cluster combinando oportunidad, credibilidad y relevancia.

### Exportación Estructurada: Mapear las entidades extraídas a objetos de dominio STIX (SDOs) y objetos ciber-observables (SCOs)8.3. 

### Entregable Técnico Requerido
Archivo serializado stix_cti_graph.json que contiene los patrones de ataque extraídos, incluyendo la identidad del actor de amenazas, el malware referenciado, la CVE asociada y la infraestructura de ataque78. (Este archivo es indispensable para el Lab 2).

## Recursos involucrados:
_Entrada: data/darkweb_forum_dump.json, config.jsonScript ejecutable: lab1_cti_ner/extract_cti.pySalida generada: lab1_cti_ner/stix_cti_graph.json

## Procedimiento Técnico de Ejecución
1. Inspeccionar las publicaciones de foros subterráneos disponibles en data/darkweb_forum_dump.json.
2. Observarás menciones a vulnerabilidades (como CVE-2023-34362), grupos de amenazas (TA505, Scattered Spider, BlackCat) e infraestructura C2.
3. Ejecutar el pipeline de extracción y puntuación:python3 lab1_cti_ner/extract_cti.py_

## Interpretación de Resultados y Métricas Operativas
El script aplica el esquema de Reconocimiento de Entidades Nombradas (NER) alineado con STIX 2.1 y evalúa la completitud narrativa del evento mediante la fórmula del framework EventHunter: $$C(c_i) = w_\alpha \cdot \log(1 + |\text{unique\_entities}|) + w_\beta \cdot \log(1 + |\text{unique\_types}|)$$Las publicaciones con mayor número de tipos y entidades técnicas (CVEs, IPs, hashes) obtienen un Priority Score superior ($\approx 2.48 - 2.67$), mientras que publicaciones genéricas sin indicadores obtienen un puntaje marginal ($0.58$), mitigando la fatiga de alertas en el SOC.
Artefacto verificado: Se crea lab1_cti_ner/stix_cti_graph.json, estructurado como un STIX 2.1 Bundle con objetos de tipo threat-actor, vulnerability, indicator y sus relaciones (relationship: targets).
