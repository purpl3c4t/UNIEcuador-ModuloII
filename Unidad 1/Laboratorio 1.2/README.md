# Laboratorio 2: Manipulación Adversarial de Baselines y Blindaje con Z-Score Robusto (MAD)

## Objetivo
Simular la inyección gradual de tráfico ("Ataque del Sapo Hervido" / Slow-and-Low drift) a lo largo de 4 semanas para constatar cómo la media y la desviación estándar clásicas duplican el umbral de alerta (variance bloat), y verificar la inmunidad del estimador basado en Mediana y MAD.

## Instrucciones Paso a Paso
1. Generar la serie temporal de 28 días ejecutando `python3 generate_poison_data.py`.
2. Ejecutar la evaluación comparativa `python3 evaluate_poisoning.py`.
3. Analizar la tabla de deformación del umbral y observar cómo el ataque de exfiltración de 165 pps en la semana 4 evade el detector clásico pero es interceptado por el detector robusto.

## Preguntas de Control
* ¿Por qué el punto de ruptura (breakdown point) de la media es 0% mientras que el de la mediana es 50%?
* ¿Qué función cumple el factor de consistencia 1.4826?
