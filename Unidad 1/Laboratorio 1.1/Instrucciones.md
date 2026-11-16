# Laboratorio 1.1: Detección de Living off the Land con Deep Autoencoders
---
## Objetivo: 
Demostrar el fenómeno del "colapso de contexto" mediante utilidades nativas firmadas por Microsoft (LOLBins), constatar la ineficacia de un SIEM de firmas y construir un detector no supervisado basado en Deep Autoencoders para alertar sobre ejecuciones atípicas mediante el Error Cuadrático Medio (MSE).

Abuso de utilidades nativas (*LOLBins* como `certutil.exe`), demostración del colapso de contexto y entrenamiento de un *Deep Autoencoder Subcompleto* en PyTorch para establecer la línea base y el umbral de anomalía basado en el Error Cuadrático Medio (MSE). Genera el conjunto de telemetría y el modelo baseline requerido para la siguiente práctica.

## Entregable Requerido para Lab 2: 
El conjunto de datos de telemetría benigna normalizada (`baseline_telemetry.csv`) y los pesos del modelo autoencoder entrenado (`autoencoder_baseline.pt`). 

## Marco Teórico y Planteamiento del Escenario

Los atacantes modernos utilizan ejecutables firmados por el sistema operativo (certutil.exe, powershell.exe, rundll32.exe) para ejecutar código arbitrario y transferir datos eludiendo las firmas tradicionales. Un SIEM basado en reglas ve un binario válido de Microsoft y transacciones HTTPS en el puerto 443, produciendo cero alertas.La defensa con UEBA modela el comportamiento mediante un Autoencoder Subcompleto ($p < n$). 

Al forzar la compresión en un espacio latente de baja dimensión, la red neuronal solo aprende las correlaciones habituales de la operación benigna. Cuando entra un comando con argumentos atípicos, entropía anormal o invocación fuera de horario, la red no puede reconstruir el vector original, disparando el Error Cuadrático Medio: `$$\text{MSE} = \frac{1}{n} \sum_{i=1}^{n} (x_i - \hat{x}_i)^2$$2.`

## Guía Paso a Paso de Ejecución (20 min)

A)  Cada carpeta contiene su propio script de generación de datos (`generate_*.py`), el script analítico principal y un `README.md` con las preguntas de control.
B)  La salida de cada laboratorio sirve como base conceptual y matemática para el siguiente.

### Paso 1.1: Generación de Telemetría Sintética y Colapso de Contexto
Configurar un script en Python para generar 10,000 eventos de actividad legítima de administradores de sistemas (consultas habituales, horarios diurnos, rutas estándar) y 100 eventos de ataque evasivo que abusan de certutil.exe para descargar un payload en Base64 depositado en %TEMP%. **Script:** `lab1_telemetry_generator.py*`

<img width="748" height="493" alt="image" src="https://github.com/user-attachments/assets/988723a6-8192-4662-84ce-aa6c25bed88f" />

### Paso 1.2: Entrenamiento del Autoencoder en PyTorch
Implementar y entrena la red neuronal utilizando únicamente el subconjunto benigno:# lab1_autoencoder.py

<img width="751" height="594" alt="image" src="https://github.com/user-attachments/assets/4c389a3f-1db1-47aa-99f9-f1d2f0c1471e" />

### Paso 1.3: Evaluación del Umbral de Anomalía
Calcular el error de reconstrucción sobre el tráfico normal para fijar el umbral analítico al percentil 99 ($P_{99}$), y evalúa las muestras de ataque evasivo.

<img width="759" height="426" alt="image" src="https://github.com/user-attachments/assets/b6f16649-e400-4edc-b533-116ae1768a1b" />

## Preguntas de Control y Validación 
---
Si un atacante reduce la longitud de su comando utilizando nombres cortos de carpetas y ejecuta en horario diurno:
* ¿cuál de las características restantes mantendría elevado el error MSE del autoencoder?
* ¿Por qué una regla de correlación estática en el SIEM como CommandLine CONTAINS "certutil.exe" fracasa en entornos empresariales donde los administradores usan esa herramienta para renovar certificados de Active Directory?
