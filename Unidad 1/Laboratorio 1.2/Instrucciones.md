# Laboratorio 1.2: Manipulación Adversarial de Baselines y Blindaje con Z-Score Robusto (MAD)
## Objetivo: 
Ejecutar un ataque de "Sapo Hervido" (Boiling Frog) inyectando tráfico gradual en la ventana de reentrenamiento del baseline, verificar la ceguera del detector clásico por inflación de varianza (variance bloat) e implementar una defensa con Z-Score Robusto basado en la Mediana y la MAD.

Ataque de Baseline Poisoning mediante inyección progresiva de ruido (chaff / sapo hervido) sobre la ventana de reentrenamiento. Demostración del colapso del umbral clásico ($\mu + 3\sigma$) por inflación de varianza y construcción de un detector resiliente con Z-Score Robusto basado en Mediana y MAD.

### Insumo de Entrada Requerido: 
Archivo baseline_telemetry.csv del Laboratorio 1.

### Entregable Requerido para Lab 3: 
Función calibrada de detección de umbrales basada en MAD (robust_detector.py) y registro de métricas tolerantes a anomalías.

## Marco Teórico y Planteamiento del Escenario 

Las plataformas analíticas reentrenan periódicamente sus baselines para adaptarse al cambio legítimo del negocio (concept drift). Un adversario persistente inyecta tráfico sintético de distracción (chaff) manteniéndose siempre por debajo del umbral de alerta vigente.

Bajo la regla estadística clásica $\mu + 3\sigma$, la media se desplaza y la desviación estándar $\sigma$ se infla rápidamente, duplicando el umbral de alerta y permitiendo que la exfiltración masiva pase desapercibida. La defensa matemática requiere estimadores con un Punto de Ruptura (Breakdown Point) del 50%: `$$\text{MAD} = \text{mediana}\Big(\big|x_i - \text{mediana}(X)\big|\Big)$$ $$\text{Z-Score Robusto} = \frac{x_i - \text{Mediana}}{1.4826 \cdot \text{MAD}}$$`

## Guía Paso a Paso de Ejecución 

### **ENTREGABLE TAREA**: 
Esta red produce datos sumamente contaminados donde el umbral robusto (Mediana/MAD) colapsa drásticamente, bypasseando para ambos (clásico y robusto). ¿qué parámetro hace que el atacante pueda burlar totalmente la seguridad mediante MAD? Modifícalo para decrecer el ruido introducido a la red e incluye en tu archivo MD la linea de código.

### Paso 2.1: Simulación del Ataque de Inyección Gradual (Boiling Frog)
Se someterá la telemetría del Laboratorio 1 a cuatro semanas simuladas de reentrenamiento, agregando una tasa de contaminación incremental de tráfico atípico (del 2% al 15% semanal).# lab2_baseline_poisoning.py

<img width="763" height="463" alt="image" src="https://github.com/user-attachments/assets/6714e415-950f-49fe-96a3-d62b7863ed29" />

### Paso 2.2: Construcción del Detector Robusto para el Pipeline
Encapsular la lógica matemática en un módulo reusable que exporta la función evaluate_sample(x) utilizando el Z-score normalizado de MAD, descartando cualquier influencia de la media clásica.

<img width="772" height="694" alt="image" src="https://github.com/user-attachments/assets/26e70aaf-f81e-4a0a-856f-1b4d6882b570" />


## Preguntas de Control y Validación 
* En la Semana 4, ¿cuál fue el porcentaje exacto de inflación del umbral clásico frente a la variación contenida del umbral robusto?
* ¿Por qué el factor de escala $1.4826$ es indispensable al utilizar la MAD en distribuciones que se asemejan a una normal Gaussiana?
