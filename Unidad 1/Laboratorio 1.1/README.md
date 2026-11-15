# Laboratorio 1: Detección de Living off the Land con Deep Autoencoders

## Objetivo
Entrenar una red neuronal subcompleta (cuello de botella) en PyTorch utilizando telemetría de ejecución de comandos legítimos, y evaluar su capacidad para detectar comandos ofuscados (LOLBins) mediante el Error Cuadrático Medio (MSE).

## Instrucciones Paso a Paso
1. Generar la telemetría sintética ejecutando `python3 generate_data.py`. Esto creará los archivos en la carpeta `data/`.
2. Ejecutar el script de entrenamiento `python3 train_autoencoder.py`.
3. Observar la convergencia de la función de pérdida y la definición del umbral estadístico al Percentil 99.
4. Analizar la matriz de confusión y el reporte de clasificación.

## Preguntas de Control
* ¿Por qué el decodificador falla en reconstruir los comandos de certutil.exe a pesar de que el proceso está firmado digitalmente?
* ¿Qué pasaría con la tasa de falsos positivos si cambiamos el umbral al Percentil 95?
