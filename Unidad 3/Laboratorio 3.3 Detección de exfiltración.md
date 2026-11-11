# Laboratorio 3: Detección de Exfiltración por Canales Confiables con IA Híbrida

## Fundamento Técnico y Objetivo 
* La exfiltración avanzada en la nube elude los firewalls de inspección profunda (DPI) canalizando datos a través de servicios legítimos: replicación cruzada (cross-account) en almacenamiento de objetos (Amazon S3, Azure Blob) y tunelización cifrada DNS-over-HTTPS (DoH) hacia resolutores públicos de alta reputación. Al carecer de firmas conocidas, la detección exige un modelado híbrido no supervisado: un Autoencoder Neuronal comprime los flujos multidimensionales a un cuello de botella latente ($z \in \mathbb{R}^k$), y un Isolation Forest aísla las anomalías estocásticas dentro de dicho subespacio compacto evaluando el Error Cuadrático Medio (MSE) de reconstrucción.
* Objetivo: Generar flujos de red sintéticos que combinen tráfico legítimo con fugas masivas a S3 y fugas graduales (low-and-slow) por DoH, entrenar la arquitectura neuronal híbrida, aislar las transferencias anómalas en el puerto 443 y exportar la alerta estructurada enriquecida para el SOAR.
* **Tiempo objetivo: 30 minutos**

## Script en recursos:
* generate_vpc_traffic.py (Python / NumPy / Pandas)
* hybrid_exfiltration_detector.py (Python / PyTorch / Scikit-learn)
*
## Paso a Paso de Ejecución

#### Navega al directorio del laboratorio:cd ../lab3_exfiltration_detection
1. Genera el dataset de telemetría de flujos de red:python3 generate_vpc_traffic.py
2. Ejecuta el pipeline de entrenamiento e inferencia no supervisada híbrida vinculando el manifiesto del Laboratorio 2:
   python3 hybrid_exfiltration_detector.py \
  --manifest ../lab2_api_monitoring/compromised_manifest.json \
  --flows vpc_flows.csv

3. Observa las etapas del modelo en consola:
   * Compresión del Autoencoder: Reducción de las 5 variables de red a un espacio latente de 3 dimensiones ($k=3$) tras 25 épocas de optimización Adam.
   * Aislamiento en Espacio Latente: El Isolation Forest evalúa las representaciones comprimidas con un ratio de contaminación del 2.5%.
   * Filtro de Fusión: Intersección entre predicciones del Isolation Forest ($s(x) \to 1$) y errores de reconstrucción que superan el percentil 97.5 ($MSE > \tau$).
   * Verificación: Constata que el modelo aísla con precisión tanto los flujos de replicación asimétrica a S3 (bytes_in_ratio < 0.05) como las ráfagas anómalas de DoH, y confirma la exportación del archivo alert_payload.json con severidad CRITICAL y confianza superior al 95%.

4. **Generar el tráfico de flujos de red:** Sintetiza la telemetría de red con tráfico legítimo y canales encubiertos:

```
python recursos/generate_vpc_traffic.py

```

5. *Verificación:* Comprueba la creación de `vpc_flows.csv`.

6. **Ejecutar el modelo híbrido (Autoencoder + Isolation Forest):** Inicia el pipeline de machine learning:

```
python recursos/hybrid_exfiltration_detector.py

```

7. **Interpretación matemática del modelo:**
  * El Autoencoder comprime las 5 características a un espacio latente de 3 dimensiones.
  * El Isolation Forest identifica las muestras que quedan aisladas a menor profundidad dentro del espacio latente proyectado [7, 8].
  * La correlación entre el error MSE elevado de reconstrucción y la puntuación de aislamiento aísla con precisión las transferencias masivas a S3 y las fugas DoH [2, 5].
  * *Verificación:* Comprueba la generación de `alert_payload.json` con la puntuación de confianza y el ID de la instancia anómala.
