### Laboratorio 3: Detección de Exfiltración por Canales Confiables con IA Híbrida

**Tiempo objetivo: 30 minutos**

1. **Generar el tráfico de flujos de red:** Sintetiza la telemetría de red con tráfico legítimo y canales encubiertos:

```
python recursos/generate_vpc_traffic.py

```

*Verificación:* Comprueba la creación de `vpc_flows.csv`.

1. **Ejecutar el modelo híbrido (Autoencoder + Isolation Forest):** Inicia el pipeline de machine learning [2, 7, 8]:

```
python recursos/hybrid_exfiltration_detector.py

```

2. **Interpretación matemática del modelo:**
  * El Autoencoder comprime las 5 características a un espacio latente de 3 dimensiones [2, 7].
  * El Isolation Forest identifica las muestras que quedan aisladas a menor profundidad dentro del espacio latente proyectado [7, 8].
  * La correlación entre el error MSE elevado de reconstrucción y la puntuación de aislamiento aísla con precisión las transferencias masivas a S3 y las fugas DoH [2, 5].
  * *Verificación:* Comprueba la generación de `alert_payload.json` con la puntuación de confianza y el ID de la instancia anómala.

3. **Guarda el archivo en `recursos/generate_vpc_traffic.py`:**  Genera flujos sintéticos de red (`vpc_flows.csv`) con telemetría normal y dos patrones de exfiltración encubierta por canales confiables: sincronización masiva a cubos S3/Blob de cuentas externas y fuga gradual (*low-and-slow*) vía consultas cifradas DoH (puerto 443) [2, 5, 6].

4. **Detector Híbrido Autoencoder + Isolation Forest (`hybrid_exfiltration_detector.py`)**: Implementa la arquitectura no supervisada híbrida para detectar la exfiltración sin necesidad de etiquetas previas, exportando la alerta estructurada `alert_payload.json` hacia el SOAR.
Guarda el archivo en `recursos/hybrid_exfiltration_detector.py`:
