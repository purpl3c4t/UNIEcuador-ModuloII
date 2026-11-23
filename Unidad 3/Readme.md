# Guía de Ejecución Rápida de los Laboratorios (Unidad 3)

## Instalación de dependencias
```bash
pip install flask requests pandas numpy torch scikit-learn
```

## Secuencia de ejecución

### Laboratorio 1: Explotación y Blindaje de Identidad (IMDSv1 vs IMDSv2)
1. Terminal 1: Iniciar el servidor vulnerable:
   ```bash
   python recursos/imds_vulnerable_service.py
   ```
2. Terminal 2: Explotar SSRF para sustraer credenciales IMDSv1:
   ```bash
   curl -s "http://localhost:8080/preview?url=http://localhost:8080/latest/meta-data/iam/security-credentials/DevSecOpsInstanceRole"
   ```
3. Forzar remediación a IMDSv2:
   ```bash
   curl -X POST http://localhost:8080/admin/remediate_imds
   ```
4. Generar la telemetría del Lab 1:
   ```bash
   python recursos/generate_lab1_telemetry.py
   ```

### Laboratorio 2: Monitoreo Predictivo de APIs y Secuestro de Servicios
1. Ejecutar análisis de telemetría:
   ```bash
   python recursos/api_anomaly_detector.py
   ```
   *(Genera `compromised_manifest.json`)*.

### Laboratorio 3: Detección de Exfiltración por Canales Confiables con IA
1. Generar los flujos de red:
   ```bash
   python recursos/generate_vpc_traffic.py
   ```
2. Entrenar y ejecutar el modelo híbrido (Autoencoder + Isolation Forest):
   ```bash
   python recursos/hybrid_exfiltration_detector.py
   ```
   *(Genera `alert_payload.json`)*.

### Laboratorio 4: Respuesta Predictiva y Resiliencia en SOAR
1. Ejecutar el orquestador resiliente con backoff exponencial:
   ```bash
   python recursos/soar_resilient_playbook.py
   ```
