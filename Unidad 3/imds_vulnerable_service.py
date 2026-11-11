import json
import uuid
import time
import requests
from flask import Flask, request, jsonify, Response

app = Flask(__name__)

# Estado del emulador IMDS
IMDS_STATE = {
    "http_tokens": "optional",  # 'optional' permite IMDSv1; 'required' fuerza IMDSv2
    "tokens": {},               # Almacena tokens válidos y expiración
    "role_name": "DevSecOpsInstanceRole",
    "credentials": {
        "Code": "Success",
        "LastUpdated": "2026-11-11T03:00:00Z",
        "Type": "AWS-HMAC",
        "AccessKeyId": "ASIAVULNERABLEKEY101",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "Token": "IQoJb3JpZ2luX2VjEEXAMPLETOKENFLUSHEDFROMIMDS1==",
        "Expiration": "2026-11-11T09:00:00Z"
    }
}

# --- ENDPOINTS EMULADOS DEL METADATA SERVICE (169.254.169.254) ---

@app.route('/latest/api/token', methods=['PUT'])
def get_imds_token():
    """Generación de Token de sesión para IMDSv2"""
    if 'X-Forwarded-For' in request.headers:
        return Response("Proxy headers not allowed", status=400)
    
    ttl = request.headers.get('X-aws-ec2-metadata-token-ttl-seconds')
    if not ttl:
        return Response("Missing TTL header", status=400)
    
    token = str(uuid.uuid4())
    IMDS_STATE["tokens"][token] = time.time() + int(ttl)
    return Response(token, status=200, mimetype='text/plain')

@app.route('/latest/meta-data/iam/security-credentials/', methods=['GET'])
def list_iam_roles():
    """Lista roles disponibles en la instancia"""
    token = request.headers.get('X-aws-ec2-metadata-token')
    if IMDS_STATE["http_tokens"] == "required":
        if not token or token not in IMDS_STATE["tokens"] or IMDS_STATE["tokens"][token] < time.time():
            return Response("401 Unauthorized - IMDSv2 token required", status=401)
            
    return Response(IMDS_STATE["role_name"], status=200, mimetype='text/plain')

@app.route('/latest/meta-data/iam/security-credentials/<role_name>', methods=['GET'])
def get_iam_credentials(role_name):
    """Retorna credenciales STS de la instancia"""
    token = request.headers.get('X-aws-ec2-metadata-token')
    if IMDS_STATE["http_tokens"] == "required":
        if not token or token not in IMDS_STATE["tokens"] or IMDS_STATE["tokens"][token] < time.time():
            return Response("401 Unauthorized - IMDSv2 token required", status=401)
            
    if role_name == IMDS_STATE["role_name"]:
        return jsonify(IMDS_STATE["credentials"])
    return Response("Role not found", status=404)

@app.route('/admin/remediate_imds', methods=['POST'])
def remediate_imds():
    """Endpoint de control para alternar a IMDSv2 forzado (remediación)"""
    IMDS_STATE["http_tokens"] = "required"
    return jsonify({"status": "SUCCESS", "http_tokens": "required"})

# --- APLICACIÓN WEB VULNERABLE A SSRF ---

@app.route('/preview', methods=['GET'])
def vulnerable_preview():
    """Endpoint vulnerable a Server-Side Request Forgery"""
    target_url = request.args.get('url')
    if not target_url:
        return jsonify({"error": "Missing 'url' parameter"}), 400
    try:
        resp = requests.get(target_url, timeout=3)
        return Response(resp.content, status=resp.status_code, content_type=resp.headers.get('content-type', 'text/plain'))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    print("[*] Iniciando servidor vulnerable y simulador IMDS en http://localhost:8080")
    app.run(host='0.0.0.0', port=8080)
