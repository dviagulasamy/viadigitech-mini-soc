#!/usr/bin/env python3
"""
ViaDigiTech SOC — Serveur d'actions opérationnelles
Port 8022, accessible via NPM reverse proxy sur /action/
Endpoints : /ban, /unban, /analyze, /report, /whitelist/add, /whitelist/remove, /status
"""

import os
import re
import subprocess
import threading
import time
import json
import requests
from flask import Flask, request, jsonify, Response, stream_with_context
from functools import wraps
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    _limiter_ok = True
except ImportError:
    _limiter_ok = False

app = Flask(__name__)
try:
    from flasgger import Swagger
    app.config['SWAGGER'] = {
        'title': 'ViaDigiTech SOC API',
        'uiversion': 3,
        'specs_route': '/action/docs/'
    }
    Swagger(app)
    _swagger_ok = True
except ImportError:
    _swagger_ok = False

if _limiter_ok:
    limiter = Limiter(app, key_func=get_remote_address, default_limits=["60 per minute"])

ACTIONS_KEY  = os.environ.get("SOC_ACTIONS_KEY", "")
OLLAMA_URL   = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "qwen2.5:3b"
IP_RE        = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# ─────────────────────────────────────────
# Auth
# ─────────────────────────────────────────

def require_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not ACTIONS_KEY:
            return jsonify({"ok": False, "error": "Actions API désactivée (SOC_ACTIONS_KEY non définie)"}), 403
        key = request.headers.get("X-SOC-Key", "")
        if key != ACTIONS_KEY:
            return jsonify({"ok": False, "error": "Clé invalide"}), 403
        return f(*args, **kwargs)
    return decorated

def valid_ip(ip):
    if not IP_RE.match(ip):
        return False
    parts = ip.split(".")
    return all(0 <= int(p) <= 255 for p in parts)

# ─────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────

@app.route("/status")
def status():
    """
    Statut du SOC
    ---
    tags: [SOC]
    security: [{ApiKeyAuth: []}]
    responses:
      200:
        description: Métriques courantes
    """
    return jsonify({"ok": True, "service": "SOC Actions API", "model": OLLAMA_MODEL})

@app.route("/ban", methods=["POST"])
@require_key
def ban():
    """
    Bannir une IP via Fail2Ban
    ---
    tags: [SOC]
    security: [{ApiKeyAuth: []}]
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            ip:
              type: string
              example: "1.2.3.4"
    responses:
      200:
        description: IP bannie avec succès
      400:
        description: IP invalide
      403:
        description: Clé API invalide
    """
    ip = (request.json or {}).get("ip", "").strip()
    if not valid_ip(ip):
        return jsonify({"ok": False, "error": f"IP invalide : {ip}"}), 400
    try:
        r = subprocess.run(
            ["sudo", "fail2ban-client", "set", "sshd", "banip", ip],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0:
            print(f"[Actions] BAN {ip} → OK")
            return jsonify({"ok": True, "message": f"{ip} bannie via Fail2Ban"})
        else:
            return jsonify({"ok": False, "error": r.stderr.strip() or "Erreur fail2ban"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/unban", methods=["POST"])
@require_key
def unban():
    """
    Débannir une IP via Fail2Ban
    ---
    tags: [SOC]
    security: [{ApiKeyAuth: []}]
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            ip:
              type: string
              example: "1.2.3.4"
    responses:
      200:
        description: IP débannie avec succès
      400:
        description: IP invalide
      403:
        description: Clé API invalide
    """
    ip = (request.json or {}).get("ip", "").strip()
    if not valid_ip(ip):
        return jsonify({"ok": False, "error": f"IP invalide : {ip}"}), 400
    try:
        r = subprocess.run(
            ["sudo", "fail2ban-client", "set", "sshd", "unbanip", ip],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0:
            print(f"[Actions] UNBAN {ip} → OK")
            return jsonify({"ok": True, "message": f"{ip} débannie"})
        else:
            return jsonify({"ok": False, "error": r.stderr.strip() or "IP non trouvée dans la liste"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/analyze", methods=["POST"])
@require_key
def analyze():
    prompt = (request.json or {}).get("prompt", "").strip()
    if not prompt:
        return jsonify({"ok": False, "error": "Prompt vide"}), 400
    if len(prompt) > 1000:
        return jsonify({"ok": False, "error": "Prompt trop long (max 1000 caractères)"}), 400

    full_prompt = f"""IMPORTANT : réponds UNIQUEMENT en français.
Tu es un analyste SOC du serveur VPS ViaDigiTech. Réponds de manière concise et opérationnelle.

Question : {prompt}

Maximum 150 mots."""

    try:
        r = requests.post(
            OLLAMA_URL,
            json={"model": OLLAMA_MODEL, "prompt": full_prompt, "stream": False},
            timeout=120
        )
        response = r.json().get("response", "").strip()
        print(f"[Actions] ANALYZE → {len(response)} chars")
        return jsonify({"ok": True, "response": response})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/report", methods=["POST"])
@require_key
def report():
    """Déclenche report.py en arrière-plan et répond immédiatement."""
    def _run():
        subprocess.run(
            ["python3", "/home/ubuntu/secops/report.py"],
            capture_output=True, text=True, timeout=300
        )
    threading.Thread(target=_run, daemon=True).start()
    print("[Actions] REPORT → démarré en arrière-plan")
    return jsonify({"ok": True, "message": "Rapport en cours de génération — vous le recevrez par mail dans ~1 min"})

@app.route("/whitelist/add", methods=["POST"])
@require_key
def whitelist_add():
    ip = (request.json or {}).get("ip", "").strip()
    if not valid_ip(ip):
        return jsonify({"ok": False, "error": f"IP invalide : {ip}"}), 400
    try:
        r = subprocess.run(
            ["sudo", "fail2ban-client", "set", "sshd", "addignoreip", ip],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0:
            print(f"[Actions] WHITELIST ADD {ip} → OK")
            return jsonify({"ok": True, "message": f"{ip} ajoutée à la whitelist"})
        return jsonify({"ok": False, "error": r.stderr.strip() or "Erreur fail2ban"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/whitelist/remove", methods=["POST"])
@require_key
def whitelist_remove():
    ip = (request.json or {}).get("ip", "").strip()
    if not valid_ip(ip):
        return jsonify({"ok": False, "error": f"IP invalide : {ip}"}), 400
    try:
        r = subprocess.run(
            ["sudo", "fail2ban-client", "set", "sshd", "delignoreip", ip],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0:
            print(f"[Actions] WHITELIST REMOVE {ip} → OK")
            return jsonify({"ok": True, "message": f"{ip} retirée de la whitelist"})
        return jsonify({"ok": False, "error": r.stderr.strip() or "IP non trouvée dans la whitelist"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# ─────────────────────────────────────────
# SSE — métriques live
# ─────────────────────────────────────────

def collect_live_metrics():
    """Collecte métriques légères pour SSE (CPU, RAM, bans, menace)."""
    import psutil
    try:
        bans = int(subprocess.run(
            ["fail2ban-client", "status", "sshd"],
            capture_output=True, text=True, timeout=5
        ).stdout.split("Currently banned:")[1].split()[0]) if os.path.exists("/run/fail2ban/fail2ban.sock") else 0
    except Exception:
        bans = 0
    return {
        "cpu": psutil.cpu_percent(interval=1),
        "ram": psutil.virtual_memory().percent,
        "bans": bans,
        "ts": int(time.time())
    }

@app.route("/stream")
def sse_stream():
    """SSE endpoint — métriques live toutes les 30s."""
    api_key = request.headers.get("X-SOC-Key", "")
    if ACTIONS_KEY and api_key != ACTIONS_KEY:
        return jsonify({"error": "Unauthorized"}), 401
    def generate():
        while True:
            try:
                data = collect_live_metrics()
                yield f"data: {json.dumps(data)}\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
            time.sleep(30)
    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no"
        }
    )

# ─────────────────────────────────────────
# Main
# ─────────────────────────────────────────

if __name__ == "__main__":
    if not ACTIONS_KEY:
        print("[Actions] ATTENTION : SOC_ACTIONS_KEY non définie — API désactivée")
    else:
        print(f"[Actions] Clé API configurée ({len(ACTIONS_KEY)} chars)")
    print("[Actions] Démarrage sur 0.0.0.0:8022")
    app.run(host="0.0.0.0", port=8022, debug=False)
