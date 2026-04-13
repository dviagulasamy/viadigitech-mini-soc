#!/usr/bin/env python3
"""
ViaDigiTech SOC — Serveur d'actions opérationnelles
Port 8022, accessible via Caddy reverse proxy sur /action/
Endpoints : /ban, /unban, /analyze, /status
"""

import os
import re
import subprocess
import requests
from flask import Flask, request, jsonify
from functools import wraps

app = Flask(__name__)

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
    return jsonify({"ok": True, "service": "SOC Actions API", "model": OLLAMA_MODEL})

@app.route("/ban", methods=["POST"])
@require_key
def ban():
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
