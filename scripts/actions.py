#!/usr/bin/env python3
"""
ViaDigiTech SOC — Serveur d'actions opérationnelles
Port 8022, accessible via NPM reverse proxy sur /action/
Endpoints : /ban, /unban, /analyze, /report, /whitelist/add, /whitelist/remove, /status
"""

import os
import re
import csv
import hmac
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
    limiter = Limiter(key_func=get_remote_address, default_limits=["60 per minute"])
    limiter.init_app(app)

ACTIONS_KEY   = os.environ.get("SOC_ACTIONS_KEY", "")
DASHBOARD_PWD = os.environ.get("SOC_DASHBOARD_PWD", "")  # Mot de passe mire de connexion (distinct de la clé API)
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

@app.route("/auth", methods=["POST"])
@(_limiter.limit("5 per minute") if _limiter_ok else lambda f: f)
def auth():
    """Valide le mot de passe de la mire de connexion (SOC_DASHBOARD_PWD)."""
    data = request.get_json(force=True) or {}
    pwd = str(data.get("password", ""))
    if not DASHBOARD_PWD:
        return jsonify({"ok": False, "error": "SOC_DASHBOARD_PWD non défini"}), 403
    if hmac.compare_digest(pwd, DASHBOARD_PWD):
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "Mot de passe invalide"}), 403

@app.route("/status")
@require_key
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
# Logs
# ─────────────────────────────────────────

LOG_FILE = "/home/ubuntu/secops/detector.log"

@app.route("/logs")
@require_key
def get_logs():
    """
    Dernières lignes du log detector
    ---
    tags: [SOC]
    parameters:
      - name: n
        in: query
        type: integer
        default: 30
    responses:
      200:
        description: Lignes de log
    """
    n = min(int(request.args.get("n", 30)), 200)
    lines = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE) as f:
            lines = f.readlines()[-n:]
    return jsonify({"lines": [l.rstrip() for l in lines]})

# ─────────────────────────────────────────
# Config SOC
# ─────────────────────────────────────────

SOC_CONFIG_FILE = "/home/ubuntu/secops/soc_config.json"
SOC_CONFIG_DEFAULTS = {
    "ban_threshold": 80,
    "warn_disk": 75,
    "crit_disk": 88,
    "warn_ram": 75,
    "crit_ram": 90,
    "warn_cpu": 70,
    "crit_cpu": 85,
    "sse_interval": 30,
    "autologout": 0,
    "notif_level": "all",
    "oncall": False,
    "oncall_name": "David",
    "f2b_bantime": 3600,
    "f2b_maxretry": 5,
    "f2b_findtime": 600,
    "subnet_ban_enabled": False,
    "subnet_ban_threshold": 3,
    "telegram_token": "",
    "telegram_chat_id": "",
}

def load_soc_config():
    if not os.path.exists(SOC_CONFIG_FILE):
        with open(SOC_CONFIG_FILE, "w") as f:
            json.dump(SOC_CONFIG_DEFAULTS, f, indent=2)
        return dict(SOC_CONFIG_DEFAULTS)
    try:
        with open(SOC_CONFIG_FILE) as f:
            cfg = json.load(f)
        # Merge avec defaults pour les clés manquantes
        for k, v in SOC_CONFIG_DEFAULTS.items():
            cfg.setdefault(k, v)
        return cfg
    except Exception:
        return dict(SOC_CONFIG_DEFAULTS)

@app.route("/config", methods=["GET"])
@require_key
def get_config():
    """
    Lire la configuration SOC
    ---
    tags: [SOC]
    security: [{ApiKeyAuth: []}]
    responses:
      200:
        description: Configuration courante
    """
    return jsonify(load_soc_config())

@app.route("/config", methods=["POST"])
@require_key
def set_config():
    """
    Mettre à jour la configuration SOC
    ---
    tags: [SOC]
    parameters:
      - in: body
        schema:
          type: object
    responses:
      200:
        description: Config mise à jour
    """
    data = request.get_json(force=True) or {}
    cfg = load_soc_config()
    # Valider et mettre à jour uniquement les clés connues
    allowed_int = ["ban_threshold", "warn_disk", "crit_disk", "warn_ram", "crit_ram",
                   "warn_cpu", "crit_cpu", "sse_interval", "autologout",
                   "f2b_bantime", "f2b_maxretry", "f2b_findtime", "subnet_ban_threshold"]
    allowed_bool = ["oncall", "subnet_ban_enabled"]
    allowed_str = ["oncall_name", "telegram_token", "telegram_chat_id"]
    for k in allowed_int:
        if k in data:
            try:
                val = int(data[k])
                if 0 <= val <= 500:
                    cfg[k] = val
            except (ValueError, TypeError):
                pass
    for k in allowed_bool:
        if k in data:
            cfg[k] = bool(data[k])
    for k in allowed_str:
        if k in data:
            cfg[k] = str(data[k])[:50]
    if "notif_level" in data and data["notif_level"] in ("all", "critical", "multi"):
        cfg["notif_level"] = data["notif_level"]
    try:
        with open(SOC_CONFIG_FILE, "w") as f:
            json.dump(cfg, f, indent=2)
        return jsonify({"ok": True, "config": cfg})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

IMGDIR_REPORTS  = "/var/www/html/viadigitech-reports"
GEO_CACHE_FILE  = "/home/ubuntu/secops/geo_cache.json"
SOC_HEALTH_FILE = "/home/ubuntu/secops/soc_health.json"


@app.route("/health", methods=["GET"])
def get_health():
    """Retourne l'état de santé minimal du SOC — pas d'auth requise (uptime check)."""
    if not os.path.exists(SOC_HEALTH_FILE):
        return jsonify({"ok": False, "overall": "UNKNOWN"})
    try:
        with open(SOC_HEALTH_FILE) as f:
            data = json.load(f)
        # Exposer uniquement le statut global, pas le détail des services
        return jsonify({"ok": True, "overall": data.get("overall", "UNKNOWN"), "ts": data.get("ts", "")})
    except Exception as e:
        return jsonify({"ok": False, "overall": "ERROR"}), 500


@app.route("/notify/telegram", methods=["POST"])
@require_key
def notify_telegram():
    """Envoie une notification Telegram manuelle depuis le dashboard."""
    data = request.get_json(force=True) or {}
    message = str(data.get("message", "")).strip()[:500]
    if not message:
        return jsonify({"ok": False, "error": "Message vide"}), 400
    cfg = load_soc_config()
    token   = cfg.get("telegram_token", "")   or os.environ.get("TELEGRAM_TOKEN", "")
    chat_id = cfg.get("telegram_chat_id", "") or os.environ.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat_id:
        return jsonify({"ok": False, "error": "Telegram non configuré (token/chat_id manquants)"}), 400
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": message, "parse_mode": "HTML"},
            timeout=8
        )
        return jsonify({"ok": r.status_code == 200, "detail": r.json() if r.status_code == 200 else r.text})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/fail2ban/status", methods=["GET"])
@require_key
def fail2ban_status():
    """Lit les paramètres actuels de la jail sshd Fail2Ban."""
    result = {}
    for param in ["bantime", "maxretry", "findtime"]:
        r = subprocess.run(
            ["sudo", "fail2ban-client", "get", "sshd", param],
            capture_output=True, text=True, timeout=5
        )
        try:
            result[param] = int(r.stdout.strip())
        except Exception:
            result[param] = None
    return jsonify({"ok": True, **result})

@app.route("/fail2ban/apply", methods=["POST"])
@require_key
def fail2ban_apply():
    """Applique les paramètres Fail2Ban stockés dans soc_config.json."""
    cfg = load_soc_config()
    bantime  = int(cfg.get("f2b_bantime",  3600))
    maxretry = int(cfg.get("f2b_maxretry", 5))
    findtime = int(cfg.get("f2b_findtime", 600))
    results = {}
    for param, val in [("bantime", bantime), ("maxretry", maxretry), ("findtime", findtime)]:
        r = subprocess.run(
            ["sudo", "fail2ban-client", "set", "sshd", param, str(val)],
            capture_output=True, text=True, timeout=10
        )
        results[param] = r.returncode == 0
    ok = all(results.values())
    print(f"[Actions] FAIL2BAN APPLY bantime={bantime}s maxretry={maxretry} findtime={findtime}s → {results}")
    return jsonify({"ok": ok, "results": results, "bantime": bantime, "maxretry": maxretry, "findtime": findtime})

@app.route("/maintenance/purge", methods=["POST"])
@require_key
def maintenance_purge():
    """Supprime les fichiers PNG de rapports de plus de 30 jours."""
    cutoff = time.time() - 30 * 86400
    deleted, freed = 0, 0
    if os.path.exists(IMGDIR_REPORTS):
        for fname in os.listdir(IMGDIR_REPORTS):
            if not fname.endswith(".png"):
                continue
            fpath = os.path.join(IMGDIR_REPORTS, fname)
            try:
                if os.path.getmtime(fpath) < cutoff:
                    freed += os.path.getsize(fpath)
                    os.remove(fpath)
                    deleted += 1
            except Exception:
                pass
    print(f"[Actions] PURGE → {deleted} PNG supprimés, {freed // 1024} KB libérés")
    return jsonify({"ok": True, "deleted": deleted, "freed_kb": freed // 1024})

@app.route("/maintenance/clear-geo", methods=["POST"])
@require_key
def maintenance_clear_geo():
    """Vide le cache de géolocalisation des IPs."""
    try:
        if os.path.exists(GEO_CACHE_FILE):
            os.remove(GEO_CACHE_FILE)
        return jsonify({"ok": True, "message": "Cache géo supprimé"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# ─────────────────────────────────────────
# Annotations
# ─────────────────────────────────────────

ANNOTATIONS_FILE = "/home/ubuntu/secops/annotations.json"

@app.route("/annotation/add", methods=["POST"])
@require_key
def add_annotation():
    """
    Ajouter une annotation SOC
    ---
    tags: [SOC]
    parameters:
      - in: body
        schema:
          type: object
    responses:
      200:
        description: Annotation ajoutée
    """
    data = request.get_json(force=True) or {}
    note = str(data.get("note", ""))[:200]
    author = str(data.get("author", "SOC"))[:30]
    if not note:
        return jsonify({"ok": False, "error": "note vide"}), 400
    ann = []
    if os.path.exists(ANNOTATIONS_FILE):
        try:
            with open(ANNOTATIONS_FILE) as f:
                ann = json.load(f)
        except Exception:
            ann = []
    from datetime import datetime
    ann.append({"ts": datetime.now().strftime("%Y-%m-%d %H:%M"), "note": note, "author": author})
    ann = ann[-50:]  # garder 50 max
    with open(ANNOTATIONS_FILE, "w") as f:
        json.dump(ann, f, indent=2)
    return jsonify({"ok": True})

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

AUDIT_LOG = "/home/ubuntu/secops/audit_actions.csv"
TI_MATCHES_FILE = "/home/ubuntu/secops/ti_matches.json"


# ─────────────────────────────────────────
# F12 — Export SIEM/CEF
# ─────────────────────────────────────────

@app.route("/export/siem", methods=["GET"])
@require_key
def export_siem():
    import csv as _csv
    fmt = request.args.get("format", "json")
    rows = []
    if os.path.exists(AUDIT_LOG):
        with open(AUDIT_LOG) as f:
            reader = _csv.reader(f)
            for row in reader:
                if len(row) < 4 or row[0] == "timestamp":
                    continue
                rows.append(row)
    rows = rows[-500:]  # 500 derniers événements

    if fmt == "cef":
        lines = []
        for row in rows:
            ts, ip, action = row[0][:19], row[1].strip(), row[2].strip()
            score  = row[3].strip() if len(row) > 3 else "0"
            reason = (row[4][:120] if len(row) > 4 else "").replace(",", " ")
            sev    = "9" if "BAN" in action else ("6" if "WATCH" in action else "3")
            lines.append(
                f"CEF:0|ViaDigiTech|SOC|1.0|{action}|SSH Threat Detection|{sev}|"
                f"src={ip} dpt=22 act={action} cs1={score} cs1Label=AbuseScore "
                f"msg={reason} end={ts}"
            )
        content = "\n".join(lines)
        return Response(
            content,
            mimetype="text/plain",
            headers={"Content-Disposition": "attachment;filename=soc_events.cef"}
        )
    else:
        events = [
            {"ts": r[0], "src_ip": r[1].strip(), "action": r[2].strip(),
             "score": r[3].strip(), "reason": r[4].strip() if len(r) > 4 else ""}
            for r in rows
        ]
        return jsonify({
            "events": events,
            "count": len(events),
            "format": "json-siem",
            "exported_at": __import__("datetime").datetime.now().isoformat()
        })


# ─────────────────────────────────────────
# F10 — Blocage ASN
# ─────────────────────────────────────────

@app.route("/block/asn", methods=["POST"])
@require_key
def block_asn():
    """Bannit toutes les IPs connues d'un ASN via Fail2Ban."""
    data = request.get_json(silent=True) or {}
    asn  = data.get("asn", "").strip()
    if not asn or not asn.startswith("AS"):
        return jsonify({"ok": False, "error": "ASN invalide (format: AS12345)"}), 400

    # Chercher les IPs de cet ASN dans ti_matches + geo_cache
    ips_to_ban = set()

    if os.path.exists(TI_MATCHES_FILE):
        try:
            with open(TI_MATCHES_FILE) as f:
                ti = json.load(f)
            for ip in ti:
                if valid_ip(ip):
                    ips_to_ban.add(ip)
        except Exception:
            pass

    if os.path.exists(GEO_CACHE_FILE):
        try:
            with open(GEO_CACHE_FILE) as f:
                geo = json.load(f)
            for ip, info in geo.items():
                if info.get("asn") == asn and valid_ip(ip):
                    ips_to_ban.add(ip)
        except Exception:
            pass

    banned = 0
    errors = []
    for ip in ips_to_ban:
        try:
            r = subprocess.run(
                ["sudo", "fail2ban-client", "set", "sshd", "banip", ip],
                capture_output=True, text=True, timeout=10
            )
            if r.returncode == 0:
                banned += 1
            else:
                errors.append(ip)
        except Exception as e:
            errors.append(ip)

    return jsonify({
        "ok": True,
        "asn": asn,
        "banned": banned,
        "total_candidates": len(ips_to_ban),
        "errors": errors[:5]
    })


@app.route("/notifications", methods=["GET"])
@require_key
def get_notifications():
    """Retourne les dernières entrées d'audit_actions.csv pour le panneau de notifications."""
    try:
        limit = min(int(request.args.get("limit", 80)), 200)
        audit_path = "/home/ubuntu/secops/audit_actions.csv"
        rows = []
        if os.path.exists(audit_path):
            with open(audit_path, newline="", encoding="utf-8") as f:
                # Lire manuellement pour gérer les virgules dans le champ reason
                lines = f.readlines()
            for line in lines[1:]:  # skip header
                parts = line.strip().split(",", 4)
                if len(parts) >= 4:
                    rows.append({
                        "timestamp": parts[0],
                        "ip":        parts[1],
                        "action":    parts[2],
                        "score":     parts[3],
                        "reason":    parts[4] if len(parts) > 4 else ""
                    })
        rows = rows[-limit:][::-1]
        # Ajouter les events du digest buffer s'il existe
        digest_path = "/home/ubuntu/secops/mail_digest_buffer.json"
        pending_count = 0
        if os.path.exists(digest_path):
            with open(digest_path) as f:
                buf = json.load(f)
                pending_count = len(buf.get("events", []))
        return jsonify({"ok": True, "notifications": rows, "total": len(rows), "digest_pending": pending_count})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/digest/flush", methods=["POST"])
@require_key
def flush_digest():
    """Force l'envoi immédiat du buffer digest en cours."""
    digest_path = "/home/ubuntu/secops/mail_digest_buffer.json"
    try:
        if not os.path.exists(digest_path):
            return jsonify({"ok": False, "error": "Aucun buffer digest trouvé"}), 404
        with open(digest_path) as f:
            buf = json.load(f)
        events = buf.get("events", [])
        if not events:
            return jsonify({"ok": True, "count": 0, "message": "Buffer vide, rien à envoyer"})
        # Appeler detector via subprocess pour déclencher le digest
        import smtplib
        from email.mime.multipart import MIMEMultipart as _MMP
        from email.mime.text import MIMEText as _MMT
        from datetime import datetime as _dt
        mail_from = os.environ.get("SOC_MAIL_FROM", "secops@viadigitech.com")
        mail_to   = os.environ.get("SOC_MAIL_TO", "david@viadigitech.com").split(",")
        n = len(events)
        rows = ""
        for e in events[:50]:
            color = "#ef4444" if e.get("niveau") == "CRITIQUE" else "#f59e0b"
            ts_s = e.get("ts", "")[:16].replace("T", " ")
            rows += (f"<tr><td style='padding:6px 8px;border:1px solid #334155;color:#64748b;font-size:11px'>{ts_s}</td>"
                     f"<td style='padding:6px 8px;border:1px solid #334155;color:{color};font-weight:bold;font-size:11px'>{e.get('niveau','')}</td>"
                     f"<td style='padding:6px 8px;border:1px solid #334155;font-size:12px'>{e.get('message','')}</td></tr>")
        html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="background:#0f172a;font-family:'Segoe UI',sans-serif;color:#e2e8f0">
<div style="max-width:680px;margin:0 auto;padding:24px">
  <div style="background:#1a2744;border-left:4px solid #6366f1;border-radius:10px;padding:20px;margin-bottom:20px">
    <div style="font-size:11px;color:#64748b;text-transform:uppercase">DIGEST SOC — envoi manuel</div>
    <div style="font-size:22px;font-weight:800;margin:6px 0">📬 {n} événement(s)</div>
  </div>
  <table style="width:100%;border-collapse:collapse">
    <thead><tr>
      <th style="padding:8px;background:#0f172a;text-align:left;font-size:11px;color:#64748b;border:1px solid #334155">Heure</th>
      <th style="padding:8px;background:#0f172a;text-align:left;font-size:11px;color:#64748b;border:1px solid #334155">Niveau</th>
      <th style="padding:8px;background:#0f172a;text-align:left;font-size:11px;color:#64748b;border:1px solid #334155">Événement</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div></body></html>"""
        now = _dt.now()
        msg = _MMP("alternative")
        msg["From"]    = mail_from
        msg["To"]      = ", ".join(mail_to)
        msg["Subject"] = f"[SOC Digest Manuel] {n} événement(s) — {now.strftime('%d/%m %H:%M')}"
        msg.attach(_MMT(html, "html", "utf-8"))
        with smtplib.SMTP("localhost") as s:
            s.sendmail(mail_from, mail_to, msg.as_string())
        # Vider le buffer
        with open(digest_path, "w") as f:
            json.dump({"last_sent": now.isoformat(), "events": []}, f)
        return jsonify({"ok": True, "count": n})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


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
