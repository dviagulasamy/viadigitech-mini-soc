#!/usr/bin/env python3
"""
ViaDigiTech SOC — Détecteur d'alertes temps réel (toutes les 15 min)
Vérifie les seuils critiques et envoie un mail d'alerte si dépassement.
"""

import os
import re
import json
import smtplib
import sys

import subprocess
import psutil
import requests
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import csv
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# F7 — Threat Intelligence feeds
sys.path.insert(0, os.path.dirname(__file__))
try:
    from ti_feeds import check_ip_ti, persist_ti_match
    TI_AVAILABLE = True
except ImportError:
    TI_AVAILABLE = False
    def check_ip_ti(ip):
        return {"matched": False, "sources": [], "tags": [], "score_bonus": 0}
    def persist_ti_match(ip, ti_result):
        pass

# F17 — SQLite
try:
    from soc_db import db_write_audit, db_add_score_history, db_get_stats
    DB_AVAILABLE = True
except ImportError:
    DB_AVAILABLE = False
    def db_write_audit(ip, action, score, reason=""): pass
    def db_add_score_history(ip, score, action=""): pass
    def db_get_stats(hours=24): return {"avg_score": 0}

# ─────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────
MAIL_FROM        = os.environ.get("SOC_MAIL_FROM", "secops@yourdomain.com")
MAIL_TO          = os.environ.get("SOC_MAIL_TO", "admin@yourdomain.com").split(",")
ABUSEIPDB_KEY    = os.environ.get("ABUSEIPDB_KEY", "")
TELEGRAM_TOKEN   = os.environ.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
AUTH_LOG             = "/var/log/auth.log"
STATE_FILE           = "/tmp/soc_detector_state.txt"
AUDIT_LOG              = "/home/ubuntu/secops/audit_actions.csv"
THREAT_PATTERNS_FILE   = "/home/ubuntu/secops/threat_patterns.json"
DIGEST_BUFFER_FILE     = "/home/ubuntu/secops/mail_digest_buffer.json"
TELEGRAM_DIGEST_FILE   = "/home/ubuntu/secops/telegram_digest_buffer.json"
THRESHOLD_ALERT_FILE   = "/tmp/soc_threshold_alert.json"
WINDOW_MIN       = 15   # fenêtre d'analyse en minutes

# Mode : "dryrun" = mail de confirmation, "auto" = ban immédiat
AUTO_BAN_MODE    = "auto"
AUTO_BAN_SCORE   = 80    # score AbuseIPDB minimum pour ban auto

# Seuils d'alerte
SEUILS = {
    "ssh_fails":    20,    # tentatives SSH en 15 min
    "new_bans":      8,    # nouveaux bans Fail2Ban en 15 min (relevé: trop bruyant à 5)
    "cpu_percent":  90,    # CPU %
    "ram_percent":  90,    # RAM %
    "disk_percent": 90,    # Disque %
}

# Whitelist IP — chargée depuis SOC_WHITELIST ou soc_config.json (jamais en dur dans le code)
_wl_env = os.environ.get("SOC_WHITELIST", "")
WHITELIST = [ip.strip() for ip in _wl_env.split(",") if ip.strip()] if _wl_env else []

# ─────────────────────────────────────────
# CONCURRENCE OLLAMA
# ─────────────────────────────────────────

def is_report_running():
    """Retourne True si report.py tourne (évite la contention CPU avec Ollama à 7h)."""
    for proc in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmdline = " ".join(proc.info["cmdline"] or [])
            if "report.py" in cmdline and proc.pid != os.getpid():
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return False

def _telegram_post(msg):
    """Envoi direct Telegram (interne)."""
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "HTML"},
            timeout=5,
        )
    except Exception as e:
        print(f"[Telegram] Erreur : {e}")

def send_telegram(msg):
    """Envoie ou bufferise un message Telegram selon le mode configuré (F16)."""
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        with open("/home/ubuntu/secops/soc_config.json") as f:
            cfg = json.load(f)
        tg_mode = cfg.get("telegram_mode", "immediate")
    except Exception:
        tg_mode = "immediate"

    if tg_mode == "digest":
        # Bufferiser le message
        buf = []
        if os.path.exists(TELEGRAM_DIGEST_FILE):
            try:
                with open(TELEGRAM_DIGEST_FILE) as f:
                    buf = json.load(f)
            except Exception:
                buf = []
        buf.append({"ts": datetime.now().isoformat()[:16], "msg": msg})
        with open(TELEGRAM_DIGEST_FILE, "w") as f:
            json.dump(buf, f)
    else:
        _telegram_post(msg)

def flush_telegram_digest():
    """Vide le buffer Telegram digest et envoie un résumé groupé (F16)."""
    if not os.path.exists(TELEGRAM_DIGEST_FILE):
        return
    try:
        with open(TELEGRAM_DIGEST_FILE) as f:
            buf = json.load(f)
    except Exception:
        return
    if not buf:
        return
    try:
        with open("/home/ubuntu/secops/soc_config.json") as f:
            cfg = json.load(f)
        interval_min = int(cfg.get("telegram_digest_interval", 30))
    except Exception:
        interval_min = 30

    # Vérifie si l'intervalle est écoulé depuis le dernier flush
    last_flush_file = "/tmp/soc_tg_last_flush.txt"
    if os.path.exists(last_flush_file):
        try:
            with open(last_flush_file) as f:
                last = datetime.fromisoformat(f.read().strip())
            if (datetime.now() - last).total_seconds() < interval_min * 60:
                return
        except Exception:
            pass

    hostname = os.uname().nodename
    lines = [f"📋 <b>Digest Telegram SOC — {hostname}</b> ({len(buf)} alertes)"]
    for item in buf[-20:]:  # max 20 lignes
        lines.append(f"[{item['ts'][11:]}] {item['msg'][:120]}")
    _telegram_post("\n".join(lines))

    with open(TELEGRAM_DIGEST_FILE, "w") as f:
        json.dump([], f)
    with open(last_flush_file, "w") as f:
        f.write(datetime.now().isoformat())

# ─────────────────────────────────────────
# COLLECTE
# ─────────────────────────────────────────

def get_system():
    return {
        "cpu":  psutil.cpu_percent(interval=1),
        "ram":  psutil.virtual_memory().percent,
        "disk": psutil.disk_usage("/").percent,
    }

def get_ssh_fails(since_minutes):
    since = datetime.now() - timedelta(minutes=since_minutes)
    count = 0
    ips = Counter()
    if not os.path.exists(AUTH_LOG):
        return 0, ips
    with open(AUTH_LOG, "r", errors="ignore") as f:
        lines = f.readlines()[-5000:]
    year = datetime.now().year
    for line in lines:
        if "Failed password" not in line and "Invalid user" not in line:
            continue
        try:
            ts = datetime.strptime(line[:15] + f" {year}", "%b %d %H:%M:%S %Y")
        except:
            continue
        if ts >= since:
            count += 1
            m = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', line)
            if m and m.group(1) not in WHITELIST:
                ips[m.group(1)] += 1
    return count, ips

def get_new_bans(since_minutes):
    since = datetime.now() - timedelta(minutes=since_minutes)
    bans = []
    ban_log = "/var/log/fail2ban.log"
    if not os.path.exists(ban_log):
        return bans
    with open(ban_log, "r", errors="ignore") as f:
        lines = f.readlines()[-2000:]
    for line in lines:
        if "Ban" not in line:
            continue
        try:
            ts = datetime.strptime(line[:19], "%Y-%m-%d %H:%M:%S")
        except:
            continue
        if ts >= since:
            m = re.search(r'Ban\s+(\d+\.\d+\.\d+\.\d+)', line)
            if m and m.group(1) not in WHITELIST:
                bans.append(m.group(1))
    return bans

# ─────────────────────────────────────────
# ABUSEIPDB — vérification et ban automatique
# ─────────────────────────────────────────

def check_abuseipdb(ip):
    """Retourne le score AbuseIPDB (0-100) et les infos de l'IP."""
    if not ABUSEIPDB_KEY:
        return None
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 30},
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            timeout=10
        )
        data = r.json().get("data", {})
        return {
            "score":    data.get("abuseConfidenceScore", 0),
            "country":  data.get("countryCode", ""),
            "isp":      data.get("isp", ""),
            "isTor":    data.get("isTor", False),
            "reports":  data.get("totalReports", 0),
        }
    except Exception as e:
        print(f"[AbuseIPDB] Erreur pour {ip}: {e}")
        return None

def ban_ip_fail2ban(ip, jail="sshd"):
    """Bannit une IP via fail2ban-client."""
    try:
        result = subprocess.run(
            ["sudo", "fail2ban-client", "set", jail, "banip", ip],
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0
    except Exception as e:
        print(f"[Ban] Erreur: {e}")
        return False

def write_audit(ip, action, score, reason):
    """Enregistre dans CSV legacy + SQLite (F17)."""
    os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
    header = not os.path.exists(AUDIT_LOG)
    with open(AUDIT_LOG, "a") as f:
        if header:
            f.write("timestamp,ip,action,score,reason\n")
        f.write(f"{datetime.now().isoformat()},{ip},{action},{score},{reason}\n")
    if DB_AVAILABLE:
        db_write_audit(ip, action, score, reason)

def load_threat_patterns():
    """Charge le fichier de mémoire des patterns de menace."""
    if not os.path.exists(THREAT_PATTERNS_FILE):
        return {}
    try:
        with open(THREAT_PATTERNS_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

def update_threat_patterns(ip, action, score):
    """Met à jour la mémoire des patterns après chaque action."""
    patterns = load_threat_patterns()
    subnet = ".".join(ip.split(".")[:3]) + ".0/24"

    # Entrée par IP
    if ip not in patterns:
        patterns[ip] = {"first_seen": datetime.now().isoformat()[:10], "bans": 0, "score_max": 0, "actions": []}
    if action in ("BAN_AUTO", "BAN_OLLAMA"):
        patterns[ip]["bans"] += 1
    patterns[ip]["score_max"] = max(patterns[ip].get("score_max", 0), score)
    patterns[ip]["actions"].append({"ts": datetime.now().isoformat()[:16], "action": action})
    patterns[ip]["actions"] = patterns[ip]["actions"][-10:]  # garder 10 dernières
    # F15 — historique de scores (30 derniers)
    if "score_history" not in patterns[ip]:
        patterns[ip]["score_history"] = []
    patterns[ip]["score_history"].append({"ts": datetime.now().isoformat()[:16], "score": score})
    patterns[ip]["score_history"] = patterns[ip]["score_history"][-30:]
    if DB_AVAILABLE:
        db_add_score_history(ip, score, action)

    # Entrée par /24
    if subnet not in patterns:
        patterns[subnet] = {"first_seen": datetime.now().isoformat()[:10], "bans": 0, "ips": []}
    if action in ("BAN_AUTO", "BAN_OLLAMA"):
        patterns[subnet]["bans"] += 1
    if ip not in patterns[subnet]["ips"]:
        patterns[subnet]["ips"].append(ip)
    patterns[subnet]["ips"] = patterns[subnet]["ips"][-20:]

    try:
        with open(THREAT_PATTERNS_FILE, "w") as f:
            json.dump(patterns, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[Patterns] Erreur écriture: {e}")

def ollama_decide(ip, attempts, info):
    """
    Interroge qwen2.5:3b pour une décision sur une IP en zone grise (score 40-79%).
    Retourne {"action": "BAN"|"SURVEILLE"|"IGNORE", "raison": "...", "urgence": "..."}
    """
    patterns = load_threat_patterns()
    subnet = ".".join(ip.split(".")[:3]) + ".0/24"
    ip_history = patterns.get(ip, {})
    subnet_history = patterns.get(subnet, {})
    history_ctx = ""
    if ip_history.get("bans", 0) > 0:
        history_ctx += f"\nHISTORIQUE IP: {ip_history['bans']} bans depuis {ip_history.get('first_seen','?')}."
    if subnet_history.get("bans", 0) > 1:
        history_ctx += f"\nHISTORIQUE /24: {subnet_history['bans']} bans sur ce sous-réseau."

    prompt = (
        f"Tu es un analyste SOC. Réponds UNIQUEMENT en JSON valide, sans texte autour.\n"
        f"Contexte:\n"
        f"- IP: {ip}\n"
        f"- Tentatives SSH en 15min: {attempts}\n"
        f"- Score AbuseIPDB: {info['score']}%\n"
        f"- Pays: {info['country']}, FAI: {info['isp']}\n"
        f"- Nœud TOR: {info['isTor']}\n"
        f"- Signalements totaux: {info['reports']}{history_ctx}\n"
        f"Format: {{\"action\": \"BAN\" ou \"SURVEILLE\" ou \"IGNORE\", "
        f"\"raison\": \"une phrase\", \"urgence\": \"haute\" ou \"moyenne\" ou \"faible\"}}"
    )
    try:
        r = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": "qwen2.5:3b", "prompt": prompt, "stream": False},
            timeout=90
        )
        response = r.json().get("response", "").strip()
        # Extraire le JSON même si du texte parasite l'entoure
        start, end = response.find("{"), response.rfind("}") + 1
        if start >= 0 and end > start:
            return json.loads(response[start:end])
    except Exception as e:
        print(f"[Ollama] Erreur pour {ip}: {e}")
    return {"action": "SURVEILLE", "raison": "Décision Ollama indisponible", "urgence": "faible"}

# ─────────────────────────────────────────
# F8 — SCORING ADAPTATIF MULTI-FACTEURS
# ─────────────────────────────────────────

HIGH_RISK_COUNTRIES = {"CN", "RU", "KP", "IR", "VN", "TW", "NG", "BR", "UA", "RO"}
MEDIUM_RISK_COUNTRIES = {"TR", "TH", "ID", "PK", "BD", "GH", "MX", "PH"}


def count_ip_in_audit(ip, days=7):
    """Nombre de fois que cette IP apparaît dans l'audit sur les N derniers jours."""
    since = datetime.now() - timedelta(days=days)
    count = 0
    if not os.path.exists(AUDIT_LOG):
        return 0
    try:
        with open(AUDIT_LOG) as f:
            for line in f:
                if ip not in line:
                    continue
                parts = line.strip().split(",", 4)
                if len(parts) < 3 or parts[1].strip() != ip:
                    continue
                try:
                    ts = datetime.fromisoformat(parts[0][:19])
                    if ts >= since:
                        count += 1
                except Exception:
                    pass
    except Exception:
        pass
    return count


def compute_composite_score(base_score, ip, country, ti_result):
    """
    Score composite = score AbuseIPDB + bonus contextuels.
    Maintient la logique existante, enrichit avec TI / récidive / pays / heure.
    """
    bonus = 0

    # TI feeds match → +20
    bonus += ti_result.get("score_bonus", 0)

    # Récidive 7 jours → jusqu'à +15
    recidive = count_ip_in_audit(ip, days=7)
    if recidive >= 5:
        bonus += 15
    elif recidive >= 3:
        bonus += 10
    elif recidive >= 1:
        bonus += 4

    # Pays à risque → +8 ou +4
    if country in HIGH_RISK_COUNTRIES:
        bonus += 8
    elif country in MEDIUM_RISK_COUNTRIES:
        bonus += 4

    # Heure nocturne (22h-6h) ou WE → +5
    now = datetime.now()
    if now.hour < 6 or now.hour >= 22 or now.weekday() >= 5:
        bonus += 5

    return min(base_score + bonus, 100)


# ─────────────────────────────────────────
# F9 — RÉPONSE GRADUÉE
# ─────────────────────────────────────────

BAN_TEMP_SCORE = 70   # score composite ≥ 70 → BAN_TEMP
# AUTO_BAN_SCORE (80) défini en config reste le seuil BAN_AUTO


def enrich_and_act(top_ips):
    """
    Vérifie les top IPs sur AbuseIPDB + TI feeds (F7), calcule le score composite (F8)
    et applique la réponse graduée (F9) :
      composite ≥ AUTO_BAN_SCORE (80) → BAN_AUTO
      composite ≥ BAN_TEMP_SCORE  (70) → BAN_TEMP
      composite ≥ 40               → Ollama décide (zone grise)
      composite < 40               → SURVEILLE
    """
    actions = []
    hostname = os.uname().nodename

    for ip, attempts in top_ips.most_common(5):
        info = check_abuseipdb(ip)
        if not info:
            continue

        abuse_score = info["score"]
        country     = info.get("country", "")

        # F14 — Geo-blocking : ban immédiat si pays bloqué
        try:
            with open("/home/ubuntu/secops/soc_config.json") as _f:
                _cfg = json.load(_f)
            blocked_countries = [c.upper() for c in _cfg.get("blocked_countries", [])]
        except Exception:
            blocked_countries = []
        if country and country.upper() in blocked_countries:
            action = "BAN_GEO"
            write_audit(ip, action, 100, f"Geo-block: pays {country} bloqué ({attempts} tentatives)")
            if AUTO_BAN_MODE == "auto":
                ban_ip_fail2ban(ip)
                update_threat_patterns(ip, action, 100)
            actions.append({"ip": ip, "action": action, "score": 100, "info": info,
                            "reason": f"Geo-block {country}"})
            send_telegram(
                f"🌍 <b>BAN GEO</b>\nIP: <code>{ip}</code>\nPays bloqué: {country}\n"
                f"Serveur: {hostname}"
            )
            print(f"[GeoBlock] {ip} ({country}) → BAN_GEO")
            continue

        # F7 — TI check
        ti_result = check_ip_ti(ip)
        if ti_result.get("matched"):
            persist_ti_match(ip, ti_result)
            ti_tag = f" | TI: {', '.join(ti_result['sources'])} [{', '.join(ti_result['tags'])}]"
        else:
            ti_tag = ""

        # F8 — Score composite
        composite = compute_composite_score(abuse_score, ip, country, ti_result)

        reason = (
            f"{attempts} tentatives, AbuseIPDB {abuse_score}%, "
            f"composite {composite}%, {country}, {info['isp']}{ti_tag}"
        )

        # F9 — Réponse graduée
        if composite >= AUTO_BAN_SCORE:
            # Tier 1 : BAN définitif
            if AUTO_BAN_MODE == "auto":
                success = ban_ip_fail2ban(ip)
                action  = "BAN_AUTO" if success else "BAN_ECHEC"
            else:
                action = "DRYRUN_BAN"
            write_audit(ip, action, composite, reason)
            if action == "BAN_AUTO":
                update_threat_patterns(ip, "BAN_AUTO", composite)
            actions.append({"ip": ip, "action": action, "score": composite, "info": info, "reason": reason})
            print(f"[AutoBan] {ip} — composite {composite}% → {action}")
            if action == "BAN_AUTO":
                ti_line = f"\nTI: {', '.join(ti_result['sources'])}" if ti_result.get("matched") else ""
                send_telegram(
                    f"🚨 <b>BAN AUTO</b>\nIP: <code>{ip}</code>\n"
                    f"Score: {composite}% (AbuseIPDB {abuse_score}%){ti_line}\n"
                    f"Serveur: {hostname}"
                )

        elif composite >= BAN_TEMP_SCORE:
            # Tier 2 : BAN temporaire (score élevé mais sous le seuil définitif)
            if AUTO_BAN_MODE == "auto":
                success = ban_ip_fail2ban(ip)
                action  = "BAN_TEMP" if success else "BAN_ECHEC"
            else:
                action = "DRYRUN_BAN_TEMP"
            write_audit(ip, action, composite, reason)
            if action == "BAN_TEMP":
                update_threat_patterns(ip, "BAN_TEMP", composite)
            actions.append({"ip": ip, "action": action, "score": composite, "info": info, "reason": reason})
            print(f"[BanTemp] {ip} — composite {composite}% → {action}")
            if action == "BAN_TEMP":
                ti_line = f"\nTI: {', '.join(ti_result['sources'])}" if ti_result.get("matched") else ""
                send_telegram(
                    f"⚠️ <b>BAN TEMPORAIRE</b>\nIP: <code>{ip}</code>\n"
                    f"Score: {composite}%{ti_line}\n"
                    f"Serveur: {hostname}"
                )

        elif composite >= 40:
            # Tier 3 : Zone grise → Ollama
            if is_report_running():
                print(f"[Ollama] Zone grise {ip} — report.py actif, décision différée")
                decision = {"action": "SURVEILLE", "raison": "Décision différée (report.py actif)", "urgence": "faible"}
            else:
                print(f"[Ollama] Zone grise {ip} (composite {composite}%) — consultation qwen2.5:3b...")
                decision = ollama_decide(ip, attempts, info)
            ollama_action  = decision.get("action", "SURVEILLE")
            ollama_raison  = decision.get("raison", "")
            ollama_urgence = decision.get("urgence", "faible")
            reason_full    = f"{reason} | Ollama: {ollama_raison} (urgence: {ollama_urgence})"

            if ollama_action == "BAN" and AUTO_BAN_MODE == "auto":
                success = ban_ip_fail2ban(ip)
                action  = "BAN_OLLAMA" if success else "BAN_ECHEC"
            else:
                action = f"OLLAMA_{ollama_action}"

            write_audit(ip, action, composite, reason_full)
            if action == "BAN_OLLAMA":
                update_threat_patterns(ip, "BAN_OLLAMA", composite)
            actions.append({
                "ip": ip, "action": action, "score": composite,
                "info": info, "reason": reason_full, "ollama": decision
            })
            print(f"[Ollama] {ip} → {action} ({ollama_raison})")

        else:
            # Tier 4 : surveillance passive
            actions.append({"ip": ip, "action": "SURVEILLE", "score": composite, "info": info, "reason": reason})

    return actions

# ─────────────────────────────────────────
# DÉDUPLICATION — évite les alertes répétitives
# ─────────────────────────────────────────

def already_alerted(key, minutes=30):
    """Retourne True si une alerte pour cette clé a été envoyée il y a moins de `minutes` min."""
    if not os.path.exists(STATE_FILE):
        return False
    with open(STATE_FILE, "r") as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) == 2 and parts[0] == key:
                try:
                    ts = datetime.fromisoformat(parts[1])
                    if datetime.now() - ts < timedelta(minutes=minutes):
                        return True
                except:
                    pass
    return False

def mark_alerted(key):
    lines = []
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            lines = [l for l in f.readlines() if not l.startswith(key + "|")]
    lines.append(f"{key}|{datetime.now().isoformat()}\n")
    with open(STATE_FILE, "w") as f:
        f.writelines(lines[-50:])

# ─────────────────────────────────────────
# DIGEST EMAIL — buffer + envoi groupé
# ─────────────────────────────────────────

def load_mail_config():
    """Lit les paramètres email depuis soc_config.json."""
    defaults = {
        "mail_mode": "immediate",
        "mail_digest_hours": 4,
        "mail_types_ban_auto": True,
        "mail_types_ban_temp": True,
        "mail_types_honeypot": True,
        "mail_types_low_slow": True,
        "mail_types_system": True,
    }
    try:
        with open("/home/ubuntu/secops/soc_config.json") as f:
            cfg = json.load(f)
        for k, v in defaults.items():
            defaults[k] = cfg.get(k, v)
    except Exception:
        pass
    return defaults

def _alert_type(alertes, actions):
    """Détermine le type principal d'une liste d'alertes pour le filtre mail_types."""
    types = set()
    for a in actions:
        if a["action"] == "BAN_AUTO":
            types.add("ban_auto")
        elif a["action"] in ("BAN_TEMP", "DRYRUN_BAN"):
            types.add("ban_temp")
    for a in alertes:
        msg = a.get("message", "").lower()
        if "honeypot" in msg:
            types.add("honeypot")
        elif "low" in msg and "slow" in msg:
            types.add("low_slow")
        elif any(k in msg for k in ("cpu", "ram", "disque", "disk")):
            types.add("system")
        elif "ssh" in msg or "ban" in msg:
            types.add("ban_auto")
    return types or {"system"}

def is_mail_type_enabled(cfg, types):
    """Retourne True si au moins un des types est activé dans la config mail."""
    mapping = {
        "ban_auto": "mail_types_ban_auto",
        "ban_temp": "mail_types_ban_temp",
        "honeypot": "mail_types_honeypot",
        "low_slow": "mail_types_low_slow",
        "system":   "mail_types_system",
    }
    return any(cfg.get(mapping.get(t, "mail_types_system"), True) for t in types)

def append_to_digest(alertes, actions, sys_metrics):
    """Ajoute les alertes au buffer digest."""
    buf = {"last_sent": None, "events": []}
    if os.path.exists(DIGEST_BUFFER_FILE):
        try:
            with open(DIGEST_BUFFER_FILE) as f:
                buf = json.load(f)
        except Exception:
            pass
    if buf.get("last_sent") is None:
        buf["last_sent"] = datetime.now().isoformat()
    for a in alertes:
        buf["events"].append({
            "ts": datetime.now().isoformat(),
            "niveau": a["niveau"],
            "message": a["message"],
        })
    with open(DIGEST_BUFFER_FILE, "w") as f:
        json.dump(buf, f)

def flush_digest_if_ready(mail_cfg, sys_metrics, ssh_fails, top_ips, new_bans):
    """Envoie le digest si l'intervalle est écoulé et qu'il y a des événements."""
    if not os.path.exists(DIGEST_BUFFER_FILE):
        return False
    try:
        with open(DIGEST_BUFFER_FILE) as f:
            buf = json.load(f)
    except Exception:
        return False
    events = buf.get("events", [])
    if not events:
        return False
    last_sent_str = buf.get("last_sent")
    try:
        last_sent = datetime.fromisoformat(last_sent_str)
    except Exception:
        last_sent = datetime.now() - timedelta(hours=999)
    interval_h = int(mail_cfg.get("mail_digest_hours", 4))
    if datetime.now() - last_sent < timedelta(hours=interval_h):
        return False
    # Envoyer le digest
    send_digest_mail(events, sys_metrics, mail_cfg)
    # Réinitialiser le buffer
    with open(DIGEST_BUFFER_FILE, "w") as f:
        json.dump({"last_sent": datetime.now().isoformat(), "events": []}, f)
    return True

def send_digest_mail(events, sys_metrics, mail_cfg):
    """Envoie un email digest regroupant tous les événements accumulés."""
    now = datetime.now()
    hostname = os.uname().nodename
    n = len(events)
    critiques = sum(1 for e in events if e.get("niveau") == "CRITIQUE")
    avertissements = n - critiques
    # Plage de temps couverte
    try:
        ts_start = events[-1]["ts"][:16].replace("T", " ")
        ts_end   = events[0]["ts"][:16].replace("T", " ")
    except Exception:
        ts_start = ts_end = now.strftime("%d/%m %H:%M")

    rows = ""
    for e in events[:50]:
        color = "#ef4444" if e.get("niveau") == "CRITIQUE" else "#f59e0b"
        ts_short = e.get("ts", "")[:16].replace("T", " ")
        rows += (
            f"<tr><td style='padding:6px 8px;border:1px solid #334155;color:#64748b;font-size:11px'>{ts_short}</td>"
            f"<td style='padding:6px 8px;border:1px solid #334155;color:{color};font-weight:bold;font-size:11px'>{e.get('niveau','')}</td>"
            f"<td style='padding:6px 8px;border:1px solid #334155;font-size:12px'>{e.get('message','')}</td></tr>"
        )
    if n > 50:
        rows += f"<tr><td colspan='3' style='padding:6px;text-align:center;color:#64748b;font-size:11px'>… et {n-50} autres événements</td></tr>"

    interval_h = mail_cfg.get("mail_digest_hours", 4)
    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0f172a;font-family:'Segoe UI',sans-serif;color:#e2e8f0">
<div style="max-width:680px;margin:0 auto;padding:24px">
  <div style="background:#1a2744;border-left:4px solid #6366f1;border-radius:10px;padding:20px 24px;margin-bottom:20px">
    <div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.08em">DIGEST SOC — {hostname}</div>
    <div style="font-size:22px;font-weight:800;color:#e2e8f0;margin:6px 0">📬 {n} événement(s) — {interval_h}h</div>
    <div style="font-size:12px;color:#94a3b8">{ts_start} → {ts_end}</div>
    <div style="display:flex;gap:16px;margin-top:12px">
      <span style="background:#7f1d1d;color:#fca5a5;padding:3px 10px;border-radius:5px;font-size:12px">🚨 {critiques} critique(s)</span>
      <span style="background:#78350f;color:#fde68a;padding:3px 10px;border-radius:5px;font-size:12px">⚠️ {avertissements} avertissement(s)</span>
    </div>
  </div>
  <div style="background:#1e293b;border-radius:10px;overflow:hidden;margin-bottom:16px">
    <table style="width:100%;border-collapse:collapse">
      <thead><tr>
        <th style="padding:8px;background:#0f172a;text-align:left;font-size:11px;color:#64748b;border:1px solid #334155">Heure</th>
        <th style="padding:8px;background:#0f172a;text-align:left;font-size:11px;color:#64748b;border:1px solid #334155">Niveau</th>
        <th style="padding:8px;background:#0f172a;text-align:left;font-size:11px;color:#64748b;border:1px solid #334155">Événement</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
  <div style="text-align:center;font-size:10px;color:#334155">ViaDigiTech SOC IA — digest toutes les {interval_h}h · {now.strftime('%d/%m/%Y %H:%M')}</div>
</div></body></html>"""

    subject = f"[SOC Digest] {n} événement(s) sur {interval_h}h — {now.strftime('%d/%m %H:%M')}"
    try:
        msg = MIMEMultipart("alternative")
        msg["From"]    = MAIL_FROM
        msg["To"]      = ", ".join(MAIL_TO)
        msg["Subject"] = subject
        msg.attach(MIMEText(html, "html", "utf-8"))
        with smtplib.SMTP("localhost") as s:
            s.sendmail(MAIL_FROM, MAIL_TO, msg.as_string())
        print(f"[Digest] Mail digest envoyé : {n} événements sur {interval_h}h")
    except Exception as e:
        print(f"[Digest] Erreur envoi digest : {e}")

# ─────────────────────────────────────────
# ANALYSE IA — OLLAMA (alertes temps réel)
# ─────────────────────────────────────────

def ollama_alert_analysis(alertes, sys_metrics, ssh_fails, new_bans, actions):
    """Génère une analyse IA contextuelle pour le mail d'alerte. Retourne du texte HTML-safe."""
    bans_auto = [a for a in actions if a["action"] in ("BAN_AUTO", "DRYRUN_BAN")]
    bans_detail = ", ".join(
        f"{a['ip']} ({a['info'].get('country','?')}, score {a['score']}%)"
        for a in bans_auto[:5]
    ) if bans_auto else "aucun"

    niveaux = [a["niveau"] for a in alertes]
    has_critical = "CRITIQUE" in niveaux

    prompt = f"""IMPORTANT : réponds UNIQUEMENT en français, sans mélanger d'autres langues.

Tu es un analyste SOC. Une alerte vient d'être déclenchée sur le serveur VPS ViaDigiTech. Analyse la situation et donne une réponse courte et opérationnelle.

CONTEXTE DE L'ALERTE :
- Heure : {datetime.now().strftime('%H:%M')}
- Niveau : {"CRITIQUE" if has_critical else "AVERTISSEMENT"}
- Alertes déclenchées : {[a['message'] for a in alertes]}
- CPU actuel : {sys_metrics['cpu']:.1f}%
- RAM actuelle : {sys_metrics['ram']:.1f}%
- Disque : {sys_metrics['disk']:.1f}%
- Tentatives SSH (15 min) : {ssh_fails}
- Nouveaux bans fail2ban (15 min) : {len(new_bans)}
- IPs bannies via AbuseIPDB : {bans_detail}

Réponds en 3 points numérotés, en français :
1. DIAGNOSTIC : que se passe-t-il concrètement ? (1 phrase)
2. RISQUE IMMÉDIAT : quel est le vrai danger si cette alerte est ignorée ?
3. ACTION : une seule commande ou action à faire maintenant (sois précis)

Maximum 100 mots. Pas de formule de politesse."""

    try:
        r = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": "qwen2.5:3b", "prompt": prompt, "stream": False},
            timeout=120
        )
        return r.json().get("response", "").strip()
    except Exception as e:
        return f"[Analyse IA indisponible : {e}]"


# ─────────────────────────────────────────
# ALERTE MAIL
# ─────────────────────────────────────────

def send_alert(alertes, sys_metrics, ssh_fails, top_ips, new_bans, actions=None, ai_analysis=None):
    now = datetime.now()
    hostname = os.uname().nodename
    actions = actions or []

    # Couleur header selon gravité
    has_critical = any(a["niveau"] == "CRITIQUE" for a in alertes)
    header_bg    = "#7f1d1d" if has_critical else "#78350f"
    header_border = "#ef4444" if has_critical else "#f59e0b"
    header_color  = "#fca5a5" if has_critical else "#fde68a"
    icon = "🚨" if has_critical else "⚠️"

    # Lignes alertes
    rows = ""
    for a in alertes:
        color = "#ef4444" if a["niveau"] == "CRITIQUE" else "#f59e0b"
        rows += f"<tr><td style='padding:8px;border:1px solid #334155;color:{color};font-weight:bold;width:120px'>{a['niveau']}</td><td style='padding:8px;border:1px solid #334155'>{a['message']}</td></tr>"

    # Section actions AbuseIPDB
    actions_html = ""
    if actions:
        action_rows = ""
        for a in actions:
            info = a.get("info", {})
            if a["action"] == "BAN_AUTO":
                badge = "<span style='background:#dc2626;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px'>BAN AUTO</span>"
            elif a["action"] == "DRYRUN_BAN":
                badge = "<span style='background:#d97706;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px'>DRY-RUN</span>"
            else:
                badge = "<span style='background:#334155;color:#94a3b8;padding:2px 8px;border-radius:4px;font-size:11px'>SURVEILLE</span>"
            tor = " 🧅 TOR" if info.get("isTor") else ""
            action_rows += f"""<tr>
              <td style='padding:7px;border:1px solid #334155;font-family:monospace;font-size:12px'>{a['ip']}</td>
              <td style='padding:7px;border:1px solid #334155;text-align:center'><b style='color:#f87171'>{a['score']}%</b></td>
              <td style='padding:7px;border:1px solid #334155;font-size:12px'>{info.get('country','?')} — {info.get('isp','?')}{tor}</td>
              <td style='padding:7px;border:1px solid #334155'>{badge}</td>
            </tr>"""
        actions_html = f"""<div class="card">
  <div style="font-weight:bold;color:#a5b4fc;margin-bottom:10px">🔍 Analyse AbuseIPDB</div>
  <table><thead><tr><th>IP</th><th>Score</th><th>Origine</th><th>Action</th></tr></thead>
  <tbody>{action_rows}</tbody></table>
</div>"""

    # Top IPs
    top_ip_rows = ""
    for ip, count in top_ips.most_common(5):
        top_ip_rows += f"<tr><td style='padding:6px;border:1px solid #334155;font-family:monospace;font-size:12px'>{ip}</td><td style='padding:6px;border:1px solid #334155;text-align:right'>{count}</td></tr>"

    bans_str = " &nbsp;·&nbsp; ".join(new_bans[:10]) if new_bans else "Aucun"

    # Audit récent
    audit_rows = ""
    if os.path.exists(AUDIT_LOG):
        with open(AUDIT_LOG) as f:
            lines = f.readlines()[-6:]
        for line in lines[1:]:  # skip header
            parts = line.strip().split(",", 4)
            if len(parts) >= 4:
                ts = parts[0][11:16]  # HH:MM
                audit_rows += f"<tr><td style='padding:5px;border:1px solid #1e2035;color:#64748b;font-size:11px'>{ts}</td><td style='padding:5px;border:1px solid #1e2035;font-family:monospace;font-size:11px'>{parts[1]}</td><td style='padding:5px;border:1px solid #1e2035;font-size:11px'>{parts[2]}</td><td style='padding:5px;border:1px solid #1e2035;font-size:11px'>{parts[3]}%</td></tr>"

    # Bloc analyse IA
    ai_html = ""
    if ai_analysis:
        ai_formatted = ai_analysis.replace("\n", "<br>").replace("  ", "&nbsp;&nbsp;")
        ai_html = f"""<div class="card" style="border-left:3px solid #818cf8">
  <div style="font-weight:bold;color:#a5b4fc;margin-bottom:10px">🤖 Analyse IA · qwen2.5:3b</div>
  <div style="background:#0f1117;border:1px solid #2d3154;border-radius:8px;padding:14px;font-size:13px;line-height:1.75;color:#e2e8f0">{ai_formatted}</div>
</div>"""

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<style>
  body {{ font-family: -apple-system, sans-serif; background: #0f1117; color: #e2e8f0; margin: 0; padding: 16px; }}
  .card {{ background: #1a1f2e; border: 1px solid #2d3154; border-radius: 10px; padding: 18px; margin-bottom: 14px; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
  th {{ background: #1e2035; padding: 8px; border: 1px solid #334155; text-align: left; color: #a5b4fc; font-size: 12px; text-transform: uppercase; letter-spacing: .5px; }}
</style>
</head><body>
<div style="max-width:660px;margin:auto">

<div style="background:{header_bg};border:2px solid {header_border};border-radius:10px;padding:16px;margin-bottom:14px">
  <div style="font-size:17px;font-weight:bold;color:{header_color}">{icon} ALERTE SOC — {hostname}</div>
  <div style="color:{header_color};font-size:12px;margin-top:4px;opacity:.85">{now.strftime('%d/%m/%Y %H:%M:%S')} &nbsp;·&nbsp; {len(alertes)} alerte(s) &nbsp;·&nbsp; mode <b>{"AUTO-BAN" if AUTO_BAN_MODE == "auto" else "DRY-RUN"}</b></div>
</div>

<div class="card">
  <div style="font-weight:bold;color:#a5b4fc;margin-bottom:10px">Alertes</div>
  <table><thead><tr><th style="width:110px">Niveau</th><th>Détail</th></tr></thead>
  <tbody>{rows}</tbody></table>
</div>

{ai_html}

{actions_html}

<div class="card">
  <div style="font-weight:bold;color:#a5b4fc;margin-bottom:10px">Métriques système</div>
  <table><thead><tr><th>Indicateur</th><th>Valeur</th><th>Seuil</th><th>Statut</th></tr></thead>
  <tbody>
    <tr><td style='padding:6px;border:1px solid #334155'>CPU</td><td style='padding:6px;border:1px solid #334155'>{sys_metrics['cpu']:.1f}%</td><td style='padding:6px;border:1px solid #334155'>{SEUILS['cpu_percent']}%</td><td style='padding:6px;border:1px solid #334155;color:{"#ef4444" if sys_metrics["cpu"] >= SEUILS["cpu_percent"] else "#22c55e"}'>{"⚠ Critique" if sys_metrics["cpu"] >= SEUILS["cpu_percent"] else "✓ Normal"}</td></tr>
    <tr><td style='padding:6px;border:1px solid #334155'>RAM</td><td style='padding:6px;border:1px solid #334155'>{sys_metrics['ram']:.1f}%</td><td style='padding:6px;border:1px solid #334155'>{SEUILS['ram_percent']}%</td><td style='padding:6px;border:1px solid #334155;color:{"#ef4444" if sys_metrics["ram"] >= SEUILS["ram_percent"] else "#22c55e"}'>{"⚠ Critique" if sys_metrics["ram"] >= SEUILS["ram_percent"] else "✓ Normal"}</td></tr>
    <tr><td style='padding:6px;border:1px solid #334155'>Disque</td><td style='padding:6px;border:1px solid #334155'>{sys_metrics['disk']:.1f}%</td><td style='padding:6px;border:1px solid #334155'>{SEUILS['disk_percent']}%</td><td style='padding:6px;border:1px solid #334155;color:{"#ef4444" if sys_metrics["disk"] >= SEUILS["disk_percent"] else "#22c55e"}'>{"⚠ Critique" if sys_metrics["disk"] >= SEUILS["disk_percent"] else "✓ Normal"}</td></tr>
    <tr><td style='padding:6px;border:1px solid #334155'>SSH échecs (15min)</td><td style='padding:6px;border:1px solid #334155'>{ssh_fails}</td><td style='padding:6px;border:1px solid #334155'>{SEUILS["ssh_fails"]}</td><td style='padding:6px;border:1px solid #334155;color:{"#ef4444" if ssh_fails >= SEUILS["ssh_fails"] else "#22c55e"}'>{"⚠ Critique" if ssh_fails >= SEUILS["ssh_fails"] else "✓ Normal"}</td></tr>
    <tr><td style='padding:6px;border:1px solid #334155'>Nouveaux bans (15min)</td><td style='padding:6px;border:1px solid #334155'>{len(new_bans)}</td><td style='padding:6px;border:1px solid #334155'>{SEUILS["new_bans"]}</td><td style='padding:6px;border:1px solid #334155;color:{"#ef4444" if len(new_bans) >= SEUILS["new_bans"] else "#22c55e"}'>{"⚠ Critique" if len(new_bans) >= SEUILS["new_bans"] else "✓ Normal"}</td></tr>
  </tbody></table>
</div>

{"" if not top_ips else f'<div class="card"><div style="font-weight:bold;color:#a5b4fc;margin-bottom:10px">Top IPs attaquantes (15min)</div><table><thead><tr><th>IP</th><th style="text-align:right">Tentatives</th></tr></thead><tbody>' + top_ip_rows + '</tbody></table></div>'}

{"" if not new_bans else f'<div class="card"><div style="font-weight:bold;color:#a5b4fc;margin-bottom:6px">Nouveaux bans Fail2Ban (15min)</div><div style="font-size:12px;color:#94a3b8;font-family:monospace;line-height:1.8">{bans_str}</div></div>'}

{("" if not audit_rows else '<div class="card"><div style="font-weight:bold;color:#a5b4fc;margin-bottom:8px">Journal audit (dernières actions)</div><table><thead><tr><th>Heure</th><th>IP</th><th>Action</th><th>Score</th></tr></thead><tbody>' + audit_rows + '</tbody></table></div>')}

<div style="text-align:center;font-size:11px;color:#334155;margin-top:6px;padding-top:10px;border-top:1px solid #1e2035">
  ViaDigiTech AI SecOps · {hostname} · détecteur 15min · AbuseIPDB enrichi
</div>

</div></body></html>"""

    # Sujet adapté au contenu
    bans_auto = sum(1 for a in actions if a["action"] == "BAN_AUTO")
    subject_detail = f"{bans_auto} IP(s) bannies" if bans_auto else f"{len(alertes)} événement(s)"
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"{icon} SOC {hostname} — {subject_detail}"
    msg["From"]    = MAIL_FROM
    msg["To"]      = ", ".join(MAIL_TO)
    msg.attach(MIMEText(html, "html", "utf-8"))
    with smtplib.SMTP("localhost", 25, timeout=15) as s:
        s.sendmail(MAIL_FROM, MAIL_TO, msg.as_string())

# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────

def main():
    now = datetime.now()
    print(f"[{now:%H:%M:%S}] Détection en cours...")

    sys_metrics = get_system()
    ssh_fails, top_ips = get_ssh_fails(WINDOW_MIN)
    new_bans = get_new_bans(WINDOW_MIN)

    alertes = []

    if ssh_fails >= SEUILS["ssh_fails"] and not already_alerted("ssh_fails"):
        alertes.append({"niveau": "CRITIQUE", "message": f"{ssh_fails} tentatives SSH en {WINDOW_MIN} min"})
        mark_alerted("ssh_fails")

    if len(new_bans) >= SEUILS["new_bans"] and not already_alerted("new_bans"):
        alertes.append({"niveau": "CRITIQUE", "message": f"{len(new_bans)} nouvelles IPs bannies en {WINDOW_MIN} min"})
        mark_alerted("new_bans")

    if sys_metrics["cpu"] >= SEUILS["cpu_percent"] and not already_alerted("cpu"):
        alertes.append({"niveau": "AVERTISSEMENT", "message": f"CPU à {sys_metrics['cpu']:.1f}%"})
        mark_alerted("cpu")

    if sys_metrics["ram"] >= SEUILS["ram_percent"] and not already_alerted("ram"):
        alertes.append({"niveau": "AVERTISSEMENT", "message": f"RAM à {sys_metrics['ram']:.1f}%"})
        mark_alerted("ram")

    if sys_metrics["disk"] >= SEUILS["disk_percent"] and not already_alerted("disk"):
        alertes.append({"niveau": "CRITIQUE", "message": f"Disque à {sys_metrics['disk']:.1f}% — intervention requise"})
        mark_alerted("disk")

    # Enrichissement AbuseIPDB sur les top IPs attaquantes
    actions = []
    if top_ips and ABUSEIPDB_KEY:
        print(f"[{now:%H:%M:%S}] Vérification AbuseIPDB ({len(top_ips)} IPs)...")
        actions = enrich_and_act(top_ips)
        bans_auto = [a for a in actions if a["action"] in ("BAN_AUTO", "DRYRUN_BAN")]
        # Dédup bans_auto : 1 seul mail d'alerte par heure pour les auto-bans
        if bans_auto and not already_alerted("bans_auto_batch", minutes=60):
            mark_alerted("bans_auto_batch")
            for a in bans_auto:
                niveau = "CRITIQUE" if a["action"] == "BAN_AUTO" else "AVERTISSEMENT"
                label = "Banni automatiquement" if a["action"] == "BAN_AUTO" else "Ban recommandé (dry-run)"
                alertes.append({
                    "niveau": niveau,
                    "message": f"{a['ip']} — score AbuseIPDB {a['score']}% — {label} ({a['info']['country']}, {a['info']['isp']})"
                })

    if alertes:
        # Filtre notif_level depuis soc_config.json
        notif_level = "all"
        mail_cfg = load_mail_config()
        try:
            with open("/home/ubuntu/secops/soc_config.json") as _f:
                notif_level = json.load(_f).get("notif_level", "all")
        except Exception:
            pass
        critiques = [a for a in alertes if a["niveau"] == "CRITIQUE"]
        if notif_level == "critical":
            alertes_to_send = [a for a in alertes if a["niveau"] == "CRITIQUE"]
        elif notif_level == "multi":
            alertes_to_send = alertes if len(alertes) >= 2 else []
        else:
            alertes_to_send = alertes

        if alertes_to_send:
            # Vérifier les types d'alertes activés
            alert_types = _alert_type(alertes_to_send, actions)
            mail_enabled = is_mail_type_enabled(mail_cfg, alert_types)
            mail_mode = mail_cfg.get("mail_mode", "immediate")

            if not mail_enabled:
                print(f"[{now:%H:%M:%S}] {len(alertes_to_send)} alerte(s) → type désactivé dans config mail")
            elif mail_mode == "digest":
                append_to_digest(alertes_to_send, actions, sys_metrics)
                flushed = flush_digest_if_ready(mail_cfg, sys_metrics, ssh_fails, top_ips, new_bans)
                if not flushed:
                    buf_count = 0
                    try:
                        with open(DIGEST_BUFFER_FILE) as _bf:
                            buf_count = len(json.load(_bf).get("events", []))
                    except Exception:
                        pass
                    print(f"[{now:%H:%M:%S}] {len(alertes_to_send)} alerte(s) → mode digest, buffer={buf_count} événements")
            else:
                if is_report_running():
                    print(f"[{now:%H:%M:%S}] {len(alertes_to_send)} alerte(s) → report.py actif, analyse IA skippée (contention CPU)")
                    ai_analysis = None
                else:
                    print(f"[{now:%H:%M:%S}] {len(alertes_to_send)} alerte(s) → analyse IA + envoi mail...")
                    ai_analysis = ollama_alert_analysis(alertes_to_send, sys_metrics, ssh_fails, new_bans, actions)
                send_alert(alertes_to_send, sys_metrics, ssh_fails, top_ips, new_bans, actions, ai_analysis)
                print(f"[{now:%H:%M:%S}] Alerte envoyée à {MAIL_TO}")
        else:
            print(f"[{now:%H:%M:%S}] {len(alertes)} alerte(s) filtrée(s) (niveau: {notif_level})")
        # Telegram toujours sur les critiques, indépendamment du filtre mail
        if critiques:
            hostname = os.uname().nodename
            msg_lines = [f"⚠️ <b>ALERTE SOC — {hostname}</b>"]
            for a in critiques:
                msg_lines.append(f"• {a['message']}")
            msg_lines.append(f"CPU: {sys_metrics['cpu']:.1f}% | RAM: {sys_metrics['ram']:.1f}% | Disk: {sys_metrics['disk']:.1f}%")
            send_telegram("\n".join(msg_lines))
    else:
        # En mode digest, vérifier si un flush est dû même sans nouvelles alertes
        mail_cfg = load_mail_config()
        if mail_cfg.get("mail_mode") == "digest":
            flush_digest_if_ready(mail_cfg, sys_metrics, ssh_fails, top_ips, new_bans)
        print(f"[{now:%H:%M:%S}] Aucune alerte. CPU:{sys_metrics['cpu']:.1f}% RAM:{sys_metrics['ram']:.1f}% Disk:{sys_metrics['disk']:.1f}% SSH:{ssh_fails} Bans:{len(new_bans)}")

    check_subnet_auto_ban()
    check_low_slow()
    check_composite_threshold()
    flush_telegram_digest()

def check_subnet_auto_ban():
    """Ban automatique d'un /24 si ≥ N IPs distinctes bannies dans la dernière heure."""
    try:
        with open("/home/ubuntu/secops/soc_config.json") as f:
            cfg = json.load(f)
        enabled   = cfg.get("subnet_ban_enabled", False)
        threshold = int(cfg.get("subnet_ban_threshold", 3))
    except Exception:
        return

    if not enabled:
        return

    since = datetime.now() - timedelta(hours=1)
    subnet_ips = defaultdict(set)

    if os.path.exists(AUDIT_LOG):
        with open(AUDIT_LOG) as f:
            for line in f:
                if line.startswith("timestamp"):
                    continue
                parts = line.strip().split(",", 4)
                if len(parts) < 3:
                    continue
                if "BAN_AUTO" not in parts[2] and "BAN_OLLAMA" not in parts[2]:
                    continue
                try:
                    ts = datetime.strptime(parts[0][:19], "%Y-%m-%d %H:%M:%S")
                    if ts < since:
                        continue
                except Exception:
                    continue
                ip = parts[1].strip()
                ip_parts = ip.split(".")
                if len(ip_parts) == 4:
                    subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                    subnet_ips[subnet].add(ip)

    for subnet, ips in subnet_ips.items():
        if len(ips) < threshold:
            continue
        key = f"subnet_ban_{subnet}"
        if already_alerted(key, minutes=360):
            continue
        try:
            result = subprocess.run(
                ["sudo", "fail2ban-client", "set", "sshd", "banip", subnet],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                top5 = ", ".join(sorted(ips)[:5])
                write_audit(subnet, "BAN_SUBNET24", 100,
                            f"{len(ips)} IPs distinctes en 1h: {top5}")
                mark_alerted(key)
                print(f"[BanSubnet] {subnet} → BAN_SUBNET24 ({len(ips)} IPs: {top5})")
                hostname = os.uname().nodename
                send_telegram(f"🚨 <b>BAN /24</b>\nBloc: <code>{subnet}</code>\n{len(ips)} IPs distinctes bannies en 1h\nServeur: {hostname}")
            else:
                print(f"[BanSubnet] {subnet} → échec: {result.stderr.strip()}")
        except Exception as e:
            print(f"[BanSubnet] Erreur pour {subnet}: {e}")

def check_low_slow():
    """Détecte les attaques SSH étalées sur 24h sous le radar Fail2Ban (10-200 tentatives)."""
    LOW_SLOW_MIN   = 10
    LOW_SLOW_MAX   = 200
    DEDUP_MIN      = 360   # 6h entre deux alertes pour la même IP

    _, ips_24h = get_ssh_fails(24 * 60)
    if not ips_24h:
        return

    try:
        banned_out = subprocess.run(
            ["sudo", "fail2ban-client", "status", "sshd"],
            capture_output=True, text=True, timeout=5
        ).stdout
        banned_now = set()
        for line in banned_out.splitlines():
            if "Banned IP list" in line:
                banned_now = set(line.split(":")[-1].split())
                break
    except Exception:
        banned_now = set()

    suspects = []
    for ip, count in ips_24h.items():
        if count < LOW_SLOW_MIN or count > LOW_SLOW_MAX:
            continue
        if ip in WHITELIST or ip in banned_now:
            continue
        key = f"lowslow_{ip}"
        if already_alerted(key, minutes=DEDUP_MIN):
            continue
        mark_alerted(key)
        suspects.append({"ip": ip, "count": count})

    if not suspects:
        return

    now = datetime.now()
    print(f"[{now:%H:%M:%S}] Low&Slow: {len(suspects)} IP(s) suspectes sur 24h")

    for s in suspects:
        write_audit(s["ip"], "LOW_SLOW", 30,
                    f"Low&Slow: {s['count']} tentatives SSH en 24h sous le radar Fail2Ban")

    top3 = sorted(suspects, key=lambda x: x["count"], reverse=True)[:3]
    lines = "\n".join(f"• <code>{s['ip']}</code> — {s['count']} tentatives" for s in top3)
    hostname = os.uname().nodename
    send_telegram(
        f"🐢 <b>ATTAQUE LOW&SLOW</b>\n"
        f"{len(suspects)} IP(s) sous le radar Fail2Ban (24h)\n"
        f"{lines}\n"
        f"Serveur: {hostname}"
    )


def check_composite_threshold():
    """F18 — Alerte si le score composite moyen des dernières 24h dépasse le seuil configuré."""
    try:
        with open("/home/ubuntu/secops/soc_config.json") as f:
            cfg = json.load(f)
        threshold = int(cfg.get("composite_avg_threshold", 0))
    except Exception:
        return
    if threshold <= 0 or not DB_AVAILABLE:
        return

    stats = db_get_stats(hours=24)
    avg = stats.get("avg_score", 0)
    if avg < threshold:
        return

    # Déduplication : une alerte max par heure
    if os.path.exists(THRESHOLD_ALERT_FILE):
        try:
            with open(THRESHOLD_ALERT_FILE) as f:
                last = datetime.fromisoformat(json.load(f).get("last_alert", "2000-01-01"))
            if (datetime.now() - last).total_seconds() < 3600:
                return
        except Exception:
            pass

    hostname = os.uname().nodename
    msg = (
        f"📊 <b>ALERTE SEUIL COMPOSITE</b>\n"
        f"Score moyen 24h : <b>{avg:.1f}%</b> (seuil : {threshold}%)\n"
        f"Bans : {stats['total_bans']} | Serveur : {hostname}"
    )
    _telegram_post(msg)
    print(f"[ThresholdAlert] Score moyen {avg:.1f}% > seuil {threshold}%")
    with open(THRESHOLD_ALERT_FILE, "w") as f:
        json.dump({"last_alert": datetime.now().isoformat()}, f)


if __name__ == "__main__":
    main()
