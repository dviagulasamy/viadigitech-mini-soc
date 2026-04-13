#!/usr/bin/env python3
"""
ViaDigiTech SOC — Détecteur d'alertes temps réel (toutes les 15 min)
Vérifie les seuils critiques et envoie un mail d'alerte si dépassement.
"""

import os
import re
import json
import smtplib

import subprocess
import psutil
import requests
from datetime import datetime, timedelta
from collections import Counter
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# ─────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────
MAIL_FROM        = os.environ.get("SOC_MAIL_FROM", "secops@localhost")
MAIL_TO          = os.environ.get("SOC_MAIL_TO", "admin@example.com").split(",")
ABUSEIPDB_KEY    = os.environ.get("ABUSEIPDB_KEY", "")
AUTH_LOG         = "/var/log/auth.log"
STATE_FILE       = "/tmp/soc_detector_state.txt"
AUDIT_LOG        = "/home/ubuntu/secops/audit_actions.csv"
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

# Whitelist IP — jamais alertées
WHITELIST = ["176.134.132.129"]

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
    """Enregistre l'action dans le log d'audit CSV."""
    os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
    header = not os.path.exists(AUDIT_LOG)
    with open(AUDIT_LOG, "a") as f:
        if header:
            f.write("timestamp,ip,action,score,reason\n")
        f.write(f"{datetime.now().isoformat()},{ip},{action},{score},{reason}\n")

def ollama_decide(ip, attempts, info):
    """
    Interroge qwen2.5:3b pour une décision sur une IP en zone grise (score 40-79%).
    Retourne {"action": "BAN"|"SURVEILLE"|"IGNORE", "raison": "...", "urgence": "..."}
    """
    prompt = (
        f"Tu es un analyste SOC. Réponds UNIQUEMENT en JSON valide, sans texte autour.\n"
        f"Contexte:\n"
        f"- IP: {ip}\n"
        f"- Tentatives SSH en 15min: {attempts}\n"
        f"- Score AbuseIPDB: {info['score']}%\n"
        f"- Pays: {info['country']}, FAI: {info['isp']}\n"
        f"- Nœud TOR: {info['isTor']}\n"
        f"- Signalements totaux: {info['reports']}\n"
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

def enrich_and_act(top_ips):
    """Vérifie les top IPs sur AbuseIPDB et agit selon le mode + Ollama pour zone grise."""
    actions = []
    for ip, attempts in top_ips.most_common(5):
        info = check_abuseipdb(ip)
        if not info:
            continue
        score = info["score"]
        reason = f"{attempts} tentatives, score {score}%, {info['country']}, {info['isp']}"

        if score >= AUTO_BAN_SCORE:
            # Score élevé → ban direct
            if AUTO_BAN_MODE == "auto":
                success = ban_ip_fail2ban(ip)
                action = "BAN_AUTO" if success else "BAN_ECHEC"
            else:
                action = "DRYRUN_BAN"
            write_audit(ip, action, score, reason)
            actions.append({"ip": ip, "action": action, "score": score, "info": info, "reason": reason})
            print(f"[{'AutoBan' if AUTO_BAN_MODE == 'auto' else 'DryRun'}] {ip} — score {score}% → {action}")

        elif score >= 40:
            # Zone grise → Ollama décide (sauf si report.py tourne)
            if is_report_running():
                print(f"[Ollama] Zone grise {ip} — report.py actif, décision différée")
                decision = {"action": "SURVEILLE", "raison": "Décision différée (report.py actif)", "urgence": "faible"}
            else:
                print(f"[Ollama] Zone grise {ip} (score {score}%) — consultation qwen2.5:3b...")
                decision = ollama_decide(ip, attempts, info)
            ollama_action = decision.get("action", "SURVEILLE")
            ollama_raison = decision.get("raison", "")
            ollama_urgence = decision.get("urgence", "faible")
            reason_full = f"{reason} | Ollama: {ollama_raison} (urgence: {ollama_urgence})"

            if ollama_action == "BAN" and AUTO_BAN_MODE == "auto":
                success = ban_ip_fail2ban(ip)
                action = f"BAN_OLLAMA" if success else "BAN_ECHEC"
            else:
                action = f"OLLAMA_{ollama_action}"

            write_audit(ip, action, score, reason_full)
            actions.append({
                "ip": ip, "action": action, "score": score,
                "info": info, "reason": reason_full,
                "ollama": decision
            })
            print(f"[Ollama] {ip} → {action} ({ollama_raison})")

        else:
            actions.append({"ip": ip, "action": "SURVEILLE", "score": score, "info": info, "reason": reason})

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
        if is_report_running():
            print(f"[{now:%H:%M:%S}] {len(alertes)} alerte(s) → report.py actif, analyse IA skippée (contention CPU)")
            ai_analysis = None
        else:
            print(f"[{now:%H:%M:%S}] {len(alertes)} alerte(s) → analyse IA + envoi mail...")
            ai_analysis = ollama_alert_analysis(alertes, sys_metrics, ssh_fails, new_bans, actions)
        send_alert(alertes, sys_metrics, ssh_fails, top_ips, new_bans, actions, ai_analysis)
        print(f"[{now:%H:%M:%S}] Alerte envoyée à {MAIL_TO}")
    else:
        print(f"[{now:%H:%M:%S}] Aucune alerte. CPU:{sys_metrics['cpu']:.1f}% RAM:{sys_metrics['ram']:.1f}% Disk:{sys_metrics['disk']:.1f}% SSH:{ssh_fails} Bans:{len(new_bans)}")

if __name__ == "__main__":
    main()
