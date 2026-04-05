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
AUTO_BAN_MODE    = "dryrun"
AUTO_BAN_SCORE   = 80    # score AbuseIPDB minimum pour ban auto

# Seuils d'alerte
SEUILS = {
    "ssh_fails":    20,    # tentatives SSH en 15 min
    "new_bans":      5,    # nouveaux bans Fail2Ban en 15 min
    "cpu_percent":  90,    # CPU %
    "ram_percent":  90,    # RAM %
    "disk_percent": 90,    # Disque %
}

# Whitelist IP — jamais alertées
WHITELIST = []

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
            ["fail2ban-client", "set", jail, "banip", ip],
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

def enrich_and_act(top_ips):
    """Vérifie les top IPs sur AbuseIPDB et agit selon le mode."""
    actions = []
    for ip, attempts in top_ips.most_common(5):
        info = check_abuseipdb(ip)
        if not info:
            continue
        score = info["score"]
        reason = f"{attempts} tentatives, score {score}%, {info['country']}, {info['isp']}"
        if score >= AUTO_BAN_SCORE:
            if AUTO_BAN_MODE == "auto":
                success = ban_ip_fail2ban(ip)
                action = "BAN_AUTO" if success else "BAN_ECHEC"
                write_audit(ip, action, score, reason)
                actions.append({"ip": ip, "action": action, "score": score, "info": info, "reason": reason})
                print(f"[AutoBan] {ip} — score {score}% → {action}")
            else:  # dryrun
                write_audit(ip, "DRYRUN_BAN", score, reason)
                actions.append({"ip": ip, "action": "DRYRUN_BAN", "score": score, "info": info, "reason": reason})
                print(f"[DryRun] {ip} — score {score}% → ban recommandé (mode dryrun)")
        else:
            actions.append({"ip": ip, "action": "SURVEILLE", "score": score, "info": info, "reason": reason})
    return actions

# ─────────────────────────────────────────
# DÉDUPLICATION — évite les alertes répétitives
# ─────────────────────────────────────────

def already_alerted(key):
    """Retourne True si une alerte pour cette clé a été envoyée il y a moins de 30 min."""
    if not os.path.exists(STATE_FILE):
        return False
    with open(STATE_FILE, "r") as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) == 2 and parts[0] == key:
                try:
                    ts = datetime.fromisoformat(parts[1])
                    if datetime.now() - ts < timedelta(minutes=30):
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
# ALERTE MAIL
# ─────────────────────────────────────────

def send_alert(alertes, sys_metrics, ssh_fails, top_ips, new_bans):
    now = datetime.now()
    hostname = os.uname().nodename

    rows = ""
    for a in alertes:
        rows += f"<tr><td style='padding:8px;border:1px solid #ef4444;color:#ef4444;font-weight:bold'>{a['niveau']}</td><td style='padding:8px;border:1px solid #334155'>{a['message']}</td></tr>"

    top_ip_rows = ""
    for ip, count in top_ips.most_common(5):
        top_ip_rows += f"<tr><td style='padding:6px;border:1px solid #334155'>{ip}</td><td style='padding:6px;border:1px solid #334155;text-align:right'>{count}</td></tr>"

    bans_str = ", ".join(new_bans[:10]) if new_bans else "Aucun"

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<style>
  body {{ font-family: sans-serif; background: #0f1117; color: #e2e8f0; margin: 0; padding: 20px; }}
  .card {{ background: #1a1f2e; border: 1px solid #2d3154; border-radius: 10px; padding: 20px; margin-bottom: 16px; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th {{ background: #1e2035; padding: 8px; border: 1px solid #334155; text-align: left; color: #a5b4fc; }}
</style>
</head><body>
<div style="max-width:640px;margin:auto">

<div style="background:#7f1d1d;border:2px solid #ef4444;border-radius:10px;padding:16px;margin-bottom:16px">
  <div style="font-size:18px;font-weight:bold;color:#fca5a5">🚨 ALERTE SOC — {hostname}</div>
  <div style="color:#fca5a5;font-size:13px">{now.strftime('%d/%m/%Y %H:%M:%S')} — {len(alertes)} alerte(s) détectée(s)</div>
</div>

<div class="card">
  <div style="font-weight:bold;color:#a5b4fc;margin-bottom:10px">Alertes actives</div>
  <table><thead><tr><th>Niveau</th><th>Détail</th></tr></thead>
  <tbody>{rows}</tbody></table>
</div>

<div class="card">
  <div style="font-weight:bold;color:#a5b4fc;margin-bottom:10px">Métriques système</div>
  <table><thead><tr><th>Indicateur</th><th>Valeur</th><th>Seuil</th></tr></thead>
  <tbody>
    <tr><td style='padding:6px;border:1px solid #334155'>CPU</td><td style='padding:6px;border:1px solid #334155'>{sys_metrics['cpu']:.1f}%</td><td style='padding:6px;border:1px solid #334155'>{SEUILS['cpu_percent']}%</td></tr>
    <tr><td style='padding:6px;border:1px solid #334155'>RAM</td><td style='padding:6px;border:1px solid #334155'>{sys_metrics['ram']:.1f}%</td><td style='padding:6px;border:1px solid #334155'>{SEUILS['ram_percent']}%</td></tr>
    <tr><td style='padding:6px;border:1px solid #334155'>Disque</td><td style='padding:6px;border:1px solid #334155'>{sys_metrics['disk']:.1f}%</td><td style='padding:6px;border:1px solid #334155'>{SEUILS['disk_percent']}%</td></tr>
    <tr><td style='padding:6px;border:1px solid #334155'>SSH échecs (15min)</td><td style='padding:6px;border:1px solid #334155'>{ssh_fails}</td><td style='padding:6px;border:1px solid #334155'>{SEUILS['ssh_fails']}</td></tr>
    <tr><td style='padding:6px;border:1px solid #334155'>Nouveaux bans (15min)</td><td style='padding:6px;border:1px solid #334155'>{len(new_bans)}</td><td style='padding:6px;border:1px solid #334155'>{SEUILS['new_bans']}</td></tr>
  </tbody></table>
</div>

{"" if not top_ips else f'''<div class="card">
  <div style="font-weight:bold;color:#a5b4fc;margin-bottom:10px">Top IPs attaquantes (15min)</div>
  <table><thead><tr><th>IP</th><th style="text-align:right">Tentatives</th></tr></thead>
  <tbody>{top_ip_rows}</tbody></table>
</div>'''}

<div class="card">
  <div style="font-weight:bold;color:#a5b4fc;margin-bottom:6px">Nouveaux bans Fail2Ban</div>
  <div style="font-size:13px;color:#94a3b8">{bans_str}</div>
</div>

<div style="text-align:center;font-size:11px;color:#334155;margin-top:8px">
  AI SecOps · {hostname} · détecteur 15min
</div>
</div></body></html>"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"🚨 SOC ALERTE — {len(alertes)} événement(s) sur {hostname}"
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
        if bans_auto:
            for a in bans_auto:
                niveau = "CRITIQUE" if a["action"] == "BAN_AUTO" else "AVERTISSEMENT"
                label = "Banni automatiquement" if a["action"] == "BAN_AUTO" else "Ban recommandé (dry-run)"
                alertes.append({
                    "niveau": niveau,
                    "message": f"{a['ip']} — score AbuseIPDB {a['score']}% — {label} ({a['info']['country']}, {a['info']['isp']})"
                })

    if alertes:
        print(f"[{now:%H:%M:%S}] {len(alertes)} alerte(s) → envoi mail...")
        send_alert(alertes, sys_metrics, ssh_fails, top_ips, new_bans)
        print(f"[{now:%H:%M:%S}] Alerte envoyée à {MAIL_TO}")
    else:
        print(f"[{now:%H:%M:%S}] Aucune alerte. CPU:{sys_metrics['cpu']:.1f}% RAM:{sys_metrics['ram']:.1f}% Disk:{sys_metrics['disk']:.1f}% SSH:{ssh_fails} Bans:{len(new_bans)}")

if __name__ == "__main__":
    main()
