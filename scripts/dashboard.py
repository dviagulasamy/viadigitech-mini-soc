#!/usr/bin/env python3
"""
ViaDigiTech SOC — Génération du dashboard HTML temps réel
Exécuté toutes les 15 min via cron, servi par Caddy.
"""

import os
import json
import subprocess
from datetime import datetime, timedelta
from collections import Counter
import re
import psutil

OUTPUT_FILE  = "/var/www/html/viadigitech-reports/soc/index.html"
AUDIT_LOG    = "/home/ubuntu/secops/audit_actions.csv"
DETECTOR_LOG = "/home/ubuntu/secops/detector.log"
AUTH_LOG     = "/var/log/auth.log"

os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

# ─────────────────────────────────────────
# COLLECTE
# ─────────────────────────────────────────

def run(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except:
        return ""

def get_metrics():
    cpu  = psutil.cpu_percent(interval=1)
    mem  = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    return {"cpu": cpu, "ram": mem.percent, "disk": disk.percent,
            "ram_used": round(mem.used/1e9,1), "ram_total": round(mem.total/1e9,1),
            "disk_used": round(disk.used/1e9,1), "disk_total": round(disk.total/1e9,1)}

def get_banned_ips():
    out = run("sudo fail2ban-client status sshd")
    count, ips = 0, []
    for line in out.splitlines():
        if "Currently banned" in line:
            try: count = int(line.split(":")[-1].strip())
            except: pass
        if "Banned IP list" in line:
            ips = line.split(":")[-1].strip().split()
    return count, ips

def get_ssh_stats(hours=24):
    since = datetime.now() - timedelta(hours=hours)
    fails = Counter()
    total = 0
    if not os.path.exists(AUTH_LOG):
        return total, fails
    with open(AUTH_LOG, errors="ignore") as f:
        lines = f.readlines()[-15000:]
    year = datetime.now().year
    for line in lines:
        if "Failed password" not in line and "Invalid user" not in line:
            continue
        try:
            ts = datetime.strptime(line[:15] + f" {year}", "%b %d %H:%M:%S %Y")
        except:
            continue
        if ts >= since:
            total += 1
            m = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", line)
            if m: fails[m.group(1)] += 1
    return total, fails

def get_audit_recent(n=15):
    if not os.path.exists(AUDIT_LOG):
        return []
    with open(AUDIT_LOG) as f:
        lines = f.readlines()
    rows = []
    for line in reversed(lines[1:]):
        parts = line.strip().split(",", 4)
        if len(parts) >= 4:
            rows.append(parts)
        if len(rows) >= n:
            break
    return rows

def get_detector_log(n=8):
    if not os.path.exists(DETECTOR_LOG):
        return []
    with open(DETECTOR_LOG) as f:
        return f.readlines()[-n:]

def get_docker_containers():
    out = run("sudo docker ps --format '{{json .}}'")
    containers = []
    for line in out.splitlines():
        try: containers.append(json.loads(line.strip()))
        except: pass
    return containers

# ─────────────────────────────────────────
# GÉNÉRATION HTML
# ─────────────────────────────────────────

def gauge_color(val, warn=75, crit=90):
    if val >= crit: return "#ef4444"
    if val >= warn: return "#f59e0b"
    return "#22c55e"

def build_html():
    now        = datetime.now()
    metrics    = get_metrics()
    ban_count, banned_ips = get_banned_ips()
    ssh_total, ssh_fails  = get_ssh_stats(24)
    audit_rows = get_audit_recent(15)
    det_log    = get_detector_log(8)
    containers = get_docker_containers()
    hostname   = os.uname().nodename

    # Jauges métriques
    def gauge(label, val, unit="%", warn=75, crit=90):
        color = gauge_color(val, warn, crit)
        return f"""<div class="gauge">
          <div class="gauge-label">{label}</div>
          <div class="gauge-val" style="color:{color}">{val:.1f}{unit}</div>
          <div class="gauge-bar"><div style="width:{min(val,100):.0f}%;background:{color};height:6px;border-radius:3px;transition:width .5s"></div></div>
        </div>"""

    gauges = (gauge("CPU", metrics["cpu"]) +
              gauge("RAM", metrics["ram"]) +
              gauge("Disque", metrics["disk"]))

    # Top IPs attaquantes
    top_ip_rows = ""
    for ip, count in ssh_fails.most_common(10):
        is_banned = "🔴" if ip in banned_ips else "🟡"
        top_ip_rows += f"<tr><td>{is_banned} {ip}</td><td style='text-align:right'>{count}</td></tr>"

    # Audit récent
    audit_html = ""
    for row in audit_rows:
        ts = row[0][11:16] if len(row[0]) > 11 else row[0]
        ip, action, score = row[1], row[2], row[3]
        if "BAN_AUTO" in action or "BAN_OLLAMA" in action:
            badge = f"<span style='background:#dc2626;color:#fff;padding:2px 7px;border-radius:4px;font-size:11px'>{action}</span>"
        elif "DRYRUN" in action:
            badge = f"<span style='background:#d97706;color:#fff;padding:2px 7px;border-radius:4px;font-size:11px'>{action}</span>"
        elif "OLLAMA" in action:
            badge = f"<span style='background:#7c3aed;color:#fff;padding:2px 7px;border-radius:4px;font-size:11px'>{action}</span>"
        else:
            badge = f"<span style='background:#334155;color:#94a3b8;padding:2px 7px;border-radius:4px;font-size:11px'>{action}</span>"
        audit_html += f"<tr><td style='color:#64748b;font-size:11px'>{ts}</td><td style='font-family:monospace;font-size:12px'>{ip}</td><td>{badge}</td><td style='text-align:right;color:#f59e0b'>{score}%</td></tr>"

    # Containers Docker
    containers_html = ""
    for c in containers[:8]:
        name   = c.get("Names","?")[:25]
        status = c.get("Status","?")[:20]
        color  = "#22c55e" if "Up" in status else "#ef4444"
        containers_html += f"""<div class="container-card">
          <div style="font-weight:600;color:#a5b4fc;font-size:12px">{name}</div>
          <div style="font-size:11px;color:{color};margin-top:3px">● {status}</div>
        </div>"""

    # Log détecteur
    det_html = "".join(f"<div style='font-size:11px;color:#64748b;line-height:1.6'>{l.strip()}</div>" for l in det_log)

    # Bannies récentes (5 dernières)
    recent_bans = banned_ips[-5:] if banned_ips else []
    bans_html = " &nbsp;·&nbsp; ".join(f"<code style='font-size:11px;color:#f87171'>{ip}</code>" for ip in recent_bans) or "<span style='color:#22c55e'>Aucune récente</span>"

    html = f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="300">
<title>SOC Dashboard — {hostname}</title>
<style>
  * {{ box-sizing:border-box; margin:0; padding:0 }}
  body {{ font-family:-apple-system,sans-serif; background:#0a0d14; color:#e2e8f0; padding:16px }}
  h2 {{ font-size:11px; text-transform:uppercase; letter-spacing:1.5px; color:#475569; margin-bottom:12px; font-weight:600 }}
  .grid {{ display:grid; gap:14px }}
  .g2 {{ grid-template-columns:repeat(2,1fr) }}
  .g3 {{ grid-template-columns:repeat(3,1fr) }}
  .g4 {{ grid-template-columns:repeat(4,1fr) }}
  @media(max-width:768px){{ .g2,.g3,.g4 {{ grid-template-columns:1fr }} }}
  .card {{ background:#111827; border:1px solid #1e2942; border-radius:12px; padding:16px }}
  .stat-big {{ font-size:28px; font-weight:700; line-height:1 }}
  .stat-label {{ font-size:11px; color:#64748b; margin-top:4px }}
  table {{ width:100%; border-collapse:collapse; font-size:13px }}
  td,th {{ padding:7px 8px; border-bottom:1px solid #1e2942 }}
  th {{ color:#64748b; font-size:11px; text-transform:uppercase; font-weight:600 }}
  .gauge {{ margin-bottom:14px }}
  .gauge-label {{ font-size:11px; color:#64748b; margin-bottom:3px }}
  .gauge-val {{ font-size:22px; font-weight:700; margin-bottom:5px }}
  .gauge-bar {{ background:#1e2942; border-radius:3px; overflow:hidden; height:6px }}
  .container-card {{ background:#0f1623; border:1px solid #1e2942; border-radius:8px; padding:10px; margin-bottom:8px }}
  .header-bar {{ background:linear-gradient(135deg,#1e1b4b,#0f172a); border:1px solid #312e81; border-radius:12px; padding:16px 20px; margin-bottom:16px; display:flex; justify-content:space-between; align-items:center }}
</style>
</head><body>

<div class="header-bar">
  <div>
    <div style="font-size:16px;font-weight:700;color:#a5b4fc">🛡️ ViaDigiTech SOC Dashboard</div>
    <div style="font-size:11px;color:#475569;margin-top:3px">{hostname} · Mis à jour : {now.strftime('%d/%m/%Y %H:%M:%S')} · Actualisation auto 5 min</div>
  </div>
  <div style="text-align:right">
    <div style="font-size:11px;color:#64748b">SSH échecs 24h</div>
    <div style="font-size:22px;font-weight:700;color:{'#ef4444' if ssh_total > 100 else '#f59e0b' if ssh_total > 20 else '#22c55e'}">{ssh_total}</div>
  </div>
</div>

<!-- Stat cards -->
<div class="grid g4" style="margin-bottom:14px">
  <div class="card">
    <div class="stat-big" style="color:#ef4444">{ban_count}</div>
    <div class="stat-label">IPs bannies (total)</div>
  </div>
  <div class="card">
    <div class="stat-big" style="color:#f59e0b">{ssh_total}</div>
    <div class="stat-label">Échecs SSH 24h</div>
  </div>
  <div class="card">
    <div class="stat-big" style="color:{gauge_color(metrics['ram'])}">{metrics['ram']:.0f}%</div>
    <div class="stat-label">RAM ({metrics['ram_used']}GB / {metrics['ram_total']}GB)</div>
  </div>
  <div class="card">
    <div class="stat-big" style="color:{gauge_color(metrics['disk'])}">{metrics['disk']:.0f}%</div>
    <div class="stat-label">Disque ({metrics['disk_used']}GB / {metrics['disk_total']}GB)</div>
  </div>
</div>

<div class="grid g2" style="margin-bottom:14px">
  <!-- Métriques système -->
  <div class="card">
    <h2>Métriques système</h2>
    {gauges}
  </div>
  <!-- Conteneurs Docker -->
  <div class="card">
    <h2>Conteneurs Docker ({len(containers)})</h2>
    {containers_html or '<div style="color:#475569;font-size:13px">Aucun container actif</div>'}
  </div>
</div>

<div class="grid g2" style="margin-bottom:14px">
  <!-- Top IPs attaquantes -->
  <div class="card">
    <h2>Top IPs attaquantes 24h</h2>
    {"<div style='color:#475569;font-size:13px'>Aucune activité détectée</div>" if not top_ip_rows else f"<table><thead><tr><th>IP</th><th style='text-align:right'>Tentatives</th></tr></thead><tbody>{top_ip_rows}</tbody></table>"}
  </div>
  <!-- Journal d'audit -->
  <div class="card">
    <h2>Journal d'audit (dernières actions)</h2>
    {"<div style='color:#475569;font-size:13px'>Aucune action enregistrée</div>" if not audit_html else f"<table><thead><tr><th>Heure</th><th>IP</th><th>Action</th><th style='text-align:right'>Score</th></tr></thead><tbody>{audit_html}</tbody></table>"}
  </div>
</div>

<!-- Bans récents + log détecteur -->
<div class="grid g2">
  <div class="card">
    <h2>Dernières IPs bannies</h2>
    <div style="line-height:2">{bans_html}</div>
  </div>
  <div class="card">
    <h2>Log détecteur (temps réel)</h2>
    {det_html or '<div style="color:#475569;font-size:13px">Aucun log disponible</div>'}
  </div>
</div>

</body></html>"""
    return html

# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────

if __name__ == "__main__":
    html = build_html()
    with open(OUTPUT_FILE, "w") as f:
        f.write(html)
    print(f"[{datetime.now():%H:%M:%S}] Dashboard généré → {OUTPUT_FILE}")
