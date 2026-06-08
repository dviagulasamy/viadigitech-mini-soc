#!/usr/bin/env python3
"""
ViaDigiTech SOC — Rapport hebdomadaire (7 jours)
Exécuté chaque lundi à 7h via cron.
Génère un rapport HTML sur 7 jours + comparatif J-7 vs J-14, top IPs, graphique 7j.
"""

import os
import re
import json
import fcntl
import smtplib
import subprocess
from datetime import datetime, timedelta
from collections import Counter
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import psutil
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import requests

# ─────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────
LOCK_FILE      = "/tmp/report_weekly.lock"
MAIL_FROM      = os.environ.get("SOC_MAIL_FROM", "secops@viadigitech.com")
MAIL_TO        = os.environ.get("SOC_MAIL_TO", "david@viadigitech.com").split(",")
DASHBOARD_URL  = "http://graph.viadigitech.com/soc/"
OLLAMA_URL     = "http://localhost:11434/api/generate"
OLLAMA_MODEL   = "qwen2.5:3b"
OLLAMA_TIMEOUT = 300
AUTH_LOG       = "/var/log/auth.log"
AUDIT_LOG      = "/home/ubuntu/secops/audit_actions.csv"
IMGDIR         = "/var/www/html/viadigitech-reports"
IMG_BASE_URL   = "http://graph.viadigitech.com"
OUTPUT_FILE    = "/var/www/html/viadigitech-reports/weekly_report.html"
MAX_LOG_LINES  = 50000

C = {
    "bg":      "#0f1117", "surface": "#1a1d2e", "border": "#2d3154",
    "accent":  "#6366f1", "green":   "#22c55e", "yellow": "#eab308",
    "red":     "#ef4444", "text":    "#e2e8f0", "muted":  "#64748b",
}

TS = datetime.now().strftime("%Y-%m-%d_%H-%M")

# ─────────────────────────────────────────
# COLLECTE
# ─────────────────────────────────────────

def get_system_metrics():
    cpu    = psutil.cpu_percent(interval=2)
    mem    = psutil.virtual_memory()
    disk   = psutil.disk_usage("/")
    swap   = psutil.swap_memory()
    boot   = datetime.fromtimestamp(psutil.boot_time())
    uptime = datetime.now() - boot
    l1, l5, l15 = psutil.getloadavg()
    ncpu   = psutil.cpu_count()
    return {
        "cpu_percent":   cpu,
        "load_1": round(l1,2), "load_5": round(l5,2), "load_15": round(l15,2),
        "cpu_count":     ncpu,
        "mem_total_gb":  round(mem.total/1e9,1),
        "mem_used_gb":   round(mem.used/1e9,1),
        "mem_percent":   mem.percent,
        "disk_total_gb": round(disk.total/1e9,1),
        "disk_used_gb":  round(disk.used/1e9,1),
        "disk_percent":  disk.percent,
        "swap_total_gb": round(swap.total/1e9,1),
        "swap_used_gb":  round(swap.used/1e9,1),
        "uptime_days":   uptime.days,
        "uptime_hours":  uptime.seconds // 3600,
        "boot_time":     boot.strftime("%d/%m/%Y %H:%M"),
    }

def run_cmd(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except: return ""

def parse_auth_log_period(since_hours=168):
    """Analyse auth.log sur la période donnée (168h = 7 jours)."""
    failed_ips, failed_users, accepted = Counter(), Counter(), []
    since = datetime.now() - timedelta(hours=since_hours)
    total = 0
    if not os.path.exists(AUTH_LOG):
        return failed_ips, failed_users, accepted, total
    with open(AUTH_LOG, "r", errors="ignore") as f:
        lines = f.readlines()[-MAX_LOG_LINES:]
    year = datetime.now().year
    for line in lines:
        try:
            ts = datetime.strptime(f"{year} {line[:15]}", "%Y %b %d %H:%M:%S")
            if ts < since: continue
        except: continue
        if "Failed password" in line or "Invalid user" in line:
            total += 1
            ip = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            usr = re.search(r"(?:for (?:invalid user )?|Invalid user )(\S+) from", line)
            if ip:  failed_ips[ip.group(1)]  += 1
            if usr: failed_users[usr.group(1)] += 1
        elif "Accepted" in line:
            ip  = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            usr = re.search(r"for (\S+) from", line)
            if ip and usr:
                accepted.append({"user": usr.group(1), "ip": ip.group(1), "time": line[:15].strip()})
    return failed_ips, failed_users, accepted, total

def get_fail2ban_bans_period(since_hours=168):
    """Bans fail2ban sur la période (168h = 7 jours)."""
    bans = Counter()
    since = datetime.now() - timedelta(hours=since_hours)
    log = "/var/log/fail2ban.log"
    if not os.path.exists(log): return bans
    with open(log, errors="ignore") as f:
        for line in f:
            if "Ban" not in line: continue
            try:
                ts = datetime.strptime(line[:19], "%Y-%m-%d %H:%M:%S")
                if ts < since: continue
            except: continue
            m = re.search(r"Ban\s+(\d+\.\d+\.\d+\.\d+)", line)
            if m: bans[m.group(1)] += 1
    return bans

def get_bans_per_day(days=7):
    """Retourne le nombre de bans par jour sur `days` jours depuis audit_actions.csv."""
    day_bans = Counter()
    if not os.path.exists(AUDIT_LOG):
        return day_bans
    with open(AUDIT_LOG, errors="ignore") as f:
        for line in f:
            if line.startswith("timestamp"): continue
            parts = line.strip().split(",", 4)
            if len(parts) < 3: continue
            try:
                d = parts[0][:10]
                cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
                if d >= cutoff and ("BAN_AUTO" in parts[2] or "BAN_OLLAMA" in parts[2]):
                    day_bans[d] += 1
            except:
                pass
    return day_bans

def get_audit_weekly(days=7):
    """Dernières actions audit sur 7 jours."""
    rows = []
    if not os.path.exists(AUDIT_LOG):
        return rows
    cutoff = (datetime.now() - timedelta(days=days)).isoformat()
    with open(AUDIT_LOG, errors="ignore") as f:
        lines = f.readlines()
    for line in reversed(lines[1:]):
        parts = line.strip().split(",", 4)
        if len(parts) >= 4 and parts[0] >= cutoff:
            rows.append(parts)
        if len(rows) >= 50:
            break
    return rows

# ─────────────────────────────────────────
# COMPARATIF J-7 vs J-14
# ─────────────────────────────────────────

def get_period_stats(offset_days, span_days=7):
    """Statistiques SSH pour une période [now - offset_days - span_days, now - offset_days]."""
    end   = datetime.now() - timedelta(days=offset_days)
    start = end - timedelta(days=span_days)
    total = 0
    bans  = 0
    if not os.path.exists(AUTH_LOG):
        return total, bans
    with open(AUTH_LOG, "r", errors="ignore") as f:
        lines = f.readlines()[-MAX_LOG_LINES:]
    year = datetime.now().year
    for line in lines:
        try:
            ts = datetime.strptime(f"{year} {line[:15]}", "%Y %b %d %H:%M:%S")
            if not (start <= ts < end): continue
        except: continue
        if "Failed password" in line or "Invalid user" in line:
            total += 1
    # Bans fail2ban
    log = "/var/log/fail2ban.log"
    if os.path.exists(log):
        with open(log, errors="ignore") as f:
            for line in f:
                if "Ban" not in line: continue
                try:
                    ts = datetime.strptime(line[:19], "%Y-%m-%d %H:%M:%S")
                    if not (start <= ts < end): continue
                    if re.search(r"Ban\s+\d+\.\d+\.\d+\.\d+", line):
                        bans += 1
                except: continue
    return total, bans

# ─────────────────────────────────────────
# GRAPHIQUES
# ─────────────────────────────────────────

def _save(fig, name):
    os.makedirs(IMGDIR, exist_ok=True)
    path = f"{IMGDIR}/weekly-{name}-{TS}.png"
    fig.savefig(path, dpi=110, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    return f"{IMG_BASE_URL}/weekly-{name}-{TS}.png"

def chart_bans_7j(day_bans):
    """Graphique barres : bans par jour sur 7 jours."""
    today = datetime.now().date()
    labels = []
    values = []
    for i in range(6, -1, -1):
        d = (today - timedelta(days=i))
        labels.append(d.strftime("%d/%m"))
        values.append(day_bans.get(d.strftime("%Y-%m-%d"), 0))

    fig, ax = plt.subplots(figsize=(10, 3.5), facecolor=C["surface"])
    ax.set_facecolor(C["surface"])
    colors = [C["red"] if v == max(values) and v > 0 else C["accent"] for v in values]
    bars = ax.bar(labels, values, color=colors, width=0.6, edgecolor="none")
    for bar, v in zip(bars, values):
        if v > 0:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(values, default=1)*0.02,
                    str(v), ha="center", va="bottom", color=C["text"], fontsize=9)
    ax.set_title("Bans automatiques — 7 derniers jours", color=C["text"], fontsize=12, fontweight="bold", pad=10)
    ax.tick_params(colors=C["text"], labelsize=9)
    ax.spines[:].set_color(C["border"])
    ax.set_ylabel("Bans", color=C["muted"], fontsize=9)
    fig.tight_layout()
    return _save(fig, "bans7j")

def chart_top_ips(failed_ips, n=10):
    """Graphique barres horizontales : top IPs attaquantes sur 7 jours."""
    if not failed_ips: return None
    top = failed_ips.most_common(n)
    ips, counts = zip(*top)
    fig, ax = plt.subplots(figsize=(9, max(3, len(top)*0.55)), facecolor=C["surface"])
    ax.set_facecolor(C["surface"])
    colors = [C["red"] if c == max(counts) else C["accent"] for c in counts]
    bars = ax.barh(list(ips), list(counts), color=colors, height=0.6, edgecolor="none")
    for bar, count in zip(bars, counts):
        ax.text(bar.get_width() + max(counts)*0.01, bar.get_y()+bar.get_height()/2,
                str(count), va="center", color=C["text"], fontsize=9)
    ax.set_xlabel("Tentatives SSH", color=C["muted"], fontsize=9)
    ax.set_title("Top 10 IPs attaquantes — 7 jours", color=C["text"], fontsize=12, fontweight="bold", pad=10)
    ax.tick_params(colors=C["text"], labelsize=8)
    ax.spines[:].set_color(C["border"])
    ax.set_xlim(0, max(counts)*1.18)
    ax.invert_yaxis()
    fig.tight_layout()
    return _save(fig, "top_ips")

# ─────────────────────────────────────────
# ANALYSE IA OLLAMA
# ─────────────────────────────────────────

def ollama_query(prompt, timeout=OLLAMA_TIMEOUT):
    try:
        resp = requests.post(OLLAMA_URL,
            json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            timeout=timeout)
        resp.raise_for_status()
        return resp.json().get("response", "").strip()
    except Exception as e:
        return f"[Analyse indisponible : {e}]"

def build_weekly_ai_analysis(metrics, failed_ips, failed_users, total_attempts,
                              bans, total_s1, bans_s1, total_s2, bans_s2):
    now = datetime.now()
    week_num = now.isocalendar()[1]

    # Comparatif semaine vs semaine précédente
    delta_att  = total_s1 - total_s2
    delta_bans = bans_s1  - bans_s2
    delta_att_txt  = f"+{delta_att}"  if delta_att  >= 0 else str(delta_att)
    delta_bans_txt = f"+{delta_bans}" if delta_bans >= 0 else str(delta_bans)

    top_ips = failed_ips.most_common(5)

    prompt = f"""IMPORTANT : réponds UNIQUEMENT en français, sans mélanger d'autres langues.

Tu es l'analyste SOC du serveur VPS ViaDigiTech. Voici le bilan hebdomadaire (semaine {week_num}) :

MÉTRIQUES ACTUELLES :
- CPU : {metrics['cpu_percent']}% | RAM : {metrics['mem_percent']}% | Disque : {metrics['disk_percent']}%

SÉCURITÉ SSH — 7 DERNIERS JOURS :
- Tentatives totales : {total_attempts}
- IPs uniques : {len(failed_ips)}
- Top 5 IPs attaquantes : {top_ips}
- Bans fail2ban total : {sum(bans.values())}

COMPARATIF SEMAINE PRÉCÉDENTE :
- Tentatives SSH : {total_s1} cette semaine vs {total_s2} la semaine précédente ({delta_att_txt})
- Bans fail2ban : {bans_s1} cette semaine vs {bans_s2} la semaine précédente ({delta_bans_txt})

Rédige un bilan hebdomadaire en 4 points numérotés, en français :
1. BILAN GLOBAL : résume la semaine en 2 phrases (menace globale, tendance)
2. POINTS CHAUDS : les 2-3 éléments les plus préoccupants cette semaine
3. ÉVOLUTION vs S-1 : interprète le comparatif (aggravation / amélioration / stable)
4. RECOMMANDATIONS : 1-2 actions concrètes à envisager pour la semaine suivante

Maximum 200 mots. Sois factuel et opérationnel. Signe "— SOC IA ViaDigiTech"."""

    print("  → Analyse hebdomadaire IA...")
    return ollama_query(prompt)

# ─────────────────────────────────────────
# TEMPLATE HTML
# ─────────────────────────────────────────

def _color(val, warn=70, crit=85):
    return "#ef4444" if val >= crit else ("#eab308" if val >= warn else "#22c55e")

def _dot(val, warn=70, crit=85):
    return "dot-red" if val >= crit else ("dot-yellow" if val >= warn else "dot-green")

def build_html(metrics, failed_ips, failed_users, total_attempts, accepted,
               bans, day_bans, ai_analysis, charts,
               total_s1, bans_s1, total_s2, bans_s2):
    now = datetime.now()
    hostname = os.uname().nodename
    week_num = now.isocalendar()[1]

    # Comparatif
    delta_att  = total_s1 - total_s2
    delta_bans = bans_s1  - bans_s2
    def delta_badge(d):
        if d > 0:
            return f'<span style="color:#ef4444">▲ +{d}</span>'
        elif d < 0:
            return f'<span style="color:#22c55e">▼ {d}</span>'
        return '<span style="color:#64748b">= 0</span>'

    # Top 10 IPs
    top_ips_rows = "".join(
        f'<tr><td style="color:#64748b;width:28px">{i}</td>'
        f'<td style="font-family:monospace;color:#818cf8">{ip}</td>'
        f'<td style="text-align:right;padding-right:16px;font-weight:700;color:#ef4444">{cnt}</td></tr>'
        for i, (ip, cnt) in enumerate(failed_ips.most_common(10), 1)
    )

    # Audit récent
    audit_rows = ""
    for parts in get_audit_weekly(7)[:20]:
        ts = parts[0][11:16] if len(parts[0]) > 15 else parts[0][:10]
        action_color = "#ef4444" if "BAN" in parts[2] else "#64748b"
        audit_rows += (
            f"<tr><td style='padding:5px;border:1px solid #1e2035;color:#64748b;font-size:11px'>{parts[0][:10]} {ts}</td>"
            f"<td style='padding:5px;border:1px solid #1e2035;font-family:monospace;font-size:11px'>{parts[1]}</td>"
            f"<td style='padding:5px;border:1px solid #1e2035;font-size:11px;color:{action_color}'>{parts[2]}</td>"
            f"<td style='padding:5px;border:1px solid #1e2035;font-size:11px'>{parts[3]}%</td></tr>"
        )

    def img(url, alt, mt=12):
        return f'<img src="{url}" width="100%" style="border-radius:8px;margin-top:{mt}px;display:block" alt="{alt}">' if url else ""

    def fmt(text):
        return text.replace("\n", "<br>").replace("  ", "&nbsp;&nbsp;")

    cpu_c  = _color(metrics["cpu_percent"], 60, 80)
    mem_c  = _color(metrics["mem_percent"], 70, 85)
    disk_c = _color(metrics["disk_percent"], 75, 88)

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>SOC — Rapport Hebdomadaire S{week_num}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0f1117;font-family:-apple-system,'Segoe UI',Roboto,sans-serif;color:#ffffff;padding:20px}}
  .w{{max-width:780px;margin:0 auto}}
  .card{{background:#1a1d2e;border:1px solid #2d3154;border-radius:12px;padding:24px;margin-bottom:16px}}
  .title{{font-size:13px;font-weight:600;color:#a0aec0;text-transform:uppercase;letter-spacing:1px;margin-bottom:16px;padding-bottom:10px;border-bottom:1px solid #2d3154}}
  .metric{{background:#0f1117;border:1px solid #2d3154;border-radius:10px;padding:14px;text-align:center}}
  .mval{{font-size:22px;font-weight:700;color:#ffffff}}
  .mlabel{{font-size:11px;color:#a0aec0;margin-top:3px;text-transform:uppercase;letter-spacing:.5px;font-weight:600}}
  .msub{{font-size:11px;color:#cbd5e1;margin-top:2px}}
  .pill{{display:inline-flex;align-items:center;gap:6px;background:#1e2035;border:1px solid #2d3154;border-radius:20px;padding:6px 12px;font-size:12px;margin:3px;color:#ffffff}}
  .dot{{width:7px;height:7px;border-radius:50%}}
  .dot-green{{background:#22c55e;box-shadow:0 0 5px #22c55e}}
  .dot-yellow{{background:#eab308;box-shadow:0 0 5px #eab308}}
  .dot-red{{background:#ef4444;box-shadow:0 0 5px #ef4444}}
  table{{width:100%;border-collapse:collapse;font-size:13px}}
  th{{background:#0f1117;padding:9px 10px;text-align:left;color:#ffffff;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid #2d3154}}
  td{{padding:9px 10px;border-bottom:1px solid #1e2035;color:#ffffff}}
  tr:last-child td{{border-bottom:none}}
  .ai-box{{background:#0f1117;border:1px solid #2d3154;border-left:3px solid #6366f1;border-radius:8px;padding:18px;font-size:13px;line-height:1.75;color:#ffffff}}
</style>
</head>
<body>
<div class="w">

<!-- HEADER -->
<div class="card" style="border-top:3px solid #6366f1">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:12px">
    <div>
      <div style="font-size:22px;font-weight:700;color:#fff">🛡️ AI SecOps — Rapport Hebdomadaire</div>
      <div style="font-size:13px;color:#a0aec0;margin-top:4px">{hostname} &nbsp;·&nbsp; Semaine {week_num} &nbsp;·&nbsp; {now.strftime('%d/%m/%Y %H:%M')}</div>
    </div>
    <div style="background:#1e2035;border:1px solid #2d3154;border-radius:20px;padding:7px 16px;font-size:12px;color:#ffffff;white-space:nowrap">
      Uptime {metrics['uptime_days']}j {metrics['uptime_hours']}h
    </div>
  </div>
  <div style="margin-top:16px;display:flex;flex-wrap:wrap">
    <span class="pill"><span class="dot {_dot(metrics['cpu_percent'],60,80)}"></span>CPU {metrics['cpu_percent']}%</span>
    <span class="pill"><span class="dot {_dot(metrics['mem_percent'],70,85)}"></span>RAM {metrics['mem_percent']}%</span>
    <span class="pill"><span class="dot {_dot(metrics['disk_percent'],75,88)}"></span>Disque {metrics['disk_percent']}%</span>
    <span class="pill"><span class="dot dot-red"></span>{total_attempts} tentatives SSH (7j)</span>
    <span class="pill"><span class="dot dot-yellow"></span>{sum(bans.values())} bans (7j)</span>
  </div>
</div>

<!-- ANALYSE IA HEBDOMADAIRE -->
<div class="card" style="border-top:3px solid #818cf8">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">
    <span style="font-size:22px">🤖</span>
    <div>
      <div style="font-weight:700;color:#ffffff;font-size:15px">Bilan de la semaine {week_num}</div>
      <div style="font-size:11px;color:#a5b4fc;font-weight:600;letter-spacing:.5px">ANALYSE HEBDOMADAIRE · {OLLAMA_MODEL.upper()}</div>
    </div>
  </div>
  <div class="ai-box">{fmt(ai_analysis)}</div>
</div>

<!-- COMPARATIF S-1 vs S-2 -->
<div class="card">
  <div class="title">📊 Comparatif — Cette semaine vs Semaine précédente</div>
  <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-bottom:16px">
    <div class="metric">
      <div class="mval" style="color:#ef4444">{total_s1}</div>
      <div class="mlabel">Tentatives SSH (S{week_num})</div>
      <div class="msub">{delta_badge(delta_att)} vs S{week_num - 1} ({total_s2})</div>
    </div>
    <div class="metric">
      <div class="mval" style="color:#eab308">{bans_s1}</div>
      <div class="mlabel">Bans fail2ban (S{week_num})</div>
      <div class="msub">{delta_badge(delta_bans)} vs S{week_num - 1} ({bans_s2})</div>
    </div>
  </div>
</div>

<!-- MÉTRIQUES SYSTÈME -->
<div class="card">
  <div class="title">🖥️ Métriques Système (actuelles)</div>
  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px">
    <div class="metric"><div class="mval" style="color:{cpu_c}">{metrics['cpu_percent']}%</div><div class="mlabel">CPU</div><div class="msub">Load {metrics['load_1']}/{metrics['load_5']}</div></div>
    <div class="metric"><div class="mval" style="color:{mem_c}">{metrics['mem_percent']}%</div><div class="mlabel">RAM</div><div class="msub">{metrics['mem_used_gb']}/{metrics['mem_total_gb']} Go</div></div>
    <div class="metric"><div class="mval" style="color:{disk_c}">{metrics['disk_percent']}%</div><div class="mlabel">Disque</div><div class="msub">{metrics['disk_used_gb']}/{metrics['disk_total_gb']} Go</div></div>
    <div class="metric"><div class="mval" style="color:#22c55e">{metrics['swap_used_gb']}G</div><div class="mlabel">Swap</div><div class="msub">/{metrics['swap_total_gb']} Go</div></div>
  </div>
</div>

<!-- GRAPHIQUE BANS 7J -->
<div class="card">
  <div class="title">📈 Graphique bans automatiques — 7 jours</div>
  {img(charts.get('bans7j'), 'Bans 7 jours', 0)}
</div>

<!-- TOP 10 IPs -->
<div class="card">
  <div class="title">🔐 Sécurité SSH — 7 jours</div>
  <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:16px">
    <div class="metric"><div class="mval" style="color:#ef4444">{total_attempts}</div><div class="mlabel">Tentatives</div></div>
    <div class="metric"><div class="mval" style="color:#eab308">{len(failed_ips)}</div><div class="mlabel">IPs uniques</div></div>
    <div class="metric"><div class="mval" style="color:#22c55e">{len(accepted)}</div><div class="mlabel">Connexions légitimes</div></div>
  </div>
  {img(charts.get('top_ips'), 'Top IPs attaquantes')}
  <div style="margin-top:18px">
    <div style="font-size:11px;color:#64748b;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Top 10 IPs attaquantes (7 jours)</div>
    <table><thead><tr><th>#</th><th>IP</th><th style="text-align:right;padding-right:16px">Tentatives</th></tr></thead>
    <tbody>{top_ips_rows}</tbody></table>
  </div>
</div>

<!-- AUDIT ACTIONS -->
{"" if not audit_rows else f'<div class="card"><div class="title">🔍 Audit actions SOC — 7 jours</div><table><thead><tr><th>Horodatage</th><th>IP</th><th>Action</th><th>Score</th></tr></thead><tbody>' + audit_rows + '</tbody></table></div>'}

<!-- FOOTER -->
<div style="text-align:center;margin-top:8px;padding:16px;border-top:1px solid #1e2035">
  <a href="{DASHBOARD_URL}" style="display:inline-block;background:linear-gradient(135deg,#312e81,#1e1b4b);border:1px solid #4338ca;color:#a5b4fc;text-decoration:none;padding:9px 22px;border-radius:8px;font-size:13px;font-weight:600;margin-bottom:12px">
    🖥️ Ouvrir le Dashboard SOC
  </a>
  <div style="font-size:11px;color:#334155;margin-top:8px">
    <span style="color:#a0aec0">AI SecOps Weekly · {hostname} · S{week_num} · {now.strftime('%d/%m/%Y %H:%M')} · {OLLAMA_MODEL}</span>
  </div>
</div>

</div>
</body>
</html>"""

# ─────────────────────────────────────────
# ENVOI MAIL
# ─────────────────────────────────────────

def send_mail(html, subject):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = MAIL_FROM
    msg["To"]      = ", ".join(MAIL_TO)
    msg.attach(MIMEText(html, "html", "utf-8"))
    with smtplib.SMTP("localhost", 25, timeout=30) as s:
        s.sendmail(MAIL_FROM, MAIL_TO, msg.as_string())

# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────

def main():
    # Lock anti double exécution
    lockf = open(LOCK_FILE, "w")
    try:
        import fcntl
        fcntl.flock(lockf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print(f"[{datetime.now():%H:%M:%S}] Rapport hebdo déjà en cours — abandon.")
        return

    now = datetime.now()
    week_num = now.isocalendar()[1]
    print(f"[{now:%H:%M:%S}] Rapport hebdomadaire — Semaine {week_num}")

    print(f"[{now:%H:%M:%S}] Collecte métriques système...")
    metrics = get_system_metrics()

    print(f"[{now:%H:%M:%S}] Analyse logs SSH (7 jours)...")
    failed_ips, failed_users, accepted, total = parse_auth_log_period(168)
    bans = get_fail2ban_bans_period(168)
    day_bans = get_bans_per_day(7)

    print(f"[{now:%H:%M:%S}] Comparatif S-1 vs S-2...")
    total_s1, bans_s1 = get_period_stats(0, 7)
    total_s2, bans_s2 = get_period_stats(7, 7)

    print(f"[{now:%H:%M:%S}] Génération des graphiques...")
    charts = {
        "bans7j":  chart_bans_7j(day_bans),
        "top_ips": chart_top_ips(failed_ips),
    }
    print(f"  Graphiques : {[k for k,v in charts.items() if v]}")

    print(f"[{now:%H:%M:%S}] Analyse IA Ollama (peut prendre 1-2 min)...")
    ai_analysis = build_weekly_ai_analysis(
        metrics, failed_ips, failed_users, total,
        bans, total_s1, bans_s1, total_s2, bans_s2
    )

    print(f"[{now:%H:%M:%S}] Assemblage HTML...")
    html = build_html(
        metrics, failed_ips, failed_users, total, accepted,
        bans, day_bans, ai_analysis, charts,
        total_s1, bans_s1, total_s2, bans_s2
    )

    # Sauvegarde locale
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        f.write(html)
    print(f"[{now:%H:%M:%S}] Rapport HTML sauvegardé → {OUTPUT_FILE}")

    # Sujet mail
    ban_count = sum(bans.values())
    if ban_count > 100 or total > 2000:
        icon, label = "🔴", "CRITIQUE"
    elif ban_count > 50 or total > 1000:
        icon, label = "🟠", "ÉLEVÉE"
    elif ban_count > 15 or total > 300:
        icon, label = "🟡", "MODÉRÉE"
    else:
        icon, label = "🟢", "NORMALE"

    subject = f"{icon} [SOC] Rapport hebdomadaire ViaDigiTech — semaine {week_num} · Menace {label} · {ban_count} bans · {total} tentatives SSH"
    print(f"[{now:%H:%M:%S}] Envoi mail à {MAIL_TO}...")
    send_mail(html, subject)
    print(f"[{now:%H:%M:%S}] ✓ Rapport hebdomadaire envoyé.")

if __name__ == "__main__":
    main()
