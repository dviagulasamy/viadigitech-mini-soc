#!/usr/bin/env python3
"""
AI SecOps Daily Report — ViaDigiTech
Métriques système + analyse sécurité + commentaire Ollama + graphiques web.
"""

import os
import re
import json
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
MAIL_FROM     = "secops@vps-23de4a3d.vps.ovh.net"
MAIL_TO       = ["david@viadigitech.com"]
MAIL_SUBJECT  = "🛡️ AI SecOps — Rapport du {date}"
OLLAMA_URL    = "http://localhost:11434/api/generate"
OLLAMA_MODEL  = "llama3.2:3b"
OLLAMA_TIMEOUT = 300          # 5 min max pour le prompt long
AUTH_LOG      = "/var/log/auth.log"
IMGDIR        = "/var/www/html/viadigitech-reports"
IMG_BASE_URL  = "http://graph.viadigitech.com"
MAX_LOG_LINES = 8000

# ─────────────────────────────────────────
# COLLECTE SYSTÈME
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

def get_top_processes(n=6):
    procs = []
    for p in psutil.process_iter(["pid","name","cpu_percent","memory_percent","username"]):
        try: procs.append(p.info)
        except: pass
    return sorted(procs, key=lambda x: x["memory_percent"] or 0, reverse=True)[:n]

def run_cmd(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except: return ""

def get_docker_info():
    raw = run_cmd("docker ps --format '{{json .}}'")
    containers = []
    for line in raw.splitlines():
        try: containers.append(json.loads(line.strip()))
        except: pass
    return containers

# ─────────────────────────────────────────
# ANALYSE SÉCURITÉ
# ─────────────────────────────────────────

def parse_auth_log(since_hours=24):
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

def get_fail2ban_bans(since_hours=24):
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

# ─────────────────────────────────────────
# GRAPHIQUES — sauvés sur disque + URL web
# ─────────────────────────────────────────

C = {
    "bg":      "#0f1117", "surface": "#1a1d2e", "border": "#2d3154",
    "accent":  "#6366f1", "green":   "#22c55e", "yellow": "#eab308",
    "red":     "#ef4444", "text":    "#e2e8f0", "muted":  "#64748b",
}

TS = datetime.now().strftime("%Y-%m-%d_%H-%M")

def _save(fig, name):
    os.makedirs(IMGDIR, exist_ok=True)
    path = f"{IMGDIR}/secops-{name}-{TS}.png"
    fig.savefig(path, dpi=110, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    return f"{IMG_BASE_URL}/secops-{name}-{TS}.png"

def chart_gauges(m):
    fig, axes = plt.subplots(1, 3, figsize=(10, 3.2), facecolor=C["surface"])
    items = [("CPU", m["cpu_percent"], "%"), ("RAM", m["mem_percent"], "%"), ("Disque", m["disk_percent"], "%")]
    for ax, (label, val, unit) in zip(axes, items):
        color = C["green"] if val < 60 else (C["yellow"] if val < 80 else C["red"])
        ax.set_facecolor(C["surface"])
        bg = plt.matplotlib.patches.Wedge((0.5, 0.3), 0.38, 0, 360, width=0.10,
                                           facecolor=C["border"], transform=ax.transAxes)
        arc = plt.matplotlib.patches.Wedge((0.5, 0.3), 0.38, 90, 90 - val/100*360,
                                            width=0.10, facecolor=color, transform=ax.transAxes)
        ax.add_patch(bg); ax.add_patch(arc)
        ax.text(0.5, 0.28, f"{val:.0f}{unit}", transform=ax.transAxes,
                ha="center", va="center", fontsize=20, fontweight="bold", color=color)
        ax.text(0.5, 0.82, label, transform=ax.transAxes,
                ha="center", fontsize=12, color=C["text"])
        ax.axis("off")
    fig.suptitle("Ressources système", color=C["text"], fontsize=12, fontweight="bold", y=1.02)
    fig.tight_layout()
    return _save(fig, "gauges")

def chart_memory(m):
    fig, axes = plt.subplots(1, 2, figsize=(7, 3.2), facecolor=C["surface"])
    for ax, (title, used, total, color) in zip(axes, [
        ("RAM",  m["mem_used_gb"],  m["mem_total_gb"],  C["accent"]),
        ("Swap", m["swap_used_gb"], m["swap_total_gb"], C["green"]),
    ]):
        free = max(0, total - used)
        ax.set_facecolor(C["surface"])
        ax.pie([used, free], colors=[color, C["border"]], startangle=90,
               wedgeprops=dict(width=0.45, edgecolor=C["surface"], linewidth=2))
        ax.text(0, 0, f"{used:.1f}G\n/{total:.1f}G", ha="center", va="center",
                fontsize=10, color=C["text"], fontweight="bold")
        ax.set_title(title, color=C["text"], fontsize=11, fontweight="bold")
    fig.tight_layout()
    return _save(fig, "memory")

def chart_attackers(failed_ips, n=10):
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
    ax.set_xlabel("Tentatives", color=C["muted"], fontsize=9)
    ax.set_title("Top IPs attaquantes (24h)", color=C["text"], fontsize=12, fontweight="bold", pad=10)
    ax.tick_params(colors=C["text"], labelsize=8)
    ax.spines[:].set_color(C["border"])
    ax.set_xlim(0, max(counts)*1.18)
    ax.invert_yaxis()
    fig.tight_layout()
    return _save(fig, "attackers")

def chart_users(failed_users, n=10):
    if not failed_users: return None
    top = failed_users.most_common(n)
    users, counts = zip(*top)
    fig, ax = plt.subplots(figsize=(9, 3.5), facecolor=C["surface"])
    ax.set_facecolor(C["surface"])
    x = range(len(users))
    ax.bar(x, counts, color=C["yellow"], width=0.6, edgecolor="none")
    for xi, count in zip(x, counts):
        ax.text(xi, count + max(counts)*0.02, str(count), ha="center", color=C["text"], fontsize=8)
    ax.set_xticks(list(x))
    ax.set_xticklabels(list(users), rotation=35, ha="right", color=C["text"], fontsize=8)
    ax.set_title("Usernames les plus ciblés (24h)", color=C["text"], fontsize=12, fontweight="bold", pad=10)
    ax.tick_params(colors=C["text"])
    ax.spines[:].set_color(C["border"])
    fig.tight_layout()
    return _save(fig, "users")

def chart_history():
    """Courbes historiques CPU / SSH depuis le CSV de l'ancien script."""
    csv_path = "/home/ubuntu/viadigitech-soc-v5-3/logs/banned-history.csv"
    if not os.path.exists(csv_path): return None
    try:
        import pandas as pd
        df = pd.read_csv(csv_path, parse_dates=["date"])
        df = df.tail(30)
        if len(df) < 3: return None
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 5), facecolor=C["surface"])
        for ax in (ax1, ax2): ax.set_facecolor(C["surface"]); ax.spines[:].set_color(C["border"])
        ax1.plot(df["date"], df["cpu"], color=C["accent"], linewidth=2, marker="o", markersize=3)
        ax1.fill_between(df["date"], df["cpu"], alpha=0.15, color=C["accent"])
        ax1.set_ylabel("CPU %", color=C["text"], fontsize=9); ax1.tick_params(colors=C["text"], labelsize=8)
        ax1.set_title("Historique 30 jours", color=C["text"], fontsize=12, fontweight="bold")
        ax2.plot(df["date"], df["ssh_fail"], color=C["red"], linewidth=2, marker="o", markersize=3)
        ax2.fill_between(df["date"], df["ssh_fail"], alpha=0.15, color=C["red"])
        ax2.set_ylabel("Tentatives SSH", color=C["text"], fontsize=9); ax2.tick_params(colors=C["text"], labelsize=8)
        fig.tight_layout()
        return _save(fig, "history")
    except Exception as e:
        print(f"  [historique ignoré: {e}]")
        return None

# ─────────────────────────────────────────
# ANALYSE IA — OLLAMA
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

def build_ai_analysis(metrics, failed_ips, failed_users, total_attempts, accepted, containers, bans):
    now = datetime.now()

    # 1. Commentaire matinal — ton direct, bref
    prompt_morning = f"""Tu es l'assistant IA SecOps du serveur VPS ViaDigiTech. Chaque matin tu rédiges un bref message de synthèse personnalisé.

Données du {now.strftime('%A %d %B %Y à %H:%M')} :
- CPU : {metrics['cpu_percent']}% | Load : {metrics['load_1']}/{metrics['load_5']}/{metrics['load_15']} sur {metrics['cpu_count']} CPUs
- RAM : {metrics['mem_percent']}% ({metrics['mem_used_gb']} Go / {metrics['mem_total_gb']} Go)
- Disque : {metrics['disk_percent']}% ({metrics['disk_used_gb']} Go / {metrics['disk_total_gb']} Go)
- Uptime : {metrics['uptime_days']} jours
- Tentatives SSH échouées (24h) : {total_attempts}
- IPs bannies par fail2ban (24h) : {sum(bans.values())}
- Connexions SSH acceptées : {len(accepted)}
- Conteneurs Docker actifs : {len(containers)}

Rédige un message de bonjour professionnel et chaleureux (3-4 phrases max), comme si tu t'adressais directement à l'administrateur. Mentionne ce qui se passe concrètement ce matin : si tout va bien, dis-le clairement. Si quelque chose mérite attention, signale-le. Utilise un ton direct et humain, pas robotique."""

    # 2. Analyse sécurité détaillée
    top_ips = failed_ips.most_common(5)
    top_users = failed_users.most_common(5)
    prompt_security = f"""Tu es expert en cybersécurité Linux. Analyse ces données de sécurité SSH des dernières 24h :

Tentatives totales : {total_attempts}
IPs uniques : {len(failed_ips)}
Top 5 IPs : {top_ips}
Usernames ciblés : {top_users}
IPs bannies fail2ban : {sum(bans.values())} ({len(bans)} IPs)
Connexions légitimes acceptées : {len(accepted)}

Réponds en 4 points numérotés :
1. NIVEAU DE MENACE : (FAIBLE / MODÉRÉ / ÉLEVÉ / CRITIQUE) — justification en 1 phrase
2. PATTERN DÉTECTÉ : quel type d'attaque, est-ce coordonné ou aléatoire ?
3. FAIL2BAN : est-il efficace ? Faut-il ajuster la config ?
4. ACTION RECOMMANDÉE : une seule action concrète prioritaire

Sois précis et concis. Maximum 150 mots."""

    # 3. Analyse performance
    prompt_perf = f"""Tu es expert en administration système Linux. Évalue ces métriques :

CPU : {metrics['cpu_percent']}% (load {metrics['load_1']}/{metrics['load_5']}/{metrics['load_15']} / {metrics['cpu_count']} CPUs)
RAM : {metrics['mem_percent']}% ({metrics['mem_used_gb']}/{metrics['mem_total_gb']} Go)
Disque : {metrics['disk_percent']}% ({metrics['disk_used_gb']}/{metrics['disk_total_gb']} Go)
Swap : {metrics['swap_used_gb']}/{metrics['swap_total_gb']} Go

Donne une évaluation en 3 points :
1. ÉTAT GLOBAL : (OPTIMAL / CORRECT / DÉGRADÉ / CRITIQUE)
2. POINT D'ATTENTION : le seul indicateur qui mérite surveillance
3. CONSEIL : une optimisation concrète si nécessaire, sinon "RAS"

Maximum 80 mots."""

    print("  → Commentaire matinal...")
    morning = ollama_query(prompt_morning)
    print("  → Analyse sécurité...")
    security = ollama_query(prompt_security)
    print("  → Analyse performance...")
    perf = ollama_query(prompt_perf)

    return morning, security, perf

# ─────────────────────────────────────────
# TEMPLATE HTML
# ─────────────────────────────────────────

def _color(val, warn=60, crit=80):
    return "#ef4444" if val >= crit else ("#eab308" if val >= warn else "#22c55e")

def _dot(val, warn=60, crit=80):
    return "dot-red" if val >= crit else ("dot-yellow" if val >= warn else "dot-green")

def build_html(metrics, failed_ips, failed_users, total_attempts, accepted,
               containers, bans, ai_morning, ai_security, ai_perf, charts):
    now = datetime.now()
    hostname = os.uname().nodename

    # Top IPs rows
    top_ips_rows = "".join(
        f'<tr><td style="color:#64748b;width:28px">{i}</td>'
        f'<td style="font-family:monospace;color:#818cf8">{ip}</td>'
        f'<td style="text-align:right;padding-right:16px;font-weight:700;color:#ef4444">{cnt}</td></tr>'
        for i, (ip, cnt) in enumerate(failed_ips.most_common(10), 1)
    )

    # Accepted rows
    accepted_section = ""
    if accepted:
        rows = "".join(
            f'<tr><td style="color:#22c55e">✓</td><td>{a["user"]}</td>'
            f'<td style="font-family:monospace;color:#818cf8">{a["ip"]}</td>'
            f'<td style="color:#64748b">{a["time"]}</td></tr>'
            for a in accepted[-5:]
        )
        accepted_section = f"""
        <div style="margin-top:18px">
          <div style="font-size:11px;color:#64748b;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Connexions acceptées</div>
          <table width="100%" style="border-collapse:collapse;font-size:13px">
            <tr style="border-bottom:1px solid #2d3154"><th style="padding:8px;text-align:left;color:#a0aec0;font-size:11px"></th><th style="padding:8px;text-align:left;color:#a0aec0;font-size:11px">USER</th><th style="padding:8px;text-align:left;color:#a0aec0;font-size:11px">IP</th><th style="padding:8px;text-align:left;color:#a0aec0;font-size:11px">HEURE</th></tr>
            {rows}
          </table>
        </div>"""

    # Docker cards
    docker_cards = ""
    for c in containers[:8]:
        name   = c.get("Names", c.get("Name", "?"))[:30]
        image  = c.get("Image", "?")[:40]
        status = c.get("Status", "running")[:25]
        docker_cards += f"""
        <div style="background:#0f1117;border:1px solid #2d3154;border-radius:8px;padding:12px;margin-bottom:8px">
          <div style="font-weight:600;color:#a5b4fc;margin-bottom:4px">{name}</div>
          <div style="font-size:11px;color:#64748b">{image}</div>
          <div style="font-size:11px;color:#22c55e;margin-top:3px">● {status}</div>
        </div>"""

    # Images conditionnelles
    def img(url, alt, mt=12):
        return f'<img src="{url}" width="100%" style="border-radius:8px;margin-top:{mt}px;display:block" alt="{alt}">' if url else ""

    cpu_c  = _color(metrics["cpu_percent"], 60, 80)
    mem_c  = _color(metrics["mem_percent"], 70, 85)
    disk_c = _color(metrics["disk_percent"], 75, 88)

    # Formater les analyses IA (retours à la ligne → <br>)
    def fmt(text):
        return text.replace("\n", "<br>").replace("  ", "&nbsp;&nbsp;")

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
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
  .ai-morning{{background:linear-gradient(135deg,#1e1b4b,#1a1d2e);border:1px solid #3730a3;border-left:3px solid #818cf8;border-radius:10px;padding:20px;font-size:14px;line-height:1.8;color:#ffffff}}
</style>
</head>
<body>
<div class="w">

<!-- HEADER -->
<div class="card" style="border-top:3px solid #6366f1">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:12px">
    <div>
      <div style="font-size:22px;font-weight:700;color:#fff">🛡️ AI SecOps — Rapport Quotidien</div>
      <div style="font-size:13px;color:#a0aec0;margin-top:4px">{hostname} &nbsp;·&nbsp; {now.strftime('%A %d %B %Y à %H:%M')}</div>
    </div>
    <div style="background:#1e2035;border:1px solid #2d3154;border-radius:20px;padding:7px 16px;font-size:12px;color:#ffffff;white-space:nowrap">
      Uptime {metrics['uptime_days']}j {metrics['uptime_hours']}h
    </div>
  </div>
  <div style="margin-top:16px;display:flex;flex-wrap:wrap">
    <span class="pill"><span class="dot {_dot(metrics['cpu_percent'],60,80)}"></span>CPU {metrics['cpu_percent']}%</span>
    <span class="pill"><span class="dot {_dot(metrics['mem_percent'],70,85)}"></span>RAM {metrics['mem_percent']}%</span>
    <span class="pill"><span class="dot {_dot(metrics['disk_percent'],75,88)}"></span>Disque {metrics['disk_percent']}%</span>
    <span class="pill"><span class="dot dot-red"></span>{total_attempts} tentatives SSH</span>
    <span class="pill"><span class="dot dot-yellow"></span>{sum(bans.values())} IPs bannies</span>
    <span class="pill"><span class="dot dot-green"></span>{len(containers)} conteneurs</span>
  </div>
</div>

<!-- COMMENTAIRE MATINAL IA -->
<div class="card" style="border-top:3px solid #818cf8">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">
    <span style="font-size:22px">🤖</span>
    <div>
      <div style="font-weight:700;color:#ffffff;font-size:15px">Bonjour David</div>
      <div style="font-size:11px;color:#a5b4fc;font-weight:600;letter-spacing:.5px">COMMENTAIRE MATINAL · {OLLAMA_MODEL.upper()}</div>
    </div>
  </div>
  <div class="ai-morning">{fmt(ai_morning)}</div>
</div>

<!-- MÉTRIQUES -->
<div class="card">
  <div class="title">📊 Métriques Système</div>
  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px">
    <div class="metric"><div class="mval" style="color:{cpu_c}">{metrics['cpu_percent']}%</div><div class="mlabel">CPU</div><div class="msub">Load {metrics['load_1']}/{metrics['load_5']}</div></div>
    <div class="metric"><div class="mval" style="color:{mem_c}">{metrics['mem_percent']}%</div><div class="mlabel">RAM</div><div class="msub">{metrics['mem_used_gb']}/{metrics['mem_total_gb']} Go</div></div>
    <div class="metric"><div class="mval" style="color:{disk_c}">{metrics['disk_percent']}%</div><div class="mlabel">Disque</div><div class="msub">{metrics['disk_used_gb']}/{metrics['disk_total_gb']} Go</div></div>
    <div class="metric"><div class="mval" style="color:#22c55e">{metrics['swap_used_gb']}G</div><div class="mlabel">Swap</div><div class="msub">/{metrics['swap_total_gb']} Go dispo</div></div>
  </div>
  {img(charts['gauges'], 'Gauges', 0)}
  {img(charts['memory'], 'Mémoire', 14)}
  {img(charts.get('history'), 'Historique', 14)}
  <!-- Analyse perf IA -->
  <div style="margin-top:16px">
    <div style="font-size:11px;color:#a5b4fc;font-weight:700;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">✦ Analyse performance · {OLLAMA_MODEL}</div>
    <div class="ai-box">{fmt(ai_perf)}</div>
  </div>
</div>

<!-- SÉCURITÉ -->
<div class="card">
  <div class="title">🔐 Sécurité SSH — 24 dernières heures</div>
  <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:16px">
    <div class="metric"><div class="mval" style="color:#ef4444">{total_attempts}</div><div class="mlabel">Tentatives</div></div>
    <div class="metric"><div class="mval" style="color:#eab308">{len(failed_ips)}</div><div class="mlabel">IPs uniques</div></div>
    <div class="metric"><div class="mval" style="color:#22c55e">{len(accepted)}</div><div class="mlabel">Acceptées</div></div>
  </div>
  <!-- Analyse sécu IA -->
  <div style="margin-bottom:16px">
    <div style="font-size:11px;color:#a5b4fc;font-weight:700;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">✦ Analyse sécurité · {OLLAMA_MODEL}</div>
    <div class="ai-box">{fmt(ai_security)}</div>
  </div>
  {img(charts.get('attackers'), 'Top attaquants')}
  {img(charts.get('users'), 'Usernames ciblés', 12)}
  <!-- Tableau IPs -->
  <div style="margin-top:18px">
    <div style="font-size:11px;color:#64748b;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Top 10 IPs attaquantes</div>
    <table><thead><tr><th>#</th><th>IP</th><th style="text-align:right;padding-right:16px">Tentatives</th></tr></thead>
    <tbody>{top_ips_rows}</tbody></table>
  </div>
  {accepted_section}
</div>

<!-- DOCKER -->
<div class="card">
  <div class="title">🐳 Conteneurs Docker actifs ({len(containers)})</div>
  <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:10px">
    {"".join(f'<div style="background:#0f1117;border:1px solid #2d3154;border-radius:8px;padding:12px"><div style="font-weight:600;color:#a5b4fc;margin-bottom:3px">{c.get("Names","?")[:30]}</div><div style="font-size:11px;color:#64748b">{c.get("Image","?")[:40]}</div><div style="font-size:11px;color:#22c55e;margin-top:3px">● {c.get("Status","?")[:25]}</div></div>' for c in containers[:8])}
  </div>
</div>

<!-- FOOTER -->
<div style="text-align:center;font-size:11px;color:#334155;margin-top:8px;padding:14px;border-top:1px solid #1e2035">
  <span style="color:#a0aec0">AI SecOps · {hostname} · {now.strftime('%d/%m/%Y %H:%M')} · {OLLAMA_MODEL}</span>
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
    now = datetime.now()
    print(f"[{now:%H:%M:%S}] Collecte métriques...")
    metrics    = get_system_metrics()
    containers = get_docker_info()

    print(f"[{now:%H:%M:%S}] Analyse logs SSH...")
    failed_ips, failed_users, accepted, total = parse_auth_log(24)
    bans = get_fail2ban_bans(24)

    print(f"[{now:%H:%M:%S}] Génération des graphiques...")
    charts = {
        "gauges":    chart_gauges(metrics),
        "memory":    chart_memory(metrics),
        "attackers": chart_attackers(failed_ips),
        "users":     chart_users(failed_users),
        "history":   chart_history(),
    }
    print(f"  Graphiques : {[k for k,v in charts.items() if v]}")

    print(f"[{now:%H:%M:%S}] Analyse IA Ollama (peut prendre 1-2 min)...")
    morning, security, perf = build_ai_analysis(
        metrics, failed_ips, failed_users, total, accepted, containers, bans
    )

    print(f"[{now:%H:%M:%S}] Assemblage HTML...")
    html = build_html(metrics, failed_ips, failed_users, total,
                      accepted, containers, bans, morning, security, perf, charts)

    subject = MAIL_SUBJECT.format(date=now.strftime("%d/%m/%Y"))
    print(f"[{now:%H:%M:%S}] Envoi à {MAIL_TO}...")
    send_mail(html, subject)

    with open("/home/ubuntu/secops/last_report.html", "w") as f:
        f.write(html)

    print(f"[{now:%H:%M:%S}] ✓ Rapport envoyé et sauvegardé.")

if __name__ == "__main__":
    main()
