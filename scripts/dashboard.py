#!/usr/bin/env python3
"""
ViaDigiTech SOC — Dashboard HTML temps réel
Exécuté toutes les 15 min via cron, servi par Caddy.
v3 : onglets IA, graphique 7 jours, boutons d'action opérationnels.
"""

import os
import json
import subprocess
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import re
import psutil

OUTPUT_FILE  = "/var/www/html/viadigitech-reports/soc/index.html"
AUDIT_LOG    = "/home/ubuntu/secops/audit_actions.csv"
DETECTOR_LOG = "/home/ubuntu/secops/detector.log"
AUTH_LOG     = "/var/log/auth.log"
AI_SUMMARY   = "/home/ubuntu/secops/last_ai_summary.json"
SSH_LOG_LINES = 8000

# Seuils couleur unifiés
WARN_CPU, CRIT_CPU   = 70, 85
WARN_MEM, CRIT_MEM   = 75, 88
WARN_DISK, CRIT_DISK = 75, 88

# URL actions API (Caddy reverse proxy → actions.py:8022)
ACTIONS_API  = "/action"
# Clé API embarquée pour le dashboard (lue depuis env, fallback vide = désactivé)
ACTIONS_KEY  = os.environ.get("SOC_ACTIONS_KEY", "")

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
    cpu   = psutil.cpu_percent(interval=1)
    mem   = psutil.virtual_memory()
    disk  = psutil.disk_usage("/")
    swap  = psutil.swap_memory()
    boot  = datetime.fromtimestamp(psutil.boot_time())
    uptime = datetime.now() - boot
    l1, _, _ = psutil.getloadavg()
    return {
        "cpu": cpu, "load1": round(l1, 2),
        "ram": mem.percent, "ram_used": round(mem.used/1e9, 1), "ram_total": round(mem.total/1e9, 1),
        "disk": disk.percent, "disk_used": round(disk.used/1e9, 1), "disk_total": round(disk.total/1e9, 1),
        "swap_used": round(swap.used/1e9, 1), "swap_total": round(swap.total/1e9, 1),
        "uptime_days": uptime.days, "uptime_hours": uptime.seconds // 3600,
    }

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
    accepted = []
    total = 0
    if not os.path.exists(AUTH_LOG):
        return total, fails, accepted
    with open(AUTH_LOG, errors="ignore") as f:
        lines = f.readlines()[-SSH_LOG_LINES:]
    year = datetime.now().year
    for line in lines:
        try:
            ts = datetime.strptime(line[:15] + f" {year}", "%b %d %H:%M:%S %Y")
        except:
            continue
        if ts < since:
            continue
        if "Failed password" in line or "Invalid user" in line:
            total += 1
            m = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", line)
            if m: fails[m.group(1)] += 1
        elif "Accepted" in line:
            ip  = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            usr = re.search(r"for (\S+) from", line)
            if ip and usr and not ip.group(1).startswith("10."):
                accepted.append({"user": usr.group(1), "ip": ip.group(1)})
    return total, fails, accepted

def get_bans_today():
    today = datetime.now().strftime("%Y-%m-%d")
    if not os.path.exists(AUDIT_LOG):
        return 0
    with open(AUDIT_LOG) as f:
        return sum(1 for l in f if today in l and "BAN_AUTO" in l)

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

def get_bans_history(days=7):
    """Retourne 2 listes [labels, counts] pour les 7 derniers jours depuis audit_actions.csv."""
    labels, bans, watches = [], [], []
    today = datetime.now().date()
    day_bans    = defaultdict(int)
    day_watches = defaultdict(int)
    if os.path.exists(AUDIT_LOG):
        with open(AUDIT_LOG) as f:
            for line in f:
                if line.startswith("timestamp"): continue
                parts = line.strip().split(",", 4)
                if len(parts) < 3: continue
                try:
                    d = parts[0][:10]
                    if "BAN_AUTO" in parts[2] or "BAN_OLLAMA" in parts[2]:
                        day_bans[d] += 1
                    elif "SURVEILLE" in parts[2] or "OLLAMA_" in parts[2]:
                        day_watches[d] += 1
                except:
                    pass
    for i in range(days - 1, -1, -1):
        d = (today - timedelta(days=i)).strftime("%Y-%m-%d")
        labels.append((today - timedelta(days=i)).strftime("%d/%m"))
        bans.append(day_bans.get(d, 0))
        watches.append(day_watches.get(d, 0))
    return labels, bans, watches

def get_detector_log(n=12):
    if not os.path.exists(DETECTOR_LOG):
        return []
    with open(DETECTOR_LOG) as f:
        return f.readlines()[-n:]

def get_docker_containers():
    out = run("sg docker -c \"docker ps --format '{{json .}}'\"")
    if not out:
        out = run("sudo docker ps --format '{{json .}}'")
    containers = []
    for line in out.splitlines():
        try: containers.append(json.loads(line.strip()))
        except: pass
    return containers

def get_ai_summary():
    if not os.path.exists(AI_SUMMARY):
        return None
    try:
        with open(AI_SUMMARY) as f:
            return json.load(f)
    except:
        return None

# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def gc(val, warn, crit):
    if val >= crit: return "#ef4444"
    if val >= warn: return "#f59e0b"
    return "#22c55e"

def gauge(label, val, unit="%", warn=75, crit=88, sub=""):
    color = gc(val, warn, crit)
    sub_html = f"<div style='font-size:10px;color:#475569;margin-top:2px'>{sub}</div>" if sub else ""
    return f"""<div class="gauge">
      <div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:4px">
        <span style="font-size:11px;color:#64748b">{label}</span>
        <span style="font-size:20px;font-weight:700;color:{color}">{val:.1f}{unit}</span>
      </div>
      <div style="background:#1e2942;border-radius:3px;overflow:hidden;height:5px">
        <div style="width:{min(val,100):.0f}%;background:{color};height:5px;border-radius:3px;transition:width .5s"></div>
      </div>
      {sub_html}
    </div>"""

def safe_js(text):
    """Échappe le texte pour injection dans un littéral JS."""
    return text.replace("\\", "\\\\").replace("`", "\\`").replace("${", "\\${")

# ─────────────────────────────────────────
# GÉNÉRATION HTML
# ─────────────────────────────────────────

def build_html():
    now          = datetime.now()
    metrics      = get_metrics()
    ban_count, banned_ips = get_banned_ips()
    ssh_total, ssh_fails, accepted = get_ssh_stats(24)
    bans_today   = get_bans_today()
    audit_rows   = get_audit_recent(15)
    det_log      = get_detector_log(12)
    containers   = get_docker_containers()
    ai_summary   = get_ai_summary()
    hostname     = os.uname().nodename
    hist_labels, hist_bans, hist_watches = get_bans_history(7)

    # Tendance bans : aujourd'hui vs hier
    trend_val  = hist_bans[-1] - hist_bans[-2] if len(hist_bans) >= 2 else 0
    trend_html = ""
    if trend_val > 0:
        trend_html = f"<span style='color:#ef4444;font-size:11px;margin-left:6px'>↑ +{trend_val} vs hier</span>"
    elif trend_val < 0:
        trend_html = f"<span style='color:#22c55e;font-size:11px;margin-left:6px'>↓ {trend_val} vs hier</span>"
    else:
        trend_html = f"<span style='color:#64748b;font-size:11px;margin-left:6px'>= stable</span>"

    # ── Jauges ──
    gauges_html = (
        gauge("CPU", metrics["cpu"], warn=WARN_CPU, crit=CRIT_CPU,
              sub=f"Load {metrics['load1']}") +
        gauge("RAM", metrics["ram"], warn=WARN_MEM, crit=CRIT_MEM,
              sub=f"{metrics['ram_used']}GB / {metrics['ram_total']}GB") +
        gauge("Disque", metrics["disk"], warn=WARN_DISK, crit=CRIT_DISK,
              sub=f"{metrics['disk_used']}GB / {metrics['disk_total']}GB") +
        gauge("Swap", metrics["swap_used"] / max(metrics["swap_total"], 0.1) * 100,
              sub=f"{metrics['swap_used']}GB / {metrics['swap_total']}GB",
              warn=60, crit=80)
    )

    # ── Top IPs ──
    top_ip_rows = ""
    for ip, count in ssh_fails.most_common(10):
        is_banned = "🔴" if ip in banned_ips else "🟡"
        action_btn = ""
        if ACTIONS_KEY:
            action_btn = f"""<button onclick="banIP('{ip}')" style="background:#7f1d1d;border:none;color:#fca5a5;padding:2px 8px;border-radius:4px;font-size:10px;cursor:pointer;margin-left:4px">Bannir</button>"""
        top_ip_rows += f"<tr><td style='font-family:monospace;font-size:12px'>{is_banned} {ip}{action_btn}</td><td style='text-align:right;font-weight:700;color:#ef4444'>{count}</td></tr>"

    # ── Connexions légitimes ──
    accepted_html = ""
    for a in accepted[-5:]:
        accepted_html += f"<tr><td style='color:#22c55e;font-size:11px'>✓</td><td style='font-family:monospace;font-size:12px'>{a['ip']}</td><td style='font-size:12px;color:#94a3b8'>{a['user']}</td></tr>"

    # ── Audit ──
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
        unban_btn = ""
        if ACTIONS_KEY and ("BAN" in action):
            unban_btn = f"""<button onclick="unbanIP('{ip}')" style="background:#14532d;border:none;color:#86efac;padding:1px 6px;border-radius:4px;font-size:10px;cursor:pointer;margin-left:4px">Débannir</button>"""
        audit_html += f"<tr><td style='color:#64748b;font-size:11px;white-space:nowrap'>{ts}</td><td style='font-family:monospace;font-size:11px'>{ip}</td><td>{badge}{unban_btn}</td><td style='text-align:right;color:#f59e0b;font-size:12px'>{score}%</td></tr>"

    # ── Containers ──
    containers_html = ""
    for c in containers[:12]:
        name   = (c.get("Names") or c.get("Name", "?"))[:22]
        image  = c.get("Image", "?").split("/")[-1][:28]
        status = c.get("Status", "?")[:22]
        color  = "#22c55e" if "Up" in status else "#ef4444"
        containers_html += f"""<div class="container-card">
          <div style="font-weight:600;color:#a5b4fc;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{name}</div>
          <div style="font-size:10px;color:#475569;margin-top:1px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{image}</div>
          <div style="font-size:11px;color:{color};margin-top:3px">● {status}</div>
        </div>"""

    # ── Log détecteur ──
    det_html = ""
    for l in det_log:
        line = l.strip()
        color = "#ef4444" if "alerte(s)" in line or "AutoBan" in line else ("#22c55e" if "Aucune alerte" in line else "#64748b")
        det_html += f"<div style='font-size:11px;color:{color};line-height:1.7;font-family:monospace'>{line}</div>"

    # ── Onglets IA ──
    ai_tabs_html = ""
    if ai_summary:
        date_r   = ai_summary.get("date", "—")
        ai_new_btn = "<button onclick=\"askAI()\" style='background:#312e81;border:1px solid #4338ca;color:#a5b4fc;padding:5px 14px;border-radius:6px;font-size:12px;cursor:pointer'>&#x26A1; Nouvelle analyse</button>" if ACTIONS_KEY else ""

        def fmt_ai(text):
            return text.replace("\n", "<br>").replace("  ", "&nbsp;&nbsp;")

        ai_morning_html  = fmt_ai(ai_summary.get("morning", "Non disponible"))
        ai_security_html = fmt_ai(ai_summary.get("security", "Non disponible"))
        ai_perf_html     = fmt_ai(ai_summary.get("perf", "Non disponible"))

        ai_tabs_html = f"""
<div class="card" style="border-left:3px solid #818cf8;margin-bottom:14px">
  <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:14px">
    <h2 style="margin:0">&#x1F916; Analyse IA — {date_r}</h2>
    {ai_new_btn}
  </div>
  <div style="display:flex;gap:8px;margin-bottom:12px;border-bottom:1px solid #1e2942;padding-bottom:10px">
    <button onclick="showTab('tab-morning')" id="btn-morning" class="tab-btn tab-active">Synthèse</button>
    <button onclick="showTab('tab-security')" id="btn-security" class="tab-btn">Sécurité</button>
    <button onclick="showTab('tab-perf')" id="btn-perf" class="tab-btn">Performance</button>
  </div>
  <div id="tab-morning" class="tab-pane" style="background:#0a0d14;border:1px solid #1e2942;border-radius:8px;padding:14px;font-size:13px;line-height:1.75;color:#e2e8f0">
    {ai_morning_html}
  </div>
  <div id="tab-security" class="tab-pane" style="display:none;background:#0a0d14;border:1px solid #1e2942;border-radius:8px;padding:14px;font-size:13px;line-height:1.75;color:#e2e8f0">
    {ai_security_html}
  </div>
  <div id="tab-perf" class="tab-pane" style="display:none;background:#0a0d14;border:1px solid #1e2942;border-radius:8px;padding:14px;font-size:13px;line-height:1.75;color:#e2e8f0">
    {ai_perf_html}
  </div>
</div>"""
    else:
        ai_tabs_html = """<div class="card" style="margin-bottom:14px;border-left:3px solid #334155">
          <h2>🤖 Analyse IA</h2>
          <div style="color:#475569;font-size:13px;padding:10px 0">Rapport IA non disponible — sera généré demain à 7h</div>
        </div>"""

    # ── Graphique 7 jours ──
    hist_labels_js = json.dumps(hist_labels)
    hist_bans_js   = json.dumps(hist_bans)
    hist_watch_js  = json.dumps(hist_watches)

    # Couleurs stat cards
    cpu_color  = gc(metrics["cpu"],  WARN_CPU,  CRIT_CPU)
    ram_color  = gc(metrics["ram"],  WARN_MEM,  CRIT_MEM)
    disk_color = gc(metrics["disk"], WARN_DISK, CRIT_DISK)

    # JS actions (seulement si clé configurée)
    actions_js = ""
    if ACTIONS_KEY:
        actions_js = f"""
async function apiCall(endpoint, data) {{
  const res = await fetch('{ACTIONS_API}' + endpoint, {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json', 'X-SOC-Key': '{ACTIONS_KEY}'}},
    body: JSON.stringify(data)
  }});
  return res.json();
}}

async function banIP(ip) {{
  if (!confirm(`Bannir l'IP ${{ip}} via Fail2Ban ?`)) return;
  const r = await apiCall('/ban', {{ip}});
  showToast(r.ok ? `✓ ${{ip}} bannie` : `Erreur: ${{r.error}}`, r.ok);
}}

async function unbanIP(ip) {{
  if (!confirm(`Débannir l'IP ${{ip}} ?`)) return;
  const r = await apiCall('/unban', {{ip}});
  showToast(r.ok ? `✓ ${{ip}} débannie` : `Erreur: ${{r.error}}`, r.ok);
}}

async function askAI() {{
  const prompt = window.prompt('Question pour le SOC IA :', 'Quel est le niveau de risque actuel sur le serveur ?');
  if (!prompt) return;
  showToast('Analyse en cours...', true, 3000);
  const r = await apiCall('/analyze', {{prompt}});
  if (r.ok) {{
    document.getElementById('ai-response-box').style.display = 'block';
    document.getElementById('ai-response-text').innerHTML = r.response.replace(/\\n/g,'<br>');
  }} else {{
    showToast('Erreur IA : ' + r.error, false);
  }}
}}

function showToast(msg, ok, duration=4000) {{
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.style.background = ok ? '#14532d' : '#7f1d1d';
  t.style.color = ok ? '#86efac' : '#fca5a5';
  t.style.display = 'block';
  setTimeout(() => t.style.display = 'none', duration);
}}
"""

    html = f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="300">
<title>SOC Dashboard — {hostname}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  * {{ box-sizing:border-box; margin:0; padding:0 }}
  body {{ font-family:-apple-system,'Segoe UI',sans-serif; background:#0a0d14; color:#e2e8f0; padding:16px }}
  h2 {{ font-size:11px; text-transform:uppercase; letter-spacing:1.5px; color:#475569; margin-bottom:12px; font-weight:600 }}
  .grid {{ display:grid; gap:14px }}
  .g2 {{ grid-template-columns:repeat(2,1fr) }}
  .g3 {{ grid-template-columns:repeat(3,1fr) }}
  .g4 {{ grid-template-columns:repeat(4,1fr) }}
  .g6 {{ grid-template-columns:repeat(6,1fr) }}
  @media(max-width:900px){{ .g2,.g3,.g4,.g6 {{ grid-template-columns:1fr }} }}
  @media(min-width:901px) and (max-width:1200px){{ .g6 {{ grid-template-columns:repeat(3,1fr) }} }}
  .card {{ background:#111827; border:1px solid #1e2942; border-radius:12px; padding:16px }}
  .stat-big {{ font-size:28px; font-weight:700; line-height:1 }}
  .stat-label {{ font-size:11px; color:#64748b; margin-top:4px }}
  .stat-sub {{ font-size:10px; color:#334155; margin-top:2px }}
  table {{ width:100%; border-collapse:collapse; font-size:13px }}
  td,th {{ padding:7px 8px; border-bottom:1px solid #1e2942 }}
  th {{ color:#64748b; font-size:11px; text-transform:uppercase; font-weight:600 }}
  tr:last-child td {{ border-bottom:none }}
  .gauge {{ margin-bottom:12px }}
  .container-card {{ background:#0a0d14; border:1px solid #1e2942; border-radius:8px; padding:10px; margin-bottom:6px }}
  .header-bar {{ background:linear-gradient(135deg,#1e1b4b,#0f172a); border:1px solid #312e81; border-radius:12px; padding:16px 20px; margin-bottom:16px }}
  .tab-btn {{ background:#0a0d14; border:1px solid #1e2942; color:#64748b; padding:5px 14px; border-radius:6px; font-size:12px; cursor:pointer; transition:all .2s }}
  .tab-btn:hover {{ border-color:#4338ca; color:#a5b4fc }}
  .tab-active {{ background:#1e1b4b; border-color:#4338ca; color:#a5b4fc; font-weight:600 }}
  #toast {{ display:none; position:fixed; bottom:20px; right:20px; padding:10px 18px; border-radius:8px; font-size:13px; font-weight:600; z-index:9999; box-shadow:0 4px 12px rgba(0,0,0,.5) }}
  #ai-response-box {{ display:none; margin-top:12px; background:#0a0d14; border:1px solid #312e81; border-radius:8px; padding:14px; font-size:13px; line-height:1.75; color:#e2e8f0 }}
</style>
</head><body>

<div id="toast"></div>

<!-- HEADER -->
<div class="header-bar">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:10px">
    <div>
      <div style="font-size:17px;font-weight:700;color:#a5b4fc">🛡️ ViaDigiTech SOC Dashboard</div>
      <div style="font-size:11px;color:#475569;margin-top:4px">{hostname} &nbsp;·&nbsp; {now.strftime('%d/%m/%Y %H:%M:%S')} &nbsp;·&nbsp; Actualisation auto 5 min</div>
    </div>
    <div style="display:flex;gap:16px;flex-wrap:wrap;align-items:center">
      <div style="text-align:right">
        <div style="font-size:10px;color:#475569">Uptime</div>
        <div style="font-size:15px;font-weight:700;color:#94a3b8">{metrics['uptime_days']}j {metrics['uptime_hours']}h</div>
      </div>
      <div style="text-align:right">
        <div style="font-size:10px;color:#475569">Auto-bans aujourd'hui</div>
        <div style="font-size:22px;font-weight:700;color:#ef4444">{bans_today}{trend_html}</div>
      </div>
      <div style="text-align:right">
        <div style="font-size:10px;color:#475569">SSH échecs 24h</div>
        <div style="font-size:22px;font-weight:700;color:{'#ef4444' if ssh_total > 200 else '#f59e0b' if ssh_total > 50 else '#22c55e'}">{ssh_total}</div>
      </div>
    </div>
  </div>
</div>

<!-- STAT CARDS -->
<div class="grid g6" style="margin-bottom:14px">
  <div class="card">
    <div class="stat-big" style="color:{cpu_color}">{metrics['cpu']:.0f}%</div>
    <div class="stat-label">CPU</div>
    <div class="stat-sub">Load {metrics['load1']}</div>
  </div>
  <div class="card">
    <div class="stat-big" style="color:{ram_color}">{metrics['ram']:.0f}%</div>
    <div class="stat-label">RAM</div>
    <div class="stat-sub">{metrics['ram_used']}GB / {metrics['ram_total']}GB</div>
  </div>
  <div class="card">
    <div class="stat-big" style="color:{disk_color}">{metrics['disk']:.0f}%</div>
    <div class="stat-label">Disque</div>
    <div class="stat-sub">{metrics['disk_used']}GB / {metrics['disk_total']}GB</div>
  </div>
  <div class="card">
    <div class="stat-big" style="color:#ef4444">{ban_count}</div>
    <div class="stat-label">IPs bannies (Fail2Ban)</div>
  </div>
  <div class="card">
    <div class="stat-big" style="color:#f59e0b">{ssh_total}</div>
    <div class="stat-label">Échecs SSH 24h</div>
    <div class="stat-sub">{len(ssh_fails)} IPs distinctes</div>
  </div>
  <div class="card">
    <div class="stat-big" style="color:#a5b4fc">{len(containers)}</div>
    <div class="stat-label">Containers Docker</div>
    <div class="stat-sub">{sum(1 for c in containers if 'Up' in c.get('Status',''))} actifs</div>
  </div>
</div>

<!-- ANALYSE IA (onglets) -->
{ai_tabs_html}

<!-- Réponse IA à la demande -->
<div id="ai-response-box" style="margin-bottom:14px">
  <h2 style="margin-bottom:8px">⚡ Réponse IA temps réel</h2>
  <div id="ai-response-text"></div>
</div>

<!-- GRAPHIQUE 7 JOURS + MÉTRIQUES -->
<div class="grid g2" style="margin-bottom:14px">
  <div class="card">
    <h2>Activité — 7 derniers jours</h2>
    <canvas id="histChart" height="180"></canvas>
  </div>
  <div class="card">
    <h2>Métriques système</h2>
    {gauges_html}
  </div>
</div>

<!-- TOP IPs + AUDIT -->
<div class="grid g2" style="margin-bottom:14px">
  <div class="card">
    <h2>Top IPs attaquantes 24h</h2>
    {"<div style='color:#475569;font-size:13px'>Aucune activité</div>" if not top_ip_rows else f"<table><thead><tr><th>IP</th><th style='text-align:right'>Tentatives</th></tr></thead><tbody>{top_ip_rows}</tbody></table>"}
    {f'<div style="margin-top:14px"><h2>Connexions légitimes 24h</h2><table><thead><tr><th></th><th>IP</th><th>Utilisateur</th></tr></thead><tbody>{accepted_html}</tbody></table></div>' if accepted_html else ""}
  </div>
  <div class="card">
    <h2>Journal d'audit (dernières actions)</h2>
    {"<div style='color:#475569;font-size:13px'>Aucune action</div>" if not audit_html else f"<table><thead><tr><th>Heure</th><th>IP</th><th>Action</th><th style='text-align:right'>Score</th></tr></thead><tbody>{audit_html}</tbody></table>"}
  </div>
</div>

<!-- CONTAINERS + LOG DÉTECTEUR -->
<div class="grid g2" style="margin-bottom:14px">
  <div class="card">
    <h2>Conteneurs Docker ({len(containers)})</h2>
    <div style="max-height:280px;overflow-y:auto">
      {containers_html or '<div style="color:#475569;font-size:13px">Aucun container détecté</div>'}
    </div>
  </div>
  <div class="card">
    <h2>Log détecteur (15 min)</h2>
    <div style="background:#0a0d14;border-radius:8px;padding:12px;max-height:280px;overflow-y:auto">
      {det_html or '<div style="color:#475569;font-size:13px">Aucun log</div>'}
    </div>
  </div>
</div>

<!-- FOOTER -->
<div style="text-align:center;font-size:11px;color:#1e2942;padding:10px;border-top:1px solid #111827;margin-top:4px">
  ViaDigiTech AI SecOps · {hostname} · dashboard 15min · seuils CPU {WARN_CPU}/{CRIT_CPU}% · RAM {WARN_MEM}/{CRIT_MEM}% · Disk {WARN_DISK}/{CRIT_DISK}%
</div>

<script>
// ── Onglets IA ──
function showTab(id) {{
  document.querySelectorAll('.tab-pane').forEach(p => p.style.display = 'none');
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('tab-active'));
  document.getElementById(id).style.display = 'block';
  const btnId = 'btn-' + id.replace('tab-','');
  const btn = document.getElementById(btnId);
  if (btn) btn.classList.add('tab-active');
}}

// ── Graphique 7 jours ──
(function() {{
  const ctx = document.getElementById('histChart').getContext('2d');
  new Chart(ctx, {{
    type: 'bar',
    data: {{
      labels: {hist_labels_js},
      datasets: [
        {{
          label: 'Bans auto',
          data: {hist_bans_js},
          backgroundColor: 'rgba(239,68,68,0.7)',
          borderColor: '#ef4444',
          borderWidth: 1,
          borderRadius: 4,
        }},
        {{
          label: 'Surveillés',
          data: {hist_watch_js},
          backgroundColor: 'rgba(99,102,241,0.5)',
          borderColor: '#6366f1',
          borderWidth: 1,
          borderRadius: 4,
        }}
      ]
    }},
    options: {{
      responsive: true,
      plugins: {{
        legend: {{ labels: {{ color: '#94a3b8', font: {{ size: 11 }} }} }},
        tooltip: {{ mode: 'index' }}
      }},
      scales: {{
        x: {{ ticks: {{ color: '#64748b' }}, grid: {{ color: '#1e2942' }} }},
        y: {{ ticks: {{ color: '#64748b' }}, grid: {{ color: '#1e2942' }}, beginAtZero: true }}
      }}
    }}
  }});
}})();

// ── Actions API ──
{actions_js}
</script>

</body></html>"""
    return html

# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────

if __name__ == "__main__":
    html = build_html()
    with open(OUTPUT_FILE, "w") as f:
        f.write(html)
    print(f"[{datetime.now():%H:%M:%S}] Dashboard v3 généré → {OUTPUT_FILE}")
