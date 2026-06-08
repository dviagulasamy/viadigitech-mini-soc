#!/usr/bin/env python3
"""
ViaDigiTech SOC — Dashboard HTML temps réel
Exécuté toutes les 15 min via cron, servi par Nginx Proxy Manager.
v5 : navigation multi-écrans (Overview / Sécurité / Performance / IA / Infrastructure).
"""

import os
import json
import subprocess
import urllib.request
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import re
import psutil

OUTPUT_FILE  = "/var/www/html/viadigitech-reports/soc/index.html"
AUDIT_LOG    = "/home/ubuntu/secops/audit_actions.csv"
DETECTOR_LOG = "/home/ubuntu/secops/detector.log"
AUTH_LOG     = "/var/log/auth.log"
AI_SUMMARY   = "/home/ubuntu/secops/last_ai_summary.json"
METRICS_CSV  = "/home/ubuntu/secops/metrics_history.csv"
GEO_CACHE    = "/home/ubuntu/secops/geo_cache.json"
SSH_LOG_LINES = 8000

WARN_CPU, CRIT_CPU   = 70, 85
WARN_MEM, CRIT_MEM   = 75, 88
WARN_DISK, CRIT_DISK = 75, 88

ACTIONS_API = "/action"
ACTIONS_KEY = os.environ.get("SOC_ACTIONS_KEY", "")

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
    swap = psutil.swap_memory()
    boot = datetime.fromtimestamp(psutil.boot_time())
    uptime = datetime.now() - boot
    l1, _, _ = psutil.getloadavg()
    return {
        "cpu": cpu, "load1": round(l1, 2),
        "ram": mem.percent, "ram_used": round(mem.used/1e9,1), "ram_total": round(mem.total/1e9,1),
        "disk": disk.percent, "disk_used": round(disk.used/1e9,1), "disk_total": round(disk.total/1e9,1),
        "swap_used": round(swap.used/1e9,1), "swap_total": round(swap.total/1e9,1),
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

def get_audit_recent(n=20):
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

def get_detector_log(n=20):
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

def append_metrics_history(metrics):
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
    new_line = f"{now_str},{metrics['cpu']:.1f},{metrics['ram']:.1f},{metrics['disk']:.1f}\n"
    cutoff = datetime.now() - timedelta(days=7)
    rows = []
    if os.path.exists(METRICS_CSV):
        with open(METRICS_CSV) as f:
            for l in f:
                if l.startswith("timestamp"): continue
                try:
                    ts = datetime.strptime(l[:16], "%Y-%m-%d %H:%M")
                    if ts >= cutoff:
                        rows.append(l)
                except:
                    pass
    rows.append(new_line)
    with open(METRICS_CSV, "w") as f:
        f.write("timestamp,cpu,ram,disk\n")
        f.writelines(rows)

def get_metrics_history(hours=24):
    if not os.path.exists(METRICS_CSV):
        return [], [], [], []
    cutoff = datetime.now() - timedelta(hours=hours)
    labels, cpu_v, ram_v, disk_v = [], [], [], []
    with open(METRICS_CSV) as f:
        for line in f:
            if line.startswith("timestamp"): continue
            parts = line.strip().split(",")
            if len(parts) < 4: continue
            try:
                ts = datetime.strptime(parts[0], "%Y-%m-%d %H:%M")
                if ts < cutoff: continue
                labels.append(ts.strftime("%H:%M"))
                cpu_v.append(float(parts[1]))
                ram_v.append(float(parts[2]))
                disk_v.append(float(parts[3]))
            except:
                pass
    return labels, cpu_v, ram_v, disk_v

def get_service_status():
    services = [
        ("fail2ban",     "Fail2Ban"),
        ("postfix",      "Postfix"),
        ("soc-actions",  "SOC Actions"),
        ("soc-dashboard","SOC Dashboard"),
        ("ollama",       "Ollama"),
    ]
    result = []
    for svc, label in services:
        status = run(f"systemctl is-active {svc} 2>/dev/null").strip()
        result.append((label, status))
    return result

def get_geo_data(ips):
    cache = {}
    if os.path.exists(GEO_CACHE):
        try:
            with open(GEO_CACHE) as f:
                cache = json.load(f)
        except:
            pass
    to_lookup = [ip for ip in ips if ip not in cache][:20]
    if to_lookup:
        try:
            payload = json.dumps([
                {"query": ip, "fields": "query,lat,lon,country,city,countryCode,status"}
                for ip in to_lookup
            ]).encode()
            req = urllib.request.Request(
                "http://ip-api.com/batch", data=payload,
                headers={"Content-Type": "application/json"}, method="POST"
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                for item in json.loads(resp.read()):
                    if item.get("status") != "fail":
                        cache[item["query"]] = {
                            "lat": item.get("lat", 0), "lon": item.get("lon", 0),
                            "country": item.get("country", "?"),
                            "city": item.get("city", ""),
                            "cc": item.get("countryCode", "")
                        }
        except:
            pass
        try:
            with open(GEO_CACHE, "w") as f:
                json.dump(cache, f)
        except:
            pass
    return {ip: cache[ip] for ip in ips if ip in cache}

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

# ─────────────────────────────────────────
# BUILD HTML
# ─────────────────────────────────────────

def build_html():
    now        = datetime.now()
    metrics    = get_metrics()
    append_metrics_history(metrics)
    ban_count, banned_ips = get_banned_ips()
    ssh_total, ssh_fails, accepted = get_ssh_stats(24)
    bans_today = get_bans_today()
    audit_rows = get_audit_recent(20)
    det_log    = get_detector_log(20)
    containers = get_docker_containers()
    ai_summary = get_ai_summary()
    hostname   = os.uname().nodename
    hist_labels, hist_bans, hist_watches = get_bans_history(7)
    srv_status = get_service_status()
    perf_labels, perf_cpu, perf_ram, perf_disk = get_metrics_history(24)
    top_ips    = [ip for ip, _ in ssh_fails.most_common(20)]
    geo_data   = get_geo_data(top_ips)

    # ── Badges services (résumé header) ──
    svc_down = [l for l, s in srv_status if s != "active"]
    svc_badge = ""
    if svc_down:
        svc_badge = f"<span style='background:#7f1d1d;color:#fca5a5;border-radius:6px;padding:2px 10px;font-size:11px;font-weight:600'>⚠ {len(svc_down)} service(s) KO</span>"

    # ── Alertes ──
    alert_banners = ""
    if metrics["disk"] >= CRIT_DISK:
        alert_banners += f'<div class="alert-banner alert-crit">🔴 DISQUE CRITIQUE — {metrics["disk"]:.1f}% utilisé ({metrics["disk_used"]}GB / {metrics["disk_total"]}GB)</div>'
    elif metrics["disk"] >= WARN_DISK:
        alert_banners += f'<div class="alert-banner alert-warn">🟠 DISQUE AVERTISSEMENT — {metrics["disk"]:.1f}% utilisé</div>'
    if metrics["ram"] >= CRIT_MEM:
        alert_banners += f'<div class="alert-banner alert-crit">🔴 RAM CRITIQUE — {metrics["ram"]:.1f}% ({metrics["ram_used"]}GB / {metrics["ram_total"]}GB)</div>'

    # ── Tendance bans ──
    trend_val = hist_bans[-1] - hist_bans[-2] if len(hist_bans) >= 2 else 0
    if trend_val > 0:
        trend_html = f"<span style='color:#ef4444;font-size:11px;margin-left:6px'>↑ +{trend_val} vs hier</span>"
    elif trend_val < 0:
        trend_html = f"<span style='color:#22c55e;font-size:11px;margin-left:6px'>↓ {trend_val} vs hier</span>"
    else:
        trend_html = "<span style='color:#64748b;font-size:11px;margin-left:6px'>= stable</span>"

    cpu_color  = gc(metrics["cpu"],  WARN_CPU,  CRIT_CPU)
    ram_color  = gc(metrics["ram"],  WARN_MEM,  CRIT_MEM)
    disk_color = gc(metrics["disk"], WARN_DISK, CRIT_DISK)

    # ── Jauges ──
    gauges_html = (
        gauge("CPU",    metrics["cpu"],  warn=WARN_CPU,  crit=CRIT_CPU,  sub=f"Load {metrics['load1']}") +
        gauge("RAM",    metrics["ram"],  warn=WARN_MEM,  crit=CRIT_MEM,  sub=f"{metrics['ram_used']}GB / {metrics['ram_total']}GB") +
        gauge("Disque", metrics["disk"], warn=WARN_DISK, crit=CRIT_DISK, sub=f"{metrics['disk_used']}GB / {metrics['disk_total']}GB") +
        gauge("Swap",   metrics["swap_used"]/max(metrics["swap_total"],0.1)*100,
              sub=f"{metrics['swap_used']}GB / {metrics['swap_total']}GB", warn=60, crit=80)
    )

    # ── Statut services (écran Overview) ──
    services_cards = ""
    for label, status in srv_status:
        ok = status == "active"
        services_cards += f"""<div style="background:{'#0d2318' if ok else '#2d0a0a'};border:1px solid {'#166534' if ok else '#7f1d1d'};border-radius:8px;padding:10px 14px;display:flex;align-items:center;gap:10px">
          <span style="color:{'#22c55e' if ok else '#ef4444'};font-size:16px">{'●' if ok else '✕'}</span>
          <div><div style="font-size:12px;font-weight:600;color:#e2e8f0">{label}</div>
          <div style="font-size:10px;color:{'#22c55e' if ok else '#ef4444'}">{status}</div></div>
        </div>"""

    # ── Top IPs ──
    top_ip_rows = ""
    for ip, count in ssh_fails.most_common(15):
        is_banned = "🔴" if ip in banned_ips else "🟡"
        geo = geo_data.get(ip, {})
        loc = f"<span style='color:#475569;font-size:10px;margin-left:6px'>{geo.get('cc','')} {geo.get('city','')}</span>" if geo else ""
        btn = f"""<button onclick="banIP('{ip}')" class="btn-danger">Bannir</button>""" if ACTIONS_KEY else ""
        top_ip_rows += f"<tr><td style='font-family:monospace;font-size:12px'>{is_banned} {ip}{loc}{btn}</td><td style='text-align:right;font-weight:700;color:#ef4444'>{count}</td></tr>"

    # ── Connexions légitimes ──
    accepted_html = ""
    for a in accepted[-8:]:
        accepted_html += f"<tr><td style='color:#22c55e;font-size:11px'>✓</td><td style='font-family:monospace;font-size:12px'>{a['ip']}</td><td style='font-size:12px;color:#94a3b8'>{a['user']}</td></tr>"

    # ── Audit ──
    audit_html = ""
    for row in audit_rows:
        ts = row[0][11:16] if len(row[0]) > 11 else row[0]
        ip, action, score = row[1], row[2], row[3]
        if "BAN_AUTO" in action or "BAN_OLLAMA" in action:
            badge = f"<span class='badge badge-red'>{action}</span>"
        elif "DRYRUN" in action:
            badge = f"<span class='badge badge-orange'>{action}</span>"
        elif "OLLAMA" in action:
            badge = f"<span class='badge badge-purple'>{action}</span>"
        else:
            badge = f"<span class='badge badge-gray'>{action}</span>"
        unban_btn = f"""<button onclick="unbanIP('{ip}')" class="btn-success">Débannir</button>""" if ACTIONS_KEY and "BAN" in action else ""
        audit_html += f"<tr><td style='color:#64748b;font-size:11px;white-space:nowrap'>{ts}</td><td style='font-family:monospace;font-size:11px'>{ip}</td><td>{badge}{unban_btn}</td><td style='text-align:right;color:#f59e0b;font-size:12px'>{score}%</td></tr>"

    # ── Containers ──
    containers_html = ""
    for c in containers:
        name   = (c.get("Names") or c.get("Name","?"))[:26]
        image  = c.get("Image","?").split("/")[-1][:30]
        status = c.get("Status","?")[:24]
        ports  = c.get("Ports","")[:40]
        color  = "#22c55e" if "Up" in status else "#ef4444"
        containers_html += f"""<div class="container-card">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <div style="font-weight:600;color:#a5b4fc;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:60%">{name}</div>
            <div style="font-size:11px;color:{color}">● {status}</div>
          </div>
          <div style="font-size:10px;color:#475569;margin-top:2px">{image}</div>
          {'<div style="font-size:10px;color:#334155;margin-top:2px">' + ports + '</div>' if ports else ''}
        </div>"""

    # ── Log détecteur ──
    det_html = ""
    for l in det_log:
        line = l.strip()
        color = "#ef4444" if "alerte(s)" in line or "AutoBan" in line else ("#22c55e" if "Aucune alerte" in line else "#64748b")
        det_html += f"<div style='font-size:11px;color:{color};line-height:1.8;font-family:monospace'>{line}</div>"

    # ── IA ──
    if ai_summary:
        date_r = ai_summary.get("date","—")
        ai_new_btn = "<button onclick='askAI()' class='btn-primary'>⚡ Nouvelle analyse</button>" if ACTIONS_KEY else ""
        def fmt(t): return t.replace("\n","<br>").replace("  ","&nbsp;&nbsp;")
        ai_screen_html = f"""
<div class="card" style="border-left:3px solid #818cf8;margin-bottom:14px">
  <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:14px">
    <h2 style="margin:0">🤖 Analyse IA — {date_r}</h2>
    {ai_new_btn}
  </div>
  <div style="display:flex;gap:8px;margin-bottom:12px;border-bottom:1px solid #1e2942;padding-bottom:10px">
    <button onclick="showTab('tab-morning')" id="btn-morning" class="tab-btn tab-active">Synthèse</button>
    <button onclick="showTab('tab-security')" id="btn-security" class="tab-btn">Sécurité</button>
    <button onclick="showTab('tab-perf')" id="btn-perf" class="tab-btn">Performance</button>
  </div>
  <div id="tab-morning" class="tab-pane" style="background:#0a0d14;border:1px solid #1e2942;border-radius:8px;padding:16px;font-size:13px;line-height:1.85;color:#e2e8f0">{fmt(ai_summary.get("morning","Non disponible"))}</div>
  <div id="tab-security" class="tab-pane" style="display:none;background:#0a0d14;border:1px solid #1e2942;border-radius:8px;padding:16px;font-size:13px;line-height:1.85;color:#e2e8f0">{fmt(ai_summary.get("security","Non disponible"))}</div>
  <div id="tab-perf" class="tab-pane" style="display:none;background:#0a0d14;border:1px solid #1e2942;border-radius:8px;padding:16px;font-size:13px;line-height:1.85;color:#e2e8f0">{fmt(ai_summary.get("perf","Non disponible"))}</div>
</div>
<div id="ai-response-box" style="display:none;margin-bottom:14px">
  <div class="card" style="border-left:3px solid #4338ca">
    <h2 style="margin-bottom:10px">⚡ Réponse IA temps réel</h2>
    <div id="ai-response-text" style="font-size:13px;line-height:1.85;color:#e2e8f0"></div>
  </div>
</div>"""
    else:
        ai_screen_html = """<div class="card" style="border-left:3px solid #334155">
          <h2>🤖 Analyse IA</h2>
          <div style="color:#475569;font-size:13px;padding:16px 0;text-align:center">Rapport IA non disponible — sera généré demain à 7h UTC</div>
        </div>"""

    # ── Données JS ──
    hist_labels_js = json.dumps(hist_labels)
    hist_bans_js   = json.dumps(hist_bans)
    hist_watch_js  = json.dumps(hist_watches)
    perf_labels_js = json.dumps(perf_labels)
    perf_cpu_js    = json.dumps(perf_cpu)
    perf_ram_js    = json.dumps(perf_ram)
    perf_disk_js   = json.dumps(perf_disk)

    # Marqueurs Leaflet
    geo_markers_js = ""
    for ip, count in ssh_fails.most_common(20):
        geo = geo_data.get(ip)
        if not geo: continue
        lat, lon     = geo["lat"], geo["lon"]
        country      = geo.get("country","?").replace("'","\\'")
        city         = geo.get("city","").replace("'","\\'")
        radius       = min(5 + count // 8, 22)
        opacity      = min(0.4 + count / 200, 0.85)
        geo_markers_js += (
            f"L.circleMarker([{lat},{lon}],"
            f"{{radius:{radius},color:'#ef4444',fillColor:'#ef4444',"
            f"fillOpacity:{opacity:.2f},weight:1.5}})"
            f".addTo(map)"
            f".bindPopup('<b style=\"font-family:monospace\">{ip}</b>"
            f"<br><span style=\"color:#94a3b8\">{country} {city}</span>"
            f"<br><b style=\"color:#ef4444\">{count} tentatives</b>');\n"
        )

    # ── JS Actions ──
    actions_js = ""
    if ACTIONS_KEY:
        actions_js = f"""
function getKey(){{
  let k=sessionStorage.getItem('soc_api_key');
  if(!k){{k=window.prompt('Clé API SOC :')||'';if(k)sessionStorage.setItem('soc_api_key',k);}}
  return k;
}}
async function apiCall(ep,data){{
  const key=getKey();
  if(!key)return{{ok:false,error:'Clé manquante'}};
  const res=await fetch('{ACTIONS_API}'+ep,{{method:'POST',headers:{{'Content-Type':'application/json','X-SOC-Key':key}},body:JSON.stringify(data)}});
  const r=await res.json();
  if(res.status===401||res.status===403){{sessionStorage.removeItem('soc_api_key');return{{ok:false,error:'Clé invalide'}};}}
  return r;
}}
async function banIP(ip){{if(!confirm(`Bannir ${{ip}} ?`))return;const r=await apiCall('/ban',{{ip}});showToast(r.ok?`✓ ${{ip}} bannie`:`Erreur: ${{r.error}}`,r.ok);}}
async function unbanIP(ip){{if(!confirm(`Débannir ${{ip}} ?`))return;const r=await apiCall('/unban',{{ip}});showToast(r.ok?`✓ ${{ip}} débannie`:`Erreur: ${{r.error}}`,r.ok);}}
async function askAI(){{
  window.pauseRefresh();
  const p=window.prompt('Question SOC IA :','Quel est le niveau de risque actuel ?');
  window.resumeRefresh();
  if(!p)return;
  showToast('Analyse en cours...',true,4000);
  const r=await apiCall('/analyze',{{prompt:p}});
  if(r.ok){{document.getElementById('ai-response-box').style.display='block';document.getElementById('ai-response-text').innerHTML=r.response.replace(/\\n/g,'<br>');}}
  else showToast('Erreur IA : '+r.error,false);
}}"""

    html = f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SOC — {hostname}</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,'Segoe UI',sans-serif;background:#0a0d14;color:#e2e8f0;display:flex;flex-direction:column;min-height:100vh}}
h2{{font-size:11px;text-transform:uppercase;letter-spacing:1.5px;color:#475569;margin-bottom:12px;font-weight:600}}
/* ── Navigation ── */
.topbar{{background:#0d1117;border-bottom:1px solid #1e2942;padding:0 20px;display:flex;align-items:center;gap:0;position:sticky;top:0;z-index:1000}}
.topbar-brand{{font-size:14px;font-weight:700;color:#a5b4fc;padding:14px 20px 14px 0;border-right:1px solid #1e2942;margin-right:8px;white-space:nowrap}}
.nav-item{{padding:14px 16px;font-size:12px;font-weight:500;color:#475569;cursor:pointer;border-bottom:2px solid transparent;transition:all .2s;white-space:nowrap;user-select:none}}
.nav-item:hover{{color:#94a3b8;border-bottom-color:#334155}}
.nav-item.active{{color:#a5b4fc;border-bottom-color:#6366f1;font-weight:600}}
.topbar-right{{margin-left:auto;display:flex;align-items:center;gap:12px;font-size:11px;color:#334155;padding-left:16px}}
/* ── Layout ── */
.main{{flex:1;padding:16px 20px}}
.screen{{display:none}}
.screen.active{{display:block}}
/* ── Grilles ── */
.grid{{display:grid;gap:14px}}
.g2{{grid-template-columns:repeat(2,1fr)}}
.g3{{grid-template-columns:repeat(3,1fr)}}
.g4{{grid-template-columns:repeat(4,1fr)}}
.g5{{grid-template-columns:repeat(5,1fr)}}
.g6{{grid-template-columns:repeat(6,1fr)}}
@media(max-width:900px){{.g2,.g3,.g4,.g5,.g6{{grid-template-columns:1fr}}}}
@media(min-width:901px) and (max-width:1200px){{.g6{{grid-template-columns:repeat(3,1fr)}}.g5{{grid-template-columns:repeat(3,1fr)}}}}
/* ── Cards ── */
.card{{background:#111827;border:1px solid #1e2942;border-radius:12px;padding:16px}}
.stat-big{{font-size:28px;font-weight:700;line-height:1}}
.stat-label{{font-size:11px;color:#64748b;margin-top:4px}}
.stat-sub{{font-size:10px;color:#334155;margin-top:2px}}
/* ── Tables ── */
table{{width:100%;border-collapse:collapse;font-size:13px}}
td,th{{padding:8px 8px;border-bottom:1px solid #1e2942}}
th{{color:#64748b;font-size:11px;text-transform:uppercase;font-weight:600}}
tr:last-child td{{border-bottom:none}}
/* ── Gauges ── */
.gauge{{margin-bottom:12px}}
/* ── Containers ── */
.container-card{{background:#0a0d14;border:1px solid #1e2942;border-radius:8px;padding:10px 12px;margin-bottom:6px}}
/* ── Tabs IA ── */
.tab-btn{{background:#0a0d14;border:1px solid #1e2942;color:#64748b;padding:6px 16px;border-radius:6px;font-size:12px;cursor:pointer;transition:all .2s}}
.tab-btn:hover{{border-color:#4338ca;color:#a5b4fc}}
.tab-active{{background:#1e1b4b;border-color:#4338ca;color:#a5b4fc;font-weight:600}}
/* ── Boutons ── */
.btn-danger{{background:#7f1d1d;border:none;color:#fca5a5;padding:2px 8px;border-radius:4px;font-size:10px;cursor:pointer;margin-left:6px}}
.btn-success{{background:#14532d;border:none;color:#86efac;padding:2px 6px;border-radius:4px;font-size:10px;cursor:pointer;margin-left:4px}}
.btn-primary{{background:#312e81;border:1px solid #4338ca;color:#a5b4fc;padding:5px 14px;border-radius:6px;font-size:12px;cursor:pointer}}
/* ── Badges ── */
.badge{{padding:2px 7px;border-radius:4px;font-size:11px;font-weight:500}}
.badge-red{{background:#dc2626;color:#fff}}
.badge-orange{{background:#d97706;color:#fff}}
.badge-purple{{background:#7c3aed;color:#fff}}
.badge-gray{{background:#334155;color:#94a3b8}}
/* ── Alertes ── */
.alert-banner{{border-radius:8px;padding:10px 16px;margin-bottom:10px;font-weight:600;font-size:13px}}
.alert-crit{{background:#450a0a;border:1px solid #dc2626;color:#fca5a5}}
.alert-warn{{background:#451a03;border:1px solid #d97706;color:#fcd34d}}
/* ── Carte ── */
#geomap{{height:460px;border-radius:8px;background:#0a0d14}}
.leaflet-tile{{filter:brightness(0.55) saturate(0.35)}}
.leaflet-container{{background:#0a0d14}}
.leaflet-popup-content-wrapper{{background:#1e2942;border:1px solid #334155;color:#e2e8f0;border-radius:8px}}
.leaflet-popup-tip{{background:#1e2942}}
/* ── Toast ── */
#toast{{display:none;position:fixed;bottom:20px;right:20px;padding:10px 18px;border-radius:8px;font-size:13px;font-weight:600;z-index:9999;box-shadow:0 4px 12px rgba(0,0,0,.5)}}
</style>
</head><body>

<div id="toast"></div>

<!-- ═══ BARRE DE NAVIGATION ═══ -->
<nav class="topbar">
  <div class="topbar-brand">🛡️ ViaDigiTech SOC</div>
  <div class="nav-item active" onclick="showScreen('overview')"     id="nav-overview">     Vue globale</div>
  <div class="nav-item"        onclick="showScreen('security')"     id="nav-security">     Sécurité</div>
  <div class="nav-item"        onclick="showScreen('performance')"  id="nav-performance">  Performance</div>
  <div class="nav-item"        onclick="showScreen('ia')"           id="nav-ia">           IA</div>
  <div class="nav-item"        onclick="showScreen('infra')"        id="nav-infra">        Infrastructure</div>
  <div class="topbar-right">
    <span>{svc_badge}</span>
    <span style="color:#334155">{hostname} · {now.strftime('%d/%m %H:%M')}</span>
  </div>
</nav>

<div class="main">
{alert_banners}

<!-- ════════════════════════════════════ -->
<!-- ÉCRAN 1 : VUE GLOBALE               -->
<!-- ════════════════════════════════════ -->
<div class="screen active" id="screen-overview">

  <!-- Stat cards -->
  <div class="grid g6" style="margin-bottom:14px">
    <div class="card">
      <div class="stat-big" style="color:{cpu_color}">{metrics['cpu']:.0f}%</div>
      <div class="stat-label">CPU</div><div class="stat-sub">Load {metrics['load1']}</div>
    </div>
    <div class="card">
      <div class="stat-big" style="color:{ram_color}">{metrics['ram']:.0f}%</div>
      <div class="stat-label">RAM</div><div class="stat-sub">{metrics['ram_used']}GB / {metrics['ram_total']}GB</div>
    </div>
    <div class="card">
      <div class="stat-big" style="color:{disk_color}">{metrics['disk']:.0f}%</div>
      <div class="stat-label">Disque</div><div class="stat-sub">{metrics['disk_used']}GB / {metrics['disk_total']}GB</div>
    </div>
    <div class="card">
      <div class="stat-big" style="color:#ef4444">{ban_count}</div>
      <div class="stat-label">IPs bannies</div>
    </div>
    <div class="card">
      <div class="stat-big" style="color:#f59e0b">{ssh_total}</div>
      <div class="stat-label">Échecs SSH 24h</div>
      <div class="stat-sub">{len(ssh_fails)} IPs distinctes</div>
    </div>
    <div class="card">
      <div class="stat-big" style="color:#ef4444">{bans_today}{trend_html}</div>
      <div class="stat-label">Auto-bans aujourd'hui</div>
    </div>
  </div>

  <!-- Statut services -->
  <div class="grid g5" style="margin-bottom:14px">
    {services_cards}
  </div>

  <!-- Uptime + activité 7j -->
  <div class="grid g2" style="margin-bottom:14px">
    <div class="card">
      <h2>Activité — 7 derniers jours</h2>
      <canvas id="histChart" height="200"></canvas>
    </div>
    <div class="card">
      <h2>Métriques système</h2>
      {gauges_html}
      <div style="margin-top:14px;padding-top:12px;border-top:1px solid #1e2942;font-size:11px;color:#64748b">
        Uptime : <span style="color:#94a3b8;font-weight:600">{metrics['uptime_days']}j {metrics['uptime_hours']}h</span>
        &nbsp;·&nbsp; Containers : <span style="color:#a5b4fc;font-weight:600">{sum(1 for c in containers if 'Up' in c.get('Status',''))}/{len(containers)} actifs</span>
      </div>
    </div>
  </div>

</div><!-- /screen-overview -->

<!-- ════════════════════════════════════ -->
<!-- ÉCRAN 2 : SÉCURITÉ                  -->
<!-- ════════════════════════════════════ -->
<div class="screen" id="screen-security">

  <!-- Carte géo pleine largeur -->
  <div class="card" style="margin-bottom:14px">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <h2 style="margin:0">Carte des attaques — origines géographiques</h2>
      <span style="font-size:11px;color:#334155">{len(geo_data)} IPs géolocalisées · ip-api.com</span>
    </div>
    <div id="geomap"></div>
  </div>

  <!-- Top IPs + Audit -->
  <div class="grid g2" style="margin-bottom:14px">
    <div class="card">
      <h2>Top IPs attaquantes 24h</h2>
      {"<div style='color:#475569;font-size:13px;padding:12px 0'>Aucune activité SSH suspecte</div>" if not top_ip_rows else f"<div style='max-height:380px;overflow-y:auto'><table><thead><tr><th>IP</th><th style='text-align:right'>Tentatives</th></tr></thead><tbody>{top_ip_rows}</tbody></table></div>"}
      {f'<div style="margin-top:14px;padding-top:12px;border-top:1px solid #1e2942"><h2>Connexions légitimes 24h</h2><table><thead><tr><th></th><th>IP</th><th>Utilisateur</th></tr></thead><tbody>{accepted_html}</tbody></table></div>' if accepted_html else ""}
    </div>
    <div class="card">
      <h2>Journal d'audit — dernières actions</h2>
      {"<div style='color:#475569;font-size:13px;padding:12px 0'>Aucune action enregistrée</div>" if not audit_html else f"<div style='max-height:380px;overflow-y:auto'><table><thead><tr><th>Heure</th><th>IP</th><th>Action</th><th style='text-align:right'>Score</th></tr></thead><tbody>{audit_html}</tbody></table></div>"}
    </div>
  </div>

</div><!-- /screen-security -->

<!-- ════════════════════════════════════ -->
<!-- ÉCRAN 3 : PERFORMANCE               -->
<!-- ════════════════════════════════════ -->
<div class="screen" id="screen-performance">

  <!-- CPU/RAM/Disk 24h -->
  <div class="card" style="margin-bottom:14px">
    <h2>CPU / RAM / Disque — 24 dernières heures</h2>
    {'<canvas id="perfChart" height="120"></canvas>' if perf_labels else '<div style="color:#475569;font-size:13px;padding:24px 0;text-align:center">Historique en cours de constitution — disponible dans 15 min</div>'}
  </div>

  <!-- Jauges + swap -->
  <div class="grid g2" style="margin-bottom:14px">
    <div class="card">
      <h2>État actuel</h2>
      {gauges_html}
    </div>
    <div class="card">
      <h2>Résumé</h2>
      <table>
        <tr><td style="color:#64748b">CPU</td><td style="font-weight:600;color:{cpu_color}">{metrics['cpu']:.1f}%</td><td style="color:#64748b;font-size:11px">Load avg {metrics['load1']}</td></tr>
        <tr><td style="color:#64748b">RAM</td><td style="font-weight:600;color:{ram_color}">{metrics['ram']:.1f}%</td><td style="color:#64748b;font-size:11px">{metrics['ram_used']} / {metrics['ram_total']} GB</td></tr>
        <tr><td style="color:#64748b">Disque</td><td style="font-weight:600;color:{disk_color}">{metrics['disk']:.1f}%</td><td style="color:#64748b;font-size:11px">{metrics['disk_used']} / {metrics['disk_total']} GB</td></tr>
        <tr><td style="color:#64748b">Swap</td><td style="font-weight:600;color:#94a3b8">{metrics['swap_used']} GB</td><td style="color:#64748b;font-size:11px">/ {metrics['swap_total']} GB</td></tr>
        <tr><td style="color:#64748b">Uptime</td><td style="font-weight:600;color:#94a3b8" colspan="2">{metrics['uptime_days']}j {metrics['uptime_hours']}h</td></tr>
      </table>
    </div>
  </div>

  <!-- Log détecteur -->
  <div class="card">
    <h2>Log détecteur temps réel (toutes les 15 min)</h2>
    <div style="background:#0a0d14;border-radius:8px;padding:14px;max-height:320px;overflow-y:auto">
      {det_html or '<div style="color:#475569;font-size:13px">Aucun log</div>'}
    </div>
  </div>

</div><!-- /screen-performance -->

<!-- ════════════════════════════════════ -->
<!-- ÉCRAN 4 : IA                        -->
<!-- ════════════════════════════════════ -->
<div class="screen" id="screen-ia">
  {ai_screen_html}
</div><!-- /screen-ia -->

<!-- ════════════════════════════════════ -->
<!-- ÉCRAN 5 : INFRASTRUCTURE            -->
<!-- ════════════════════════════════════ -->
<div class="screen" id="screen-infra">

  <!-- Statut services -->
  <div class="card" style="margin-bottom:14px">
    <h2>Statut des services</h2>
    <div class="grid g5" style="margin-top:4px">{services_cards}</div>
  </div>

  <!-- Containers -->
  <div class="card" style="margin-bottom:14px">
    <h2>Conteneurs Docker — {len(containers)} total · {sum(1 for c in containers if 'Up' in c.get('Status',''))} actifs</h2>
    <div class="grid g3" style="margin-top:4px">
      {containers_html or '<div style="color:#475569;font-size:13px">Aucun container détecté</div>'}
    </div>
  </div>

</div><!-- /screen-infra -->

</div><!-- /main -->

<!-- ── Footer ── -->
<div style="text-align:center;font-size:10px;color:#1e2942;padding:8px;border-top:1px solid #0d1117">
  ViaDigiTech AI SecOps v5 · {hostname} · dashboard 15min · seuils CPU {WARN_CPU}/{CRIT_CPU}% · RAM {WARN_MEM}/{CRIT_MEM}% · Disk {WARN_DISK}/{CRIT_DISK}%
</div>

<script>
// ── Navigation ──
function showScreen(id) {{
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('screen-' + id).classList.add('active');
  document.getElementById('nav-' + id).classList.add('active');
  // Recalcule la carte Leaflet quand l'écran sécurité devient visible
  if (id === 'security' && window._leafletMap) {{
    setTimeout(() => window._leafletMap.invalidateSize(), 50);
  }}
  // Recalcule les charts performance
  if (id === 'performance') {{
    setTimeout(() => window.dispatchEvent(new Event('resize')), 50);
  }}
  // Sauvegarde l'écran actif
  sessionStorage.setItem('soc_screen', id);
}}

// ── Restore dernier écran ──
(function() {{
  const saved = sessionStorage.getItem('soc_screen');
  if (saved) showScreen(saved);
}})();

// ── Onglets IA ──
function showTab(id) {{
  document.querySelectorAll('.tab-pane').forEach(p => p.style.display='none');
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('tab-active'));
  document.getElementById(id).style.display='block';
  const btn = document.getElementById('btn-' + id.replace('tab-',''));
  if (btn) btn.classList.add('tab-active');
}}

// ── Refresh intelligent ──
(function() {{
  let lastActivity = Date.now(), paused = false;
  document.addEventListener('click', () => lastActivity = Date.now());
  document.addEventListener('keydown', () => lastActivity = Date.now());
  window.pauseRefresh  = () => {{ paused = true; }};
  window.resumeRefresh = () => {{ paused = false; lastActivity = Date.now(); }};
  setTimeout(function check() {{
    if (!paused && Date.now() - lastActivity > 10000) {{ location.reload(); return; }}
    setTimeout(check, 300000);
  }}, 300000);
}})();

// ── Toast ──
function showToast(msg, ok, duration=4000) {{
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.style.background = ok ? '#14532d' : '#7f1d1d';
  t.style.color = ok ? '#86efac' : '#fca5a5';
  t.style.display = 'block';
  setTimeout(() => t.style.display = 'none', duration);
}}

// ── Graphique 7 jours ──
(function() {{
  const el = document.getElementById('histChart');
  if (!el) return;
  new Chart(el.getContext('2d'), {{
    type: 'bar',
    data: {{
      labels: {hist_labels_js},
      datasets: [
        {{ label:'Bans auto', data:{hist_bans_js}, backgroundColor:'rgba(239,68,68,0.7)', borderColor:'#ef4444', borderWidth:1, borderRadius:4 }},
        {{ label:'Surveillés', data:{hist_watch_js}, backgroundColor:'rgba(99,102,241,0.5)', borderColor:'#6366f1', borderWidth:1, borderRadius:4 }}
      ]
    }},
    options: {{
      responsive:true,
      plugins:{{ legend:{{ labels:{{ color:'#94a3b8', font:{{ size:11 }} }} }}, tooltip:{{ mode:'index' }} }},
      scales:{{ x:{{ ticks:{{ color:'#64748b' }}, grid:{{ color:'#1e2942' }} }}, y:{{ ticks:{{ color:'#64748b' }}, grid:{{ color:'#1e2942' }}, beginAtZero:true }} }}
    }}
  }});
}})();

// ── Graphique CPU/RAM/Disk 24h ──
(function() {{
  const el = document.getElementById('perfChart');
  if (!el) return;
  new Chart(el.getContext('2d'), {{
    type: 'line',
    data: {{
      labels: {perf_labels_js},
      datasets: [
        {{ label:'CPU %',  data:{perf_cpu_js},  borderColor:'#f59e0b', backgroundColor:'rgba(245,158,11,0.07)', borderWidth:2, pointRadius:0, tension:0.3, fill:true }},
        {{ label:'RAM %',  data:{perf_ram_js},  borderColor:'#6366f1', backgroundColor:'rgba(99,102,241,0.07)', borderWidth:2, pointRadius:0, tension:0.3, fill:true }},
        {{ label:'Disk %', data:{perf_disk_js}, borderColor:'#22c55e', backgroundColor:'rgba(34,197,94,0.05)',  borderWidth:1.5, pointRadius:0, tension:0.3, borderDash:[4,4], fill:true }}
      ]
    }},
    options: {{
      responsive:true,
      plugins:{{ legend:{{ labels:{{ color:'#94a3b8', font:{{ size:11 }} }} }}, tooltip:{{ mode:'index', intersect:false }} }},
      scales:{{ x:{{ ticks:{{ color:'#64748b', maxTicksLimit:10 }}, grid:{{ color:'#1e2942' }} }}, y:{{ ticks:{{ color:'#64748b' }}, grid:{{ color:'#1e2942' }}, min:0, max:100 }} }}
    }}
  }});
}})();

// ── Carte Leaflet ──
(function() {{
  const map = L.map('geomap', {{ zoomControl:true, attributionControl:false }}).setView([20, 10], 2);
  window._leafletMap = map;
  L.tileLayer('https://{{s}}.basemaps.cartocdn.com/dark_all/{{z}}/{{x}}/{{y}}{{r}}.png', {{
    subdomains:'abcd', maxZoom:19
  }}).addTo(map);
  {geo_markers_js}
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
    print(f"[{datetime.now():%H:%M:%S}] Dashboard v5 généré → {OUTPUT_FILE}")
