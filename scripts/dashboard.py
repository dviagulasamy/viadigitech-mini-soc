#!/usr/bin/env python3
"""
ViaDigiTech SOC — Dashboard HTML temps réel
Exécuté toutes les 15 min via cron, servi par Nginx Proxy Manager.
v6 : score menace, timeline, heatmap, corrélation /24, whitelist, notifications, rapport ad-hoc.
"""

import os
import json
import subprocess
import urllib.request
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import re
import psutil

# ── PWA manifest path ──
MANIFEST_PATH = "/var/www/html/viadigitech-reports/soc/manifest.json"

OUTPUT_FILE  = "/var/www/html/viadigitech-reports/soc/index.html"
AUDIT_LOG    = "/home/ubuntu/secops/audit_actions.csv"
DETECTOR_LOG = "/home/ubuntu/secops/detector.log"
AUTH_LOG     = "/var/log/auth.log"
AI_SUMMARY   = "/home/ubuntu/secops/last_ai_summary.json"
METRICS_CSV  = "/home/ubuntu/secops/metrics_history.csv"
GEO_CACHE    = "/home/ubuntu/secops/geo_cache.json"
SSH_LOG_LINES = 12000

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
                accepted.append({"user": usr.group(1), "ip": ip.group(1), "ts": ts.strftime("%H:%M")})
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

# ── NOUVELLES FONCTIONS ──

def compute_threat_score(metrics, ssh_total, bans_today, ban_count):
    """Calcule un score de menace 0-100."""
    score = 0
    score += min(ssh_total / 300 * 30, 30)
    score += min(bans_today / 15 * 25, 25)
    score += min(ban_count  / 40 * 15, 15)
    if metrics["cpu"] >= CRIT_CPU:
        score += 15
    elif metrics["cpu"] >= WARN_CPU:
        score += 7
    if metrics["disk"] >= CRIT_DISK:
        score += 15
    elif metrics["disk"] >= WARN_DISK:
        score += 7
    return min(int(score), 100)

def get_timeline_events(hours=24):
    """Fusionne les événements de toutes les sources en une timeline triée."""
    events = []
    since = datetime.now() - timedelta(hours=hours)
    year  = datetime.now().year

    # Audit log
    if os.path.exists(AUDIT_LOG):
        with open(AUDIT_LOG) as f:
            for line in f:
                if line.startswith("timestamp"): continue
                parts = line.strip().split(",", 4)
                if len(parts) < 4: continue
                try:
                    ts = datetime.strptime(parts[0][:19], "%Y-%m-%d %H:%M:%S")
                    if ts < since: continue
                    action = parts[2]
                    if "BAN" in action:
                        etype, icon, color = "ban",     "🔴", "#ef4444"
                    elif "UNBAN" in action:
                        etype, icon, color = "unban",   "🟢", "#22c55e"
                    elif "OLLAMA" in action or "SURVEILLE" in action:
                        etype, icon, color = "analyze", "🟣", "#a78bfa"
                    else:
                        etype, icon, color = "action",  "⚪", "#64748b"
                    events.append({
                        "ts": ts, "label": ts.strftime("%H:%M"),
                        "type": etype, "icon": icon, "color": color,
                        "title": f"{action} — {parts[1]}",
                        "detail": f"Score : {parts[3]}%" if len(parts) > 3 else ""
                    })
                except:
                    pass

    # Auth log : connexions acceptées + première tentative par IP par heure
    if os.path.exists(AUTH_LOG):
        seen_fail_ip_hour = set()
        with open(AUTH_LOG, errors="ignore") as f:
            lines = f.readlines()[-SSH_LOG_LINES:]
        for line in lines:
            try:
                ts = datetime.strptime(line[:15] + f" {year}", "%b %d %H:%M:%S %Y")
                if ts < since: continue
                if "Accepted" in line:
                    ip  = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
                    usr = re.search(r"for (\S+) from", line)
                    if ip and usr and not ip.group(1).startswith("10."):
                        events.append({
                            "ts": ts, "label": ts.strftime("%H:%M"),
                            "type": "ssh_ok", "icon": "✅", "color": "#22c55e",
                            "title": f"Connexion SSH acceptée — {ip.group(1)}",
                            "detail": f"Utilisateur : {usr.group(1)}"
                        })
                elif "Failed password" in line or "Invalid user" in line:
                    ip = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", line)
                    if ip:
                        key = f"{ip.group(1)}-{ts.strftime('%Y-%m-%d %H')}"
                        if key not in seen_fail_ip_hour:
                            seen_fail_ip_hour.add(key)
                            events.append({
                                "ts": ts, "label": ts.strftime("%H:%M"),
                                "type": "ssh_fail", "icon": "⚠️", "color": "#f59e0b",
                                "title": f"Tentatives SSH — {ip.group(1)}",
                                "detail": ""
                            })
            except:
                pass

    # Detector log : lignes d'alerte
    if os.path.exists(DETECTOR_LOG):
        with open(DETECTOR_LOG) as f:
            for line in f.readlines()[-50:]:
                line = line.strip()
                if "alerte(s)" in line or "AutoBan" in line:
                    try:
                        hm = re.search(r"\[(\d{2}:\d{2}:\d{2})\]", line)
                        if not hm: continue
                        today = datetime.now().strftime("%Y-%m-%d")
                        ts = datetime.strptime(f"{today} {hm.group(1)}", "%Y-%m-%d %H:%M:%S")
                        if ts < since: continue
                        events.append({
                            "ts": ts, "label": ts.strftime("%H:%M"),
                            "type": "alert", "icon": "🚨", "color": "#ef4444",
                            "title": "Alerte SOC détectée",
                            "detail": line[10:80]
                        })
                    except:
                        pass

    events.sort(key=lambda e: e["ts"], reverse=True)
    return events[:120]

def get_attack_heatmap(days=7):
    """Retourne une matrice 7×24 des tentatives SSH par jour/heure."""
    matrix = [[0]*24 for _ in range(days)]
    today  = datetime.now().date()
    year   = datetime.now().year
    if not os.path.exists(AUTH_LOG):
        return matrix, []
    with open(AUTH_LOG, errors="ignore") as f:
        lines = f.readlines()[-SSH_LOG_LINES:]
    cutoff = datetime.now() - timedelta(days=days)
    for line in lines:
        if "Failed password" not in line and "Invalid user" not in line:
            continue
        try:
            ts = datetime.strptime(line[:15] + f" {year}", "%b %d %H:%M:%S %Y")
            if ts < cutoff: continue
            day_idx = (today - ts.date()).days
            if 0 <= day_idx < days:
                matrix[days - 1 - day_idx][ts.hour] += 1
        except:
            pass
    day_labels = [(today - timedelta(days=i)).strftime("%d/%m") for i in range(days-1, -1, -1)]
    return matrix, day_labels

def get_subnet_correlation(ssh_fails):
    """Regroupe les IPs attaquantes par sous-réseau /24."""
    subnet_ips   = defaultdict(set)
    subnet_count = defaultdict(int)
    for ip, count in ssh_fails.items():
        parts = ip.split(".")
        if len(parts) == 4:
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            subnet_ips[subnet].add(ip)
            subnet_count[subnet] += count
    result = sorted(
        [{"subnet": s, "ips": len(subnet_ips[s]), "attempts": subnet_count[s]}
         for s in subnet_ips],
        key=lambda x: x["attempts"], reverse=True
    )
    return result[:10]

def get_whitelist():
    """Retourne la liste des IPs ignorées par Fail2Ban."""
    out = run("sudo fail2ban-client get sshd ignoreip 2>/dev/null")
    ips = []
    for item in out.replace(",", " ").split():
        item = item.strip()
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}", item) or "/" in item:
            ips.append(item)
    return ips

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
    import hashlib as _hl
    _pwd = os.environ.get("SOC_DASHBOARD_PWD", "")
    if not _pwd:  # Charger depuis .env si absent de l'environnement
        _env_path = os.path.join(os.path.dirname(__file__), ".env")
        try:
            for _line in open(_env_path):
                _line = _line.strip()
                if _line.startswith("SOC_DASHBOARD_PWD=your_dashboard_password_here
                    _pwd = _line.split("=", 1)[1].strip()
                    break
        except Exception:
            pass
    pwd_hash = _hl.sha256(_pwd.encode()).hexdigest() if _pwd else ""
    now        = datetime.now()
    metrics    = get_metrics()
    append_metrics_history(metrics)
    ban_count, banned_ips = get_banned_ips()
    ssh_total, ssh_fails, accepted = get_ssh_stats(24)
    bans_today = get_bans_today()
    audit_rows = get_audit_recent(20)

    # ── KPIs SOC ──
    ban_auto_count = sum(1 for r in audit_rows if "BAN_AUTO" in r[2])
    ban_ollama_count = sum(1 for r in audit_rows if "BAN_OLLAMA" in r[2])
    total_bans_recent = ban_auto_count + ban_ollama_count
    coverage_rate = min(int(ban_count / max(ssh_total, 1) * 100), 100) if ssh_total > 0 else 0
    recidivists = len([ip for ip, cnt in ssh_fails.items() if cnt > 20])

    det_log    = get_detector_log(20)
    containers = get_docker_containers()
    ai_summary = get_ai_summary()
    hostname   = os.uname().nodename
    hist_labels, hist_bans, hist_watches = get_bans_history(7)
    srv_status = get_service_status()
    perf_labels, perf_cpu, perf_ram, perf_disk = get_metrics_history(24)
    top_ips    = [ip for ip, _ in ssh_fails.most_common(20)]
    geo_data   = get_geo_data(top_ips)
    timeline   = get_timeline_events(24)
    heatmap, heatmap_days = get_attack_heatmap(7)
    subnets    = get_subnet_correlation(ssh_fails)
    whitelist  = get_whitelist()
    threat     = compute_threat_score(metrics, ssh_total, bans_today, ban_count)

    # ── Annotations ──
    ann_path = "/home/ubuntu/secops/annotations.json"
    if not os.path.exists(ann_path):
        with open(ann_path, "w") as f: f.write("[]")
    try:
        with open(ann_path) as f:
            annotations = json.load(f)
    except Exception:
        annotations = []
    annotations_js = json.dumps(annotations)

    # ── Score menace ──
    if threat >= 70:
        threat_color, threat_label, threat_bg = "#ef4444", "ÉLEVÉE", "#450a0a"
    elif threat >= 40:
        threat_color, threat_label, threat_bg = "#f59e0b", "MODÉRÉE", "#451a03"
    else:
        threat_color, threat_label, threat_bg = "#22c55e", "FAIBLE", "#0d2318"

    # ── Services ──
    svc_down = [l for l, s in srv_status if s != "active"]
    svc_badge = f"<span style='background:#7f1d1d;color:#fca5a5;border-radius:6px;padding:2px 10px;font-size:11px;font-weight:600'>⚠ {len(svc_down)} KO</span>" if svc_down else ""

    services_cards = ""
    for label, status in srv_status:
        ok = status == "active"
        dot = '<span class="dot-active"></span>' if ok else '<span class="dot-down"></span>'
        services_cards += f"""<div style="background:{'#05160e' if ok else '#180808'};border:1px solid {'#166534' if ok else '#7f1d1d'};border-radius:10px;padding:12px 14px;display:flex;align-items:center;gap:10px;transition:border-color .2s">
          {dot}
          <div><div style="font-size:12px;font-weight:600;color:#e2e8f0">{label}</div>
          <div style="font-size:10px;color:{'#4ade80' if ok else '#f87171'};margin-top:2px">{status}</div></div>
        </div>"""

    services_compact = ""
    for label, status in srv_status:
        ok = status == "active"
        dot = '<span class="dot-active"></span>' if ok else '<span class="dot-down"></span>'
        services_compact += f'<div style="display:flex;align-items:center;gap:6px;background:{"#05160e" if ok else "#180808"};border:1px solid {"#166534" if ok else "#7f1d1d"};border-radius:8px;padding:7px 12px">{dot}<span style="font-size:12px;font-weight:500;color:#e2e8f0">{label}</span></div>'

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
    if trend_val > 0:   trend_html = f"<span style='color:#ef4444;font-size:11px;margin-left:6px'>↑ +{trend_val}</span>"
    elif trend_val < 0: trend_html = f"<span style='color:#22c55e;font-size:11px;margin-left:6px'>↓ {trend_val}</span>"
    else:               trend_html = "<span style='color:#64748b;font-size:11px;margin-left:6px'>= stable</span>"

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

    # ── Top IPs ──
    top_ip_rows = ""
    for ip, count in ssh_fails.most_common(15):
        is_banned = "🔴" if ip in banned_ips else "🟡"
        geo = geo_data.get(ip, {})
        loc = f"<span style='color:#475569;font-size:10px;margin-left:6px'>{geo.get('cc','')} {geo.get('city','')}</span>" if geo else ""
        btn = f"""<button onclick="banIP('{ip}')" class="btn-danger">Bannir</button>""" if ACTIONS_KEY else ""
        ip_link = f"<span onclick=\"openWorkbench('{ip}')\" style=\"cursor:pointer;color:#a5b4fc;text-decoration:underline dotted\">{ip}</span>"
        top_ip_rows += f"<tr data-ip='{ip}'><td style='font-family:monospace;font-size:12px'>{is_banned} {ip_link}{loc}{btn}</td><td style='text-align:right;font-weight:700;color:#ef4444'>{count}</td></tr>"

    # ── Connexions légitimes ──
    accepted_html = ""
    for a in accepted[-8:]:
        accepted_html += f"<tr><td style='color:#22c55e;font-size:11px'>✓</td><td style='font-family:monospace;font-size:12px'>{a['ip']}</td><td style='font-size:12px;color:#94a3b8'>{a['user']}</td><td style='color:#64748b;font-size:11px'>{a.get('ts','')}</td></tr>"

    # ── Audit ──
    audit_html = ""
    for row in audit_rows:
        ts = row[0][11:16] if len(row[0]) > 11 else row[0]
        ip, action, score = row[1], row[2], row[3]
        if "BAN_AUTO" in action or "BAN_OLLAMA" in action:
            badge = f"<span class='badge badge-red'>{action}</span>"
            atype = "ban"
        elif "UNBAN" in action:
            badge = f"<span class='badge badge-green'>{action}</span>"
            atype = "unban"
        elif "DRYRUN" in action:
            badge = f"<span class='badge badge-orange'>{action}</span>"
            atype = "dryrun"
        elif "OLLAMA" in action or "SURVEILLE" in action:
            badge = f"<span class='badge badge-purple'>{action}</span>"
            atype = "analyze"
        else:
            badge = f"<span class='badge badge-gray'>{action}</span>"
            atype = "other"
        unban_btn = f"""<button onclick="unbanIP('{ip}')" class="btn-success">Débannir</button>""" if ACTIONS_KEY and "BAN" in action else ""
        audit_html += f"<tr data-ip='{ip}' data-type='{atype}'><td style='color:#64748b;font-size:11px;white-space:nowrap'>{ts}</td><td style='font-family:monospace;font-size:11px'>{ip}</td><td>{badge}{unban_btn}</td><td style='text-align:right;color:#f59e0b;font-size:12px'>{score}%</td></tr>"

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
        ai_html = f"""
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
  <div style="margin-top:12px;padding:8px 12px;background:#1a1008;border:1px solid #78350f;border-radius:6px;font-size:11px;color:#fbbf24">
    ⚠️ <strong>Avertissement :</strong> Analyse générée par LLM local (qwen2.5:3b). Les commandes système suggérées peuvent être invalides — vérifier manuellement avant toute exécution.
  </div>
</div>
<div id="ai-response-box" style="display:none;margin-bottom:14px">
  <div class="card" style="border-left:3px solid #4338ca">
    <h2 style="margin-bottom:10px">⚡ Réponse IA temps réel</h2>
      <div id="ai-response-text" style="font-size:13px;line-height:1.85;color:#e2e8f0"></div>
    <div style="margin-top:12px;padding:8px 12px;background:#1a1008;border:1px solid #78350f;border-radius:6px;font-size:11px;color:#fbbf24">
      ⚠️ <strong>Avertissement :</strong> Les analyses IA sont générées par un LLM local (qwen2.5:3b) et peuvent contenir des erreurs ou des commandes système <strong>invalides</strong>. Ne jamais exécuter une commande suggérée par l'IA sans vérification manuelle.
    </div>
  </div>
</div>"""
    else:
        ai_html = """<div class="card" style="border-left:3px solid #334155;margin-bottom:14px">
          <h2>🤖 Analyse IA</h2>
          <div style="color:#475569;font-size:13px;padding:16px 0;text-align:center">Rapport IA non disponible — sera généré demain à 7h UTC</div>
        </div>"""

    # ── Corrélation /24 ──
    subnet_rows = ""
    for s in subnets:
        intensity = min(int(s["attempts"] / max(ssh_total, 1) * 100), 100)
        bar_color = "#ef4444" if intensity > 30 else "#f59e0b"
        subnet_rows += f"""<tr>
          <td style='font-family:monospace;font-size:12px'>{s['subnet']}</td>
          <td style='text-align:center;color:#a5b4fc'>{s['ips']}</td>
          <td style='text-align:right'>
            <div style='display:flex;align-items:center;gap:6px;justify-content:flex-end'>
              <div style='width:60px;background:#1e2942;border-radius:3px;height:4px'>
                <div style='width:{intensity}%;background:{bar_color};height:4px;border-radius:3px'></div>
              </div>
              <span style='font-weight:700;color:{bar_color};font-size:12px'>{s['attempts']}</span>
            </div>
          </td>
        </tr>"""

    # ── Whitelist ──
    whitelist_html = ""
    for ip in whitelist:
        rm_btn = f"""<button onclick="removeWhitelist('{ip}')" class="btn-danger" style="padding:1px 6px">Retirer</button>""" if ACTIONS_KEY else ""
        whitelist_html += f"<tr><td style='font-family:monospace;font-size:12px'>{ip}</td><td style='text-align:right'>{rm_btn}</td></tr>"

    # ── Timeline HTML ──
    timeline_html = ""
    prev_day = None
    for ev in timeline:
        day = ev["ts"].strftime("%d/%m/%Y")
        if day != prev_day:
            timeline_html += f"<div style='font-size:11px;color:#334155;font-weight:600;padding:12px 0 6px;border-top:1px solid #1e2942;margin-top:4px'>{day}</div>"
            prev_day = day
        timeline_html += f"""<div style="display:flex;gap:12px;align-items:flex-start;padding:8px 0;border-bottom:1px solid #0d1117">
          <div style="min-width:38px;font-size:11px;color:#475569;padding-top:2px">{ev['label']}</div>
          <div style="font-size:16px;line-height:1">{ev['icon']}</div>
          <div>
            <div style="font-size:12px;font-weight:600;color:{ev['color']}">{ev['title']}</div>
            {'<div style="font-size:11px;color:#475569;margin-top:1px">' + ev['detail'] + '</div>' if ev['detail'] else ''}
          </div>
        </div>"""
    if not timeline_html:
        timeline_html = "<div style='color:#475569;font-size:13px;padding:20px 0;text-align:center'>Aucun événement sur les 24 dernières heures</div>"

    # ── Heatmap données JS ──
    heatmap_js = json.dumps(heatmap)
    heatmap_days_js = json.dumps(heatmap_days)
    hmap_max = max((max(row) for row in heatmap if row), default=1)

    # ── Données Chart.js ──
    hist_labels_js = json.dumps(hist_labels)
    hist_bans_js   = json.dumps(hist_bans)
    hist_watch_js  = json.dumps(hist_watches)
    perf_labels_js = json.dumps(perf_labels)
    perf_cpu_js    = json.dumps(perf_cpu)
    perf_ram_js    = json.dumps(perf_ram)
    perf_disk_js   = json.dumps(perf_disk)

    # ── Marqueurs Leaflet ──
    geo_markers_js = ""
    for ip, count in ssh_fails.most_common(20):
        geo = geo_data.get(ip)
        if not geo: continue
        lat, lon    = geo["lat"], geo["lon"]
        country     = geo.get("country","?").replace("'","\\'")
        city        = geo.get("city","").replace("'","\\'")
        radius      = min(5 + count // 8, 22)
        opacity     = min(0.4 + count / 200, 0.85)
        geo_markers_js += (
            f"L.circleMarker([{lat},{lon}],"
            f"{{radius:{radius},color:'#ef4444',fillColor:'#ef4444',"
            f"fillOpacity:{opacity:.2f},weight:1.5}})"
            f".addTo(map)"
            f".bindPopup('<b style=\"font-family:monospace\">{ip}</b>"
            f"<br><span style=\"color:#94a3b8\">{country} {city}</span>"
            f"<br><b style=\"color:#ef4444\">{count} tentatives</b>');\n"
        )

    # ── Bouton rapport ──
    report_btn = "<button onclick='sendReport(this)' class='btn-primary' style='font-size:11px;padding:4px 12px'>📋 Rapport maintenant</button>" if ACTIONS_KEY else ""

    # ── Bouton IR ──
    ir_btn = f'<button onclick="openIR()" style="background:#450a0a;border:1px solid #dc2626;color:#fca5a5;padding:5px 14px;border-radius:6px;font-size:12px;cursor:pointer;font-weight:600">⚡ IR</button>'

    # ── Actions JS ──
    actions_js = ""
    if ACTIONS_KEY:
        actions_js = f"""
function getKey(){{
  let k=sessionStorage.getItem('soc_api_key');
  if(!k){{
    showPromptModal('Clé API SOC','Entrez votre clé API...',v=>{{sessionStorage.setItem('soc_api_key',v);}});
    return null;
  }}
  return k;
}}
async function apiCall(ep,data,btn){{
  let key=sessionStorage.getItem('soc_api_key');
  if(!key){{
    showPromptModal('Clé API SOC','Entrez votre clé API...',async v=>{{
      sessionStorage.setItem('soc_api_key',v);
      await apiCall(ep,data,btn);
    }});
    return null;
  }}
  if(btn){{btn.dataset.orig=btn.innerHTML;btn.innerHTML='<span class="spinner"></span>';btn.disabled=true;}}
  try{{
    const res=await fetch('{ACTIONS_API}'+ep,{{method:'POST',headers:{{'Content-Type':'application/json','X-SOC-Key':key}},body:JSON.stringify(data)}});
    const r=await res.json();
    if(res.status===401||res.status===403){{sessionStorage.removeItem('soc_api_key');showToast('Clé invalide — réessayez',false);return null;}}
    return r;
  }}catch(e){{showToast('Erreur réseau : '+e.message,false);return null;}}
  finally{{if(btn){{btn.innerHTML=btn.dataset.orig;btn.disabled=false;}}}}
}}
function banIP(ip){{
  showModal('Bannir cette IP',`Bannir ${{ip}} via Fail2Ban ?`,'Bannir',async()=>{{
    const btn=document.querySelector(`[onclick*="banIP('${{ip}}')"]`);
    const r=await apiCall('/ban',{{ip}},btn);
    if(r)showToast(r.ok?`✓ ${{ip}} bannie`:`Erreur: ${{r.error}}`,r.ok);
  }},true);
}}
function unbanIP(ip){{
  showModal('Débannir cette IP',`Lever le ban sur ${{ip}} ?`,'Débannir',async()=>{{
    const btn=document.querySelector(`[onclick*="unbanIP('${{ip}}')"]`);
    const r=await apiCall('/unban',{{ip}},btn);
    if(r)showToast(r.ok?`✓ ${{ip}} débannie`:`Erreur: ${{r.error}}`,r.ok);
  }},false);
}}
function addWhitelist(ip){{
  if(ip){{
    showModal('Whitelister',`Ajouter ${{ip}} à la whitelist Fail2Ban ?`,'Ajouter',async()=>{{
      const r=await apiCall('/whitelist/add',{{ip}},null);
      if(r)showToast(r.ok?`✓ ${{ip}} whitelistée`:`Erreur: ${{r.error}}`,r.ok);
    }},false);
  }}else{{
    showPromptModal('Ajouter à la whitelist','Adresse IP à whitelister...',async target=>{{
      const r=await apiCall('/whitelist/add',{{ip:target}},null);
      if(r)showToast(r.ok?`✓ ${{target}} whitelistée`:`Erreur: ${{r.error}}`,r.ok);
    }});
  }}
}}
function removeWhitelist(ip){{
  showModal('Retirer de la whitelist',`Supprimer ${{ip}} de la whitelist ?`,'Retirer',async()=>{{
    const r=await apiCall('/whitelist/remove',{{ip}},null);
    if(r)showToast(r.ok?`✓ ${{ip}} retirée`:`Erreur: ${{r.error}}`,r.ok);
  }},true);
}}
function sendReport(btn){{
  showModal('Générer un rapport','Envoyer le rapport SOC par email maintenant ?','Envoyer',async()=>{{
    const r=await apiCall('/report',{{}},btn);
    if(r)showToast(r.ok?`✓ ${{r.message}}`:`Erreur: ${{r.error}}`,r.ok,6000);
  }},false);
}}
function askAI(){{
  showPromptModal('Question à l\\'IA SOC','Ex: Quel est le niveau de risque actuel ?',async p=>{{
    showToast('Analyse en cours...',true,8000);
    const r=await apiCall('/analyze',{{prompt:p}},null);
    if(r&&r.ok){{
      document.getElementById('ai-response-box').style.display='block';
      document.getElementById('ai-response-text').innerHTML=r.response.replace(/\\n/g,'<br>');
    }}else if(r)showToast('Erreur IA : '+r.error,false);
  }});
}}
function askAIWithPrompt(p){{
  if(!p)return;
  showToast("Analyse en cours...",true,8000);
  apiCall('/analyze',{{prompt:p}},null).then(r=>{{
    if(r&&r.ok){{
      showScreen('overview');
      document.getElementById('ai-response-box').style.display='block';
      document.getElementById('ai-response-text').innerHTML=r.response.replace(/\\n/g,'<br>');
    }}
  }});
}}"""

    html = f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SOC — {hostname}</title>
<link rel="manifest" href="/soc/manifest.json">
<meta name="theme-color" content="#6366f1">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
/* ── Reset & base ── */
*{{box-sizing:border-box;margin:0;padding:0}}
body.theme-light{{--bg:#f0f4f8;--bg2:#ffffff;--bg3:#e8edf4;--border:#d1d9e6;--border2:#b8c4d4;--text:#1e293b;--muted:#475569;--dim:#64748b;--accent:#4f46e5;--accent-light:#4f46e5}}
:root{{--bg:#0a0d14;--bg2:#0d1117;--bg3:#111827;--border:#1e2942;--border2:#2d3f5e;--text:#e2e8f0;--muted:#64748b;--dim:#475569;--accent:#6366f1;--accent-light:#a5b4fc;--red:#ef4444;--orange:#f59e0b;--green:#22c55e}}
body{{font-family:-apple-system,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);display:flex;flex-direction:column;min-height:100vh;font-variant-numeric:tabular-nums}}
h2{{font-size:11px;text-transform:uppercase;letter-spacing:1.2px;color:var(--muted);margin-bottom:14px;font-weight:700}}

/* ── Scrollbar ── */
::-webkit-scrollbar{{width:5px;height:5px}}
::-webkit-scrollbar-track{{background:var(--bg)}}
::-webkit-scrollbar-thumb{{background:var(--dim);border-radius:3px}}
::-webkit-scrollbar-thumb:hover{{background:#475569}}

/* ── Topbar ── */
.topbar{{background:linear-gradient(90deg,var(--bg2) 0%,#0f1520 100%);border-bottom:1px solid var(--border);padding:0 24px;display:flex;align-items:center;position:sticky;top:0;z-index:1000;backdrop-filter:blur(8px)}}
.topbar-brand{{font-size:14px;font-weight:800;color:var(--accent-light);padding:14px 18px 14px 0;border-right:1px solid var(--border);margin-right:10px;white-space:nowrap;letter-spacing:-0.3px}}
.nav-item{{padding:16px 14px 14px;font-size:12px;font-weight:500;color:var(--muted);cursor:pointer;border-bottom:2px solid transparent;transition:color .18s,border-color .18s;white-space:nowrap;user-select:none;position:relative}}
.nav-item:hover{{color:#94a3b8}}
.nav-item.active{{color:var(--accent-light);border-bottom-color:var(--accent);font-weight:600}}
.topbar-right{{margin-left:auto;display:flex;align-items:center;gap:10px;padding-left:14px}}
.topbar-hostname{{font-size:11px;color:var(--dim)}}
.threat-badge{{padding:5px 13px;border-radius:20px;font-size:11px;font-weight:700;border:1px solid;letter-spacing:.3px}}

/* ── Hamburger (mobile only) ── */
.hamburger{{display:none;background:none;border:none;color:#94a3b8;font-size:22px;cursor:pointer;padding:10px 8px;line-height:1;touch-action:manipulation}}

/* ── Nav drawer — FIX: display:flex always, transform pour cacher ── */
.nav-drawer{{display:flex;flex-direction:column;position:fixed;top:0;left:0;width:72%;max-width:270px;height:100vh;background:var(--bg2);border-right:1px solid var(--border);z-index:2000;padding:0;overflow-y:auto;transform:translateX(-100%);transition:transform .28s cubic-bezier(.4,0,.2,1);box-shadow:4px 0 24px rgba(0,0,0,.5)}}
.nav-drawer.open{{transform:translateX(0)}}
.nav-overlay{{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:1999;backdrop-filter:blur(2px)}}
.nav-overlay.open{{display:block}}
.nav-drawer-header{{padding:18px 20px;border-bottom:1px solid var(--border);font-size:14px;font-weight:800;color:var(--accent-light);display:flex;align-items:center;justify-content:space-between;letter-spacing:-0.3px}}
.nav-drawer-item{{padding:15px 20px;font-size:13px;font-weight:500;color:#94a3b8;cursor:pointer;border-bottom:1px solid rgba(30,41,66,.5);transition:background .15s,color .15s;touch-action:manipulation}}
.nav-drawer-item:active{{background:#1a2436}}
.nav-drawer-item:hover,.nav-drawer-item.active{{background:var(--border);color:var(--accent-light)}}
.nav-drawer-item.active{{border-left:3px solid var(--accent);padding-left:17px;font-weight:600}}

/* ── Bottom nav (mobile) ── */
.bottom-nav{{display:none;position:fixed;bottom:0;left:0;right:0;background:rgba(13,17,23,.95);border-top:1px solid var(--border);z-index:1000;padding-bottom:env(safe-area-inset-bottom);backdrop-filter:blur(12px)}}
.bottom-nav-items{{display:flex;justify-content:space-around}}
.bn-item{{flex:1;display:flex;flex-direction:column;align-items:center;padding:9px 4px 7px;cursor:pointer;color:var(--muted);font-size:9px;font-weight:500;transition:color .15s;gap:3px;border-top:2px solid transparent;touch-action:manipulation}}
.bn-item.active{{color:var(--accent-light);border-top-color:var(--accent)}}
.bn-item svg{{width:20px;height:20px;stroke:currentColor;fill:none;stroke-width:1.8}}

/* ── Layout ── */
.main{{flex:1;padding:18px 24px;max-width:1600px;width:100%;margin:0 auto}}
.screen{{display:none;animation:fadeIn .2s ease}}
.screen.active{{display:block}}
@keyframes fadeIn{{from{{opacity:0;transform:translateY(4px)}}to{{opacity:1;transform:translateY(0)}}}}
.grid{{display:grid;gap:14px}}
.g2{{grid-template-columns:repeat(2,1fr)}}.g3{{grid-template-columns:repeat(3,1fr)}}
.g4{{grid-template-columns:repeat(4,1fr)}}.g5{{grid-template-columns:repeat(5,1fr)}}
.g6{{grid-template-columns:repeat(6,1fr)}}
@media(min-width:901px) and (max-width:1200px){{.g6{{grid-template-columns:repeat(3,1fr)}}.g5{{grid-template-columns:repeat(3,1fr)}}}}
@media(max-width:900px){{.g3,.g4,.g5{{grid-template-columns:repeat(2,1fr)}}.g6{{grid-template-columns:repeat(3,1fr)}}}}
@media(max-width:600px){{.g2,.g3,.g4,.g5,.g6{{grid-template-columns:repeat(2,1fr)}}}}
@media(max-width:400px){{.g2,.g3,.g4,.g5,.g6{{grid-template-columns:1fr}}}}

/* ── Cards ── */
.card{{background:var(--bg3);border:1px solid var(--border);border-radius:14px;padding:18px;transition:border-color .2s,box-shadow .2s}}
.card:hover{{border-color:var(--border2);box-shadow:0 2px 16px rgba(99,102,241,.06)}}
.stat-big{{font-size:30px;font-weight:800;line-height:1;letter-spacing:-1px}}
.stat-label{{font-size:11px;color:var(--muted);margin-top:5px;font-weight:500}}
.stat-sub{{font-size:10px;color:var(--dim);margin-top:3px}}

/* ── Tables ── */
.table-wrap{{overflow-x:auto;-webkit-overflow-scrolling:touch}}
table{{width:100%;border-collapse:collapse;font-size:12.5px}}
td,th{{padding:9px 8px;border-bottom:1px solid var(--border)}}
th{{color:var(--muted);font-size:10px;text-transform:uppercase;font-weight:700;letter-spacing:.8px}}
thead th{{position:sticky;top:0;background:var(--bg3);z-index:1}}
.table-wrap thead th{{position:sticky;top:0;background:var(--bg3);z-index:1}}
tbody tr{{transition:background .12s}}
tbody tr:hover{{background:rgba(30,41,66,.4)}}
tr:last-child td{{border-bottom:none}}

/* ── Gauge ── */
.gauge{{margin-bottom:14px}}
.gauge-bar{{background:#1e2942;border-radius:4px;overflow:hidden;height:6px;margin-top:5px}}
.gauge-fill{{height:6px;border-radius:4px;transition:width .6s ease}}

/* ── Components ── */
.container-card{{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin-bottom:6px;transition:border-color .15s}}
.container-card:hover{{border-color:var(--border2)}}
.tab-btn{{background:var(--bg);border:1px solid var(--border);color:var(--muted);padding:6px 16px;border-radius:6px;font-size:12px;cursor:pointer;transition:all .18s;touch-action:manipulation}}
.tab-btn:hover{{border-color:var(--accent);color:var(--accent-light)}}
.tab-active{{background:#1e1b4b;border-color:var(--accent);color:var(--accent-light);font-weight:600}}
.btn-danger{{background:#7f1d1d;border:1px solid #991b1b;color:#fca5a5;padding:6px 12px;border-radius:6px;font-size:11px;cursor:pointer;margin-left:6px;min-height:32px;touch-action:manipulation;transition:background .15s}}
.btn-danger:hover{{background:#991b1b}}
.btn-success{{background:#14532d;border:1px solid #166534;color:#86efac;padding:6px 10px;border-radius:6px;font-size:11px;cursor:pointer;margin-left:4px;min-height:32px;touch-action:manipulation;transition:background .15s}}
.btn-success:hover{{background:#166534}}
.btn-primary{{background:#312e81;border:1px solid var(--accent);color:var(--accent-light);padding:8px 18px;border-radius:8px;font-size:12px;cursor:pointer;min-height:36px;touch-action:manipulation;transition:background .15s,box-shadow .15s;font-weight:500}}
.btn-primary:hover{{background:#3730a3;box-shadow:0 0 0 3px rgba(99,102,241,.2)}}
.badge{{padding:3px 8px;border-radius:5px;font-size:11px;font-weight:600}}
.badge-red{{background:#450a0a;color:#fca5a5;border:1px solid #7f1d1d}}
.badge-orange{{background:#451a03;color:#fcd34d;border:1px solid #92400e}}
.badge-purple{{background:#2e1065;color:#c4b5fd;border:1px solid #6d28d9}}
.badge-gray{{background:var(--border);color:#94a3b8;border:1px solid var(--border2)}}
.badge-green{{background:#052e16;color:#86efac;border:1px solid #166534}}
.alert-banner{{border-radius:10px;padding:12px 18px;margin-bottom:12px;font-weight:600;font-size:13px;display:flex;align-items:center;gap:10px}}
.alert-crit{{background:#450a0a;border:1px solid #dc2626;color:#fca5a5}}
.alert-warn{{background:#451a03;border:1px solid #d97706;color:#fcd34d}}

/* ── Pulsing dot (service actif) ── */
@keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.4}}}}
.dot-active{{display:inline-block;width:8px;height:8px;background:var(--green);border-radius:50%;animation:pulse 2s infinite;flex-shrink:0}}
.dot-down{{display:inline-block;width:8px;height:8px;background:var(--red);border-radius:50%;flex-shrink:0}}

/* ── Géo map ── */
#geomap{{height:460px;border-radius:10px;background:var(--bg)}}
.leaflet-tile{{filter:brightness(0.5) saturate(0.3)}}
.leaflet-container{{background:var(--bg)}}
.leaflet-popup-content-wrapper{{background:#1e2942;border:1px solid var(--border2);color:var(--text);border-radius:10px}}
.leaflet-popup-tip{{background:#1e2942}}

/* ── Heatmap ── */
.heatmap-wrap{{overflow-x:auto;-webkit-overflow-scrolling:touch;padding-top:4px}}
.heatmap-grid{{display:grid;grid-template-columns:44px repeat(24,1fr);gap:2px;font-size:9px;min-width:520px}}
.hm-cell{{height:24px;border-radius:4px;cursor:default;transition:opacity .12s}}
.hm-cell:hover{{opacity:.7;outline:1px solid rgba(255,255,255,.4)}}
.hm-label{{display:flex;align-items:center;justify-content:flex-end;padding-right:8px;color:var(--muted);font-size:10px;height:24px;font-weight:500}}
.hm-hour{{text-align:center;color:var(--dim);padding-bottom:5px;font-size:9px}}

/* ── Filtres ── */
.filter-bar{{display:flex;gap:8px;align-items:center;margin-bottom:14px;flex-wrap:wrap}}
.filter-btn{{background:var(--border);border:1px solid var(--border2);color:var(--muted);padding:6px 16px;border-radius:8px;font-size:12px;cursor:pointer;transition:all .15s;min-height:34px;touch-action:manipulation;font-weight:500}}
.filter-btn:hover{{border-color:var(--accent);color:var(--accent-light)}}
.filter-btn.active{{background:#1e1b4b;border-color:var(--accent);color:var(--accent-light);font-weight:600}}
.search-input{{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:7px 14px;border-radius:8px;font-size:13px;flex:1;min-width:120px;outline:none;transition:border-color .18s}}
.search-input:focus{{border-color:var(--accent);box-shadow:0 0 0 3px rgba(99,102,241,.12)}}
.search-input::placeholder{{color:var(--dim)}}

/* ── Toast ── */
#toast{{display:none;position:fixed;bottom:24px;right:24px;padding:12px 22px;border-radius:10px;font-size:13px;font-weight:600;z-index:9999;box-shadow:0 8px 24px rgba(0,0,0,.6);max-width:calc(100vw - 48px);backdrop-filter:blur(8px)}}

/* ── Mobile overrides ── */
@media(max-width:768px){{
  .topbar{{padding:0 12px}}
  .nav-item{{display:none}}
  .topbar-hostname{{display:none}}
  .hamburger{{display:block}}
  .topbar-right{{gap:6px}}
  .threat-badge{{font-size:11px;padding:4px 9px}}
  .main{{padding:12px;padding-bottom:88px}}
  .card{{padding:13px;border-radius:12px}}
  .stat-big{{font-size:26px}}
  #geomap{{height:280px}}
  .bottom-nav{{display:block}}
  .btn-danger,.btn-success{{padding:8px 12px;min-height:38px}}
  .search-input{{font-size:16px}}
  #toast{{bottom:90px;right:12px;left:12px;text-align:center}}
}}
@media(max-width:480px){{
  .topbar-brand span{{display:none}}
  .threat-badge{{font-size:10px;padding:4px 8px}}
}}
/* ── Login overlay ── */
.login-overlay{{display:none;position:fixed;inset:0;background:var(--bg);z-index:9000;flex-direction:column;align-items:center;justify-content:center}}
.login-overlay.open{{display:flex}}
.login-box{{background:var(--bg2);border:1px solid var(--border2);border-radius:20px;padding:40px 48px;width:100%;max-width:380px;text-align:center;box-shadow:0 32px 80px rgba(0,0,0,.8)}}
.login-logo{{font-size:32px;margin-bottom:8px}}
.login-title{{font-size:20px;font-weight:800;color:var(--text);margin-bottom:4px}}
.login-sub{{font-size:12px;color:var(--muted);margin-bottom:28px}}
.login-input{{width:100%;background:var(--bg);border:1px solid var(--border2);color:var(--text);padding:12px 16px;border-radius:10px;font-size:14px;outline:none;margin-bottom:16px;transition:border-color .18s;box-sizing:border-box}}
.login-input:focus{{border-color:var(--accent);box-shadow:0 0 0 3px rgba(99,102,241,.15)}}
.login-btn{{width:100%;background:var(--accent);border:none;color:#fff;padding:12px;border-radius:10px;font-size:14px;font-weight:600;cursor:pointer;transition:background .15s}}
.login-btn:hover{{background:#4f46e5}}
.login-error{{font-size:12px;color:var(--red);margin-top:10px;min-height:18px}}
@keyframes loginShake{{0%,100%{{transform:translateX(0)}}25%{{transform:translateX(-8px)}}75%{{transform:translateX(8px)}}}}
.login-box.shake{{animation:loginShake .3s ease}}
/* ── Settings panel ── */
.settings-panel{{position:fixed;top:0;right:0;width:320px;height:100vh;background:var(--bg2);border-left:1px solid var(--border);z-index:7000;transform:translateX(100%);transition:transform .28s cubic-bezier(.4,0,.2,1);display:flex;flex-direction:column;overflow-y:auto;box-shadow:-8px 0 32px rgba(0,0,0,.5)}}
.settings-panel.open{{transform:translateX(0)}}
.settings-overlay{{display:none;position:fixed;inset:0;z-index:6999;background:rgba(0,0,0,.4)}}
.settings-overlay.open{{display:block}}
.settings-header{{padding:20px 20px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}}
.settings-title{{font-size:15px;font-weight:700;color:var(--text)}}
.settings-section{{padding:16px 20px;border-bottom:1px solid var(--border)}}
.settings-section-title{{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:12px}}
.settings-row{{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;gap:10px}}
.settings-label{{font-size:13px;color:var(--text)}}
.settings-sub{{font-size:11px;color:var(--muted)}}
.settings-input{{background:var(--bg);border:1px solid var(--border2);color:var(--text);padding:6px 10px;border-radius:7px;font-size:13px;width:70px;outline:none;text-align:center}}
.settings-input:focus{{border-color:var(--accent)}}
.toggle{{position:relative;width:40px;height:22px;flex-shrink:0}}
.toggle input{{opacity:0;width:0;height:0}}
.toggle-slider{{position:absolute;inset:0;background:#334155;border-radius:22px;cursor:pointer;transition:background .2s}}
.toggle-slider:before{{content:'';position:absolute;width:16px;height:16px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:transform .2s}}
.toggle input:checked+.toggle-slider{{background:var(--accent)}}
.toggle input:checked+.toggle-slider:before{{transform:translateX(18px)}}
.settings-save-btn{{margin:16px 20px;background:var(--accent);border:none;color:#fff;padding:10px;border-radius:9px;font-size:13px;font-weight:600;cursor:pointer;width:calc(100% - 40px);transition:background .15s}}
.settings-save-btn:hover{{background:#4f46e5}}
.oncall-badge{{font-size:11px;padding:2px 8px;border-radius:10px;font-weight:600}}
.oncall-on{{background:#14532d;color:#86efac}}
.oncall-off{{background:#1e2942;color:var(--muted)}}
/* ── Modal ── */
.modal-overlay{{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:3000;align-items:center;justify-content:center;backdrop-filter:blur(4px)}}
.modal-overlay.open{{display:flex}}
.modal-box{{background:#111827;border:1px solid #2d3f5e;border-radius:16px;padding:28px 32px;width:100%;max-width:420px;box-shadow:0 24px 64px rgba(0,0,0,.8);animation:modalIn .2s ease}}
@keyframes modalIn{{from{{opacity:0;transform:scale(.95)}}to{{opacity:1;transform:scale(1)}}}}
.modal-title{{font-size:16px;font-weight:700;color:#e2e8f0;margin-bottom:8px}}
.modal-msg{{font-size:13px;color:#94a3b8;line-height:1.6;margin-bottom:20px}}
.modal-input{{width:100%;background:#0a0d14;border:1px solid #2d3f5e;color:#e2e8f0;padding:10px 14px;border-radius:8px;font-size:13px;outline:none;margin-bottom:20px;transition:border-color .18s}}
.modal-input:focus{{border-color:#6366f1;box-shadow:0 0 0 3px rgba(99,102,241,.12)}}
.modal-actions{{display:flex;gap:10px;justify-content:flex-end}}
.modal-cancel{{background:transparent;border:1px solid #334155;color:#94a3b8;padding:8px 20px;border-radius:8px;font-size:13px;cursor:pointer;transition:border-color .15s}}
.modal-cancel:hover{{border-color:#475569;color:#e2e8f0}}
/* ── Spinner ── */
.spinner{{display:inline-block;width:14px;height:14px;border:2px solid rgba(255,255,255,.2);border-top-color:#fff;border-radius:50%;animation:spin .6s linear infinite;vertical-align:middle}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
/* ── Empty state ── */
.empty-state{{display:flex;flex-direction:column;align-items:center;padding:32px 16px;color:#475569;gap:10px}}
.empty-state svg{{width:36px;height:36px;stroke:#334155;fill:none;stroke-width:1.5}}
.empty-state p{{font-size:13px}}
/* ── Threat hero ── */
.threat-hero{{border-radius:14px;padding:20px 24px;display:flex;align-items:center;gap:20px;border:1px solid}}
.threat-hero-score{{font-size:52px;font-weight:800;line-height:1;letter-spacing:-3px}}
.threat-hero-bar{{height:6px;border-radius:3px;background:#1e2942;margin-top:10px;overflow:hidden}}
.threat-hero-fill{{height:6px;border-radius:3px;transition:width .8s ease}}
/* ── Sparkline canvas ── */
.sparkline{{display:block;width:100%;height:40px;margin-top:6px;opacity:.7}}
/* ── Age indicator ── */
.age-indicator{{font-size:11px;color:#475569;padding:0 8px;white-space:nowrap}}
.age-indicator.fresh{{color:#22c55e}}
.age-indicator.stale{{color:#f59e0b}}
/* ── Recherche globale Ctrl+K ── */
.cmdk-overlay{{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:4000;align-items:flex-start;justify-content:center;padding-top:15vh;backdrop-filter:blur(4px)}}
.cmdk-overlay.open{{display:flex}}
.cmdk-box{{background:#111827;border:1px solid #2d3f5e;border-radius:14px;width:100%;max-width:560px;overflow:hidden;box-shadow:0 32px 80px rgba(0,0,0,.9)}}
.cmdk-input{{width:100%;background:transparent;border:none;outline:none;padding:18px 20px;font-size:16px;color:#e2e8f0;border-bottom:1px solid #1e2942}}
.cmdk-input::placeholder{{color:#475569}}
.cmdk-results{{max-height:320px;overflow-y:auto}}
.cmdk-item{{padding:12px 20px;cursor:pointer;display:flex;align-items:center;gap:12px;font-size:13px;color:#94a3b8;transition:background .1s}}
.cmdk-item:hover,.cmdk-item.selected{{background:#1e2942;color:#e2e8f0}}
.cmdk-item-icon{{font-size:16px;width:24px;text-align:center}}
.cmdk-item-label{{flex:1}}
.cmdk-item-hint{{font-size:11px;color:#334155}}
.cmdk-footer{{padding:8px 16px;font-size:11px;color:#334155;border-top:1px solid #1e2942;display:flex;gap:16px}}
/* ── Mode IR ── */
.ir-mode body{{background:#1a0000}}
.ir-overlay{{display:none;position:fixed;inset:0;background:#0a0d14;z-index:5000;flex-direction:column;overflow-y:auto}}
.ir-overlay.open{{display:flex}}
.ir-header{{padding:16px 24px;background:#1a0000;border-bottom:2px solid #dc2626;display:flex;align-items:center;justify-content:space-between}}
.ir-title{{font-size:18px;font-weight:800;color:#fca5a5;letter-spacing:1px}}
.ir-score-big{{font-size:80px;font-weight:900;letter-spacing:-6px;line-height:1;text-align:center;margin:20px 0}}
.ir-grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:16px 24px;flex:1}}
.ir-card{{background:#111827;border:1px solid #334155;border-radius:12px;padding:16px}}
</style>
</head><body>
<div id="toast"></div>

<!-- ═══ LOGIN ═══ -->
<div class="login-overlay open" id="login-overlay">
  <div class="login-box" id="login-box">
    <div class="login-logo">🛡️</div>
    <div class="login-title">ViaDigiTech SOC</div>
    <div class="login-sub">Authentification requise</div>
    <input class="login-input" id="login-key" type="password" placeholder="Clé API SOC..." autocomplete="off">
    <button class="login-btn" onclick="doLogin()">Connexion</button>
    <div class="login-error" id="login-error"></div>
  </div>
</div>

<!-- ═══ SETTINGS ═══ -->
<div class="settings-overlay" id="settings-overlay" onclick="closeSettings()"></div>
<div class="settings-panel" id="settings-panel">
  <div class="settings-header">
    <span class="settings-title">⚙️ Paramètres</span>
    <button onclick="closeSettings()" style="background:none;border:none;color:var(--muted);font-size:18px;cursor:pointer;line-height:1">×</button>
  </div>
  <div class="settings-section">
    <div class="settings-section-title">Opérateur</div>
    <div class="settings-row">
      <div><div class="settings-label">Astreinte</div><div class="settings-sub">Statut affiché dans la topbar</div></div>
      <label class="toggle"><input type="checkbox" id="cfg-oncall" onchange="saveSettingsLive()"><span class="toggle-slider"></span></label>
    </div>
    <div class="settings-row">
      <div class="settings-label">Clé API</div>
      <button onclick="resetApiKey()" style="background:#1e2942;border:1px solid var(--border2);color:var(--muted);padding:5px 10px;border-radius:7px;font-size:11px;cursor:pointer">🔄 Reset</button>
    </div>
  </div>
  <div class="settings-section">
    <div class="settings-section-title">Interface</div>
    <div class="settings-row">
      <div class="settings-label">Mode sombre</div>
      <label class="toggle"><input type="checkbox" id="cfg-theme" onchange="applyThemeFromSettings()"><span class="toggle-slider"></span></label>
    </div>
    <div class="settings-row">
      <div><div class="settings-label">Intervalle SSE</div><div class="settings-sub">Secondes entre updates live</div></div>
      <input class="settings-input" id="cfg-sse" type="number" min="10" max="300" value="30">
    </div>
    <div class="settings-row">
      <div class="settings-label">Notifications navigateur</div>
      <label class="toggle"><input type="checkbox" id="cfg-notif"><span class="toggle-slider"></span></label>
    </div>
  </div>
  <div class="settings-section">
    <div class="settings-section-title">Administration — Seuils</div>
    <div class="settings-row">
      <div><div class="settings-label">Ban auto AbuseIPDB</div><div class="settings-sub">Score min pour ban automatique</div></div>
      <input class="settings-input" id="cfg-ban-threshold" type="number" min="50" max="100" value="80">
    </div>
    <div class="settings-row">
      <div><div class="settings-label">Alerte disque warn</div></div>
      <input class="settings-input" id="cfg-warn-disk" type="number" min="50" max="95" value="75">
    </div>
    <div class="settings-row">
      <div><div class="settings-label">Alerte disque crit</div></div>
      <input class="settings-input" id="cfg-crit-disk" type="number" min="60" max="99" value="88">
    </div>
    <div class="settings-row">
      <div><div class="settings-label">Alerte RAM warn</div></div>
      <input class="settings-input" id="cfg-warn-ram" type="number" min="50" max="95" value="75">
    </div>
    <div class="settings-row">
      <div><div class="settings-label">Alerte RAM crit</div></div>
      <input class="settings-input" id="cfg-crit-ram" type="number" min="60" max="99" value="90">
    </div>
  </div>
  <button class="settings-save-btn" onclick="saveSettings()">💾 Sauvegarder</button>
</div>

<!-- ═══ MODAL ═══ -->
<div class="modal-overlay" id="modal-overlay" onclick="handleOverlayClick(event)">
  <div class="modal-box">
    <div class="modal-title" id="modal-title"></div>
    <div class="modal-msg" id="modal-msg"></div>
    <div id="modal-input-row" style="display:none">
      <input class="modal-input" id="modal-input" type="text" autocomplete="off">
    </div>
    <div class="modal-actions">
      <button class="modal-cancel" onclick="closeModal()">Annuler</button>
      <button id="modal-confirm" class="btn-primary">Confirmer</button>
    </div>
  </div>
</div>

<!-- ═══ NAV DRAWER (mobile) ═══ -->
<div class="nav-overlay" id="nav-overlay" onclick="closeDrawer()"></div>
<div class="nav-drawer" id="nav-drawer">
  <div class="nav-drawer-header">
    <span>🛡️ ViaDigiTech SOC</span>
    <button onclick="closeDrawer()" style="background:none;border:none;color:#64748b;font-size:20px;cursor:pointer">✕</button>
  </div>
  <div class="nav-drawer-item active" onclick="showScreen('overview');closeDrawer()"    id="dnav-overview">🏠 Vue globale</div>
  <div class="nav-drawer-item"        onclick="showScreen('security');closeDrawer()"    id="dnav-security">🔒 Sécurité</div>
  <div class="nav-drawer-item"        onclick="showScreen('performance');closeDrawer()" id="dnav-performance">📈 Performance</div>
  <div class="nav-drawer-item"        onclick="showScreen('timeline');closeDrawer()"    id="dnav-timeline">🕒 Timeline</div>
  <div class="nav-drawer-item"        onclick="showScreen('infra');closeDrawer()"       id="dnav-infra">🖥️ Infrastructure</div>
  <div style="padding:16px 20px;border-top:1px solid #1e2942;margin-top:auto">
    <div style="font-size:11px;color:#334155;margin-bottom:8px">{hostname} · {now.strftime('%d/%m %H:%M')}</div>
    <div class="threat-badge" style="display:inline-block;background:{threat_bg};color:{threat_color};border-color:{threat_color}">{threat}/100 — {threat_label}</div>
  </div>
</div>

<!-- ═══ NAVIGATION DESKTOP ═══ -->
<nav class="topbar">
  <button class="hamburger" onclick="openDrawer()">☰</button>
  <div class="topbar-brand">🛡️ <span>ViaDigiTech SOC</span></div>
  <div class="nav-item active" onclick="showScreen('overview')"    id="nav-overview">Vue globale</div>
  <div class="nav-item"        onclick="showScreen('security')"    id="nav-security">Sécurité</div>
  <div class="nav-item"        onclick="showScreen('performance')" id="nav-performance">Performance</div>
  <div class="nav-item"        onclick="showScreen('timeline')"    id="nav-timeline">Timeline</div>
  <div class="nav-item"        onclick="showScreen('infra')"       id="nav-infra">Infrastructure</div>
  <div class="nav-item" onclick="showScreen('workbench')" id="nav-workbench" style="display:none">🔍 Workbench</div>
  <div class="topbar-right">
    <span class="topbar-hostname" id="topbar-hostname">{hostname}</span>
    <div id="status-bar" style="display:flex;align-items:center;gap:8px;padding-left:12px">
      <span id="st-f2b" title="Fail2Ban" style="font-size:10px;display:flex;align-items:center;gap:3px;color:var(--muted)"><span style="width:7px;height:7px;border-radius:50%;background:#334155;display:inline-block" id="dot-f2b"></span>f2b</span>
      <span id="st-api" title="API Flask" style="font-size:10px;display:flex;align-items:center;gap:3px;color:var(--muted)"><span style="width:7px;height:7px;border-radius:50%;background:#334155;display:inline-block" id="dot-api"></span>api</span>
      <span id="st-sse" title="SSE live" style="font-size:10px;display:flex;align-items:center;gap:3px;color:var(--muted)"><span style="width:7px;height:7px;border-radius:50%;background:#334155;display:inline-block" id="dot-sse"></span>sse</span>
    </div>
    <span id="oncall-badge" style="display:none" class="oncall-badge oncall-on">ON CALL</span>
    <button onclick="openSettings()" style="background:none;border:1px solid var(--border);color:var(--muted);padding:5px 10px;border-radius:6px;cursor:pointer;font-size:13px" title="Paramètres">⚙️</button>
    <button id="theme-toggle" onclick="toggleTheme()" style="background:none;border:1px solid var(--border);color:var(--muted);padding:5px 10px;border-radius:6px;cursor:pointer;font-size:13px" title="Mode sombre/clair">🌙</button>
    {ir_btn}
    {report_btn}
    <div class="threat-badge" style="background:{threat_bg};color:{threat_color};border-color:{threat_color}">
      {threat}/100 — {threat_label}
    </div>
    {svc_badge}
    <span class="age-indicator" id="age-indicator" title="Données générées à {now.strftime('%H:%M:%S')}">⟳ à l'instant</span>
  </div>
</nav>

<!-- ═══ BOTTOM NAV (mobile) ═══ -->
<nav class="bottom-nav">
  <div class="bottom-nav-items">
    <div class="bn-item active" onclick="showScreen('overview')"    id="bn-overview">
      <svg viewBox="0 0 24 24"><path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
      Vue glob.
    </div>
    <div class="bn-item" onclick="showScreen('security')"    id="bn-security">
      <svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      Sécurité
    </div>
    <div class="bn-item" onclick="showScreen('performance')" id="bn-performance">
      <svg viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
      Perfo
    </div>
    <div class="bn-item" onclick="showScreen('timeline')"    id="bn-timeline">
      <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
      Timeline
    </div>
    <div class="bn-item" onclick="showScreen('infra')"       id="bn-infra">
      <svg viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
      Infra
    </div>
  </div>
</nav>

<div class="main">
{alert_banners}

<!-- ═══════════ ÉCRAN 1 : VUE GLOBALE ═══════════ -->
<div class="screen active" id="screen-overview">

  <!-- Hero : Threat Score + Stats -->
  <div class="grid g2" style="margin-bottom:14px;grid-template-columns:280px 1fr">
    <!-- Threat Score Hero -->
    <div class="threat-hero card" style="background:{threat_bg};border-color:{threat_color};flex-direction:column;align-items:flex-start;gap:6px">
      <div style="font-size:11px;font-weight:700;color:{threat_color};letter-spacing:1.2px;text-transform:uppercase">Score de menace</div>
      <div class="threat-hero-score" style="color:{threat_color}">{threat}<span style="font-size:18px;font-weight:400;opacity:.6">/100</span></div>
      <div style="font-size:13px;font-weight:600;color:{threat_color}">{threat_label}</div>
      <div class="threat-hero-bar" style="width:100%">
        <div class="threat-hero-fill" style="width:{threat}%;background:{threat_color}"></div>
      </div>
    </div>
    <!-- Stat cards 2×3 -->
    <div class="grid g3">
      <div class="card">
        <div class="stat-big" style="color:{cpu_color}" id="live-cpu">{metrics['cpu']:.0f}%</div>
        <div class="stat-label">CPU</div>
        <div class="stat-sub">Load {metrics['load1']}</div>
        <div class="sparkline" id="sp-cpu"></div>
      </div>
      <div class="card">
        <div class="stat-big" style="color:{ram_color}" id="live-ram">{metrics['ram']:.0f}%</div>
        <div class="stat-label">RAM</div>
        <div class="stat-sub">{metrics['ram_used']}GB / {metrics['ram_total']}GB</div>
        <div class="sparkline" id="sp-ram"></div>
      </div>
      <div class="card">
        <div class="stat-big" style="color:{disk_color}">{metrics['disk']:.0f}%</div>
        <div class="stat-label">Disque</div>
        <div class="stat-sub">{metrics['disk_used']}GB / {metrics['disk_total']}GB</div>
        <div class="sparkline" id="sp-disk"></div>
      </div>
      <div class="card">
        <div class="stat-big" style="color:#ef4444" id="live-bans">{ban_count}</div>
        <div class="stat-label">IPs bannies</div>
        <div class="stat-sub">fail2ban actif</div>
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
  </div>

  <!-- Services compacts -->
  <div class="card" style="margin-bottom:14px">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;flex-wrap:wrap;gap:8px">
      <h2 style="margin:0">Services</h2>
      <span style="font-size:11px;color:#475569">Uptime {metrics['uptime_days']}j {metrics['uptime_hours']}h &nbsp;·&nbsp; Docker {sum(1 for c in containers if 'Up' in c.get('Status',''))}/{len(containers)}</span>
    </div>
    <div style="display:flex;flex-wrap:wrap;gap:8px">
      {services_compact}
    </div>
  </div>

  <!-- KPIs SOC -->
  <div class="card" style="margin-bottom:14px">
    <h2>KPIs SOC — 24h</h2>
    <div class="grid g4">
      <div style="text-align:center;padding:8px">
        <div style="font-size:26px;font-weight:800;color:#22c55e">{coverage_rate}%</div>
        <div style="font-size:11px;color:#64748b;margin-top:4px">Taux de couverture</div>
        <div style="font-size:10px;color:#334155">bans / tentatives</div>
      </div>
      <div style="text-align:center;padding:8px">
        <div style="font-size:26px;font-weight:800;color:#f59e0b">~7.5min</div>
        <div style="font-size:11px;color:#64748b;margin-top:4px">MTTD moyen</div>
        <div style="font-size:10px;color:#334155">détection → ban</div>
      </div>
      <div style="text-align:center;padding:8px">
        <div style="font-size:26px;font-weight:800;color:#a78bfa">{ban_auto_count}</div>
        <div style="font-size:11px;color:#64748b;margin-top:4px">Bans auto (AbuseIPDB)</div>
        <div style="font-size:10px;color:#334155">sur 20 dernières actions</div>
      </div>
      <div style="text-align:center;padding:8px">
        <div style="font-size:26px;font-weight:800;color:#ef4444">{recidivists}</div>
        <div style="font-size:11px;color:#64748b;margin-top:4px">Récidivistes actifs</div>
        <div style="font-size:10px;color:#334155">&gt; 20 tentatives / IP</div>
      </div>
    </div>
  </div>

  <!-- IA -->
  <div style="margin-bottom:14px">{ai_html}</div>

  <!-- Graphique 7 jours -->
  <div class="card" style="margin-bottom:14px">
    <h2>Activité — 7 derniers jours</h2>
    <div id="histChart" style="height:240px;width:100%"></div>
  </div>

</div>

<!-- ═══════════ ÉCRAN 2 : SÉCURITÉ ═══════════ -->
<div class="screen" id="screen-security">
  <!-- Barre de recherche + filtres -->
  <div class="filter-bar" style="margin-bottom:14px">
    <input type="text" class="search-input" id="ip-search" placeholder="🔍 Rechercher une IP..." oninput="filterSecurity()">
    <button class="filter-btn active" onclick="setFilter('all')"     id="f-all">Tous</button>
    <button class="filter-btn"        onclick="setFilter('ban')"     id="f-ban">BAN</button>
    <button class="filter-btn"        onclick="setFilter('unban')"   id="f-unban">UNBAN</button>
    <button class="filter-btn"        onclick="setFilter('analyze')" id="f-analyze">ANALYZE</button>
    <span style="font-size:11px;color:#334155;margin-left:4px" id="filter-count"></span>
  </div>

  <!-- Carte géo -->
  <div class="card" style="margin-bottom:14px">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <h2 style="margin:0">Carte des attaques</h2>
      <span style="font-size:11px;color:#334155">{len(geo_data)} IPs géolocalisées · ip-api.com</span>
    </div>
    <div id="geomap"></div>
  </div>

  <div class="grid g2" style="margin-bottom:14px">
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
        <h2 style="margin:0">Top IPs attaquantes 24h</h2>
        <button onclick="exportTable('ip-table','top_ips')" class="btn-primary" style="font-size:11px;padding:4px 12px">⬇ Export CSV</button>
      </div>
      <input id="filter-ip" type="text" placeholder="Filtrer par IP, pays, score..." oninput="filterTable('ip-table','filter-ip')" style="width:100%;background:var(--bg);border:1px solid var(--border);color:var(--text);padding:7px 12px;border-radius:8px;font-size:12px;outline:none;margin-bottom:8px">
      {"<div class='empty-state'><svg viewBox='0 0 24 24'><path d='M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z'/></svg><p>Aucune activité SSH suspecte</p></div>" if not top_ip_rows else f"<div class='table-wrap' style='max-height:360px;overflow-y:auto'><table id='ip-table'><thead><tr><th>IP</th><th style='text-align:right'>Tentatives</th></tr></thead><tbody>{top_ip_rows}</tbody></table></div>"}
      {f'<div style="margin-top:14px;padding-top:12px;border-top:1px solid #1e2942"><h2>Connexions légitimes 24h</h2><div class="table-wrap"><table><thead><tr><th></th><th>IP</th><th>Utilisateur</th><th>Heure</th></tr></thead><tbody>{accepted_html}</tbody></table></div></div>' if accepted_html else ""}
    </div>
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
        <h2 style="margin:0">Journal d'audit</h2>
        <button onclick="exportTable('audit-table','audit_log')" class="btn-primary" style="font-size:11px;padding:4px 12px">⬇ Export CSV</button>
      </div>
      <input id="filter-audit" type="text" placeholder="Filtrer audit log..." oninput="filterTable('audit-table','filter-audit')" style="width:100%;background:var(--bg);border:1px solid var(--border);color:var(--text);padding:7px 12px;border-radius:8px;font-size:12px;outline:none;margin-bottom:8px">
      {"<div class='empty-state'><svg viewBox='0 0 24 24'><path d='M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2'/></svg><p>Aucune action enregistrée</p></div>" if not audit_html else f"<div class='table-wrap' style='max-height:360px;overflow-y:auto'><table id='audit-table'><thead><tr><th>Heure</th><th>IP</th><th>Action</th><th style='text-align:right'>Score</th></tr></thead><tbody>{audit_html}</tbody></table></div>"}
    </div>
  </div>

  <!-- Corrélation /24 -->
  <div class="card" style="margin-bottom:14px">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <h2 style="margin:0">Corrélation par sous-réseau /24</h2>
      <span style="font-size:11px;color:#334155">{len(subnets)} blocs détectés</span>
    </div>
    {"<div class='empty-state'><svg viewBox='0 0 24 24'><circle cx='12' cy='12' r='10'/><line x1='12' y1='8' x2='12' y2='12'/><line x1='12' y1='16' x2='12.01' y2='16'/></svg><p>Aucune corrélation détectée</p></div>" if not subnet_rows else f"<div class='table-wrap'><table><thead><tr><th>Sous-réseau</th><th style='text-align:center'>IPs uniques</th><th style='text-align:right'>Tentatives</th></tr></thead><tbody>{subnet_rows}</tbody></table></div>"}
  </div>
</div>

<!-- ═══════════ ÉCRAN 3 : PERFORMANCE ═══════════ -->
<div class="screen" id="screen-performance">
  <div class="card" style="margin-bottom:14px">
    <h2>CPU / RAM / Disque — 24 dernières heures</h2>
    {'<div id="perfChart" style="height:240px;width:100%"></div>' if perf_labels else '<div style="color:#475569;font-size:13px;padding:24px 0;text-align:center">Historique en cours de constitution</div>'}
  </div>
  <div class="card" style="margin-bottom:14px">
    <h2>Heatmap des attaques SSH — 7 jours × 24 heures</h2>
    <div class="heatmap-wrap">
      <div id="heatmap-container"></div>
    </div>
    <div style="display:flex;align-items:center;gap:8px;margin-top:10px;font-size:10px;color:#475569">
      <span>0</span>
      <div style="display:flex;gap:2px">
        <div style="width:14px;height:8px;border-radius:2px;background:#0d2318"></div>
        <div style="width:14px;height:8px;border-radius:2px;background:#7f1d1d"></div>
        <div style="width:14px;height:8px;border-radius:2px;background:#ef4444"></div>
      </div>
      <span>{hmap_max}+</span>
      <span style="margin-left:8px">· hover pour le détail</span>
    </div>
  </div>
  <div class="grid g2" style="margin-bottom:14px">
    <div class="card"><h2>État actuel</h2>{gauges_html}</div>
    <div class="card">
      <h2>Résumé</h2>
      <table>
        <tr><td style="color:#64748b">CPU</td><td style="font-weight:600;color:{cpu_color}">{metrics['cpu']:.1f}%</td><td style="color:#64748b;font-size:11px">Load {metrics['load1']}</td></tr>
        <tr><td style="color:#64748b">RAM</td><td style="font-weight:600;color:{ram_color}">{metrics['ram']:.1f}%</td><td style="color:#64748b;font-size:11px">{metrics['ram_used']} / {metrics['ram_total']} GB</td></tr>
        <tr><td style="color:#64748b">Disque</td><td style="font-weight:600;color:{disk_color}">{metrics['disk']:.1f}%</td><td style="color:#64748b;font-size:11px">{metrics['disk_used']} / {metrics['disk_total']} GB</td></tr>
        <tr><td style="color:#64748b">Swap</td><td style="font-weight:600;color:#94a3b8">{metrics['swap_used']} GB</td><td style="color:#64748b;font-size:11px">/ {metrics['swap_total']} GB</td></tr>
        <tr><td style="color:#64748b">Uptime</td><td style="font-weight:600;color:#94a3b8" colspan="2">{metrics['uptime_days']}j {metrics['uptime_hours']}h</td></tr>
      </table>
    </div>
  </div>
  <!-- Note: les jauges État actuel sont uniquement dans Performance -->
  <div class="card">
    <h2>Log détecteur temps réel</h2>
    <div style="background:#0a0d14;border-radius:8px;padding:14px;max-height:280px;overflow-y:auto">
      {det_html or '<div style="color:#475569;font-size:13px">Aucun log</div>'}
    </div>
  </div>
</div>

<!-- ═══════════ ÉCRAN 4 : TIMELINE ═══════════ -->
<div class="screen" id="screen-timeline">
  <div style="background:var(--bg3);border:1px solid var(--border);border-radius:10px;padding:14px 18px;margin-bottom:16px">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
      <h3 style="margin:0;font-size:13px;color:var(--muted)">📌 Annotations opérateur</h3>
      <button onclick="addAnnotation()" class="btn-primary" style="font-size:11px;padding:4px 12px">+ Ajouter</button>
    </div>
    <div id="ann-list" style="max-height:120px;overflow-y:auto"></div>
  </div>
  <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
      <h2 style="margin:0">Timeline des événements — 24 dernières heures</h2>
      <span style="font-size:11px;color:#334155">{len(timeline)} événements</span>
    </div>
    <div style="max-height:calc(100vh - 200px);overflow-y:auto">
      {timeline_html}
    </div>
  </div>
</div>

<!-- ═══════════ ÉCRAN 5 : INFRASTRUCTURE ═══════════ -->
<div class="screen" id="screen-infra">
  <div class="card" style="margin-bottom:14px">
    <h2>Statut des services</h2>
    <div class="grid g5" style="margin-top:4px">{services_cards}</div>
  </div>
  <div class="grid g2" style="margin-bottom:14px">
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h2 style="margin:0">Whitelist Fail2Ban</h2>
        {'<button onclick="addWhitelist()" class="btn-primary" style="font-size:11px;padding:4px 12px">+ Ajouter IP</button>' if ACTIONS_KEY else ''}
      </div>
      {"<div class='empty-state'><svg viewBox='0 0 24 24'><path d='M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z'/></svg><p>Whitelist vide</p></div>" if not whitelist_html else f"<div class='table-wrap'><table><thead><tr><th>IP / Réseau</th><th></th></tr></thead><tbody>{whitelist_html}</tbody></table></div>"}
    </div>
    <div class="card">
      <h2>Conteneurs Docker — {len(containers)} · {sum(1 for c in containers if 'Up' in c.get('Status',''))} actifs</h2>
      <div class="grid g2" style="margin-top:4px">
        {containers_html or '<div style="color:#475569;font-size:13px">Aucun container détecté</div>'}
      </div>
    </div>
  </div>
  <div class="card" style="margin-top:16px">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
      <h2 style="margin:0">Journal detector (live)</h2>
      <button onclick="refreshLogs()" class="btn-primary" style="font-size:11px;padding:4px 12px">⟳ Refresh</button>
    </div>
    <div id="live-logs" style="font-family:monospace;font-size:11px;color:#94a3b8;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:12px;max-height:240px;overflow-y:auto;white-space:pre-wrap;word-break:break-all">Chargement...</div>
  </div>
<!-- ═══════════ ÉCRAN 6 : WORKBENCH IP ═══════════ -->
<div class="screen" id="screen-workbench">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">
    <button onclick="showScreen('security')" style="background:transparent;border:1px solid #334155;color:#94a3b8;padding:6px 12px;border-radius:6px;cursor:pointer;font-size:12px">← Retour</button>
    <h1 id="wb-ip-title" style="font-size:20px;font-weight:800;color:#a5b4fc;font-family:monospace"></h1>
    <div id="wb-actions" style="display:flex;gap:8px;margin-left:auto"></div>
  </div>
  <div class="grid g3" style="margin-bottom:14px">
    <div class="card"><h2>Score AbuseIPDB</h2><div id="wb-score" class="stat-big">—</div></div>
    <div class="card"><h2>Tentatives 24h</h2><div id="wb-attempts" class="stat-big" style="color:#f59e0b">—</div></div>
    <div class="card"><h2>Statut</h2><div id="wb-status" class="stat-big">—</div></div>
  </div>
  <div class="grid g2" style="margin-bottom:14px">
    <div class="card">
      <h2>Géolocalisation</h2>
      <div id="wb-geo" style="font-size:13px;color:#94a3b8;line-height:2"></div>
    </div>
    <div class="card">
      <h2>Historique des actions</h2>
      <div class="table-wrap"><table id="wb-history-table"><thead><tr><th>Heure</th><th>Action</th><th>Score</th></tr></thead><tbody id="wb-history"></tbody></table></div>
    </div>
  </div>
  <div class="card" style="margin-bottom:14px">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <h2 style="margin:0">Analyse IA sur cette IP</h2>
      <button id="wb-analyze-btn" onclick="wbAnalyze()" class="btn-primary">🤖 Analyser</button>
    </div>
    <div id="wb-ai-result" style="font-size:13px;color:#94a3b8;line-height:1.8;min-height:40px"></div>
  </div>
</div>

</div><!-- /main -->

<!-- ═══ CTRL+K SEARCH ═══ -->
<div class="cmdk-overlay" id="cmdk-overlay" onclick="closeCmdK(event)">
  <div class="cmdk-box">
    <input class="cmdk-input" id="cmdk-input" placeholder="Rechercher une IP, naviguer, lancer une analyse..." autocomplete="off">
    <div class="cmdk-results" id="cmdk-results"></div>
    <div class="cmdk-footer">
      <span>↑↓ naviguer</span><span>↵ confirmer</span><span>Esc fermer</span>
    </div>
  </div>
</div>

<!-- ═══ MODE INCIDENT RESPONSE ═══ -->
<div class="ir-overlay" id="ir-overlay">
  <div class="ir-header">
    <div class="ir-title">⚡ MODE INCIDENT RESPONSE</div>
    <div style="display:flex;align-items:center;gap:12px">
      <span id="ir-time" style="font-size:13px;color:#fca5a5;font-family:monospace"></span>
      <button onclick="closeIR()" style="background:transparent;border:1px solid #7f1d1d;color:#fca5a5;padding:6px 14px;border-radius:6px;cursor:pointer">✕ Quitter IR</button>
    </div>
  </div>
  <div style="text-align:center;padding:16px 24px 0">
    <div id="ir-score-display" class="ir-score-big"></div>
    <div id="ir-level" style="font-size:20px;font-weight:700;margin-bottom:8px"></div>
  </div>
  <div class="ir-grid">
    <div class="ir-card">
      <h2>Top menaces actives</h2>
      <div id="ir-top-ips" style="font-family:monospace;font-size:13px;line-height:2"></div>
    </div>
    <div class="ir-card">
      <h2>Actions rapides</h2>
      <div id="ir-actions" style="display:flex;flex-direction:column;gap:8px;margin-top:8px"></div>
    </div>
    <div class="ir-card" style="grid-column:1/-1">
      <h2>Derniers événements</h2>
      <div id="ir-timeline" style="font-size:12px;font-family:monospace;line-height:1.8;max-height:200px;overflow-y:auto"></div>
    </div>
  </div>
</div>

<div style="text-align:center;font-size:10px;color:#475569;padding:8px;border-top:1px solid #0d1117">
  ViaDigiTech AI SecOps v6 · {hostname} · 15min · seuils CPU {WARN_CPU}/{CRIT_CPU}% · RAM {WARN_MEM}/{CRIT_MEM}% · Disk {WARN_DISK}/{CRIT_DISK}%
</div>

<script>
// ── Login ──
const _PWD_HASH="{pwd_hash}";
async function doLogin(){{
  const pwd=document.getElementById('login-key').value;
  if(!pwd)return;
  const errEl=document.getElementById('login-error');
  errEl.textContent="";
  try{{
    const buf=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(pwd));
    const hash=Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
    if(hash===_PWD_HASH){{
      sessionStorage.setItem('soc_auth','1');
      document.getElementById('login-overlay').classList.remove('open');
    }}else{{
      const box=document.getElementById('login-box');
      errEl.textContent="Mot de passe invalide";
      box.classList.remove('shake');void box.offsetWidth;box.classList.add('shake');
    }}
  }}catch(e){{
    errEl.textContent="Erreur : "+e.message;
  }}
}}
// Exécution directe (script en fin de body, DOM déjà prêt)
(function(){{
  const auth=sessionStorage.getItem('soc_auth');
  if(auth==='1'){{
    document.getElementById('login-overlay').classList.remove('open');
  }}else{{
    setTimeout(()=>document.getElementById('login-key')?.focus(),150);
  }}
}})();
document.getElementById('login-key')?.addEventListener('keydown',e=>{{if(e.key==='Enter')doLogin();}});

// ── Settings panel ──
function openSettings(){{
  loadSettingsFromServer();
  document.getElementById('settings-panel').classList.add('open');
  document.getElementById('settings-overlay').classList.add('open');
}}
function closeSettings(){{
  document.getElementById('settings-panel').classList.remove('open');
  document.getElementById('settings-overlay').classList.remove('open');
}}
async function loadSettingsFromServer(){{
  try{{
    const r=await fetch('/action/config');
    const cfg=await r.json();
    const el=id=>document.getElementById(id);
    if(el('cfg-oncall'))el('cfg-oncall').checked=!!cfg.oncall;
    if(el('cfg-sse'))el('cfg-sse').value=cfg.sse_interval||30;
    if(el('cfg-ban-threshold'))el('cfg-ban-threshold').value=cfg.ban_threshold||80;
    if(el('cfg-warn-disk'))el('cfg-warn-disk').value=cfg.warn_disk||75;
    if(el('cfg-crit-disk'))el('cfg-crit-disk').value=cfg.crit_disk||88;
    if(el('cfg-warn-ram'))el('cfg-warn-ram').value=cfg.warn_ram||75;
    if(el('cfg-crit-ram'))el('cfg-crit-ram').value=cfg.crit_ram||90;
    if(el('cfg-theme'))el('cfg-theme').checked=document.body.classList.contains('theme-light');
    updateOncallBadge(!!cfg.oncall);
  }}catch(e){{}}
}}
async function saveSettings(){{
  const key=sessionStorage.getItem('soc_api_key')||'';
  const el=id=>document.getElementById(id);
  const payload={{
    oncall:el('cfg-oncall')?.checked||false,
    sse_interval:parseInt(el('cfg-sse')?.value||30),
    ban_threshold:parseInt(el('cfg-ban-threshold')?.value||80),
    warn_disk:parseInt(el('cfg-warn-disk')?.value||75),
    crit_disk:parseInt(el('cfg-crit-disk')?.value||88),
    warn_ram:parseInt(el('cfg-warn-ram')?.value||75),
    crit_ram:parseInt(el('cfg-crit-ram')?.value||90)
  }};
  try{{
    const r=await fetch('/action/config',{{method:'POST',headers:{{'Content-Type':'application/json','X-SOC-Key':key}},body:JSON.stringify(payload)}});
    const d=await r.json();
    if(d.ok){{showToast("Paramètres sauvegardés",true);updateOncallBadge(payload.oncall);closeSettings();}}
    else showToast("Erreur: "+d.error,false);
  }}catch(e){{showToast("Erreur réseau",false);}}
}}
function saveSettingsLive(){{
  const oncall=document.getElementById('cfg-oncall')?.checked||false;
  updateOncallBadge(oncall);
}}
function updateOncallBadge(on){{
  const b=document.getElementById('oncall-badge');
  if(!b)return;
  b.style.display=on?'inline-block':'none';
  b.className='oncall-badge '+(on?'oncall-on':'oncall-off');
  b.textContent=on?'ON CALL':'OFF';
}}
function applyThemeFromSettings(){{
  const light=document.getElementById('cfg-theme')?.checked;
  document.body.classList.toggle('theme-light',light);
  localStorage.setItem('soc_theme',light?'light':'dark');
  const btn=document.getElementById('theme-toggle');
  if(btn)btn.textContent=light?'☀️':'🌙';
}}
function resetApiKey(){{
  sessionStorage.removeItem('soc_auth');
  sessionStorage.removeItem('soc_api_key');
  closeSettings();
  document.getElementById('login-overlay').classList.add('open');
  setTimeout(()=>document.getElementById('login-key')?.focus(),100);
}}
(function(){{loadSettingsFromServer();}})();

// ── Status bar ──
function setDot(id,ok){{
  const d=document.getElementById(id);
  if(d)d.style.background=ok?'#22c55e':'#ef4444';
}}
async function refreshStatusBar(){{
  const key=sessionStorage.getItem('soc_api_key')||'';
  try{{
    const r=await fetch('/action/status',{{headers:{{'X-SOC-Key':key}},signal:AbortSignal.timeout(4000)}});
    const d=await r.json();
    setDot('dot-api',r.ok);
    setDot('dot-f2b',!!(d.fail2ban_active||d.banned_count>=0));
  }}catch(e){{setDot('dot-api',false);setDot('dot-f2b',false);}}
}}
refreshStatusBar();
setInterval(refreshStatusBar,60000);

// ── Navigation ──
function showScreen(id){{
  document.querySelectorAll('.screen').forEach(s=>s.classList.remove('active'));
  document.querySelectorAll('.nav-item,.bn-item,.nav-drawer-item').forEach(n=>n.classList.remove('active'));
  document.getElementById('screen-'+id).classList.add('active');
  const di=document.getElementById('nav-'+id);   if(di)di.classList.add('active');
  const bi=document.getElementById('bn-'+id);    if(bi)bi.classList.add('active');
  const ddi=document.getElementById('dnav-'+id); if(ddi)ddi.classList.add('active');
  if(id==='security'&&window._leafletMap) setTimeout(()=>window._leafletMap.invalidateSize(),50);
  if(id==='performance') setTimeout(()=>window.dispatchEvent(new Event('resize')),50);
  sessionStorage.setItem('soc_screen',id);
}}
(function(){{const s=sessionStorage.getItem('soc_screen');if(s)showScreen(s);}})();

// ── Drawer mobile ──
function openDrawer(){{
  document.getElementById('nav-drawer').classList.add('open');
  document.getElementById('nav-overlay').classList.add('open');
  document.body.style.overflow='hidden';
}}
function closeDrawer(){{
  document.getElementById('nav-drawer').classList.remove('open');
  document.getElementById('nav-overlay').classList.remove('open');
  document.body.style.overflow='';
}}

// ── Onglets IA ──
function showTab(id){{
  document.querySelectorAll('.tab-pane').forEach(p=>p.style.display='none');
  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('tab-active'));
  document.getElementById(id).style.display='block';
  const btn=document.getElementById('btn-'+id.replace('tab-',''));
  if(btn)btn.classList.add('tab-active');
}}

// ── Refresh intelligent ──
(function(){{
  let last=Date.now(),paused=false;
  document.addEventListener('click',()=>last=Date.now());
  document.addEventListener('keydown',()=>last=Date.now());
  window.pauseRefresh=()=>paused=true;
  window.resumeRefresh=()=>{{paused=false;last=Date.now();}};
  setTimeout(function check(){{
    if(!paused&&Date.now()-last>10000){{location.reload();return;}}
    setTimeout(check,300000);
  }},300000);
}})();

// ── Notifications browser ──
(function(){{
  const prev=parseInt(localStorage.getItem('soc_bans')||'0');
  const curr={bans_today};
  localStorage.setItem('soc_bans',curr);
  if(curr>prev&&prev>0){{
    if(Notification.permission==='granted'){{
      new Notification('🚨 SOC ViaDigiTech',{{body:`${{curr}} auto-bans aujourd'hui (+${{curr-prev}} depuis la dernière visite)`,icon:''}});
    }}
  }}
  if(Notification.permission==='default'){{
    setTimeout(()=>Notification.requestPermission(),3000);
  }}
}})();

// ── Toast ──
function showToast(msg,ok,duration=4000){{
  const t=document.getElementById('toast');
  t.textContent=msg;t.style.background=ok?'#14532d':'#7f1d1d';
  t.style.color=ok?'#86efac':'#fca5a5';t.style.display='block';
  setTimeout(()=>t.style.display='none',duration);
}}

// ── Système modal ──
function showModal(title,msg,confirmLabel,onConfirm,danger){{
  document.getElementById('modal-title').textContent=title;
  document.getElementById('modal-msg').textContent=msg;
  document.getElementById('modal-input-row').style.display='none';
  const btn=document.getElementById('modal-confirm');
  btn.textContent=confirmLabel;
  btn.className=danger?'btn-danger':'btn-primary';
  btn.onclick=()=>{{closeModal();onConfirm();}};
  document.getElementById('modal-overlay').classList.add('open');
}}
function showPromptModal(title,placeholder,onConfirm){{
  document.getElementById('modal-title').textContent=title;
  document.getElementById('modal-msg').textContent='';
  document.getElementById('modal-input-row').style.display='block';
  const inp=document.getElementById('modal-input');
  inp.value='';inp.placeholder=placeholder;
  const btn=document.getElementById('modal-confirm');
  btn.textContent='Confirmer';btn.className='btn-primary';
  btn.onclick=()=>{{const v=inp.value.trim();if(!v)return;closeModal();onConfirm(v);}};
  document.getElementById('modal-overlay').classList.add('open');
  setTimeout(()=>inp.focus(),80);
  inp.onkeydown=(e)=>{{if(e.key==='Enter')btn.click();}};
}}
function closeModal(){{
  document.getElementById('modal-overlay').classList.remove('open');
}}
function handleOverlayClick(e){{
  if(e.target===document.getElementById('modal-overlay'))closeModal();
}}

// ── Indicateur ancienneté ──
(function(){{
  const genTime=new Date();
  const el=document.getElementById('age-indicator');
  if(!el)return;
  function update(){{
    const mins=Math.floor((Date.now()-genTime)/60000);
    if(mins<1){{el.textContent="⟳ à l'instant";el.className='age-indicator fresh';}}
    else if(mins<10){{el.textContent=`⟳ il y a ${{mins}}min`;el.className='age-indicator fresh';}}
    else if(mins<20){{el.textContent=`⟳ il y a ${{mins}}min`;el.className='age-indicator';}}
    else{{el.textContent=`⟳ il y a ${{mins}}min`;el.className='age-indicator stale';}}
  }}
  update();
  setInterval(update,30000);
}})();

// ── Recherche + filtres sécurité ──
let _filter='all';
function setFilter(f){{
  _filter=f;
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('f-'+f).classList.add('active');
  filterSecurity();
}}
function filterSecurity(){{
  const q=(document.getElementById('ip-search').value||'').toLowerCase();
  let shown=0;
  document.querySelectorAll('#audit-table tbody tr').forEach(r=>{{
    const ip=r.dataset.ip||'';
    const type=r.dataset.type||'';
    const matchQ=!q||ip.includes(q);
    const matchF=_filter==='all'||type===_filter;
    r.style.display=(matchQ&&matchF)?'':'none';
    if(matchQ&&matchF)shown++;
  }});
  document.querySelectorAll('#ip-table tbody tr').forEach(r=>{{
    const ip=r.dataset.ip||'';
    r.style.display=(!q||ip.includes(q))?'':'none';
  }});
  document.getElementById('filter-count').textContent=q||_filter!=='all'?shown+' résultat(s)':'';
}}

// ── Filtre générique tableau ──
function filterTable(tableId,inputId){{
  const q=document.getElementById(inputId)?.value.toLowerCase()||'';
  const rows=document.querySelectorAll('#'+tableId+' tr');
  rows.forEach((r,i)=>{{
    if(i===0)return;
    r.style.display=q===''||r.textContent.toLowerCase().includes(q)?'':'none';
  }});
}}

// ── Graphique bans 7j ECharts ──
(function(){{
  const el=document.getElementById('histChart');if(!el)return;
  const chart=echarts.init(el,'dark');
  chart.setOption({{
    backgroundColor:'transparent',
    tooltip:{{trigger:'axis',axisPointer:{{type:'shadow'}}}},
    legend:{{textStyle:{{color:'#94a3b8',fontSize:11}},top:4}},
    grid:{{top:36,bottom:52,left:40,right:12,containLabel:true}},
    dataZoom:[{{type:'slider',height:18,bottom:4,borderColor:'#1e2942',fillerColor:'rgba(99,102,241,0.15)',handleStyle:{{color:'#6366f1'}},textStyle:{{color:'#64748b',fontSize:10}}}}],
    xAxis:{{type:'category',data:{hist_labels_js},axisLabel:{{color:'#64748b',fontSize:11}},axisLine:{{lineStyle:{{color:'#1e2942'}}}},splitLine:{{show:false}}}},
    yAxis:{{type:'value',axisLabel:{{color:'#64748b',fontSize:11}},splitLine:{{lineStyle:{{color:'#1e2942'}}}},minInterval:1}},
    series:[
      {{name:'Bans auto',type:'bar',data:{hist_bans_js},itemStyle:{{color:'rgba(239,68,68,0.75)',borderRadius:[3,3,0,0]}},barMaxWidth:32,emphasis:{{itemStyle:{{color:'#ef4444'}}}}}},
      {{name:'Surveillés',type:'bar',data:{hist_watch_js},itemStyle:{{color:'rgba(99,102,241,0.55)',borderRadius:[3,3,0,0]}},barMaxWidth:32,emphasis:{{itemStyle:{{color:'#6366f1'}}}}}}
    ]
  }});
  window.addEventListener('resize',()=>chart.resize());
}})();

// ── Graphique CPU/RAM 24h ECharts ──
(function(){{
  const el=document.getElementById('perfChart');if(!el)return;
  const chart=echarts.init(el,'dark');
  chart.setOption({{
    backgroundColor:'transparent',
    tooltip:{{trigger:'axis',axisPointer:{{type:'cross',label:{{backgroundColor:'#1e2942'}}}},formatter:function(params){{
      let s=params[0].axisValue+'<br/>';
      params.forEach(p=>{{s+=`<span style="color:${{p.color}}">●</span> ${{p.seriesName}}: <b>${{p.value}}%</b><br/>`;}});return s;
    }}}},
    legend:{{textStyle:{{color:'#94a3b8',fontSize:11}},top:0}},
    grid:{{top:32,bottom:52,left:40,right:12}},
    dataZoom:[
      {{type:'inside',throttle:50}},
      {{type:'slider',height:18,bottom:4,borderColor:'#1e2942',fillerColor:'rgba(99,102,241,0.15)',handleStyle:{{color:'#6366f1'}},textStyle:{{color:'#64748b',fontSize:10}}}}
    ],
    xAxis:{{type:'category',boundaryGap:false,data:{perf_labels_js},axisLabel:{{color:'#64748b',fontSize:10,interval:'auto',maxInterval:10}},axisLine:{{lineStyle:{{color:'#1e2942'}}}},splitLine:{{show:false}}}},
    yAxis:{{type:'value',min:0,max:100,axisLabel:{{color:'#64748b',fontSize:10,formatter:function(v){{return v+'%';}}}},splitLine:{{lineStyle:{{color:'#1e2942'}}}}}},
    series:[
      {{name:'CPU %',type:'line',data:{perf_cpu_js},lineStyle:{{color:'#f59e0b',width:2}},itemStyle:{{opacity:0}},areaStyle:{{color:'#f59e0b',opacity:0.07}},smooth:0.3,symbol:'none'}},
      {{name:'RAM %',type:'line',data:{perf_ram_js},lineStyle:{{color:'#6366f1',width:2}},itemStyle:{{opacity:0}},areaStyle:{{color:'#6366f1',opacity:0.07}},smooth:0.3,symbol:'none'}},
      {{name:'Disk %',type:'line',data:{perf_disk_js},lineStyle:{{color:'#22c55e',width:1.5,type:'dashed'}},itemStyle:{{opacity:0}},areaStyle:{{color:'#22c55e',opacity:0.05}},smooth:0.3,symbol:'none'}}
    ]
  }});
  window.addEventListener('resize',()=>chart.resize());
}})();

// ── Heatmap ──
(function(){{
  const data={heatmap_js};
  const days={heatmap_days_js};
  const maxVal={hmap_max}||1;
  const container=document.getElementById('heatmap-container');
  if(!container)return;
  let html='<div class="heatmap-grid">';
  html+='<div class="hm-label"></div>';
  for(let h=0;h<24;h++)html+=`<div class="hm-hour">${{h.toString().padStart(2,'0')}}</div>`;
  for(let d=0;d<data.length;d++){{
    html+=`<div class="hm-label">${{days[d]||''}}</div>`;
    for(let h=0;h<24;h++){{
      const v=data[d][h];
      const intensity=v/maxVal;
      let bg;
      if(v===0)bg='#0d1117';
      else if(intensity<0.25)bg='#1a0a0a';
      else if(intensity<0.5)bg='#7f1d1d';
      else if(intensity<0.75)bg='#b91c1c';
      else bg='#ef4444';
      html+=`<div class="hm-cell" style="background:${{bg}};cursor:${{v>0?'pointer':'default'}}" title="${{days[d]}} ${{h.toString().padStart(2,'0')}}h : ${{v}} tentatives" onclick="hmDrilldown('${{days[d]}}','${{h}}','${{v}}')"></div>`;
    }}
  }}
  html+='</div>';
  container.innerHTML=html;
}})();

function hmDrilldown(day,hour,count){{
  if(count=='0')return;
  showModal('Heatmap drill-down',`${{day}} — ${{String(hour).padStart(2,'0')}}h\n\n${{count}} tentatives SSH enregistrées cette heure.\n\nVoir la Timeline pour le détail par IP.`,'Voir Timeline',function(){{showScreen('timeline');}});
}}

// ── Carte Leaflet ──
(function(){{
  const map=L.map('geomap',{{zoomControl:true,attributionControl:false}}).setView([20,10],2);
  window._leafletMap=map;
  L.tileLayer('https://{{s}}.basemaps.cartocdn.com/dark_all/{{z}}/{{x}}/{{y}}{{r}}.png',{{subdomains:'abcd',maxZoom:19}}).addTo(map);
  {geo_markers_js}
}})();

// ── Sparklines ECharts ──
(function(){{
  const cpu={perf_cpu_js};
  const ram={perf_ram_js};
  const disk={perf_disk_js};
  function spark(id,data,color){{
    const el=document.getElementById(id);
    if(!el||!data||data.length<2)return;
    const d=data.slice(-8);
    const chart=echarts.init(el,null,{{renderer:'canvas',width:'auto',height:40}});
    chart.setOption({{
      animation:false,
      grid:{{top:0,bottom:0,left:0,right:0}},
      xAxis:{{type:'category',show:false,data:d.map((_,i)=>i)}},
      yAxis:{{type:'value',show:false,min:0,max:100}},
      series:[{{
        type:'line',
        data:d,
        lineStyle:{{color:color,width:1.5}},
        itemStyle:{{opacity:0}},
        areaStyle:{{color:color,opacity:0.08}},
        smooth:0.4,
        symbol:'none'
      }}]
    }});
  }}
  spark('sp-cpu',cpu,'#f59e0b');
  spark('sp-ram',ram,'#6366f1');
  spark('sp-disk',disk,'#22c55e');
}})();

// ── Stubs si pas de clé API ──
if(typeof apiCall==='undefined'){{window.apiCall=async()=>null;}}
if(typeof banIP==='undefined'){{window.banIP=()=>showToast("Actions API non configurées",false);}}
if(typeof unbanIP==='undefined'){{window.unbanIP=()=>showToast("Actions API non configurées",false);}}
if(typeof addWhitelist==='undefined'){{window.addWhitelist=()=>showToast("Actions API non configurées",false);}}
if(typeof sendReport==='undefined'){{window.sendReport=()=>showToast("Actions API non configurées",false);}}
if(typeof askAIWithPrompt==='undefined'){{window.askAIWithPrompt=()=>showToast("Actions API non configurées",false);}}

// ── Export CSV ──
function exportTable(tableId,name){{
  const tbl=document.getElementById(tableId);
  if(!tbl)return;
  const rows=[...tbl.querySelectorAll('tr')];
  const csv=rows.map(r=>[...r.cells].map(c=>'"'+c.textContent.trim().replace(/"/g,'""')+'"').join(',')).join('\\n');
  const blob=new Blob(['\\uFEFF'+csv],{{type:'text/csv;charset=utf-8'}});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download=name+'_'+new Date().toISOString().slice(0,10)+'.csv';
  a.click();
}}

// ── Ctrl+K Global Search ──
const _cmdk_nav=[
  {{id:'overview',icon:'🏠',label:'Vue globale',hint:'Écran principal'}},
  {{id:'security',icon:'🔒',label:'Sécurité',hint:'IPs, carte, audit'}},
  {{id:'performance',icon:'📈',label:'Performance',hint:'CPU, RAM, heatmap'}},
  {{id:'timeline',icon:'🕒',label:'Timeline',hint:'Événements 24h'}},
  {{id:'infra',icon:'🖥️',label:'Infrastructure',hint:'Services, Docker'}},
];
let _cmdk_sel=0;
function openCmdK(){{
  document.getElementById('cmdk-overlay').classList.add('open');
  const inp=document.getElementById('cmdk-input');
  inp.value='';
  renderCmdK('');
  setTimeout(()=>inp.focus(),50);
}}
function closeCmdK(e){{
  if(!e||e.target===document.getElementById('cmdk-overlay'))
    document.getElementById('cmdk-overlay').classList.remove('open');
}}
function renderCmdK(q){{
  const res=document.getElementById('cmdk-results');
  const ql=q.toLowerCase();
  let items=[];
  if(!ql){{
    items=_cmdk_nav.map(n=>(`<div class="cmdk-item" onclick="showScreen('${{n.id}}');closeCmdK()"><span class="cmdk-item-icon">${{n.icon}}</span><span class="cmdk-item-label">${{n.label}}</span><span class="cmdk-item-hint">${{n.hint}}</span></div>`));
  }}else{{
    _cmdk_nav.filter(n=>n.label.toLowerCase().includes(ql)||n.hint.toLowerCase().includes(ql))
      .forEach(n=>items.push(`<div class="cmdk-item" onclick="showScreen('${{n.id}}');closeCmdK()"><span class="cmdk-item-icon">${{n.icon}}</span><span class="cmdk-item-label">${{n.label}}</span><span class="cmdk-item-hint">${{n.hint}}</span></div>`));
    if(/\d/.test(ql)){{
      items.push(`<div class="cmdk-item" onclick="openWorkbench('${{q}}');closeCmdK()"><span class="cmdk-item-icon">🔍</span><span class="cmdk-item-label">Investiguer ${{q}}</span><span class="cmdk-item-hint">Workbench IP</span></div>`);
      items.push(`<div class="cmdk-item" onclick="banIP('${{q}}');closeCmdK()"><span class="cmdk-item-icon">🔴</span><span class="cmdk-item-label">Bannir ${{q}}</span><span class="cmdk-item-hint">via Fail2Ban</span></div>`);
    }}
    items.push(`<div class="cmdk-item" onclick="askAIWithPrompt('${{q}}');closeCmdK()"><span class="cmdk-item-icon">🤖</span><span class="cmdk-item-label">Analyser : ${{q}}</span><span class="cmdk-item-hint">Question à l'IA SOC</span></div>`);
  }}
  res.innerHTML=items.join('')||'<div class="cmdk-item" style="color:#475569">Aucun résultat</div>';
  _cmdk_sel=0;
}}
document.addEventListener('keydown',e=>{{
  if((e.ctrlKey||e.metaKey)&&e.key==='k'){{e.preventDefault();openCmdK();}}
  if(e.key==='Escape')closeCmdK();
}});
document.getElementById('cmdk-input')?.addEventListener('input',e=>renderCmdK(e.target.value));

// ── Raccourcis clavier 1-5 ──
document.addEventListener('keydown',function(e){{
  if(e.target.tagName==='INPUT'||e.target.tagName==='TEXTAREA')return;
  if(document.getElementById('login-overlay')?.classList.contains('open'))return;
  if(e.key==='1')showScreen('overview');
  else if(e.key==='2')showScreen('security');
  else if(e.key==='3')showScreen('performance');
  else if(e.key==='4')showScreen('timeline');
  else if(e.key==='5')showScreen('infra');
  else if(e.key==='b'||e.key==='B'){{e.preventDefault();const ip=prompt('Bannir IP:');if(ip)banIP(ip);}}
  else if(e.key==='?')openCmdK();
}});

// ── Mode IR ──
function openIR(){{
  const ol=document.getElementById('ir-overlay');
  ol.classList.add('open');
  const score={threat};
  const color=score>=70?'#ef4444':score>=40?'#f59e0b':'#22c55e';
  const level=score>=70?'MENACE ÉLEVÉE':score>=40?'MENACE MODÉRÉE':'MENACE FAIBLE';
  document.getElementById('ir-score-display').textContent=score+'/100';
  document.getElementById('ir-score-display').style.color=color;
  document.getElementById('ir-level').textContent=level;
  document.getElementById('ir-level').style.color=color;
  const rows=[...document.querySelectorAll('#ip-table tbody tr')].slice(0,5);
  document.getElementById('ir-top-ips').innerHTML=rows.length?rows.map(r=>{{
    const cells=[...r.cells];
    return `<div style="display:flex;justify-content:space-between"><span style="color:#a5b4fc">${{cells[0]?.textContent?.split('🔴')[1]?.split('🟡')[1]?.trim()||cells[0]?.textContent?.trim()}}</span><span style="color:#ef4444">${{cells[1]?.textContent?.trim()}} tent.</span></div>`;
  }}).join(''):'<div style="color:#475569">Aucune IP active</div>';
  document.getElementById('ir-actions').innerHTML=`
    <button onclick="askAIWithPrompt('Analyse de menace urgente : niveau ${{score}}/100, que faire maintenant ?')" class="btn-danger" style="text-align:left">🤖 Analyse IA urgente</button>
    <button onclick="sendReport(this)" class="btn-primary" style="text-align:left">📋 Générer rapport maintenant</button>
    <button onclick="showScreen('security');closeIR()" style="background:#1e1b4b;border:1px solid #4338ca;color:#a5b4fc;padding:8px;border-radius:6px;cursor:pointer;text-align:left">🔒 Aller à Sécurité</button>
  `;
  window._irTimer=setInterval(()=>{{
    document.getElementById('ir-time').textContent=new Date().toLocaleTimeString('fr-FR');
  }},1000);
}}
function closeIR(){{
  document.getElementById('ir-overlay').classList.remove('open');
  if(window._irTimer)clearInterval(window._irTimer);
}}

// ── Logs live infra ──
async function refreshLogs(){{
  const key=sessionStorage.getItem('soc_api_key')||'';
  const el=document.getElementById('live-logs');
  if(!el)return;
  try{{
    const r=await fetch('/action/logs?n=40',{{headers:{{'X-SOC-Key':key}}}});
    const d=await r.json();
    el.textContent=(d.lines||[]).join('\\n')||'Aucun log disponible';
    el.scrollTop=el.scrollHeight;
  }}catch(e){{el.textContent='Erreur: '+e.message;}}
}}
document.addEventListener('DOMContentLoaded',function(){{
  if(typeof showScreen==='function'){{
    const _orig=showScreen;
    window.showScreen=function(s){{_orig(s);if(s==='infra')refreshLogs();}};
  }}
}});

// ── Workbench IP ──
let _wbIp='';
function openWorkbench(ip){{
  _wbIp=ip;
  document.getElementById('wb-ip-title').textContent=ip;
  document.getElementById('wb-score').textContent='';
  document.getElementById('wb-attempts').textContent='';
  document.getElementById('wb-status').textContent='';
  document.getElementById('wb-geo').textContent='Chargement...';
  document.getElementById('wb-ai-result').textContent='';
  const allRows=[...document.querySelectorAll('#ip-table tbody tr')];
  const row=allRows.find(r=>r.dataset.ip===ip);
  const attempts=row?row.cells[1]?.textContent?.trim():'N/A';
  document.getElementById('wb-attempts').textContent=attempts;
  const isBanned=row?.cells[0]?.textContent?.includes('🔴');
  document.getElementById('wb-status').textContent=isBanned?'BANNI':'Actif';
  document.getElementById('wb-status').style.color=isBanned?'#ef4444':'#f59e0b';
  document.getElementById('wb-actions').innerHTML=isBanned?
    `<button onclick="unbanIP('${{ip}}')" class="btn-success">Débannir</button>
     <button onclick="addWhitelist('${{ip}}')" class="btn-primary" style="font-size:11px">Whitelist</button>`:
    `<button onclick="banIP('${{ip}}')" class="btn-danger">Bannir</button>
     <button onclick="addWhitelist('${{ip}}')" class="btn-primary" style="font-size:11px">Whitelist</button>`;
  const auditRows=[...document.querySelectorAll('#audit-table tbody tr')].filter(r=>r.dataset.ip===ip);
  const tbody=document.getElementById('wb-history');
  tbody.innerHTML=auditRows.length?auditRows.map(r=>{{
    const cells=[...r.cells];
    return `<tr><td style="font-size:11px;color:#64748b">${{cells[0]?.textContent}}</td><td>${{cells[2]?.innerHTML}}</td><td style="color:#f59e0b">${{cells[3]?.textContent}}</td></tr>`;
  }}).join(''):'<tr><td colspan="3" style="color:#475569;text-align:center">Aucune action récente</td></tr>';
  document.getElementById('wb-geo').innerHTML='N/A';
  document.getElementById('nav-workbench').style.display='block';
  showScreen('workbench');
}}
function wbAnalyze(){{
  if(!_wbIp)return;
  const btn=document.getElementById('wb-analyze-btn');
  const res=document.getElementById('wb-ai-result');
  res.textContent='Analyse en cours...';
  apiCall('/analyze',{{prompt:`Analyse cette IP suspecte : ${{_wbIp}}. Quel est son niveau de risque ? Faut-il la bannir définitivement ?`}},btn).then(r=>{{
    if(r&&r.ok)res.innerHTML=r.response.replace(/\\n/g,'<br>');
    else res.textContent='Erreur IA';
  }});
}}

// ── Actions API ──
{actions_js}

// ── Annotations ──
const _annotations={annotations_js};
function renderAnnotations(){{
  const el=document.getElementById('ann-list');
  if(!el)return;
  if(!_annotations.length){{el.innerHTML='<div style="color:var(--muted);font-size:12px">Aucune annotation.</div>';return;}}
  el.innerHTML=_annotations.map(a=>`<div style="padding:5px 0;border-bottom:1px solid var(--border);font-size:12px"><span style="color:var(--accent)">${{a.ts}}</span> — ${{a.note}} <span style="color:var(--dim)">(par ${{a.author||'SOC'}})</span></div>`).join('');
}}
function addAnnotation(){{
  showPromptModal("Ajouter une annotation","Texte de l'annotation...",function(txt){{
    if(!txt)return;
    const key=sessionStorage.getItem('soc_key')||'';
    fetch('/action/annotation/add',{{method:'POST',headers:{{'Content-Type':'application/json','X-SOC-Key':key}},body:JSON.stringify({{note:txt,author:'David'}})
    }}).then(r=>r.json()).then(d=>{{if(d.ok)location.reload();}}).catch(()=>{{}});
  }});
}}
renderAnnotations();

// ── SSE live metrics ──
(function(){{
  if(!window.EventSource)return;
  const key=sessionStorage.getItem('soc_key')||'';
  const src=new EventSource('/action/stream?key='+encodeURIComponent(key));
  src.onmessage=function(e){{
    try{{
      const d=JSON.parse(e.data);
      const cpuEl=document.getElementById('live-cpu');
      const ramEl=document.getElementById('live-ram');
      const banEl=document.getElementById('live-bans');
      if(cpuEl)cpuEl.textContent=d.cpu+'%';
      if(ramEl)ramEl.textContent=d.ram+'%';
      if(banEl)banEl.textContent=d.bans;
      setDot('dot-sse',true);
    }}catch(err){{}}
  }};
  src.onerror=function(){{setDot('dot-sse',false);src.close();}};
}})();

// ── Theme toggle ──
function toggleTheme(){{
  const b=document.body;
  const light=b.classList.toggle('theme-light');
  localStorage.setItem('soc_theme',light?'light':'dark');
  document.getElementById('theme-toggle').textContent=light?'☀️':'🌙';
}}
(function(){{
  if(localStorage.getItem('soc_theme')==='light'){{
    document.body.classList.add('theme-light');
    const btn=document.getElementById('theme-toggle');
    if(btn)btn.textContent='☀️';
  }}
}})();
</script>
</body></html>"""
    # Générer manifest.json PWA
    manifest = {
        "name": "ViaDigiTech SOC",
        "short_name": "SOC",
        "description": "Dashboard SecOps ViaDigiTech",
        "start_url": "/soc/",
        "display": "standalone",
        "background_color": "#0a0d14",
        "theme_color": "#6366f1",
        "icons": [{"src": "icon.svg", "sizes": "any", "type": "image/svg+xml"}]
    }
    try:
        with open(MANIFEST_PATH, "w") as f:
            json.dump(manifest, f)
    except Exception as _e:
        print(f"[Dashboard] ⚠ manifest.json non créé : {_e}")

    return html

# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────

if __name__ == "__main__":
    html = build_html()
    with open(OUTPUT_FILE, "w") as f:
        f.write(html)
    print(f"[{datetime.now():%H:%M:%S}] Dashboard v6 généré → {OUTPUT_FILE}")

    # Validation JS syntaxique (syntaxe uniquement, pas exécution)
    try:
        import subprocess as _sp, tempfile as _tf, os as _os
        _js = open(OUTPUT_FILE).read().split("<script>")[1].split("</script>")[0]
        _tmp = _tf.NamedTemporaryFile(suffix='.js', mode='w', delete=False)
        _tmp.write(_js); _tmp.close()
        _r = _sp.run(["node", "--check", _tmp.name], capture_output=True, timeout=10)
        _os.unlink(_tmp.name)
        if _r.returncode != 0:
            print(f"[Dashboard] ⚠ Erreur JS détectée : {_r.stderr.decode()[:200]}")
        else:
            print(f"[Dashboard] ✓ JS valide")
    except Exception as _e:
        pass
