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
    timeline   = get_timeline_events(24)
    heatmap, heatmap_days = get_attack_heatmap(7)
    subnets    = get_subnet_correlation(ssh_fails)
    whitelist  = get_whitelist()
    threat     = compute_threat_score(metrics, ssh_total, bans_today, ban_count)

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
        top_ip_rows += f"<tr data-ip='{ip}'><td style='font-family:monospace;font-size:12px'>{is_banned} {ip}{loc}{btn}</td><td style='text-align:right;font-weight:700;color:#ef4444'>{count}</td></tr>"

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
    report_btn = "<button onclick='sendReport()' class='btn-primary' style='font-size:11px;padding:4px 12px'>📋 Rapport maintenant</button>" if ACTIONS_KEY else ""

    # ── Actions JS ──
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
async function addWhitelist(ip){{
  const target=ip||window.prompt('IP à whitelister :');
  if(!target)return;
  const r=await apiCall('/whitelist/add',{{ip:target}});
  showToast(r.ok?`✓ ${{target}} whitelistée`:`Erreur: ${{r.error}}`,r.ok);
}}
async function removeWhitelist(ip){{
  if(!confirm(`Retirer ${{ip}} de la whitelist ?`))return;
  const r=await apiCall('/whitelist/remove',{{ip}});
  showToast(r.ok?`✓ ${{ip}} retirée`:`Erreur: ${{r.error}}`,r.ok);
}}
async function sendReport(){{
  if(!confirm('Générer et envoyer le rapport maintenant ?'))return;
  showToast('Rapport en cours de génération...', true, 5000);
  const r=await apiCall('/report',{{}});
  showToast(r.ok?`✓ ${{r.message}}`:`Erreur: ${{r.error}}`,r.ok, 6000);
}}
async function askAI(){{
  window.pauseRefresh();
  const p=window.prompt('Question SOC IA :','Quel est le niveau de risque actuel ?');
  window.resumeRefresh();
  if(!p)return;
  showToast('Analyse en cours...',true,5000);
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
/* ── Reset & base ── */
*{{box-sizing:border-box;margin:0;padding:0}}
:root{{--bg:#0a0d14;--bg2:#0d1117;--bg3:#111827;--border:#1e2942;--border2:#2d3f5e;--text:#e2e8f0;--muted:#64748b;--dim:#334155;--accent:#6366f1;--accent-light:#a5b4fc;--red:#ef4444;--orange:#f59e0b;--green:#22c55e}}
body{{font-family:-apple-system,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);display:flex;flex-direction:column;min-height:100vh;font-variant-numeric:tabular-nums}}
h2{{font-size:10px;text-transform:uppercase;letter-spacing:1.8px;color:var(--muted);margin-bottom:14px;font-weight:700}}

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
</style>
</head><body>
<div id="toast"></div>

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
  <div class="topbar-right">
    {report_btn}
    <div class="threat-badge" style="background:{threat_bg};color:{threat_color};border-color:{threat_color}">
      {threat}/100 — {threat_label}
    </div>
    {svc_badge}
    <span class="topbar-hostname">{hostname} · {now.strftime('%d/%m %H:%M')}</span>
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
  <div class="grid g6" style="margin-bottom:14px">
    <div class="card"><div class="stat-big" style="color:{cpu_color}">{metrics['cpu']:.0f}%</div><div class="stat-label">CPU</div><div class="stat-sub">Load {metrics['load1']}</div></div>
    <div class="card"><div class="stat-big" style="color:{ram_color}">{metrics['ram']:.0f}%</div><div class="stat-label">RAM</div><div class="stat-sub">{metrics['ram_used']}GB / {metrics['ram_total']}GB</div></div>
    <div class="card"><div class="stat-big" style="color:{disk_color}">{metrics['disk']:.0f}%</div><div class="stat-label">Disque</div><div class="stat-sub">{metrics['disk_used']}GB / {metrics['disk_total']}GB</div></div>
    <div class="card"><div class="stat-big" style="color:#ef4444">{ban_count}</div><div class="stat-label">IPs bannies</div></div>
    <div class="card"><div class="stat-big" style="color:#f59e0b">{ssh_total}</div><div class="stat-label">Échecs SSH 24h</div><div class="stat-sub">{len(ssh_fails)} IPs distinctes</div></div>
    <div class="card"><div class="stat-big" style="color:#ef4444">{bans_today}{trend_html}</div><div class="stat-label">Auto-bans aujourd'hui</div></div>
  </div>
  <div class="grid g5" style="margin-bottom:14px">{services_cards}</div>
  <div style="margin-bottom:14px">{ai_html}</div>
  <div class="grid g2" style="margin-bottom:14px">
    <div class="card"><h2>Activité — 7 derniers jours</h2><canvas id="histChart" height="200"></canvas></div>
    <div class="card">
      <h2>Métriques système</h2>
      {gauges_html}
      <div style="margin-top:12px;padding-top:10px;border-top:1px solid #1e2942;font-size:11px;color:#64748b">
        Uptime : <span style="color:#94a3b8;font-weight:600">{metrics['uptime_days']}j {metrics['uptime_hours']}h</span>
        &nbsp;·&nbsp; Docker : <span style="color:#a5b4fc;font-weight:600">{sum(1 for c in containers if 'Up' in c.get('Status',''))}/{len(containers)}</span>
      </div>
    </div>
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
      <h2>Top IPs attaquantes 24h</h2>
      {"<div style='color:#475569;font-size:13px;padding:12px 0'>Aucune activité SSH suspecte</div>" if not top_ip_rows else f"<div class='table-wrap' style='max-height:360px;overflow-y:auto'><table id='ip-table'><thead><tr><th>IP</th><th style='text-align:right'>Tentatives</th></tr></thead><tbody>{top_ip_rows}</tbody></table></div>"}
      {f'<div style="margin-top:14px;padding-top:12px;border-top:1px solid #1e2942"><h2>Connexions légitimes 24h</h2><div class="table-wrap"><table><thead><tr><th></th><th>IP</th><th>Utilisateur</th><th>Heure</th></tr></thead><tbody>{accepted_html}</tbody></table></div></div>' if accepted_html else ""}
    </div>
    <div class="card">
      <h2>Journal d'audit</h2>
      {"<div style='color:#475569;font-size:13px;padding:12px 0'>Aucune action enregistrée</div>" if not audit_html else f"<div class='table-wrap' style='max-height:360px;overflow-y:auto'><table id='audit-table'><thead><tr><th>Heure</th><th>IP</th><th>Action</th><th style='text-align:right'>Score</th></tr></thead><tbody>{audit_html}</tbody></table></div>"}
    </div>
  </div>

  <!-- Corrélation /24 -->
  <div class="card" style="margin-bottom:14px">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <h2 style="margin:0">Corrélation par sous-réseau /24</h2>
      <span style="font-size:11px;color:#334155">{len(subnets)} blocs détectés</span>
    </div>
    {"<div style='color:#475569;font-size:13px;padding:8px 0'>Aucune corrélation détectée</div>" if not subnet_rows else f"<div class='table-wrap'><table><thead><tr><th>Sous-réseau</th><th style='text-align:center'>IPs uniques</th><th style='text-align:right'>Tentatives</th></tr></thead><tbody>{subnet_rows}</tbody></table></div>"}
  </div>
</div>

<!-- ═══════════ ÉCRAN 3 : PERFORMANCE ═══════════ -->
<div class="screen" id="screen-performance">
  <div class="card" style="margin-bottom:14px">
    <h2>CPU / RAM / Disque — 24 dernières heures</h2>
    {'<canvas id="perfChart" height="110"></canvas>' if perf_labels else '<div style="color:#475569;font-size:13px;padding:24px 0;text-align:center">Historique en cours de constitution</div>'}
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
  <div class="card">
    <h2>Log détecteur temps réel</h2>
    <div style="background:#0a0d14;border-radius:8px;padding:14px;max-height:280px;overflow-y:auto">
      {det_html or '<div style="color:#475569;font-size:13px">Aucun log</div>'}
    </div>
  </div>
</div>

<!-- ═══════════ ÉCRAN 4 : TIMELINE ═══════════ -->
<div class="screen" id="screen-timeline">
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
      {"<div style='color:#475569;font-size:13px;padding:8px 0'>Whitelist vide</div>" if not whitelist_html else f"<div class='table-wrap'><table><thead><tr><th>IP / Réseau</th><th></th></tr></thead><tbody>{whitelist_html}</tbody></table></div>"}
    </div>
    <div class="card">
      <h2>Conteneurs Docker — {len(containers)} · {sum(1 for c in containers if 'Up' in c.get('Status',''))} actifs</h2>
      <div class="grid g2" style="margin-top:4px">
        {containers_html or '<div style="color:#475569;font-size:13px">Aucun container détecté</div>'}
      </div>
    </div>
  </div>
</div>

</div><!-- /main -->

<div style="text-align:center;font-size:10px;color:#1e2942;padding:8px;border-top:1px solid #0d1117">
  ViaDigiTech AI SecOps v6 · {hostname} · 15min · seuils CPU {WARN_CPU}/{CRIT_CPU}% · RAM {WARN_MEM}/{CRIT_MEM}% · Disk {WARN_DISK}/{CRIT_DISK}%
</div>

<script>
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

// ── Graphique 7 jours ──
(function(){{
  const el=document.getElementById('histChart');if(!el)return;
  new Chart(el.getContext('2d'),{{
    type:'bar',
    data:{{labels:{hist_labels_js},datasets:[
      {{label:'Bans auto',data:{hist_bans_js},backgroundColor:'rgba(239,68,68,0.7)',borderColor:'#ef4444',borderWidth:1,borderRadius:4}},
      {{label:'Surveillés',data:{hist_watch_js},backgroundColor:'rgba(99,102,241,0.5)',borderColor:'#6366f1',borderWidth:1,borderRadius:4}}
    ]}},
    options:{{responsive:true,plugins:{{legend:{{labels:{{color:'#94a3b8',font:{{size:11}}}}}},tooltip:{{mode:'index'}}}},
      scales:{{x:{{ticks:{{color:'#64748b'}},grid:{{color:'#1e2942'}}}},y:{{ticks:{{color:'#64748b'}},grid:{{color:'#1e2942'}},beginAtZero:true}}}}}}
  }});
}})();

// ── Graphique CPU/RAM 24h ──
(function(){{
  const el=document.getElementById('perfChart');if(!el)return;
  new Chart(el.getContext('2d'),{{
    type:'line',
    data:{{labels:{perf_labels_js},datasets:[
      {{label:'CPU %',data:{perf_cpu_js},borderColor:'#f59e0b',backgroundColor:'rgba(245,158,11,0.07)',borderWidth:2,pointRadius:0,tension:0.3,fill:true}},
      {{label:'RAM %',data:{perf_ram_js},borderColor:'#6366f1',backgroundColor:'rgba(99,102,241,0.07)',borderWidth:2,pointRadius:0,tension:0.3,fill:true}},
      {{label:'Disk %',data:{perf_disk_js},borderColor:'#22c55e',backgroundColor:'rgba(34,197,94,0.05)',borderWidth:1.5,pointRadius:0,tension:0.3,borderDash:[4,4],fill:true}}
    ]}},
    options:{{responsive:true,plugins:{{legend:{{labels:{{color:'#94a3b8',font:{{size:11}}}}}},tooltip:{{mode:'index',intersect:false}}}},
      scales:{{x:{{ticks:{{color:'#64748b',maxTicksLimit:10}},grid:{{color:'#1e2942'}}}},y:{{ticks:{{color:'#64748b'}},grid:{{color:'#1e2942'}},min:0,max:100}}}}}}
  }});
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
      html+=`<div class="hm-cell" style="background:${{bg}}" title="${{days[d]}} ${{h.toString().padStart(2,'0')}}h : ${{v}} tentatives"></div>`;
    }}
  }}
  html+='</div>';
  container.innerHTML=html;
}})();

// ── Carte Leaflet ──
(function(){{
  const map=L.map('geomap',{{zoomControl:true,attributionControl:false}}).setView([20,10],2);
  window._leafletMap=map;
  L.tileLayer('https://{{s}}.basemaps.cartocdn.com/dark_all/{{z}}/{{x}}/{{y}}{{r}}.png',{{subdomains:'abcd',maxZoom:19}}).addTo(map);
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
    print(f"[{datetime.now():%H:%M:%S}] Dashboard v6 généré → {OUTPUT_FILE}")
