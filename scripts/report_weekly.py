#!/usr/bin/env python3
"""
ViaDigiTech SOC — Rapport hebdomadaire (vendredi 08h00 via cron)
Top attaquants, tendances 7j vs semaine précédente, MTTD, analyse IA.
"""
import os
import csv
import json
import smtplib
import requests
import subprocess
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

MAIL_FROM   = os.environ.get("SOC_MAIL_FROM", "secops@yourdomain.com")
MAIL_TO     = os.environ.get("SOC_MAIL_TO",   "admin@yourdomain.com").split(",")
AUDIT_LOG   = "/home/ubuntu/secops/audit_actions.csv"
OLLAMA_URL  = "http://localhost:11434/api/generate"
DASHBOARD_URL = "http://graph.viadigitech.com/soc/"
LOCK_FILE   = "/tmp/report_weekly.lock"


# ─────────────────────────────────────────
# Lecture audit CSV
# ─────────────────────────────────────────

def read_audit(since: datetime, until: datetime):
    rows = []
    if not os.path.exists(AUDIT_LOG):
        return rows
    with open(AUDIT_LOG) as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 4 or row[0] == "timestamp":
                continue
            try:
                ts = datetime.fromisoformat(row[0][:19])
                if since <= ts < until:
                    rows.append(row)
            except Exception:
                pass
    return rows


def week_stats(rows):
    """Agrège les stats clés depuis les lignes d'audit."""
    bans, temp_bans, watches, subnets = 0, 0, 0, 0
    ips_banned = Counter()
    by_day     = defaultdict(int)

    for row in rows:
        ts, ip, action = row[0][:10], row[1].strip(), row[2].strip()
        if "BAN_AUTO" in action or "BAN_OLLAMA" in action:
            bans += 1
            ips_banned[ip] += 1
        elif "BAN_TEMP" in action:
            temp_bans += 1
            ips_banned[ip] += 1
        elif "BAN_SUBNET" in action:
            subnets += 1
        elif "SURVEILLE" in action or "OLLAMA_" in action or "WATCH" in action:
            watches += 1
        by_day[ts] += 1

    return {
        "bans": bans, "temp_bans": temp_bans,
        "watches": watches, "subnets": subnets,
        "top_ips": ips_banned.most_common(10),
        "by_day": dict(sorted(by_day.items())),
    }


def geo_country(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode,country",
                         timeout=3)
        if r.status_code == 200:
            d = r.json()
            return d.get("countryCode", ""), d.get("country", "")
    except Exception:
        pass
    return "", ""


# ─────────────────────────────────────────
# Analyse IA hebdomadaire
# ─────────────────────────────────────────

def ollama_weekly_analysis(stats_this, stats_prev):
    delta_bans = stats_this["bans"] - stats_prev["bans"]
    trend = f"+{delta_bans}" if delta_bans >= 0 else str(delta_bans)
    top3 = ", ".join(f"{ip} ({n} bans)" for ip, n in stats_this["top_ips"][:3])

    prompt = (
        f"Tu es un analyste SOC. Analyse cette semaine en cybersécurité (SSH/brute-force):\n"
        f"- Bans auto: {stats_this['bans']} ({trend} vs semaine précédente)\n"
        f"- Bans temporaires: {stats_this['temp_bans']}\n"
        f"- IPs surveillées: {stats_this['watches']}\n"
        f"- Blocs /24 bannis: {stats_this['subnets']}\n"
        f"- Top 3 attaquants: {top3}\n\n"
        f"En 3-4 phrases: résume la semaine, identifie les tendances et donne 2 recommandations concrètes. "
        f"Réponds en français, sois concis et direct."
    )
    try:
        r = requests.post(OLLAMA_URL, json={
            "model": "qwen2.5:3b",
            "prompt": prompt,
            "stream": False,
            "options": {"num_predict": 300, "temperature": 0.3}
        }, timeout=90)
        if r.status_code == 200:
            return r.json().get("response", "").strip()
    except Exception as e:
        print(f"[Weekly] Ollama error: {e}")
    return "Analyse IA non disponible cette semaine."


# ─────────────────────────────────────────
# Génération HTML
# ─────────────────────────────────────────

BAR = "█"

def sparkbar(value, max_val, width=14):
    if max_val == 0:
        return "░" * width
    filled = max(1, int(value / max_val * width)) if value > 0 else 0
    return BAR * filled + "░" * (width - filled)


def build_html(stats_this, stats_prev, ai_analysis, week_label):
    delta      = stats_this["bans"] - stats_prev["bans"]
    trend_icon = "📈" if delta > 0 else ("📉" if delta < 0 else "➡️")
    trend_txt  = f"{trend_icon} {'+' if delta >= 0 else ''}{delta} vs semaine précédente"

    max_day = max(stats_this["by_day"].values(), default=1)
    days_rows = ""
    for day, count in sorted(stats_this["by_day"].items())[-7:]:
        bar = sparkbar(count, max_day)
        days_rows += (
            f"<tr><td style='color:#94a3b8;font-size:12px;white-space:nowrap;"
            f"padding:4px 8px'>{day}</td>"
            f"<td style='font-family:monospace;font-size:11px;color:#6366f1;"
            f"padding:4px 8px'>{bar}</td>"
            f"<td style='text-align:right;font-weight:700;color:#ef4444;"
            f"padding:4px 8px'>{count}</td></tr>"
        )

    top_rows = ""
    for rank, (ip, bans) in enumerate(stats_this["top_ips"][:8], 1):
        cc, country = geo_country(ip)
        top_rows += (
            f"<tr style='border-bottom:1px solid #1e2942'>"
            f"<td style='color:#475569;font-size:12px;padding:6px 8px'>{rank}</td>"
            f"<td style='font-family:monospace;font-size:12px;padding:6px 8px;"
            f"color:#a5b4fc'>{ip}</td>"
            f"<td style='font-size:12px;padding:6px 8px;color:#94a3b8'>{cc} {country}</td>"
            f"<td style='text-align:right;font-weight:700;color:#ef4444;"
            f"padding:6px 8px'>{bans}</td></tr>"
        )

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><style>
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#020712;color:#f1f5f9;margin:0;padding:0}}
.wrap{{max-width:680px;margin:0 auto;padding:24px 16px}}
.header{{background:linear-gradient(135deg,#0d1117,#0f172a);border:1px solid #1e2942;border-radius:16px;padding:32px;text-align:center;margin-bottom:20px}}
.title{{font-size:28px;font-weight:800;letter-spacing:-1px;color:#f1f5f9}}
.sub{{font-size:13px;color:#475569;margin-top:4px}}
.week{{font-size:14px;font-weight:600;color:#6366f1;margin-top:8px}}
.card{{background:#0d1117;border:1px solid #1e2942;border-radius:12px;padding:20px;margin-bottom:14px}}
.card-title{{font-size:11px;font-weight:700;color:#475569;letter-spacing:1px;text-transform:uppercase;margin-bottom:14px}}
.stat-row{{display:flex;gap:12px;flex-wrap:wrap}}
.stat-box{{flex:1;min-width:120px;background:#020712;border-radius:8px;padding:14px;text-align:center}}
.stat-num{{font-size:32px;font-weight:800;letter-spacing:-1px}}
.stat-lbl{{font-size:11px;color:#475569;margin-top:4px}}
.trend{{font-size:12px;color:#94a3b8;text-align:center;padding:8px 0}}
table{{width:100%;border-collapse:collapse}}
th{{font-size:11px;color:#475569;text-transform:uppercase;letter-spacing:.5px;text-align:left;padding:4px 8px;border-bottom:1px solid #1e2942}}
.ai-box{{background:linear-gradient(135deg,rgba(99,102,241,.08),rgba(16,185,129,.05));border:1px solid rgba(99,102,241,.2);border-radius:12px;padding:20px;font-size:13px;line-height:1.7;color:#cbd5e1;white-space:pre-wrap}}
.btn{{display:inline-block;background:#6366f1;color:#fff;text-decoration:none;padding:12px 28px;border-radius:8px;font-weight:700;font-size:14px;margin-top:16px}}
.footer{{text-align:center;color:#334155;font-size:11px;margin-top:24px;padding-top:16px;border-top:1px solid #1e2942}}
</style></head>
<body><div class="wrap">
  <div class="header">
    <div style="font-size:36px;margin-bottom:8px">📊</div>
    <div class="title">Rapport Hebdomadaire SOC</div>
    <div class="sub">ViaDigiTech Security Operations Center</div>
    <div class="week">Semaine du {week_label}</div>
  </div>

  <div class="card">
    <div class="card-title">Bilan de la semaine</div>
    <div class="stat-row">
      <div class="stat-box">
        <div class="stat-num" style="color:#ef4444">{stats_this['bans']}</div>
        <div class="stat-lbl">Bans définitifs</div>
      </div>
      <div class="stat-box">
        <div class="stat-num" style="color:#f59e0b">{stats_this['temp_bans']}</div>
        <div class="stat-lbl">Bans temporaires</div>
      </div>
      <div class="stat-box">
        <div class="stat-num" style="color:#a78bfa">{stats_this['watches']}</div>
        <div class="stat-lbl">IPs surveillées</div>
      </div>
      <div class="stat-box">
        <div class="stat-num" style="color:#f97316">{stats_this['subnets']}</div>
        <div class="stat-lbl">Blocs /24 bannis</div>
      </div>
    </div>
    <div class="trend">{trend_txt}</div>
  </div>

  <div class="card">
    <div class="card-title">Activité quotidienne (7 derniers jours)</div>
    <table>
      <thead><tr><th>Date</th><th>Activité</th><th style="text-align:right">Actions</th></tr></thead>
      <tbody>{days_rows}</tbody>
    </table>
  </div>

  <div class="card">
    <div class="card-title">Top 8 attaquants de la semaine</div>
    <table>
      <thead><tr><th>#</th><th>IP</th><th>Pays</th><th style="text-align:right">Bans</th></tr></thead>
      <tbody>{top_rows}</tbody>
    </table>
  </div>

  <div class="card">
    <div class="card-title">🤖 Analyse IA hebdomadaire (qwen2.5:3b)</div>
    <div class="ai-box">{ai_analysis}</div>
  </div>

  <div style="text-align:center;padding:16px 0">
    <a href="{DASHBOARD_URL}" class="btn">Ouvrir le Dashboard SOC →</a>
  </div>

  <div class="footer">
    ViaDigiTech SOC — Rapport automatique · Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M')}
  </div>
</div></body></html>"""


# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────

def send_mail(html, subject):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = MAIL_FROM
    msg["To"]      = ", ".join(MAIL_TO)
    msg.attach(MIMEText(html, "html", "utf-8"))
    with smtplib.SMTP("localhost", 25, timeout=30) as s:
        s.sendmail(MAIL_FROM, MAIL_TO, msg.as_string())


def main():
    if os.path.exists(LOCK_FILE):
        age = (datetime.now().timestamp() - os.path.getmtime(LOCK_FILE)) / 60
        if age < 60:
            print("Lock actif, abandon.")
            return
    open(LOCK_FILE, "w").close()

    try:
        now        = datetime.now()
        days_since = now.weekday()
        week_start = (now - timedelta(days=days_since)).replace(
            hour=0, minute=0, second=0, microsecond=0)
        week_end   = now
        prev_start = week_start - timedelta(days=7)
        prev_end   = week_start

        rows_this  = read_audit(week_start, week_end)
        rows_prev  = read_audit(prev_start, prev_end)
        stats_this = week_stats(rows_this)
        stats_prev = week_stats(rows_prev)

        print(f"[Weekly] Cette semaine: {len(rows_this)} actions | Précédente: {len(rows_prev)}")

        ai_analysis = ollama_weekly_analysis(stats_this, stats_prev)
        week_label  = f"{week_start.strftime('%d/%m')} – {week_end.strftime('%d/%m/%Y')}"
        html        = build_html(stats_this, stats_prev, ai_analysis, week_label)

        delta     = stats_this["bans"] - stats_prev["bans"]
        trend_i   = "📈" if delta > 0 else ("📉" if delta < 0 else "➡️")
        subject   = (
            f"{trend_i} SOC Weekly — {stats_this['bans']} bans · "
            f"{'↑' if delta >= 0 else '↓'}{abs(delta)} vs préc. — {week_label}"
        )
        send_mail(html, subject)
        print(f"[Weekly] Rapport envoyé à {MAIL_TO}")
    finally:
        try:
            os.remove(LOCK_FILE)
        except Exception:
            pass


if __name__ == "__main__":
    main()
