#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, re, sys, time, requests, psutil, pandas as pd, numpy as np, matplotlib.pyplot as plt
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib

MODE = sys.argv[1] if len(sys.argv) > 1 else "production"

WORKDIR = "/home/ubuntu/viadigitech-soc-v5-3"
LOGDIR = f"{WORKDIR}/logs"
HISTORY_CSV = f"{LOGDIR}/banned-history.csv"
FAIL2BAN_LOG = "/var/log/fail2ban.log"
AUTH_LOG = "/var/log/auth.log"
IMGDIR = "/var/www/html/viadigitech-reports"
EMAIL_TO = "david@viadigitech.com"

NOW = datetime.now()
CUTOFF = NOW - timedelta(hours=24)
TS = NOW.strftime("%Y-%m-%d_%H-%M-%S")

os.makedirs(LOGDIR, exist_ok=True)
os.makedirs(IMGDIR, exist_ok=True)

# Collecte des IP bannies
bans = []
ban_re = re.compile(r'Ban\s+(\d+\.\d+\.\d+\.\d+)')
with open(FAIL2BAN_LOG, errors="ignore") as f:
    for line in f:
        if "Ban" not in line: continue
        parts = line.split()
        try:
            ts = datetime.strptime(parts[0]+" "+parts[1], "%Y-%m-%d %H:%M:%S,%f")
        except: continue
        if ts >= CUTOFF:
            m = ban_re.search(line)
            if m: bans.append(m.group(1))

ban_counts = pd.Series(bans).value_counts()
unique_ips = ban_counts.index.tolist()

# SSH failed
ssh_fail = 0
fail_re = re.compile(r'Failed password')
with open(AUTH_LOG, errors="ignore") as f:
    for line in f:
        try:
            ts = datetime.strptime(line[:15] + f" {NOW.year}", "%b %d %H:%M:%S %Y")
        except: continue
        if ts >= CUTOFF and fail_re.search(line): ssh_fail += 1

cpu_pct = psutil.cpu_percent(interval=1)
ram_pct = psutil.virtual_memory().percent

# Historique
if os.path.exists(HISTORY_CSV):
    df = pd.read_csv(HISTORY_CSV, parse_dates=['date'])
else:
    df = pd.DataFrame(columns=['date','cpu','ram_pct','ssh_fail','ban_count'])

new_row = pd.DataFrame([{
    'date': NOW,
    'cpu': cpu_pct,
    'ram_pct': ram_pct,
    'ssh_fail': ssh_fail,
    'ban_count': len(bans)
}])

df = pd.concat([df, new_row], ignore_index=True)
df.to_csv(HISTORY_CSV, index=False)

# Z-score safe
def z(s): return float('nan') if len(s)<2 or s.std()==0 else (s.iloc[-1] - s.mean()) / s.std()
z_cpu, z_ram, z_ssh, z_ban = z(df['cpu']), z(df['ram_pct']), z(df['ssh_fail']), z(df['ban_count'])

# Graphique
plt.figure(figsize=(6,3))
plt.plot(df['date'].to_numpy(), df['cpu'].to_numpy(), marker='o')
plt.title("CPU Usage (%) - Last 24h")
plt.tight_layout()
img_path = f"{IMGDIR}/graph-{TS}.png"
plt.savefig(img_path, dpi=100)
plt.close()
img_url = f"https://graph.viadigitech.com/graph-{TS}.png"

# Géolocalisation safe
geo_rows = []
if unique_ips:
    for ip in unique_ips[:10]:
        count = int(ban_counts[ip])
        try:
            resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
            geo_rows.append((ip, count, resp.get('country',''), resp.get('regionName',''), resp.get('city','')))
        except:
            geo_rows.append((ip, count, '', '', ''))

# HTML
html = f"""<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><title>SOC IA V5.3</title>
<style>body{{font-family:sans-serif}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid;padding:5px}}</style>
</head><body><h1>ViaDigiTech SOC IA V5.3 - {MODE.upper()} - {NOW.strftime('%Y-%m-%d %H:%M:%S')}</h1>

<h3>📊 Indicateurs</h3><table>
<tr><th>Indicateur</th><th>Valeur</th><th>Z-score</th><th>Statut</th></tr>
<tr><td>CPU (%)</td><td>{cpu_pct:.1f}</td><td>{z_cpu:.2f}</td><td>{'Normal' if abs(z_cpu)<2 else 'Alerte'}</td></tr>
<tr><td>RAM (%)</td><td>{ram_pct:.1f}</td><td>{z_ram:.2f}</td><td>{'Normal' if abs(z_ram)<2 else 'Alerte'}</td></tr>
<tr><td>SSH Failed</td><td>{ssh_fail}</td><td>{z_ssh:.2f}</td><td>{'Normal' if abs(z_ssh)<2 else 'Alerte'}</td></tr>
<tr><td>Banned IP</td><td>{len(bans)}</td><td>{z_ban:.2f}</td><td>{'Normal' if abs(z_ban)<2 else 'Alerte'}</td></tr>
</table>

<h3>📈 CPU Graph</h3><img src="{img_url}" width="500">

<h3>🔐 IP Bannies</h3>{', '.join(unique_ips) if unique_ips else 'Aucune'}

<h3>📍 Géolocalisation</h3><table><tr><th>IP</th><th>Count</th><th>Pays</th><th>Région</th><th>Ville</th></tr>"""
for ip, count, country, region, city in geo_rows:
    html += f"<tr><td>{ip}</td><td>{count}</td><td>{country}</td><td>{region}</td><td>{city}</td></tr>"
html += "</table></body></html>"

# Envoi email
msg = MIMEMultipart('alternative')
msg['Subject'] = f"ViaDigiTech SOC IA V5.3 Report [{TS}]"
msg['From'], msg['To'] = "root@vps", EMAIL_TO
msg.attach(MIMEText(html, 'html', 'utf-8'))
with smtplib.SMTP('localhost') as s: s.send_message(msg)
