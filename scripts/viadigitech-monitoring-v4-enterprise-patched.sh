#!/bin/bash

# ViadigiTech Mini-SOC V4 Enterprise Patched

LOG_DIR="/var/log/viadigitech-monitoring"
CSV_FILE="$LOG_DIR/banned-history.csv"
GRAPH_FILE="$LOG_DIR/history.png"
DATE=$(date '+%Y-%m-%d_%H-%M-%S')
EMAIL="TON_EMAIL_ICI"
VENV_PYTHON="/home/ubuntu/viadigitech-env/bin/python"

mkdir -p $LOG_DIR

CPU=$(top -bn1 | grep "Cpu(s)" | awk '{print 100 - $8}')
MEM_TOTAL=$(free -m | awk '/^Mem:/ {print $2}')
MEM_USED=$(free -m | awk '/^Mem:/ {print $3}')
DISK_USED=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
FAILED=$(sudo fail2ban-client status sshd 2>/dev/null | grep 'Total failed' | awk '{print $NF}')
BANNED=$(sudo fail2ban-client status sshd 2>/dev/null | grep 'Currently banned' | awk '{print $NF}')

if [ ! -f "$CSV_FILE" ]; then
    echo "Date,CPU_Usage,MEM_Used_MB,Disk_Usage,Failed_SSH,Banned_IP" > $CSV_FILE
fi
echo "$(date '+%Y-%m-%d %H:%M:%S'),$CPU,$MEM_USED,$DISK_USED,$FAILED,$BANNED" >> $CSV_FILE

SCORE=$(awk "BEGIN {printf \"%.0f\", ($BANNED*2 + $FAILED/10 + $DISK_USED/10 + $CPU/10)}")

IP_LIST=$(sudo fail2ban-client status sshd 2>/dev/null | grep 'Banned IP list' | cut -d ':' -f2)

GEOLOCATIONS=""
for IP in $IP_LIST; do
    INFO=$(curl -s http://ip-api.com/json/$IP?fields=country,query | jq -r '.country + " (" + .query + ")"')
    GEOLOCATIONS+="$INFO\n"
done

$VENV_PYTHON <<EOF
import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("${CSV_FILE}")
plt.figure(figsize=(10,5))
plt.plot(df['Date'], df['Failed_SSH'], label='SSH Failed', marker='o')
plt.plot(df['Date'], df['Banned_IP'], label='IP Banned', marker='x')
plt.xticks(rotation=45)
plt.legend()
plt.title("Fail2Ban Historical Overview")
plt.tight_layout()
plt.savefig("${GRAPH_FILE}")
EOF

MAIL_SUBJECT="ViaDigiTech Monitoring [$(hostname)] - $DATE"
MAIL_BODY="
✅ System Monitoring Report:
- CPU Usage: ${CPU}%
- Memory Used: ${MEM_USED}MB / ${MEM_TOTAL}MB
- Disk Usage: ${DISK_USED}%
- Failed SSH Logins: ${FAILED}
- Banned IPs: ${BANNED}
- Risk Score: ${SCORE}

🌐 Banned IP Geolocation:
$(echo -e $GEOLOCATIONS)
"

echo -e "$MAIL_BODY" | mutt -s "$MAIL_SUBJECT" -a "$GRAPH_FILE" -- "$EMAIL"
