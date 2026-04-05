#!/bin/bash

### ViaDigiTech Monitoring V4 ENTERPRISE - PATCHED STABLE ###

DATE=$(date '+%Y-%m-%d %H:%M:%S')
DATE_FILE=$(date '+%Y-%m-%d')
TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
HOSTNAME=$(hostname)
LOGDIR="/var/log/viadigitech-monitoring"
HISTOFILE="$LOGDIR/banned-history.csv"
DAILYREPORT="$LOGDIR/daily-report-$DATE_FILE.log"

mkdir -p $LOGDIR

# Collecte système
LOAD=$(cat /proc/loadavg | awk '{print $1}')
TOTAL_RAM=$(free -m | awk '/Mem:/ {print $2}')
USED_RAM=$(free -m | awk '/Mem:/ {print $3}')
PERCENT_RAM=$(awk "BEGIN {printf \"%.0f\", (${USED_RAM}/${TOTAL_RAM})*100}")
DISK_USAGE_RAW=$(df -h / | awk 'NR==2 {print $5}')
DISK_USAGE=$(echo $DISK_USAGE_RAW | tr -d '%')

# Fail2ban
BANNED=$(fail2ban-client status sshd | grep "Currently banned" | awk '{print $4}')
TOTAL_FAILED=$(fail2ban-client status sshd | grep "Total failed" | grep -oP '\d+$')
BANNED_IPS=$(fail2ban-client status sshd | grep "Banned IP list" | cut -d ":" -f2)

# Historique
echo "$DATE_FILE,$BANNED,$TOTAL_FAILED,\"$BANNED_IPS\"" >> $HISTOFILE

# Calcul Score
RISK_SCORE=$(($BANNED*2 + $TOTAL_FAILED/10 + $PERCENT_RAM/10 + $DISK_USAGE/10))
if [ "$RISK_SCORE" -gt 50 ]; then
    CONSEIL="🚨 Forte activité détectée. Surveillez SSH et ressources."
elif [ "$RISK_SCORE" -gt 30 ]; then
    CONSEIL="⚠️ Activité modérée. Surveillance recommandée."
else
    CONSEIL="✅ Activité normale."
fi

# Check RAM/DISK
ALERTS=""
if [ "$PERCENT_RAM" -ge 80 ]; then
    ALERTS+="⚠️ RAM > 80% ($PERCENT_RAM%)\n"
fi
if [ "$DISK_USAGE" -ge 85 ]; then
    ALERTS+="⚠️ Disque > 85% ($DISK_USAGE%)\n"
fi

# Géolocalisation (top 10 IP)
GEOLOC=""
COUNT=0
for ip in $BANNED_IPS; do
    [ $COUNT -ge 10 ] && break
    GEO=$(curl -s http://ip-api.com/json/$ip?fields=country,regionName,city,isp | jq -r '"\(.country) - \(.regionName) - \(.city) [\(.isp)]"')
    GEOLOC+="• $ip → $GEO\n"
    COUNT=$((COUNT+1))
done

# Génération graphique via python3 + matplotlib
#python3 <<EOF
/home/ubuntu/viadigitech-env/bin/python <<EOF
import pandas as pd
import matplotlib.pyplot as plt

try:
    data = pd.read_csv("$HISTOFILE", header=None, names=["Date","Banned","Failed","IPs"])
    plt.figure(figsize=(10,5))
    plt.plot(data["Date"], data["Banned"], marker='o', label="Banned IPs")
    plt.plot(data["Date"], data["Failed"], marker='x', label="Failed SSH")
    plt.title("Historique Fail2Ban - ViaDigiTech")
    plt.xticks(rotation=45)
    plt.legend()
    plt.tight_layout()
    plt.savefig("$LOGDIR/history.png")
except Exception as e:
    print("Erreur graphique:", e)
EOF

# Construction du message
MESSAGE=$(cat <<EOF
📅 Date : $DATE
🖥️ Serveur : $HOSTNAME

📊 Charge système :
- CPU Load : $LOAD
- RAM utilisée : $USED_RAM/$TOTAL_RAM MB ($PERCENT_RAM%)
- Disque utilisé : $DISK_USAGE_RAW

🔐 Fail2Ban :
- Total échecs SSH : $TOTAL_FAILED
- IP actuellement bannies : $BANNED

📍 Géolocalisation (Top 10) :
$GEOLOC

⚖️ Score de risque : $RISK_SCORE
📢 Conseils : $CONSEIL

$ALERTS

-- Rapport V4 ViaDigiTech ENTERPRISE PATCHED
EOF
)

# Log local
echo "$MESSAGE" >> $DAILYREPORT

# Envoi email avec pièce jointe graphique et timestamp dans le sujet
echo "$MESSAGE" | mutt -s "ViaDigiTech Monitoring [$HOSTNAME] - $TIMESTAMP" -a $LOGDIR/history.png -- "${SOC_MAIL_TO:-admin@example.com}"
