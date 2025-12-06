#!/bin/bash

### ViaDigiTech Monitoring V3 ENTERPRISE ###

DATE=$(date '+%Y-%m-%d %H:%M:%S')
HOSTNAME=$(hostname)
LOGDIR="/var/log/viadigitech-monitoring"
mkdir -p $LOGDIR

# Collecte CPU Load
LOAD=$(cat /proc/loadavg | awk '{print $1}')

# Collecte RAM
TOTAL_RAM=$(free -m | awk '/Mem:/ {print $2}')
USED_RAM=$(free -m | awk '/Mem:/ {print $3}')
PERCENT_RAM=$(awk "BEGIN {printf \"%.0f\", (${USED_RAM}/${TOTAL_RAM})*100}")

# Collecte Disque
DISK_USAGE_RAW=$(df -h / | awk 'NR==2 {print $5}')
DISK_USAGE=$(echo $DISK_USAGE_RAW | tr -d '%')

# Collecte Fail2Ban
BANNED=$(fail2ban-client status sshd | grep "Currently banned" | awk '{print $4}')
TOTAL_FAILED=$(fail2ban-client status sshd | grep "Total failed" | grep -oP '\d+$')
#TOTAL_FAILED=$(fail2ban-client status sshd | grep "Total failed" | awk '{print $NF}')
#TOTAL_FAILED=$(fail2ban-client status sshd | grep "Total failed" | awk '{print $4}')
BANNED_IPS=$(fail2ban-client status sshd | grep "Banned IP list" | cut -d ":" -f2)

# Historisation des IP bannies
echo "$DATE - $BANNED_IPS" >> $LOGDIR/banned-history.log

# Calcul score de risque simple
RISK_SCORE=$(($BANNED*2 + $TOTAL_FAILED/10 + $PERCENT_RAM/10 + $DISK_USAGE/10))
if [ "$RISK_SCORE" -gt 50 ]; then
    CONSEIL="🚨 Forte activité détectée. Vérifiez les accès SSH, surveillez les ressources serveur."
elif [ "$RISK_SCORE" -gt 30 ]; then
    CONSEIL="⚠️ Activité modérée. Restez vigilant."
else
    CONSEIL="✅ Activité normale."
fi

# Alerte usage RAM ou disque
ALERTS=""
if [ "$PERCENT_RAM" -ge 80 ]; then
    ALERTS+="⚠️ RAM au-dessus de 80% ($PERCENT_RAM%)\n"
fi
if [ "$DISK_USAGE" -ge 85 ]; then
    ALERTS+="⚠️ Disque root dépasse 85% ($DISK_USAGE%)\n"
fi

# Construction du rapport complet
MESSAGE=$(cat <<EOF
📅 Date : $DATE
🖥️ Serveur : $HOSTNAME

📊 Charge système :
- CPU Load (1min) : $LOAD
- RAM utilisée : $USED_RAM / $TOTAL_RAM MB ($PERCENT_RAM%)
- Disque utilisé : $DISK_USAGE_RAW

🔐 Sécurité SSH Fail2Ban :
- Total d'échecs SSH : $TOTAL_FAILED
- IP actuellement bannies : $BANNED

📄 Liste des IP bannies :
$BANNED_IPS

⚖️ Score de risque calculé : $RISK_SCORE
📢 Conseil : $CONSEIL

$ALERTS

-- Rapport ViaDigiTech V3 ENTERPRISE.
EOF
)

# Log local journalier
echo "$MESSAGE" >> $LOGDIR/daily-report-$(date '+%Y-%m-%d').log

# Envoi du rapport par mail
echo "$MESSAGE" | mail -s "ViaDigiTech VPS Monitoring [$HOSTNAME]" david@viadigitech.com
