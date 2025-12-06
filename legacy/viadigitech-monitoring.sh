#!/bin/bash

### ViaDigiTech VPS Light Monitoring V1.0 ###

DATE=$(date '+%Y-%m-%d %H:%M:%S')
HOSTNAME=$(hostname)

# Log local
LOGFILE="/var/log/viadigitech-monitoring.log"
touch $LOGFILE

echo "===== Monitoring du $DATE =====" >> $LOGFILE

# Vérif Uptime
echo "[Uptime]" >> $LOGFILE
uptime >> $LOGFILE

# Vérif CPU load
echo "[Charge CPU]" >> $LOGFILE
cat /proc/loadavg >> $LOGFILE

# Vérif espace disque
echo "[Disque]" >> $LOGFILE
df -h >> $LOGFILE

# Vérif RAM
echo "[RAM]" >> $LOGFILE
free -m >> $LOGFILE

# Vérif Fail2Ban
echo "[Fail2Ban]" >> $LOGFILE
fail2ban-client status sshd >> $LOGFILE 2>&1

echo " " >> $LOGFILE

# Email simple en cas de ban actif
BANNED=$(fail2ban-client status sshd | grep "Currently banned" | awk '{print $4}')

if [ "$BANNED" -gt 0 ]; then
    echo "Alerte Fail2Ban - $BANNED IP actuellement bannies sur $HOSTNAME" | mail -s "Alerte Fail2Ban [$HOSTNAME]" david@viadigitech.com
fi
