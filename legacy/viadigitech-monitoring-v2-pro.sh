#!/bin/bash

### ViaDigiTech VPS Monitoring V2 PRO ###

DATE=$(date '+%Y-%m-%d %H:%M:%S')
HOSTNAME=$(hostname)

# Collecte CPU Load
LOAD=$(cat /proc/loadavg | awk '{print $1}')

# Collecte RAM
TOTAL_RAM=$(free -m | awk '/Mem:/ {print $2}')
USED_RAM=$(free -m | awk '/Mem:/ {print $3}')

# Collecte espace disque racine
DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}')

# Fail2ban
BANNED=$(fail2ban-client status sshd | grep "Currently banned" | awk '{print $4}')
TOTAL_FAILED=$(fail2ban-client status sshd | grep "Total failed" | awk '{print $4}')
BANNED_IPS=$(fail2ban-client status sshd | grep "Banned IP list" | cut -d ":" -f2)

# Conseils dynamiques
if [ "$BANNED" -ge 10 ]; then
    CONSEIL="⚠️ Attention : Forte activité d'attaques SSH détectée. Surveillez régulièrement vos accès."
else
    CONSEIL="✅ Aucun pic critique détecté."
fi

# Construction du message
MESSAGE=$(cat <<EOF
Rapport ViaDigiTech VPS Monitoring — $DATE

Serveur : $HOSTNAME

📊 Charges système :
- Charge CPU (1min) : $LOAD
- RAM utilisée : $USED_RAM / $TOTAL_RAM MB
- Disque utilisé sur / : $DISK_USAGE

🔐 Sécurité Fail2Ban :
- Nombre total d'échecs SSH : $TOTAL_FAILED
- Nombre d'IP actuellement bannies : $BANNED

Liste des IP bannies :
$BANNED_IPS

📝 Conseils :
$CONSEIL

-- Rapport généré automatiquement ViaDigiTech V2 PRO
EOF
)

# Affiche dans la console (utile pour logs locaux si besoin)
echo "$MESSAGE"

# Envoi email
echo "$MESSAGE" | mail -s "Rapport ViaDigiTech [$HOSTNAME]" david@viadigitech.com
