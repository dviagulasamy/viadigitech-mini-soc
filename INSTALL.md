
# INSTALL.md — ViaDigiTech Mini-SOC IA V5.3

---

## 📌 Prérequis serveur

- Serveur VPS sous Ubuntu 22.04 (ou équivalent)
- Accès root ou sudo
- Python 3.x installé

---

## 1️⃣ Installation des dépendances système

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install python3 python3-pip python3-venv fail2ban msmtp caddy
```

---

## 2️⃣ Installation des dépendances Python

Créez un environnement virtuel (optionnel mais recommandé) :

```bash
python3 -m venv venv
source venv/bin/activate
pip install pandas matplotlib requests
```

---

## 3️⃣ Déploiement du projet

Clonez ou téléchargez le projet depuis GitHub :

```bash
git clone https://github.com/dviagulasamy/viadigitech-mini-soc.git
cd viadigitech-mini-soc
```

Placez les scripts dans le répertoire de travail :

```bash
mkdir -p /home/ubuntu/viadigitech-soc-v5-3/
cp scripts/* /home/ubuntu/viadigitech-soc-v5-3/
```

---

## 4️⃣ Configuration de la crontab

Ajoutez la tâche planifiée :

```bash
crontab -e
```

Puis insérez :

```bash
0 7 * * * /home/ubuntu/viadigitech-soc-v5-3/viadigitech-monitoring-v5-enterprise-ai.sh
```

---

## 5️⃣ Configuration SMTP simple (msmtp)

Éditer le fichier :

```bash
sudo nano /etc/msmtprc
```

Exemple de configuration OVH relay simple :

```bash
defaults
auth           off
tls            off
logfile        /var/log/msmtp.log
account        default
host           smtp.<ton_relay>.ovh.net
from           monitoring@yourdomain.com
```

---

## 6️⃣ Hébergement des rapports (Caddy)

Créer un répertoire pour les graphes :

```bash
sudo mkdir -p /var/www/html/viadigitech-reports/
```

Configurer Caddy (exemple) :

```bash
graph.viadigitech.com {
    root * /var/www/html/viadigitech-reports
    file_server
}
```

---

## 7️⃣ Vérification initiale manuelle

Lancer le script à la main pour tester :

```bash
cd /home/ubuntu/viadigitech-soc-v5-3/
bash viadigitech-monitoring-v5-enterprise-ai.sh
```

---

## 🎯 Votre SOC IA est désormais opérationnel 🚀
