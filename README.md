
# ViaDigiTech Mini-SOC IA — V5.3

> Autonomous lightweight SOC monitoring system for VPS and cloud instances, integrating Fail2Ban, Geolocation, AI-based Risk Scoring, and Automated Daily Reporting.

---

## 📊 Description

**ViaDigiTech Mini-SOC IA V5.3** est un système complet de supervision de VPS et serveurs cloud.  
Il permet d’analyser automatiquement l'état du serveur, les attaques SSH, les IP bannies par Fail2Ban, et fournit :

- Collecte des données système (CPU, RAM, Disk)
- Extraction et analyse des logs SSH et Fail2Ban
- Calcul statistique (moyenne glissante + Z-score)
- Géolocalisation des IP bannies
- Génération automatique de rapports HTML
- Génération et hébergement de graphes CPU
- Envoi quotidien des rapports par email

---

## 🛠️ Fonctionnalités principales

- Monitoring autonome quotidien
- Calcul de Z-score pour détection d’anomalies
- Géolocalisation automatique des IP bannies
- Envoi automatique des rapports via email SMTP
- Hébergement des graphes avec Caddy (reverse proxy)
- Architecture légère et industrialisable

---

## ⚙️ Architecture technique

| Composant | Fonction |
| --------- | -------- |
| Python 3.x | Traitement des données, analyse et génération de rapports |
| Shell (Bash) | Lancement planifié via crontab |
| Fail2Ban | Extraction des tentatives SSH malveillantes |
| Matplotlib / Pandas | Statistiques & graphes CPU |
| ip-api.com | Géolocalisation des IP |
| SMTP (sendmail/msmtp) | Envoi des rapports |
| Caddy | Reverse proxy HTTP pour hébergement des graphes |

---

## 📂 Arborescence du projet

```bash
viadigitech-mini-soc/
├── cron/                    # Fichiers de planification crontab
├── docs/                    # Documentation technique complète
├── scripts/                 # Scripts Python et Shell
├── data/                    # Données collectées (CSV)
├── logs/                    # Rapports HTML générés
├── INSTALL.md               # Procédure d'installation serveur
├── LICENSE                  # Licence MIT
├── README.md                # Ce fichier de présentation GitHub
└── .gitignore               # Exclusions Git
```

---

## 🔮 Backlog d'évolution possible

- Nettoyage des crontabs historiques
- Passage à SMTP sécurisé OAuth (Google Workspace)
- Reporting hebdomadaire/mensuel
- Dashboard Web UI centralisé
- Archivage automatique des historiques

---

## 🔒 Licence

MIT License - 2025 ViaDigiTech

---

## 🙏 Remerciements

Projet conçu et maintenu par **ViaDigiTech — IA Digital Security Automation**.
