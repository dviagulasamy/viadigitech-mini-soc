# ViaDigiTech Mini-SOC IA — V6.0 (SOAR Autonome)

> Système SOC léger et autonome pour VPS/cloud : détection temps réel, analyse IA, bannissement automatique, dashboard web et rapports quotidiens HTML.

---

## Description

**ViaDigiTech Mini-SOC V6.0** est une plateforme SecOps complète tournant sur un VPS Ubuntu 22.04.  
Elle surveille en continu l'état du serveur, analyse les attaques SSH, interroge AbuseIPDB, génère des analyses IA via Ollama, et envoie des alertes et rapports par email.

---

## Fonctionnalités

- **Détection temps réel** (toutes les 15 min) : CPU, RAM, disque, tentatives SSH, bans
- **Analyse IA** des alertes via Ollama (modèle `qwen2.5:3b`) — réponses en français
- **Bannissement automatique** des IP malveillantes via AbuseIPDB + Fail2Ban
- **Rapport quotidien HTML** avec graphiques 7 jours, résumé IA, historique bans
- **Dashboard web** temps réel (onglets IA, graphiques, boutons action ban/unban/analyze)
- **API d'actions** sécurisée (Flask, clé API) pour ban/unban/analyze depuis le dashboard
- **RAG AnythingLLM** : ingestion quotidienne des rapports SOC pour requêtes contextuelles
- **Déduplication des alertes** : pas de double envoi sur une même fenêtre de 15 min
- **Alertes disque/RAM** sur 2 niveaux (warning 85%/88%, critique 92% + purge auto safe)

---

## Architecture technique

| Composant | Rôle |
|-----------|------|
| `detector.py` | Détecteur alertes 15 min — SSH, seuils, AbuseIPDB, Ollama, ban auto |
| `report.py` | Rapport quotidien HTML + graphiques matplotlib + résumé IA |
| `dashboard.py` | Dashboard HTML v3 — onglets IA, graphique 7j, boutons action |
| `actions.py` | API Flask port 8022 — ban / unban / analyze (clé API requise) |
| `rag_ingest.py` | Ingestion quotidienne des rapports dans AnythingLLM |
| Ollama (`qwen2.5:3b`) | LLM local pour toutes les analyses SOC |
| AnythingLLM | RAG containerisé, requêtes contextuelles sur historique SOC |
| Postfix | SMTP local, relay vers Google Workspace |
| Nginx Proxy Manager | Reverse proxy Docker — domaines SOC |
| Fail2Ban | Bannissement IP SSH |

---

## Arborescence

```
viadigitech-mini-soc/
├── scripts/
│   ├── detector.py          # Détecteur alertes temps réel
│   ├── report.py            # Rapport quotidien
│   ├── dashboard.py         # Dashboard web v3
│   ├── actions.py           # API actions Flask
│   └── rag_ingest.py        # Ingestion RAG
├── cron/                    # Configuration crontab
├── docs/                    # Documentation technique
├── legacy/                  # Anciens scripts bash (désactivés)
├── logs/                    # Logs et rapports générés
├── INSTALL.md               # Procédure d'installation
├── PROJECT_STATE.md         # État détaillé du projet
└── README.md
```

---

## Déploiement (crontab)

Les variables d'environnement doivent être définies **avant** les jobs dans le crontab :

```
SOC_MAIL_FROM=secops@yourdomain.com
SOC_MAIL_TO=admin@yourdomain.com
ABUSEIPDB_KEY=<votre_clé>
ANYTHINGLLM_KEY=<votre_clé>
SOC_ACTIONS_KEY=<votre_clé>

0 7 * * *    python3 /home/ubuntu/secops/report.py >> report.log 2>&1
0 7 * * *    python3 /home/ubuntu/secops/rag_ingest.py >> rag_ingest.log 2>&1
*/15 * * * * python3 /home/ubuntu/secops/detector.py >> detector.log 2>&1
*/15 * * * * python3 /home/ubuntu/secops/dashboard.py >> dashboard.log 2>&1
```

---

## Domaines (Nginx Proxy Manager)

| Domaine | Service |
|---------|---------|
| `graph.viadigitech.com` | Rapports SOC + API actions (`/action/`) |
| `soc.viadigitech.com` | Dashboard (basic auth) |
| `n8n.viadigitech.com` | n8n automation |

---

## Prérequis

- Ubuntu 22.04 LTS
- Python 3.10+ avec venv (`psutil`, `requests`, `pandas`, `matplotlib`, `flask`)
- Ollama + modèle `qwen2.5:3b`
- Fail2Ban, Postfix
- Docker (AnythingLLM, Nginx Proxy Manager)

---

## Licence

MIT License — 2025-2026 ViaDigiTech

---

Projet conçu et maintenu par **ViaDigiTech — IA Digital Security Automation**.
