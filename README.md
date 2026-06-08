# ViaDigiTech Mini-SOC IA — V8.0

> Plateforme SOAR autonome pour VPS/cloud : détection temps réel, analyse IA, bannissement automatique, dashboard web SecOps complet et rapports quotidiens/hebdomadaires/mensuels HTML.

---

## Description

**ViaDigiTech Mini-SOC V8.0** est une plateforme SecOps complète tournant sur un VPS Ubuntu 22.04.  
Elle surveille en continu l'état du serveur, analyse les attaques SSH, interroge AbuseIPDB, génère des analyses IA via Ollama, et envoie des alertes et rapports par email et Telegram.

---

## Fonctionnalités

- **Détection temps réel** (toutes les 15 min) : CPU, RAM, disque, tentatives SSH, bans
- **Analyse IA** via Ollama (qwen2.5:3b) — réponses en français, disclaimer anti-hallucination
- **IA Adaptive** : mémoire des patterns IP/24 (threat_patterns.json), contexte historique injecté dans les prompts
- **Bannissement automatique** : score AbuseIPDB > 80% → BAN_AUTO, zone grise → Ollama décide
- **Alertes push Telegram** : BAN_AUTO et alertes CRITIQUE en moins de 5 secondes
- **Rapports HTML** : quotidien (7h), hebdomadaire (lundi 7h), mensuel (1er du mois 7h)
- **Dashboard web V8** — 6 écrans + interface SecOps complète :
  - Login sécurisé (SHA-256 côté client)
  - Panel Settings ⚙️ : astreinte, seuils admin, reset session
  - Graphiques ECharts v5 (zoom, drill-down heatmap)
  - Métriques live SSE (CPU/RAM/bans sans rechargement)
  - Workbench IP (investigation dédiée par IP)
  - Mode Incident Response ⚡ (plein écran urgence)
  - Ctrl+K recherche globale, raccourcis clavier 1-5
  - Export CSV/JSON, filtres live, annotations timeline
  - Mode sombre/clair, PWA installable mobile
  - Status bar (fail2ban / API / SSE)
  - Logs live detector.log dans Infrastructure
- **API d'actions sécurisée** (Flask, clé API, rate limiting 60 req/min) : ban/unban/whitelist/analyze/report/config/stream
- **Swagger UI** sur `/action/docs/`
- **RAG AnythingLLM** : ingestion quotidienne des rapports SOC
- **Déduplication des alertes** : pas de double envoi sur 15 min
- **Logrotate** : rotation daily 14j compressé pour tous les logs SOC

---

## Statistiques (06/2026)

| Métrique | Valeur |
|----------|--------|
| IPs bannies (actif) | 375 |
| Total bans depuis déploiement | 4 116+ |
| Tentatives SSH bloquées | 25 659+ |
| Uptime système | 182 jours |

---

## Architecture technique

| Composant | Rôle |
|-----------|------|
| `detector.py` | Détecteur alertes 15 min — SSH, seuils, AbuseIPDB, Ollama, ban auto, Telegram, IA adaptive |
| `report.py` | Rapport quotidien HTML + graphiques matplotlib + résumé IA |
| `report_weekly.py` | Rapport hebdomadaire HTML — top IPs, comparatif S-1, bilan IA |
| `report_monthly.py` | Rapport mensuel HTML — top /24, comparatif M-1, graphiques |
| `dashboard.py` | Dashboard HTML V8 — login, settings, 6 écrans, ECharts, SSE, Ctrl+K, IR, workbench |
| `actions.py` | API Flask port 8022 — ban/unban/whitelist/analyze/config/stream/logs + Swagger |
| `rag_ingest.py` | Ingestion quotidienne des rapports dans AnythingLLM |
| Ollama (`qwen2.5:3b`) | LLM local pour toutes les analyses SOC |
| AnythingLLM | RAG containerisé, requêtes contextuelles sur historique SOC |
| Postfix | SMTP local, relay vers Google Workspace |
| Nginx Proxy Manager | Reverse proxy Docker — domaines SOC |
| Fail2Ban | Bannissement IP SSH progressif (24h → 48h → 96h...) |

---

## Arborescence

```
viadigitech-mini-soc/
├── scripts/
│   ├── detector.py          # Détecteur alertes temps réel + Telegram + IA adaptive
│   ├── report.py            # Rapport quotidien
│   ├── report_weekly.py     # Rapport hebdomadaire (lundi 7h)
│   ├── report_monthly.py    # Rapport mensuel (1er du mois 7h)
│   ├── dashboard.py         # Dashboard web V8 — login, settings, ECharts, SSE
│   ├── actions.py           # API actions Flask + Swagger + rate limiting
│   └── rag_ingest.py        # Ingestion RAG
├── systemd/
│   ├── soc-actions.service  # Service API Flask
│   └── soc-dashboard.service# Service HTTP statique
├── docs/
│   ├── PROJECT_STATE_V7.md  # Archive V7
│   ├── PROJECT_STATE_V8.md  # État technique V8 (actuel)
│   ├── ROADMAP_V8.md        # Roadmap V8 (complétée)
│   └── architecture.md      # Architecture SOAR
├── cron/                    # Configuration crontab
├── legacy/                  # Anciens scripts bash
├── INSTALL.md               # Procédure d'installation
└── README.md
```

---

## Déploiement (crontab)

```bash
# Variables d'environnement (AVANT les jobs)
SOC_MAIL_FROM=secops@yourdomain.com
SOC_MAIL_TO=admin@yourdomain.com
ABUSEIPDB_KEY=<votre_clé>
ANYTHINGLLM_KEY=<votre_clé>
SOC_ACTIONS_KEY=<votre_clé>
SOC_DASHBOARD_PWD=your_dashboard_password_here
TELEGRAM_TOKEN=<token_bot>
TELEGRAM_CHAT_ID=<chat_id>

*/15 * * * * python3 /home/ubuntu/secops/detector.py >> detector.log 2>&1
*/15 * * * * python3 /home/ubuntu/secops/dashboard.py >> dashboard.log 2>&1
0 7  * * *   python3 /home/ubuntu/secops/report.py >> report.log 2>&1
0 7  * * *   python3 /home/ubuntu/secops/rag_ingest.py >> rag_ingest.log 2>&1
0 7  * * 1   python3 /home/ubuntu/secops/report_weekly.py >> report_weekly.log 2>&1
0 7  1 * *   python3 /home/ubuntu/secops/report_monthly.py >> report_monthly.log 2>&1
```

---

## Variables d'environnement systemd (`/etc/soc-actions.env`)

```bash
SOC_ACTIONS_KEY=<votre_clé>
SOC_DASHBOARD_PWD=your_dashboard_password_here
TELEGRAM_TOKEN=<token_bot>
TELEGRAM_CHAT_ID=<chat_id>
```

---

## Domaines (Nginx Proxy Manager)

| Domaine | Service |
|---------|---------|
| `graph.viadigitech.com/soc/` | Dashboard SOC (Basic Auth NPM) |
| `graph.viadigitech.com/action/` | API actions Flask (Clé API header) |
| `graph.viadigitech.com/action/docs/` | Swagger UI |
| `n8n.viadigitech.com` | n8n automation |

---

## Prérequis

- Ubuntu 22.04 LTS
- Python 3.10+ (`psutil`, `requests`, `pandas`, `matplotlib`, `flask`, `flask-limiter`, `flasgger`)
- Ollama + modèle `qwen2.5:3b`
- Fail2Ban, Postfix
- Docker (AnythingLLM, Nginx Proxy Manager, Coolify)
- Node.js (validation JS post-génération dashboard)

---

## Documentation

- [État du projet V8](docs/PROJECT_STATE_V8.md)
- [Archive V7](docs/PROJECT_STATE_V7.md)
- [Roadmap V8 — Complétée](docs/ROADMAP_V8.md)
- [Architecture SOAR](docs/architecture.md)
- [Installation](INSTALL.md)

---

## Licence

MIT License — 2025-2026 ViaDigiTech

---

Projet conçu et maintenu par **ViaDigiTech — IA Digital Security Automation**.
