# ViaDigiTech Mini-SOC IA — V11.0

> Plateforme SOAR autonome pour VPS/cloud : détection temps réel, geo-blocking, scoring composite multi-facteurs, Threat Intelligence, honeypot SSH, analyse IA prédictive, dashboard SecOps premium et rapports automatiques.

---

## Description

**ViaDigiTech Mini-SOC V11.0** est une plateforme SecOps complète tournant sur un VPS Ubuntu 22.04.  
Elle surveille en continu l'état du serveur, analyse les attaques SSH, bloque les pays à risque (geo-blocking), croise les IPs contre des feeds de Threat Intelligence, calcule un score composite multi-facteurs, applique une réponse graduée (BAN_GEO / BAN_AUTO / BAN_TEMP), persiste les données en SQLite et génère des alertes Telegram + rapports email HTML enrichis.

---

## Fonctionnalités

### Détection & réponse
- **Geo-blocking** (F14) : blocage immédiat (BAN_GEO) par code pays ISO — configurable depuis le dashboard
- **Scoring composite multi-facteurs** (F8) : AbuseIPDB (base) + TI feeds (+25) + récidive (+4/10/15) + pays à risque (+4/8) + heure nocturne/WE (+5)
- **Réponse graduée** (F9) : composite ≥ 80 → BAN_AUTO, 70-79 → BAN_TEMP, 40-69 → Ollama, <40 → SURVEILLE
- **Alerte seuil composite** (F18) : notification Telegram si le score moyen 24h dépasse un seuil configurable
- **Threat Intelligence** (F7) : Feodo Tracker (botnets C2) + AlienVault OTX (optionnel), cache 1h
- **Honeypot SSH** (F3) : port 2222 — ban immédiat + alerte Telegram 🍯
- **Détection Low & Slow** (F4) : 10-200 tentatives/24h sous le radar Fail2Ban
- **Ban /24 automatique** : ≥ 3 IPs distinctes d'un bloc /24 en 1h → BAN_SUBNET24

### Intelligence artificielle
- **Ollama qwen2.5:3b** : décisions zone grise (40-69), analyse urgente en mode IR
- **IA prédictive** (F6) : chaque lundi, analyse patterns de la semaine → tendances, vecteurs émergents, 3 recommandations
- **Rapport hebdomadaire** (F5) : bilan 7j vs semaine précédente, top IPs géolocalisées, analyse IA

### Dashboard V11 (7 écrans)
- **Login premium** (V7) : glassmorphism, orbes CSS animées, shield SVG pulsant
- **Vue globale** : jauge SVG radiale 270° animée (V2), compteurs incrémentaux (V3), sparklines gradient fill (V9)
- **IA & Prédictive** (F19) : écran dédié — 4 onglets Synthèse / Sécurité / Performance / 🔮 Prédictive
- **Mode IR dramatisé** (V8) : bannière rouge défilante + irBodyPulse, playbooks interactifs (F13)
- **Workbench IP** : profil complet + sparkline score composite 30j (F15) + analyse IA + historique
- **Heatmap interactive** (V6) : tooltips riches avec niveau de sévérité coloré au survol
- **Timeline verticale redesign** (V4) : ligne connectrice colorée, marqueurs circulaires, glow critiques
- **ASN agressifs** (F10) : carte top 6 ASN + bouton blocage
- **Skeleton loading** (V5) : shimmer CSS sur les stats pendant les updates SSE
- **Export SIEM/CEF** (F12) : `/action/export/siem?format=json|cef`
- **SSE mobile optimisé** (F20) : pause automatique en arrière-plan via Page Visibility API

### Alertes & rapports
- **Telegram** : BAN_GEO 🌍, BAN_AUTO 🚨, BAN_TEMP ⚠️, Honeypot 🍯, Low&Slow 🐢, BAN_SUBNET24
- **Digest Telegram** (F16) : regroupement configurable des alertes Telegram (immédiat ou digest)
- **Rapport quotidien** (7h) : HTML dark mode, sujet dynamique par niveau de menace
- **Rapport hebdomadaire** (vendredi 8h) : bilan, sparkbars, comparatif S-1
- **Rapport mensuel** (1er du mois) : top /24, comparatif M-1

---

## Architecture technique

| Composant | Rôle |
|-----------|------|
| `detector.py` | SOAR core : geo-blocking F14, scoring composite F8, réponse graduée F9, TI F7, low&slow F4, subnet ban, threshold alert F18, digest Telegram F16 |
| `dashboard.py` | Dashboard HTML V11 — 7 écrans, écran IA F19, workbench sparkline F15, SSE mobile F20, settings geo F14 |
| `actions.py` | API Flask port 8022 — 25 endpoints, /threat/ip F15, /block/country F14 |
| `soc_db.py` | **Nouveau** — SQLite F17 : audit_actions, score_history, threat_patterns, migration transparente |
| `ti_feeds.py` | Threat Intelligence — Feodo Tracker + OTX, cache TTL 1h |
| `predict_ai.py` | Analyse prédictive IA lundi → last_ai_summary.json["predictive"] |
| `honeypot.py` | Honeypot TCP port 2222 — ban immédiat (systemd) |
| `soc_healthcheck.py` | Health-check 30min → badge SOC topbar |
| `report.py` | Rapport quotidien HTML |
| `report_weekly.py` | Rapport hebdomadaire HTML |
| `report_monthly.py` | Rapport mensuel HTML |
| `rag_ingest.py` | Ingestion rapports dans AnythingLLM |
| Ollama `qwen2.5:3b` | LLM local pour analyses SOC |
| Fail2Ban | Bannissement SSH progressif |
| Nginx Proxy Manager | Reverse proxy Docker |
| **SQLite** | Persistance audit_actions + score_history (WAL mode) |

---

## Arborescence

```
viadigitech-mini-soc/
├── scripts/
│   ├── detector.py          # SOAR core — geo-blocking, scoring, TI, low&slow
│   ├── dashboard.py         # Dashboard V11 — 7 écrans, IA screen, workbench sparkline
│   ├── actions.py           # API Flask 25 endpoints
│   ├── soc_db.py            # SQLite F17 — audit + score history + threat patterns
│   ├── ti_feeds.py          # TI feeds (Feodo + OTX)
│   ├── honeypot.py          # Honeypot port 2222
│   ├── soc_healthcheck.py   # Health-check SOC
│   ├── predict_ai.py        # IA prédictive lundi
│   ├── report.py            # Rapport quotidien
│   ├── report_weekly.py     # Rapport hebdomadaire (vendredi 8h)
│   ├── report_monthly.py    # Rapport mensuel
│   └── rag_ingest.py        # Ingestion AnythingLLM
├── systemd/
│   ├── soc-actions.service  # Service API Flask
│   └── soc-honeypot.service # Service honeypot
├── docs/                    # Archives versions précédentes
├── cron/                    # Configuration crontab
├── legacy/                  # Anciens scripts bash
├── INSTALL.md               # Procédure d'installation
├── PROJECT_STATE.md         # État technique complet V11
└── README.md
```

---

## Installation rapide

### Prérequis
- Ubuntu 22.04, Python 3.10+
- Fail2Ban, Postfix, Ollama (qwen2.5:3b)
- Clé AbuseIPDB (gratuit, 1000 req/jour)
- Bot Telegram (optionnel)

### Variables d'environnement (crontab + `/etc/soc-actions.env`)

```bash
SOC_MAIL_FROM=secops@votredomaine.com
SOC_MAIL_TO=admin@votredomaine.com
ABUSEIPDB_KEY=<votre_clé>
SOC_ACTIONS_KEY=<clé_api_dashboard>
SOC_DASHBOARD_PWD=your_dashboard_password_here
TELEGRAM_TOKEN=<token_bot>           # optionnel
TELEGRAM_CHAT_ID=<chat_id>           # optionnel
OTX_KEY=<clé_alienvault>             # optionnel
```

### Crontab

```bash
*/15 * * * *  python3 /home/ubuntu/secops/detector.py >> detector.log 2>&1
*/15 * * * *  python3 /home/ubuntu/secops/dashboard.py >> dashboard.log 2>&1
*/30 * * * *  python3 /home/ubuntu/secops/soc_healthcheck.py >> healthcheck.log 2>&1
0 7  * * *    python3 /home/ubuntu/secops/report.py >> report.log 2>&1
0 7  * * *    python3 /home/ubuntu/secops/rag_ingest.py >> rag_ingest.log 2>&1
0 7  * * 1    python3 /home/ubuntu/secops/predict_ai.py >> predict_ai.log 2>&1
0 8  * * 5    python3 /home/ubuntu/secops/report_weekly.py >> report_weekly.log 2>&1
0 7  1 * *    python3 /home/ubuntu/secops/report_monthly.py >> report_monthly.log 2>&1
```

### Services systemd

```bash
sudo cp systemd/soc-actions.service /etc/systemd/system/
sudo cp systemd/soc-honeypot.service /etc/systemd/system/
sudo systemctl enable --now soc-actions soc-honeypot
```

---

## Accès web

| URL | Service |
|-----|---------|
| `https://graph.viadigitech.com` | Dashboard SOC (redirect auto → /soc/) |
| `https://graph.viadigitech.com/soc/` | Dashboard SOC (accès direct) |
| `https://graph.viadigitech.com/action/` | API actions Flask |
| `https://graph.viadigitech.com/action/docs/` | Swagger UI |

---

## Historique des versions

| Version | Items |
|---------|-------|
| **Sprint 1** | Typographie, compteurs animés, transitions, Telegram, health-check |
| **Sprint 2** | Jauge SVG 270°, timeline verticale, login glassmorphism, honeypot SSH, low&slow |
| **Sprint 3** | TI feeds, scoring adaptatif, réponse graduée, rapport hebdo, IA prédictive |
| **Sprint 4** | Skeleton loading, heatmap tooltips, IR dramatisé, sparklines gradient, ASN blocking, export SIEM, playbooks IR |
| **Post-Sprint** | Notification bell, digest email configurable, filtres mail par type |
| **V10.2** | Redirect graph.viadigitech.com, topbar mobile responsive, fix DOM workbench |
| **V11.0** | Geo-blocking F14, score history F15, digest Telegram F16, SQLite F17, alertes seuil F18, écran IA F19, SSE mobile F20 |

---

*ViaDigiTech Mini-SOC — V11.0 — 10 juin 2026*
