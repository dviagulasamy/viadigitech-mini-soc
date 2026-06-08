# ViaDigiTech Mini-SOC IA — V7.0

> Plateforme SOAR autonome pour VPS/cloud : détection temps réel, analyse IA, bannissement automatique, dashboard web responsive et rapports quotidiens HTML.

---

## Description

**ViaDigiTech Mini-SOC V7.0** est une plateforme SecOps complète tournant sur un VPS Ubuntu 22.04.  
Elle surveille en continu l'état du serveur, analyse les attaques SSH, interroge AbuseIPDB, génère des analyses IA via Ollama, et envoie des alertes et rapports par email.

---

## Fonctionnalités

- **Détection temps réel** (toutes les 15 min) : CPU, RAM, disque, tentatives SSH, bans
- **Analyse IA** via Ollama (qwen2.5:3b) — réponses en français, disclaimer anti-hallucination
- **Bannissement automatique** : score AbuseIPDB > 80% → BAN_AUTO, zone grise → Ollama décide
- **Rapport quotidien HTML** avec graphiques 7 jours, résumé IA, historique bans
- **Dashboard web responsive** — 5 écrans (Vue globale, Sécurité, Performance, Timeline, Infra)
  - Threat score hero (0-100), sparklines, heatmap 7j×24h, carte Leaflet géo
  - Navigation desktop (topbar) + mobile (bottom nav iOS + hamburger drawer)
  - Modales CSS custom (remplace confirm/prompt natifs)
  - Indicateur ancienneté des données, notifications navigateur
- **API d'actions sécurisée** (Flask, clé API) : ban/unban/whitelist/analyze/report
- **RAG AnythingLLM** : ingestion quotidienne des rapports SOC
- **Déduplication des alertes** : pas de double envoi sur 15 min
- **Alertes disque/RAM** sur 2 niveaux (warning 75%, critique 88% + purge auto safe)

---

## Statistiques (06/2026)

| Métrique | Valeur |
|----------|--------|
| IPs bannies (actif) | 371 |
| Total bans depuis déploiement | 4 110+ |
| Tentatives SSH bloquées | 25 659+ |
| Uptime système | 182 jours |

---

## Architecture technique

| Composant | Rôle |
|-----------|------|
| `detector.py` | Détecteur alertes 15 min — SSH, seuils, AbuseIPDB, Ollama, ban auto |
| `report.py` | Rapport quotidien HTML + graphiques matplotlib + résumé IA |
| `dashboard.py` | Dashboard HTML v7 — 5 écrans, responsive, modales, threat hero |
| `actions.py` | API Flask port 8022 — ban / unban / whitelist / analyze / report |
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
│   ├── detector.py          # Détecteur alertes temps réel
│   ├── report.py            # Rapport quotidien
│   ├── dashboard.py         # Dashboard web v7
│   ├── actions.py           # API actions Flask
│   └── rag_ingest.py        # Ingestion RAG
├── systemd/
│   ├── soc-actions.service  # Service API Flask
│   └── soc-dashboard.service# Service HTTP statique
├── docs/
│   ├── PROJECT_STATE_V7.md  # État technique détaillé
│   ├── ROADMAP_V8.md        # Fonctionnalités à venir
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

0 7 * * *    python3 /home/ubuntu/secops/report.py >> report.log 2>&1
0 7 * * *    python3 /home/ubuntu/secops/rag_ingest.py >> rag_ingest.log 2>&1
*/15 * * * * python3 /home/ubuntu/secops/detector.py >> detector.log 2>&1
*/15 * * * * python3 /home/ubuntu/secops/dashboard.py >> dashboard.log 2>&1
```

---

## Domaines (Nginx Proxy Manager)

| Domaine | Service |
|---------|---------|
| `graph.viadigitech.com/soc/` | Dashboard SOC + API actions |
| `n8n.viadigitech.com` | n8n automation |

---

## Prérequis

- Ubuntu 22.04 LTS
- Python 3.10+ (`psutil`, `requests`, `pandas`, `matplotlib`, `flask`)
- Ollama + modèle `qwen2.5:3b`
- Fail2Ban, Postfix
- Docker (AnythingLLM, Nginx Proxy Manager, Coolify)
- Node.js (validation JS post-génération)

---

## Documentation

- [État du projet V7](docs/PROJECT_STATE_V7.md)
- [Roadmap V8 — Fonctionnalités avancées](docs/ROADMAP_V8.md)
- [Architecture SOAR](docs/architecture.md)
- [Installation](INSTALL.md)

---

## Licence

MIT License — 2025-2026 ViaDigiTech

---

Projet conçu et maintenu par **ViaDigiTech — IA Digital Security Automation**.
