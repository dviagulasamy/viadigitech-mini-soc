# ViaDigiTech Mini-SOC — État du projet V8.0
> Archive technique — 08 juin 2026

---

## Positionnement

Plateforme SOAR légère et autonome pour VPS Ubuntu.  
Pipeline complet : **détection → enrichissement → décision IA → action → rapport → dashboard**.

Interface web comparable à Datadog Security / Splunk SIEM — légère, locale, IA-native.

---

## Stack technique (V8.0)

| Couche | Technologie | Version | Rôle |
|--------|-------------|---------|------|
| OS | Ubuntu | 22.04 LTS | Base serveur |
| Python | CPython | 3.10+ | Scripts SOC (7 modules) |
| Détection | fail2ban | 0.11+ | Bannissement SSH progressif |
| Threat Intel | AbuseIPDB | API v2 | Score de réputation IP |
| IA décision | Ollama / qwen2.5:3b | local | Zone grise + analyse ad-hoc |
| IA rapport | Ollama / qwen2.5:3b | local | Synthèse quotidienne/hebdo/mensuelle |
| IA adaptive | threat_patterns.json | local | Mémoire patterns — contexte historique |
| RAG | AnythingLLM | Docker | Mémoire contextuelle SOC |
| Mail | Postfix | relay | Google Workspace SMTP |
| Alertes push | Telegram Bot API | — | Alertes BAN_AUTO + CRITIQUE |
| Reverse proxy | Nginx Proxy Manager | Docker | SSL + routing |
| Dashboard | Python http.server | port 8088 | HTML statique généré (ECharts v5) |
| API actions | Flask + flask-limiter | port 8022 | ban/unban/analyze/report/config/stream |
| Orchestration | Coolify | Docker | Gestion conteneurs |
| Monitoring uptime | Uptime Kuma | Docker | Disponibilité services |
| Automation | n8n | Docker | Workflows SOC |
| Stockage | CSV + JSON + HTML | fichiers | Pas de base de données |

---

## Fichiers de production (V8.0)

| Fichier | Lignes | Rôle |
|---------|--------|------|
| `dashboard.py` | 2 252 | Dashboard HTML v8 — login, settings, ECharts, SSE, Ctrl+K, IR, workbench |
| `report_monthly.py` | 648 | Rapport mensuel HTML + graphiques + IA |
| `report.py` | 626 | Rapport quotidien HTML + graphiques matplotlib |
| `report_weekly.py` | 586 | Rapport hebdomadaire HTML + comparatif S-1 |
| `detector.py` | 607 | Détection + auto-ban + Telegram + IA adaptive |
| `actions.py` | 467 | API Flask — ban/unban/whitelist/analyze/config/stream/logs |
| `rag_ingest.py` | ~150 | Ingestion rapports → AnythingLLM |
| `audit_actions.csv` | 726 actions | Historique toutes les actions SOC |
| `threat_patterns.json` | — | Mémoire IA adaptive — patterns IP et /24 |
| `soc_config.json` | — | Config dynamique — seuils ban/disk/RAM |
| `annotations.json` | — | Annotations opérateur sur la timeline |
| `geo_cache.json` | — | Cache géolocalisation IPs |
| `metrics_history.csv` | — | Historique CPU/RAM/Disk 7j |

---

## Statistiques de sécurité (08/06/2026)

| Métrique | Valeur |
|----------|--------|
| IPs actuellement bannies | 375 |
| Total bans depuis déploiement | 4 116 |
| Total tentatives SSH bloquées | 25 659+ |
| Actions auditées (CSV) | 726 |
| Uptime fail2ban | 182 jours continus |
| Uptime serveur | 182 jours |

---

## Crontab ubuntu (actif)

```bash
SOC_ACTIONS_KEY=...
SOC_DASHBOARD_PWD=your_dashboard_password_here
ABUSEIPDB_KEY=...
ANYTHINGLLM_KEY=...
TELEGRAM_TOKEN=...
TELEGRAM_CHAT_ID=...
SOC_MAIL_FROM=secops@yourdomain.com
SOC_MAIL_TO=admin@yourdomain.com

*/15 * * * *  detector.py       # Détection + auto-ban + Telegram
*/15 * * * *  dashboard.py      # Génération dashboard HTML
0 7  * * *    report.py         # Rapport quotidien + mail
0 7  * * *    rag_ingest.py     # Ingestion RAG AnythingLLM
0 7  * * 1    report_weekly.py  # Rapport hebdomadaire (lundi)
0 7  1 * *    report_monthly.py # Rapport mensuel (1er du mois)
```

---

## Services systemd actifs

| Service | Port | Rôle |
|---------|------|------|
| `soc-actions` | 8022 | API Flask actions (EnvironmentFile: /etc/soc-actions.env) |
| `soc-dashboard` | 8088 | Serveur HTTP statique |
| `fail2ban` | — | Bannissement SSH |
| `postfix` | 25 | SMTP relay |

---

## Dashboard V8 — Fonctionnalités complètes

### Sécurité / Accès
| Feature | Description |
|---------|-------------|
| **Mire de connexion** | Overlay fullscreen, mot de passe SHA-256 côté client, sessionStorage |
| **Clé API SOC** | Saisie séparée dans les modales d'action (ban, unban, whitelist...) |
| **Settings panel** | Slide-over droit ⚙️ — astreinte, seuils admin, reset session |

### Navigation
| Feature | Description |
|---------|-------------|
| **5 écrans** | Vue globale, Sécurité, Performance, Timeline, Infrastructure |
| **Workbench IP** | 6e écran — investigation IP (clic sur n'importe quelle IP) |
| **Ctrl+K** | Recherche globale — navigation, IP, analyse IA |
| **Raccourcis 1-5** | Navigation clavier directe entre écrans |
| **Mode IR** | Plein écran urgence — threat score géant, top IPs, fond rouge |
| **PWA manifest** | Installable sur mobile iOS/Android |

### Interface
| Feature | Description |
|---------|-------------|
| **Mode sombre/clair** | Toggle 🌙/☀️, localStorage |
| **ECharts v5** | Bans 7j (bar + dataZoom), CPU/RAM/Disk 24h (line + zoom), sparklines |
| **Heatmap drill-down** | Clic cellule → modale détail heure + lien Timeline |
| **Status bar** | 3 dots topbar — fail2ban, API Flask, SSE stream |
| **Badge ON CALL** | Statut astreinte opérateur dans la topbar |

### Données / Actions
| Feature | Description |
|---------|-------------|
| **SSE live** | Métriques CPU/RAM/bans sans rechargement (toutes les 30s) |
| **Export CSV/JSON** | Boutons sur Top IPs, Audit log, Timeline |
| **Filtres tableaux** | Recherche live sur Top IPs et Audit log |
| **Annotations** | Notes opérateur sur la timeline (annotations.json) |
| **Logs live** | Dernières lignes detector.log dans Infrastructure |
| **KPIs SOC** | Couverture ban, MTTD, ban auto count, récidivistes |

---

## API actions (V8) — Endpoints

| Endpoint | Auth | Rôle |
|----------|------|------|
| `GET /status` | Clé API | Statut SOC |
| `POST /auth` | — | Validation mot de passe dashboard |
| `POST /ban` | Clé API | Bannir une IP |
| `POST /unban` | Clé API | Débannir une IP |
| `POST /analyze` | Clé API | Analyse IA Ollama sur une IP |
| `POST /report` | Clé API | Déclencher rapport quotidien |
| `POST /whitelist/add` | Clé API | Ajouter à la whitelist |
| `POST /whitelist/remove` | Clé API | Retirer de la whitelist |
| `GET /stream` | Clé API | SSE métriques live (30s) |
| `GET /logs` | Clé API | Dernières N lignes detector.log |
| `GET /config` | — | Lire soc_config.json |
| `POST /config` | Clé API | Modifier seuils ban/disk/RAM |
| `POST /annotation/add` | Clé API | Ajouter annotation timeline |
| `GET /action/docs/` | — | Swagger UI |

Rate limiting : 60 req/min (flask-limiter)

---

## IA Adaptive (V8)

`threat_patterns.json` enrichi à chaque BAN_AUTO ou BAN_OLLAMA :
- Par IP : `first_seen`, `bans`, `score_max`, dernières 10 actions
- Par /24 : `bans`, liste des 20 dernières IPs

Contexte injecté dans les prompts Ollama zone grise :
```
HISTORIQUE IP: 3 bans depuis 2026-04-12.
HISTORIQUE /24: 47 bans sur ce sous-réseau.
```

---

## Points de vigilance (08/06/2026)

| Risque | Valeur | Seuil | Action requise |
|--------|--------|-------|----------------|
| Disque | 83% | ⚠️ 75% / 🔴 88% | Logrotate actif (daily 14j) |
| Swap | 78% | — | Surveiller |
| Telegram | non actif | — | Ajouter TELEGRAM_TOKEN + CHAT_ID dans crontab et /etc/soc-actions.env |

---

## Historique des versions

| Version | Date | Changements majeurs |
|---------|------|---------------------|
| V1 | 2025-12 | Scripts bash monitoring basique |
| V2 | 2026-01 | Python + alertes mail |
| V3 | 2026-03 | AbuseIPDB + Ollama décision |
| V4 | 2026-04-04 | report.py HTML + graphiques matplotlib |
| V5 | 2026-04-05 | SOAR complet : auto-ban + RAG AnythingLLM |
| V5.3 | 2026-04-06 | Fix doublon alertes, dashboard unifié |
| V6.0 | 2026-04-13 | Dashboard v3, API Flask, dédup Ollama |
| V6.5 | 2026-06-08 | Dashboard v6 responsive, modales, threat hero, sparklines |
| V7.0 | 2026-06-08 | Audit UX/UI complet, mobile-first, documentation |
| **V8.0** | **2026-06-08** | **Dashboard SecOps complet — 18 features avancées + login + settings** |
