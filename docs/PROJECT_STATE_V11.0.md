
# Project State — ViaDigiTech Mini-SOC SOAR — V11.0

> Dernière mise à jour : 10 juin 2026

---

## Statut global

**V11.0 — 7 nouvelles fonctionnalités livrées + 4 correctifs critiques**

Le SOC est entièrement opérationnel. Cette version introduit la persistance SQLite, le geo-blocking, l'historique de scores, le digest Telegram, les alertes par seuil composite, un écran IA dédié et l'optimisation SSE mobile.

---

## Stack technique

| Composant | Technologie |
|-----------|-------------|
| OS | Ubuntu 22.04 |
| Python | 3.x |
| Mail | Postfix (relay Google Workspace) |
| Reverse Proxy | Nginx Proxy Manager (Docker) |
| IP Banning | Fail2Ban (bantime progressif) |
| Threat Intel | AbuseIPDB API + Feodo Tracker + AlienVault OTX |
| AI SOC | Ollama — qwen2.5:3b |
| Dashboard | Python → HTML statique → NPM proxy |
| API Actions | Flask port 8022 |
| Alertes | Telegram Bot API |
| Honeypot | TCP port 2222 (soc-honeypot.service) |
| Base de données | SQLite (WAL mode) — soc_db.py |

---

## Architecture SOAR (detector.py — toutes les 15 min)

```
auth.log → parse SSH fails → AbuseIPDB score
  ↓ F14 Geo-blocking : pays bloqué → BAN_GEO immédiat
  ↓ TI feeds (Feodo Tracker + OTX)
  ↓ Scoring composite (AbuseIPDB + TI + récidive + pays + heure)
    composite ≥ 80  → BAN_AUTO  (Fail2Ban + Telegram 🚨)
    composite 70-79 → BAN_TEMP  (Fail2Ban + Telegram ⚠️)
    composite 40-69 → Ollama qwen2.5:3b → BAN_OLLAMA ou SURVEILLE
    composite < 40  → SURVEILLE
  ↓ F15 Score history : score enregistré dans SQLite + threat_patterns.json
  ↓ check_subnet_auto_ban() — BAN_SUBNET24 si ≥ 3 IPs /24 en 1h
  ↓ check_low_slow()        — 10-200 tentatives/24h sous le radar
  ↓ check_composite_threshold() — F18 alerte si score moyen > seuil
  ↓ flush_telegram_digest() — F16 envoi groupé si mode digest
  → audit_actions.csv + SQLite + Telegram + dashboard
```

---

## Crons actifs (crontab ubuntu)

```
*/15 * * * *  detector.py        — alertes + scoring composite + Telegram
*/15 * * * *  dashboard.py       — dashboard HTML /soc/index.html
*/30 * * * *  soc_healthcheck.py — santé SOC (Ollama/F2B/API/disk)
0 7  * * *    report.py          — rapport quotidien HTML + mail
0 7  * * *    rag_ingest.py      — ingestion AnythingLLM
0 7  * * 1    predict_ai.py      — analyse prédictive IA (lundi)
0 8  * * 5    report_weekly.py   — rapport hebdo HTML + mail (vendredi)
0 7  1 * *    report_monthly.py  — rapport mensuel HTML + mail
```

---

## Scripts /home/ubuntu/secops/

| Script | Rôle |
|--------|------|
| `detector.py` | SOAR core : scoring composite F8, réponse graduée F9, TI feeds F7, low&slow F4, subnet ban, geo-blocking F14, threshold alert F18, digest Telegram F16 |
| `dashboard.py` | Dashboard HTML V11 — 7 écrans, écran IA dédié F19, workbench sparkline F15, SSE mobile F20, settings geo-blocking F14 |
| `actions.py` | API Flask port 8022 — 23 endpoints, /threat/ip F15, /block/country + /unblock/country + /countries F14 |
| `soc_db.py` | Module SQLite F17 — tables audit_actions, score_history, threat_patterns, migration transparente CSV/JSON |
| `ti_feeds.py` | Threat Intelligence — Feodo Tracker (cache 1h) + AlienVault OTX optionnel |
| `predict_ai.py` | Analyse prédictive IA lundi — tendances, vecteurs, recommandations → last_ai_summary.json |
| `report.py` | Rapport quotidien HTML + Ollama + sujet dynamique + bouton dashboard |
| `report_weekly.py` | Rapport hebdo HTML — bilan 7j vs préc., sparkbars, top IPs géo, analyse IA |
| `report_monthly.py` | Rapport mensuel HTML |
| `soc_healthcheck.py` | Health-check 30min — badge SOC OK/WARN/CRIT dans topbar |
| `honeypot.py` | Honeypot TCP port 2222 — ban immédiat + Telegram (systemd soc-honeypot.service) |
| `rag_ingest.py` | Ingestion rapports dans AnythingLLM |

---

## Services systemd

| Service | Rôle | Statut |
|---------|------|--------|
| `soc-actions.service` | API Flask port 8022 | active |
| `soc-honeypot.service` | Honeypot TCP port 2222 | active |

---

## Dashboard V11 — Fonctionnalités

### Écrans (7)
1. **Vue globale** — Jauge SVG 270° animée, stat cards avec compteurs, sparklines gradient, health badge
2. **IA & Prédictive** *(nouveau F19)* — 4 onglets : Synthèse / Sécurité / Performance / 🔮 Prédictive
3. **Sécurité** — Top IPs (badges TI 🦠), audit (BAN_TEMP/BAN_AUTO/SURVEILLE), corrélation /24, ASN agressifs, whitelist
4. **Performance** — Graphiques CPU/RAM/disk, heatmap SSH interactive (tooltips riches), logs detector
5. **Timeline** — Redesign vertical : ligne connectrice colorée, marqueurs circulaires, glow critiques
6. **Infrastructure** — Containers Docker, services systemd, whitelist, ASN, logs live
7. **Workbench IP** — Profil complet, sparkline score composite F15, analyse IA, historique actions

### Features premium
- Login glassmorphism (backdrop-filter, orbes CSS animées, shield SVG pulsant)
- Mode IR dramatisé : bannière rouge défilante + irBodyPulse sur tout le body
- Playbooks IR interactifs : 3 scénarios (Brute-force / Recon / Compromission)
- Skeleton loading sur les stats SSE
- Export SIEM/CEF via `/action/export/siem`
- Blocage ASN via `/action/block/asn`
- Workbench IP, annotations timeline, Ctrl+K, raccourcis clavier
- PWA installable, mode sombre/clair
- **SSE Page Visibility API** (F20) — pause automatique en arrière-plan mobile

---

## API Actions — Endpoints (port 8022)

| Méthode | Route | Auth | Description |
|---------|-------|------|-------------|
| POST | `/ban` | clé | Bannir une IP |
| POST | `/unban` | clé | Débannir une IP |
| POST | `/analyze` | clé | Analyse Ollama |
| POST | `/report` | clé | Rapport on-demand |
| POST | `/whitelist/add` | clé | Ajouter whitelist |
| POST | `/whitelist/remove` | clé | Retirer whitelist |
| GET | `/config` | non | Lire config |
| POST | `/config` | clé | Écrire config |
| GET | `/health` | non | Santé SOC |
| POST | `/notify/telegram` | clé | Test Telegram |
| GET | `/export/siem` | clé | Export SIEM (JSON/CEF) |
| POST | `/block/asn` | clé | Bloquer ASN |
| GET | `/logs` | clé | Logs detector |
| GET | `/fail2ban/status` | clé | Status Fail2Ban |
| POST | `/fail2ban/apply` | clé | Appliquer config F2B |
| POST | `/maintenance/purge` | clé | Purge logs anciens |
| POST | `/maintenance/clear-geo` | clé | Vider cache géo |
| POST | `/annotation/add` | clé | Annoter timeline |
| GET | `/notifications` | clé | 80 dernières actions SOC |
| POST | `/digest/flush` | clé | Envoi immédiat digest email |
| GET | `/stream` | clé | SSE métriques live |
| GET | `/threat/ip` | clé | **F15** Score history + profil IP |
| GET | `/countries` | clé | **F14** Liste pays bloqués |
| POST | `/block/country` | clé | **F14** Ajouter pays bloqué |
| POST | `/unblock/country` | clé | **F14** Retirer pays bloqué |

---

## Fichiers de données

| Fichier | Contenu |
|---------|---------|
| `soc.db` | **SQLite F17** — audit_actions, score_history, threat_patterns |
| `audit_actions.csv` | Journal CSV legacy (dual-write avec SQLite) |
| `soc_health.json` | Dernière vérification santé (toutes les 30 min) |
| `soc_config.json` | Config runtime (seuils, Telegram, whitelist, geo-blocking, digest...) |
| `threat_patterns.json` | Mémoire IP/24 (bans, score max, récidive, score_history F15) |
| `ti_matches.json` | IPs matchées contre feeds TI (Feodo/OTX) |
| `last_ai_summary.json` | Résumés IA (morning/security/perf/predictive) |
| `geo_cache.json` | Cache géolocalisation ip-api.com (ASN inclus) |
| `annotations.json` | Annotations manuelles sur la timeline |
| `metrics_history.csv` | Historique CPU/RAM/disk (7j) |
| `mail_digest_buffer.json` | Buffer alertes email digest |
| `telegram_digest_buffer.json` | **F16** Buffer alertes Telegram digest |
| `/tmp/soc_threshold_alert.json` | **F18** Horodatage dernière alerte seuil composite |

---

## Sécurité serveur

| Composant | Config |
|-----------|--------|
| UFW | ports sensibles bloqués |
| Fail2Ban | bantime progressif, permanent récidivistes, maxretry 3 |
| SSH | MaxAuthTries 3, LoginGraceTime 30, PermitRootLogin no |
| Whitelist | Chargée depuis SOC_WHITELIST (env var) |
| Honeypot | port 2222 → ban immédiat |
| API | clé X-SOC-Key, rate limiting 60 req/min |
| Dashboard | SHA-256 côté client |
| **Geo-blocking** | **F14** — pays bloqués → BAN_GEO immédiat dans detector.py |

---

## soc_config.json — Clés V11.0

```json
{
  "ban_threshold": 80,
  "warn_disk": 75, "crit_disk": 88,
  "warn_ram": 75,  "crit_ram": 90,
  "warn_cpu": 70,  "crit_cpu": 85,
  "sse_interval": 30,
  "autologout": 0,
  "mail_mode": "immediate",
  "mail_digest_hours": 4,
  "mail_types_ban_auto": true,
  "mail_types_ban_temp": true,
  "mail_types_honeypot": true,
  "mail_types_low_slow": true,
  "mail_types_system": true,
  "telegram_mode": "immediate",
  "telegram_digest_interval": 30,
  "composite_avg_threshold": 0,
  "blocked_countries": [],
  "subnet_ban_enabled": false,
  "subnet_ban_threshold": 3
}
```

---

## Roadmap complète

| Version | Items | Statut |
|---------|-------|--------|
| Sprint 1 | V1 Typo, V3 Compteurs, V10 Transitions, F1 Telegram, F2 Health-check | ✅ |
| Sprint 2 | V2 Jauge SVG, V4 Timeline, V7 Login premium, F3 Honeypot, F4 Low&Slow | ✅ |
| Sprint 3 | F5 Rapport hebdo, F6 IA prédictive, F7 TI feeds, F8 Scoring adaptatif, F9 Réponse graduée | ✅ |
| Sprint 4 | V5 Skeleton, V6 Heatmap tooltips, V8 IR dramatisé, V9 Sparklines, F10 ASN, F12 SIEM, F13 Playbooks IR | ✅ |
| Post-Sprint | N1 Notification bell, N2 Digest email, N3 Filtres mail | ✅ |
| V10.2 | B1 Redirect graph.viadigitech.com→/soc/, B2 Topbar mobile | ✅ |
| V11.0 | F14 Geo-blocking, F15 Score history, F16 Digest Telegram, F17 SQLite, F18 Seuil composite, F19 Écran IA, F20 SSE mobile | ✅ |

---

## Correctifs V10.2 (10 juin 2026)

### B1 — Redirect graph.viadigitech.com → /soc/
- `python3 -m http.server` sans `index.html` affichait le listing du répertoire
- Création de `/var/www/html/viadigitech-reports/index.html` avec meta-refresh + JS redirect

### B2 — Topbar mobile responsive
- Ajout `id='report-btn'`, `class='ir-btn'`, `class='soc-health-badge'`, `class='svc-ko-badge'`
- `@media(max-width:768px)` : masquage de tous les éléments non essentiels

### B3 — DOM screen-infra non fermé (critique)
- `</div>` manquant → `screen-workbench` imbriqué dans `screen-infra` → workbench invisible
- Fix : ajout du `</div>` de fermeture avant le commentaire ÉCRAN 6

### B4 — Bottom nav workbench sans item actif
- `showScreen('workbench')` ne trouvait pas `bn-workbench` → aucun item actif
- Fix : `navId = id === 'workbench' ? 'security' : id` dans `showScreen()`

---

## Fonctionnalités V11.0 (10 juin 2026)

### F14 — Geo-blocking par pays
- `blocked_countries[]` dans `soc_config.json`
- `detector.py` : BAN_GEO immédiat si pays bloqué, avant le scoring composite
- `actions.py` : `/block/country`, `/unblock/country`, `/countries`
- Dashboard settings : 8 presets (🇨🇳🇷🇺🇰🇵🇮🇷🇧🇾🇻🇳🇮🇳🇧🇷) + saisie manuelle + tags supprimables

### F15 — Historique de score composite par IP
- `detector.py` : `score_history[]` (30 entrées) dans `threat_patterns.json` + SQLite
- `actions.py` : `/threat/ip` — score_history + profil + audit par IP
- Dashboard Workbench : sparkline ECharts avec lignes de seuil BAN_AUTO (80%) / BAN_TEMP (70%)

### F16 — Digest Telegram
- `send_telegram()` bufferise dans `telegram_digest_buffer.json` si mode digest
- `flush_telegram_digest()` appelé à chaque run detector — intervalle configurable (min)
- Settings : mode (immédiat/digest) + intervalle

### F17 — SQLite (soc_db.py)
- Nouveau module `soc_db.py` : tables `audit_actions`, `score_history`, `threat_patterns`
- Migration automatique depuis `audit_actions.csv` et `threat_patterns.json` au premier lancement
- WAL mode, timeout 10s, dual-write (CSV legacy maintenu pour compatibilité)

### F18 — Alertes seuil composite moyen
- `check_composite_threshold()` : alerte Telegram si score moyen 24h > seuil configuré
- Déduplication 1h via `/tmp/soc_threshold_alert.json`
- `composite_avg_threshold: 0` (désactivé par défaut)

### F19 — Écran IA séparé
- Section IA extraite de `screen-overview` → `screen-ia` (7ème écran)
- Entrée dans les trois navs : desktop (`IA`), drawer (`🤖 IA & Prédictive`), bottom nav (icône)

### F20 — SSE optimisé mobile (Page Visibility API)
- `connectSSE()` encapsulé avec `visibilitychange` listener
- App en arrière-plan → SSE fermé (économie batterie mobile)
- App au premier plan → reconnexion automatique

---

*Mis à jour : 10 juin 2026 — V11.0*
