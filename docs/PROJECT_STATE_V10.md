
# Project State — ViaDigiTech Mini-SOC SOAR — V10.0 (Sprint 4 complet)

> Dernière mise à jour : juin 2026

---

## Statut global

**V10.0 — 4 sprints UX/sécurité livrés — roadmap complète**

Le SOC est entièrement opérationnel. Les 4 sprints d'améliorations UX/sécurité sont terminés (V1-V10 + F1-F13 du roadmap initial).

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

---

## Architecture SOAR (detector.py — toutes les 15 min)

```
auth.log → parse SSH fails → AbuseIPDB score
  ↓ TI feeds (Feodo Tracker + OTX)
  ↓ Scoring composite (AbuseIPDB + TI + récidive + pays + heure)
    composite ≥ 80  → BAN_AUTO  (Fail2Ban + Telegram 🚨)
    composite 70-79 → BAN_TEMP  (Fail2Ban + Telegram ⚠️)
    composite 40-69 → Ollama qwen2.5:3b → BAN_OLLAMA ou SURVEILLE
    composite < 40  → SURVEILLE
  ↓ check_subnet_auto_ban() — BAN_SUBNET24 si ≥ 3 IPs /24 en 1h
  ↓ check_low_slow()        — 10-200 tentatives/24h sous le radar
  → audit_actions.csv + Telegram + dashboard
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
| `detector.py` | SOAR core : scoring composite F8, réponse graduée F9, TI feeds F7, low&slow F4, subnet ban |
| `dashboard.py` | Dashboard HTML V10 — login premium, jauge SVG, timeline verticale, IR mode dramatisé, playbooks IR, ASN blocking |
| `actions.py` | API Flask port 8022 — ban/unban/whitelist/analyze/export SIEM/block ASN/config/stream |
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

## Dashboard V10 — Fonctionnalités

### Écrans
1. **Vue globale** — Jauge SVG 270° animée, stat cards avec compteurs, sparklines gradient, health badge
2. **Sécurité** — Top IPs (badges TI 🦠), audit (BAN_TEMP/BAN_AUTO/SURVEILLE), corrélation /24, ASN agressifs, whitelist
3. **Performance** — Graphiques CPU/RAM/disk, heatmap SSH interactive (tooltips riches), logs detector
4. **Timeline** — Redesign vertical : ligne connectrice colorée, marqueurs circulaires, glow critiques
5. **IA** — 4 onglets : Synthèse / Sécurité / Performance / 🔮 Prédictive
6. **Infra** — Containers Docker, services systemd, logs live

### Features premium
- Login glassmorphism (backdrop-filter, orbes CSS animées, shield SVG pulsant)
- Mode IR dramatisé : bannière rouge défilante + irBodyPulse sur tout le body
- Playbooks IR interactifs : 3 scénarios (Brute-force / Recon / Compromission)
- Skeleton loading sur les stats SSE
- Export SIEM/CEF via `/action/export/siem`
- Blocage ASN via `/action/block/asn`
- Workbench IP, annotations timeline, Ctrl+K, raccourcis clavier
- PWA installable, mode sombre/clair

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
| GET | `/config` | clé | Lire config |
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
| GET | `/stream` | clé | SSE métriques live |

---

## Fichiers de données

| Fichier | Contenu |
|---------|---------|
| `audit_actions.csv` | Toutes les actions SOC (BAN/UNBAN/SURVEILLE...) |
| `soc_health.json` | Dernière vérification santé (toutes les 30 min) |
| `soc_config.json` | Config runtime (seuils, Telegram, whitelist...) |
| `threat_patterns.json` | Mémoire IP/24 (bans, score max, récidive) |
| `ti_matches.json` | IPs matchées contre feeds TI (Feodo/OTX) |
| `last_ai_summary.json` | Résumés IA (morning/security/perf/predictive) |
| `geo_cache.json` | Cache géolocalisation ip-api.com (ASN inclus) |
| `annotations.json` | Annotations manuelles sur la timeline |
| `metrics_history.csv` | Historique CPU/RAM/disk (7j) |

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

---

## Roadmap sprints (complétée)

| Sprint | Items | Statut |
|--------|-------|--------|
| Sprint 1 | V1 Typo, V3 Compteurs, V10 Transitions, F1 Telegram, F2 Health-check | ✅ |
| Sprint 2 | V2 Jauge SVG, V4 Timeline, V7 Login premium, F3 Honeypot, F4 Low&Slow | ✅ |
| Sprint 3 | F5 Rapport hebdo, F6 IA prédictive, F7 TI feeds, F8 Scoring adaptatif, F9 Réponse graduée | ✅ |
| Sprint 4 | V5 Skeleton, V6 Heatmap tooltips, V8 IR dramatisé, V9 Sparklines gradient, F10 ASN, F12 SIEM export, F13 Playbooks IR | ✅ |

---

*Mis à jour : juin 2026 — V10.0*
