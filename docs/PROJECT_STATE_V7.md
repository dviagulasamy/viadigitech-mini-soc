# ViaDigiTech Mini-SOC — État du projet V7.0
> Archive technique — 08 juin 2026

---

## Positionnement

Plateforme SOAR légère et autonome pour VPS Ubuntu.  
Pipeline complet : **détection → enrichissement → décision IA → action → rapport → dashboard**.

Conçu pour fonctionner sans supervision humaine permanente, avec escalade par email et dashboard web temps réel.

---

## Stack technique actuelle

| Couche | Technologie | Version | Rôle |
|--------|-------------|---------|------|
| OS | Ubuntu | 22.04 LTS | Base serveur |
| Python | CPython | 3.10+ | Scripts SOC (5 modules) |
| Détection | fail2ban | 0.11+ | Bannissement SSH progressif |
| Threat Intel | AbuseIPDB | API v2 | Score de réputation IP |
| IA décision | Ollama / qwen2.5:3b | local | Zone grise + analyse ad-hoc |
| IA rapport | Ollama / qwen2.5:3b | local | Synthèse quotidienne |
| RAG | AnythingLLM | Docker | Mémoire contextuelle SOC |
| Mail | Postfix | relay | Google Workspace SMTP |
| Reverse proxy | Nginx Proxy Manager | Docker | SSL + routing |
| Dashboard | Python http.server | port 8088 | HTML statique généré |
| API actions | Flask | port 8022 | ban/unban/analyze/report |
| Orchestration | Coolify | Docker | Gestion conteneurs |
| Monitoring uptime | Uptime Kuma | Docker | Disponibilité services |
| Automation | n8n | Docker | Workflows SOC |
| Stockage | CSV + JSON + HTML | fichiers | Pas de base de données |

---

## Architecture SOAR (detector.py — toutes les 15 min)

```
/var/log/auth.log
    │
    ▼
Parse SSH fails (24h)
    │
    ├─ score AbuseIPDB > 80% ──────────────► BAN_AUTO (fail2ban immédiat)
    │
    ├─ score 40-79% ──► Ollama qwen2.5:3b ─► BAN_OLLAMA / SURVEILLE
    │
    └─ score < 40% ──────────────────────► IGNORE
         │
         ▼
    audit_actions.csv
    alerte mail HTML (si seuils dépassés)
    dashboard.py → /soc/index.html
```

---

## Fichiers de production

| Fichier | Taille | Rôle |
|---------|--------|------|
| `detector.py` | 26 KB | Détection + auto-ban + alertes |
| `dashboard.py` | 77 KB | Génération HTML dashboard (5 écrans) |
| `report.py` | 31 KB | Rapport quotidien HTML + graphiques |
| `actions.py` | 6.8 KB | API Flask (ban/unban/whitelist/analyze) |
| `rag_ingest.py` | 6.1 KB | Ingestion rapports → AnythingLLM |
| `audit_actions.csv` | 80 KB | 720 actions enregistrées |
| `metrics_history.csv` | ~2 KB | Historique CPU/RAM/Disk 7j |
| `geo_cache.json` | 2.3 KB | Cache géolocalisation IPs |
| `last_ai_summary.json` | 1.4 KB | Dernière synthèse IA |

---

## Statistiques de sécurité (08/06/2026)

| Métrique | Valeur |
|----------|--------|
| IPs actuellement bannies | 371 |
| Total bans depuis déploiement | 4 110 |
| Total tentatives SSH bloquées | 25 659 |
| Actions auditées (CSV) | 720 |
| Uptime fail2ban | 182 jours continus |
| Uptime serveur | 182 jours |

---

## Crontab ubuntu (actif)

```bash
ABUSEIPDB_KEY=...
ANYTHINGLLM_KEY=...
SOC_ACTIONS_KEY=...
SOC_MAIL_FROM=secops@yourdomain.com
SOC_MAIL_TO=admin@yourdomain.com

*/15 * * * *  detector.py    # Détection + auto-ban
*/15 * * * *  dashboard.py   # Génération dashboard HTML
0 7  * * *    report.py      # Rapport quotidien + mail
0 7  * * *    rag_ingest.py  # Ingestion RAG AnythingLLM
```

---

## Services systemd actifs

| Service | Port | Rôle |
|---------|------|------|
| `soc-actions` | 8022 | API Flask actions |
| `soc-dashboard` | 8088 | Serveur HTTP statique |
| `fail2ban` | — | Bannissement SSH |
| `postfix` | 25 | SMTP relay |

---

## Domaines (Nginx Proxy Manager)

| Domaine | Service | Auth |
|---------|---------|------|
| `graph.viadigitech.com/soc/` | Dashboard HTML | Basic auth NPM |
| `graph.viadigitech.com/action/` | API Flask | Clé API header |
| `soc.viadigitech.com` | Ancien dashboard | — |
| `n8n.viadigitech.com` | n8n automation | — |

---

## Dashboard V7 — Écrans

| Écran | Contenu |
|-------|---------|
| Vue globale | Threat score hero, stat cards + sparklines, services, IA, graphique 7j |
| Sécurité | Carte géo Leaflet, top IPs, audit log, corrélation /24, whitelist |
| Performance | Graphique CPU/RAM/Disk 24h, heatmap attaques 7j×24h |
| Timeline | Fusion événements auth.log + audit + detector (24h) |
| Infrastructure | Services systemd, conteneurs Docker, whitelist fail2ban |

---

## Points de vigilance (08/06/2026)

| Risque | Valeur | Seuil | Action requise |
|--------|--------|-------|----------------|
| Disque | 83% | ⚠️ 75% / 🔴 88% | Logrotate urgent |
| Swap | 78% | — | Surveiller |
| Logs sans rotation | dashboard 528K, detector 704K | — | Logrotate |
| Clés API en clair crontab | — | — | Migrer vers .env |

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
| **V7.0** | **2026-06-08** | **Audit UX/UI complet, mobile-first, audit doc** |
