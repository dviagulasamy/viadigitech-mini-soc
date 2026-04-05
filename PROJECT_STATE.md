
# Project State — ViaDigiTech Mini-SOC SOAR — V6.0 (SOAR Autonome)

---

## Global Positioning

> Autonomous SOAR (Security Orchestration, Automation and Response) for VPS, integrating Fail2Ban, AbuseIPDB reputation scoring, local AI decision-making (Ollama), automated banning, live web dashboard, daily HTML reports, and RAG memory via AnythingLLM.

**Current status: V6.0 — SOAR fully operational — detect → enrich → decide → act → report**

---

## Technical Stack

| Component | Technology |
| --------- | ----------- |
| Server OS | Ubuntu 22.04 |
| Python | 3.x (requests, psutil, subprocess) |
| Mail | msmtp (OVH relay) |
| Reverse Proxy | Nginx Proxy Manager (Docker) |
| IP Banning | Fail2Ban (bantime progressif, permanent récidivistes) |
| Threat Intel | AbuseIPDB API |
| AI SOC decisions | Ollama — qwen2.5:3b (zone grise) |
| AI daily report | Ollama — llama3.2:3b |
| RAG memory | AnythingLLM (workspace viadigitech-soc) |
| MCP Tools | FastMCP Docker (9 outils SOC) |
| Dashboard | Python http.server + HTML généré → NPM proxy |
| Data Storage | CSV + HTML reports |

---

## Architecture SOAR (detector.py — toutes les 15 min)

```
auth.log → parse SSH fails → AbuseIPDB score
  score > 80%  → BAN_AUTO (Fail2Ban immédiat)
  score 40-79% → Ollama qwen2.5:3b → décision BAN/IGNORE
  score < 40%  → IGNORE
  → audit_actions.csv + alerte mail HTML enrichie
```

---

## Crons actifs (crontab ubuntu)

```
*/15 * * * *  detector.py   — alertes + auto-ban AbuseIPDB + Ollama
*/15 * * * *  dashboard.py  — dashboard HTML /soc/index.html
0 7 * * *     report.py     — rapport quotidien HTML + mail
0 7 * * *     rag_ingest.py — ingestion rapports dans AnythingLLM
0 7 * * *     monitoring V5 — collecte CSV
```

---

## Scripts /home/ubuntu/secops/

| Script | Rôle |
|--------|------|
| detector.py | SOAR core : AbuseIPDB + auto-ban + Ollama zone grise |
| dashboard.py | Dashboard HTML → graph.viadigitech.com/ |
| report.py | Rapport quotidien HTML + Ollama llama3.2:3b + mail |
| rag_ingest.py | Ingestion rapports SOC dans AnythingLLM |

---

## Sécurité serveur

| Composant | Config |
|-----------|--------|
| UFW | ports sensibles bloqués, 8088 ouvert depuis réseaux Docker uniquement |
| Fail2Ban | bantime 24h progressif, permanent si récidive, maxretry 3 |
| SSH | MaxAuthTries 3, LoginGraceTime 30, PermitRootLogin no |
| Whitelist | 176.134.132.129 |
| sudoers | fail2ban-client sans mot de passe pour ubuntu |

---

## Accès web

| URL | Service |
|-----|---------|
| https://graph.viadigitech.com/ | Dashboard SOC (protégé Basic Auth NPM) |
| https://n8n.viadigitech.com | n8n automation |

---

## FastMCP (port 8020, Docker)

9 outils SOC : ban_ip, unban_ip, get_banned_ips, restart_service, purge_old_reports, get_soc_summary, get_system_status, get_docker_status, get_docker_stats

Config Claude Code : ~/.claude/settings.json → http://localhost:8020/mcp

---

## Modèles Ollama

- `qwen2.5:3b` — décisions SOC zone grise (detector.py)
- `llama3.2:3b` — rapport quotidien (report.py)

---

## Completed Achievements V6.0 (05/04/2026)

- SOAR autonome avec AbuseIPDB + Fail2Ban auto-ban ✅
- Décisions IA zone grise via Ollama qwen2.5:3b ✅
- Dashboard HTML live (refresh 5 min) ✅
- Alertes mail HTML enrichies (pays, ISP, score, badge) ✅
- RAG AnythingLLM — ingestion rapports quotidiens ✅
- FastMCP 9 outils SOC pour Claude Code ✅
- Sécurité renforcée (UFW, Fail2Ban progressif, SSH hardening) ✅
- Dashboard protégé Basic Auth via NPM ✅

---

*Updated: April 2026*
