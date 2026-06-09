# Roadmap UX/Sécurité — V10.0 (Sprints 1-4 complétés)

> Roadmap générée en session mai-juin 2026. Tous les items ont été livrés.

---

## Améliorations UX/UI

| # | Amélioration | Sprint | Statut |
|---|---|---|---|
| V1 | Typographie JetBrains Mono (données + titres) | 1 | ✅ |
| V2 | Jauge radiale SVG 270° score menace (stroke-dasharray animé) | 2 | ✅ |
| V3 | Compteurs animés stat cards (style Datadog, 700ms ease) | 1 | ✅ |
| V4 | Timeline verticale redesign (connecteur coloré, marqueurs, glow critiques) | 2 | ✅ |
| V5 | Skeleton loading SSE (shimmer CSS pendant refresh) | 4 | ✅ |
| V6 | Heatmap interactive (tooltips riches au hover avec sévérité) | 4 | ✅ |
| V7 | Login screen premium (glassmorphism, orbes CSS, shield SVG pulsant) | 2 | ✅ |
| V8 | Mode IR dramatisé (bannière rouge défilante, irBodyPulse sur le body) | 4 | ✅ |
| V9 | Sparklines gradient fill (dégradé 45%→1% opacity, shadowBlur ligne) | 4 | ✅ |
| V10 | Transitions page-to-page (screenIn 280ms cubic-bezier) | 1 | ✅ |

---

## Nouvelles fonctionnalités

| # | Feature | Sprint | Statut |
|---|---|---|---|
| F1 | Bot Telegram alertes critiques | 1 | ✅ |
| F2 | Health-check SOC automatique (badge topbar OK/WARN/CRIT) | 1 | ✅ |
| F3 | Honeypot SSH port 2222 (ban immédiat + Telegram 🍯) | 2 | ✅ |
| F4 | Détection Low & Slow (10-200 tentatives/24h, dédup 6h) | 2 | ✅ |
| F5 | Rapport hebdomadaire HTML (vendredi 8h, bilan 7j + IA) | 3 | ✅ |
| F6 | Analyse prédictive IA lundi (tendances + vecteurs + recommandations) | 3 | ✅ |
| F7 | Threat Intelligence feeds (Feodo Tracker + OTX, cache 1h) | 3 | ✅ |
| F8 | Scoring adaptatif multi-facteurs (AbuseIPDB + TI + récidive + pays + heure) | 3 | ✅ |
| F9 | Réponse graduée (BAN_AUTO / BAN_TEMP / Ollama / SURVEILLE) | 3 | ✅ |
| F10 | Blocage ASN (carte top 6 + endpoint /block/asn) | 4 | ✅ |
| F12 | Export SIEM/CEF (/export/siem?format=json\|cef) | 4 | ✅ |
| F13 | Playbooks IR interactifs (3 scénarios + checkboxes + rapport clipboard) | 4 | ✅ |

---

## Commits GitHub

| Commit | Sprint | Description |
|--------|--------|-------------|
| `9beeec3` | Sprint 1 | UX premium + health-check SOC + Telegram |
| `756ce8d` | Sprint 2 | Honeypot SSH + Low&Slow + jauge SVG + timeline + login premium |
| `c9c2d25` | Sprint 3 | TI feeds + scoring adaptatif + réponse graduée + rapport hebdo + IA prédictive |
| `58b2d16` | Sprint 4 | Skeleton + heatmap tooltips + IR dramatisé + sparklines + ASN + SIEM + playbooks |

---

*Roadmap complétée — juin 2026*
