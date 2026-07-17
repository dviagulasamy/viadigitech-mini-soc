# BMAD Project Analysis — ViaDigiTech Mini-SOC

## 1. Scope and mission
Project: ViaDigiTech Mini-SOC IA, a self-hosted SOC platform for Ubuntu VPS/cloud.

Core objectives observed in the repository:
- Continuous SSH attack monitoring and response
- Geo-blocking and composite threat scoring
- Honeypot on port 2222
- Dashboard and REST API for operator actions
- Alerting via Telegram/email and periodic reporting
- AI-assisted analysis and predictive summaries

## 2. Current architecture summary
The repository shows a modular architecture centered on Python scripts and Linux system services:
- detector.py: SOAR core logic, scoring, TI feeds, low/slow detection, geo-blocking, threshold alerts
- dashboard.py: visual dashboard with multiple screens and SSE-based live updates
- actions.py: Flask API exposed on port 8022
- soc_db.py: SQLite persistence for threat history and audit data
- honeypot.py: TCP honeypot on port 2222
- report*.py and predict_ai.py: reporting and predictive AI workflows

The deployment model uses:
- systemd services
- cron jobs
- Fail2Ban
- optional Telegram/OTX/Ollama integrations

## 3. What is already strong
- Clear separation between detection, dashboard, API, DB, and reporting concerns
- Production-oriented deployment with systemd services and fail2ban integration
- Good documentation coverage for architecture, deploy flow, and project state
- Mature feature scope: multi-factor scoring, honeypot, reports, AI analysis, geo-blocking

## 4. Risks and gaps to address
1. Documentation drift
   - INSTALL.md still reflects an older V5.3 flow while README and PROJECT_STATE describe V11.0 features.
   - This increases deployment and onboarding ambiguity.

2. Deployment assumptions are environment-specific
   - Paths are hard-coded around /home/ubuntu/secops or /home/ubuntu/viadigitech-soc-v5-3, which can break on different host layouts.

3. Operational reliability needs stronger validation
   - No visible test harness or CI workflow found in the repo snapshot.
   - The system would benefit from automated smoke tests and linting.

4. Dependency management is not fully explicit
   - Python dependencies are referenced in docs but not pinned in a requirements file or environment manifest.

## 5. Recommended next actions
Priority 1 — Stabilize and simplify deployment
- Add a requirements.txt (or pyproject.toml) for Python dependencies
- Standardize install paths and service definitions
- Add a bootstrap script for environment initialization

Priority 2 — Improve maintainability
- Add unit/integration tests for the core logic and API routes
- Introduce a basic CI workflow (lint + smoke tests)
- Centralize configuration in a single config module or YAML/JSON manifest

Priority 3 — Align product and engineering documentation
- Make README/INSTALL/PROJECT_STATE consistent around one versioned deployment model
- Add an operational runbook for service recovery and common failure modes

## 6. BMAD installation status
BMAD Method was successfully installed for this project at:
- _bmad/
- .claude/skills/

The analysis above is the first BMAD-oriented assessment artifact generated from the repository contents.
