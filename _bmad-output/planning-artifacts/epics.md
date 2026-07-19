---
stepsCompleted: [1, 2, 3]
inputDocuments:
  - _bmad-output/planning-artifacts/dashboard-ux-ui-audit-2026-07-20.md
  - README.md
  - PROJECT_STATE.md
---

# viadigitech-mini-soc - Epic Breakdown

## Overview

This document provides the epic and story breakdown for a scoped remediation of the SOC dashboard (`scripts/dashboard.py`), covering the top 4 findings of the UX/UI & feature-alignment audit dated 2026-07-20: SIEM/CEF export wiring, F14 geo-blocking documentation accuracy, accessible navigation markup, and a WCAG AA contrast audit. This is a brownfield, already-in-production project — no PRD/Architecture documents exist; the audit document serves as the requirements source for this narrow scope.

## Requirements Inventory

### Functional Requirements

FR1: The dashboard SHALL either wire a UI control that invokes the SIEM/CEF export endpoint (`GET /action/export/siem?format=json|cef`, `actions.py:579`), or the export feature SHALL be removed from user-facing documentation (README.md, PROJECT_STATE.md) if it will not be implemented.

FR2: Project documentation (README.md, PROJECT_STATE.md) SHALL accurately describe the geo-blocking (F14) mechanism actually used by the dashboard today — `POST /action/config` with a `blocked_countries` payload — replacing or clarifying references to the unused dedicated endpoints (`/countries`, `/block/country`, `/unblock/country`).

FR3: The dashboard navigation (desktop top-nav, mobile drawer, bottom-nav) SHALL use semantic, keyboard-operable markup (`<button>`, `<nav>`, `role="tablist"`/`role="tab"` as appropriate) instead of non-semantic `<div onclick>` handlers, while preserving current visual styling and the existing `showScreen()` synchronization behavior across all three nav surfaces.

FR4: Secondary text color contrast across all dashboard screens (both dark and light themes) SHALL be audited against WCAG 2.1 AA contrast requirements, with a findings report identifying every non-conformant text/background pairing.

### NonFunctional Requirements

NFR1: Accessibility — all interactive navigation elements must meet WCAG 2.1 AA, including visible keyboard focus states, per the Digital Factory org-wide accessibility standard.

NFR2: No regression — the navigation markup refactor (FR3) must not break the existing SSE-driven screen-switching logic or the three-way sync between desktop nav, drawer, and bottom-nav active states.

NFR3: No new frontend framework or build step may be introduced — `dashboard.py` remains a single Python script emitting static HTML/CSS/JS; all fixes must work within that constraint.

### Additional Requirements

- SIEM/CEF export and geo-blocking (F14) backend endpoints already exist and are functional in `actions.py`; FR1/FR2 are UI-wiring and documentation-accuracy work, not new backend development.
- The dashboard is regenerated on a 15-minute cron cycle (`dashboard.py` run via crontab) and served as static HTML — any UI change must survive this regeneration model (no client-side-only persistence assumptions).
- Contrast audit (FR4) should use an automated tool (e.g. axe-core, Lighthouse) rather than manual estimation, and cover both `body.theme-light` and the default dark theme.

### UX Design Requirements

UX-DR1: If kept, the SIEM/CEF export control should follow the existing action-button visual pattern already used elsewhere in the dashboard (e.g. the "📄 Générer rapport IR" button, `dashboard.py:2148`).

UX-DR2: Navigation elements converted to semantic markup must retain current visual styling (`.nav-item`, `.bn-item`, `.nav-drawer-item` classes) — this is a markup/accessibility refactor, not a visual redesign.

UX-DR3: Focus-visible states for the newly-semantic nav elements should follow the existing focus style pattern already used on `<input>` fields (`dashboard.py` lines ~1170, 1263, 1288, 1340) for visual consistency with the rest of the UI.

UX-DR4: The contrast audit (FR4) findings should be recorded per screen and per theme (dark/light), listing the specific CSS color pairs found non-conformant, to feed a future remediation pass.

### FR Coverage Map

FR1: Epic 1 - Wire or remove the SIEM/CEF export UI control
FR2: Epic 1 - Correct F14 geo-blocking documentation to match actual `/action/config` mechanism
FR3: Epic 2 - Convert dashboard nav to semantic, keyboard-operable markup
FR4: Epic 2 - WCAG 2.1 AA contrast audit across all screens/themes
NFR1: Epic 2 - Accessibility standard compliance
NFR2: Epic 2 - No regression on `showScreen()` nav sync
NFR3: Epic 1, Epic 2 - No new frontend framework/build step

## Epic List

### Epic 1: Feature/Documentation Alignment
Operators can trust that every feature described in README.md/PROJECT_STATE.md is either actually reachable from the dashboard UI, or is no longer claimed as delivered — closing the gap between documented and real behavior for SIEM/CEF export and F14 geo-blocking.
**FRs covered:** FR1, FR2

### Epic 2: Accessible Navigation & Contrast Audit
Operators using keyboard-only navigation or assistive technology can operate all three dashboard nav surfaces (desktop, drawer, bottom-nav), and the team has a concrete, per-screen record of every text/background pairing that fails WCAG 2.1 AA contrast, ready to drive a future remediation pass.
**FRs covered:** FR3, FR4, NFR1, NFR2

## Epic 1: Feature/Documentation Alignment

Operators can trust that every feature described in README.md/PROJECT_STATE.md is either actually reachable from the dashboard UI, or is no longer claimed as delivered — closing the gap between documented and real behavior for SIEM/CEF export and F14 geo-blocking.

### Story 1.1: SIEM/CEF export accessible from the dashboard UI

As a SOC operator,
I want a button to export SIEM/CEF threat data directly from the dashboard,
So that I can feed it into my external SIEM without hand-crafting API calls.

**Acceptance Criteria:**

**Given** the operator is on the Sécurité screen
**When** they click a new "Export SIEM/CEF" button
**Then** the browser downloads the export from `GET /action/export/siem?format=json|cef`
**And** the button follows the existing action-button visual pattern (e.g. "📄 Générer rapport IR")
**And** if the API call fails, a clear error message is shown to the operator

### Story 1.2: Correct F14 geo-blocking documentation

As a maintainer/contributor,
I want README.md and PROJECT_STATE.md to accurately describe the geo-blocking mechanism actually used by the dashboard,
So that future contributors don't build against non-existent wiring or waste time debugging orphaned endpoints.

**Acceptance Criteria:**

**Given** README.md and PROJECT_STATE.md currently present `/countries`, `/block/country`, `/unblock/country` as the F14 API path
**When** the documentation is updated
**Then** it accurately describes that the dashboard UI calls `POST /action/config` with a `blocked_countries` array
**And** the dedicated endpoints are documented as existing-but-unused-by-dashboard, rather than presented as the primary path

## Epic 2: Accessible Navigation & Contrast Audit

Operators using keyboard-only navigation or assistive technology can operate all three dashboard nav surfaces (desktop, drawer, bottom-nav), and the team has a concrete, per-screen record of every text/background pairing that fails WCAG 2.1 AA contrast, ready to drive a future remediation pass.

### Story 2.1: Dashboard navigation as accessible semantic markup

As a SOC operator navigating by keyboard or assistive technology,
I want the dashboard's navigation (desktop nav, mobile drawer, bottom-nav) built from semantic, focusable elements,
So that I can switch between screens without a mouse and have my screen reader correctly announce each nav item.

**Acceptance Criteria:**

**Given** the desktop nav, mobile drawer, and bottom-nav currently use `<div onclick=...>` handlers
**When** the navigation markup is converted to `<nav>`/`<button>` (and `role="tablist"`/`role="tab"` where appropriate)
**Then** every nav item is reachable and activatable via Tab + Enter/Space
**And** each nav item has a visible focus-visible style, consistent with existing `<input>` focus styles
**And** the existing `showScreen()` logic and the desktop/drawer/bottom-nav active-state sync continue to work exactly as before (no regression)
**And** current visual styling (`.nav-item`, `.bn-item`, `.nav-drawer-item` classes) is preserved

### Story 2.2: WCAG 2.1 AA contrast audit report

As a product owner,
I want an automated, per-screen contrast audit of the dashboard (dark and light themes),
So that I have a concrete backlog of non-conformant text/background pairs to prioritize for a future remediation pass.

**Acceptance Criteria:**

**Given** the dashboard has 7 screens and 2 themes (dark default, light)
**When** an automated tool (axe-core or Lighthouse) is run against each screen in both themes
**Then** a report lists every text/background color pair that fails WCAG 2.1 AA, with screen, element, and current color values
**And** the report is saved as a project artifact for future remediation planning
**And** no dashboard code is modified as part of this story (audit-only — remediation is separate future work)
