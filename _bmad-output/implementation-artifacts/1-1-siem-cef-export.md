# Story 1.1: SIEM/CEF Export in Dashboard UI

Status: ready-for-dev

<!-- Note: Validation is optional. Run validate-create-story for quality check before dev-story. -->

## Story

As a SOC operator,
I want to export SIEM/CEF threat data directly from the dashboard,
so that I can feed it into my external SIEM without hand-crafting API calls.

## Acceptance Criteria

1. Given the operator is on the Sécurité screen, when the page loads, then two export buttons are visible — "⬇ Export SIEM (JSON)" and "⬇ Export CEF" — styled identically to the existing "⬇ Export CSV" buttons already on that screen.
2. Given the operator clicks "⬇ Export SIEM (JSON)", when the request succeeds, then the browser downloads a file from `GET /action/export/siem?format=json` (with the `X-SOC-Key` header attached), named `soc_events.json`.
3. Given the operator clicks "⬇ Export CEF", when the request succeeds, then the browser downloads the file the server already names via `Content-Disposition: attachment;filename=soc_events.cef`.
4. Given the API call fails, when the response is 401/403, then the stored key is cleared and a toast error is shown, matching the exact behavior of the existing `apiCall()` helper. Given any other failure (network error, 5xx), then a toast error is shown (`showToast(..., false)`).
5. Given no API key is stored yet, when the operator clicks either export button, then they are prompted for the key via the existing `showPromptModal` flow, and the export proceeds automatically once the key is provided.

## Tasks / Subtasks

- [ ] Task 1: Add the two export buttons to the Sécurité screen (AC: #1)
  - [ ] Subtask 1.1: Add both buttons next to the "Journal d'audit" card header (`dashboard.py` ~line 1941-1945, same card as the existing `exportTable('audit-table','audit_log')` button), reusing the exact same inline style (`class="btn-primary" style="font-size:11px;padding:4px 12px"`).
- [ ] Task 2: Implement a dedicated `exportSiem(format)` JS function — do NOT reuse `apiCall()` (AC: #2, #3, #4, #5)
  - [ ] Subtask 2.1: Read the key the same way `apiCall()` does: `localStorage.getItem('soc_api_key')||sessionStorage.getItem('soc_api_key')`.
  - [ ] Subtask 2.2: If no key, call `showPromptModal(...)` exactly like `apiCall()` does, then retry the export once the key is provided.
  - [ ] Subtask 2.3: `fetch(ACTIONS_API+'/export/siem?format='+format, {headers:{'X-SOC-Key':key}})`.
  - [ ] Subtask 2.4: On 401/403: `sessionStorage.removeItem('soc_api_key')`, `showToast('Clé invalide — vérifiez dans les Paramètres', false)` (identical message to `apiCall()`).
  - [ ] Subtask 2.5: On success: `response.blob()` → `URL.createObjectURL(blob)` → click a temporary `<a download>` element → `URL.revokeObjectURL(url)`. Filename: reuse the server's `Content-Disposition` filename for CEF; default to `soc_events.json` for the JSON format (server does not set `Content-Disposition` on that branch).
  - [ ] Subtask 2.6: On any other failure: `showToast('Erreur export SIEM/CEF', false)`.
- [ ] Task 3: Tests (AC: all)
  - [ ] Subtask 3.1: New test file `tests/test_story_1_1_siem_export.py` using the existing `dashboard` fixture (`tests/conftest.py`) — call `dashboard.build_html()` and assert the returned HTML contains both new buttons (by their `onclick="exportSiem('json')"` / `onclick="exportSiem('cef')"` calls or equivalent).
  - [ ] Subtask 3.2: Assert the generated `<script>` block defines a function named `exportSiem`.

## Dev Notes

- **This is a UI-wiring story only.** The backend endpoint already exists and works: `GET /action/export/siem?format=json|cef` (`scripts/actions.py:579-623`, `@require_key` decorated — needs the `X-SOC-Key` header like every other action endpoint). **Do not modify `actions.py`.**
- **Do not reuse `apiCall()` (`dashboard.py:944`) as-is** — it is hardcoded to `method:'POST'` with a JSON body/response. `/export/siem` is a `GET`, and its `cef` format response is `text/plain` with `Content-Disposition: attachment`, not JSON. Write a small dedicated `exportSiem(format)` function, reusing only the key-retrieval / prompt-if-missing / 401-handling *conventions* from `apiCall()` — not the function itself.
- **Blob-download is required, not a plain link**: because the request needs a custom `X-SOC-Key` header, a plain `<a href="...">` won't work (browser navigation can't attach custom headers). Pattern: `fetch()` → `response.blob()` → `URL.createObjectURL(blob)` → programmatically click a temporary `<a download>` → `URL.revokeObjectURL(url)`.
- Exact reference patterns already in the codebase to copy conventions from (read these before implementing):
  - Button style/placement: `dashboard.py:1941-1949` ("Journal d'audit" card, screen `screen-security`, existing "⬇ Export CSV" button at line 1944).
  - Key retrieval + prompt-if-missing + 401/403 handling: `dashboard.py:944-961` (`apiCall`).
  - GET fetch with `X-SOC-Key` header, no JSON body: `dashboard.py:3094-3105` (`refreshLogs`).
  - Toast convention: `showToast(msg, true|false)`, used throughout (e.g. `dashboard.py:3089-3090`).
- `ACTIONS_API` (Python constant `"/action"`, `dashboard.py:49`) is already interpolated into the generated JS via f-string (see `dashboard.py:955`); reuse the same `{ACTIONS_API}` interpolation for the new fetch call so it stays consistent if the mount path ever changes.
- NFR3 (epics.md): no new frontend framework/build step — plain JS inside the existing f-string `<script>` block in `build_html()`, exactly like the rest of the file.
- **⚠️ CRITICAL — f-string brace escaping**: the entire `<script>` block (`dashboard.py` ~1027-3285) is built inside a Python f-string. Every literal `{` and `}` in the JS (object literals, function bodies, template literals, etc.) must be **doubled** (`{{` / `}}`), e.g. `async function blockASN(asn){{...}}` (see `dashboard.py:3086`). Writing normal single-brace JS here will break the Python f-string (either a `SyntaxError` at generation time or wrongly-interpreted interpolation). Only genuine Python interpolations (like `{ACTIONS_API}`) use single braces.

### Project Structure Notes

- Single production file touched: `scripts/dashboard.py` — buttons go in the `screen-security` HTML block (~line 1911-1959), the `exportSiem()` function goes in the existing `<script>` block alongside `apiCall`/`refreshLogs`/etc.
- No new files needed for the implementation. For tests, add a new file `tests/test_story_1_1_siem_export.py` (don't grow `tests/test_dashboard_smoke.py` — keep test files mapped 1:1 to stories for traceability) using the `dashboard` fixture already provided by `tests/conftest.py`.
- Test environment note: `tests/conftest.py`'s `dashboard` fixture redirects every hardcoded `/home/ubuntu/secops/*` path to temp fixtures and imports `scripts/dashboard.py` cleanly — call `dashboard.build_html()` directly, no live Flask/`actions.py` process is needed or exercised by these tests (they check generated markup/JS text, not live network calls).

### References

- [Source: scripts/actions.py:579-623] `/export/siem` endpoint implementation (JSON/CEF formats, `@require_key`)
- [Source: scripts/dashboard.py:1931-1949] Sécurité screen "Journal d'audit" card, existing "⬇ Export CSV" button
- [Source: scripts/dashboard.py:944-961] `apiCall()` — key retrieval / prompt / 401 handling conventions to mirror
- [Source: scripts/dashboard.py:3094-3105] `refreshLogs()` — GET fetch with `X-SOC-Key` header pattern to mirror
- [Source: _bmad-output/planning-artifacts/epics.md#Story 1.1] Original story requirements
- [Source: _bmad-output/planning-artifacts/dashboard-ux-ui-audit-2026-07-20.md#2] Original audit finding (orphaned SIEM/CEF endpoint, 0 occurrences of "SIEM"/"CEF" in dashboard.py before this story)
- [Source: tests/conftest.py] `dashboard` pytest fixture used for testing generated HTML/JS

## Dev Agent Record

### Agent Model Used

### Debug Log References

### Completion Notes List

### File List
