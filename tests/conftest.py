"""
Shared pytest fixtures for testing scripts/dashboard.py without modifying it.

dashboard.py hardcodes absolute production paths (/home/ubuntu/secops/*,
/var/www/..., /var/log/auth.log) both as module-level constants and as
inline string literals inside functions. Rather than refactoring the
production module for dependency injection (out of scope), these fixtures
redirect every known hardcoded path to a temp fixture file: named
constants are monkeypatched on the already-imported module object (Python
looks up globals at call time, so this works), and inline literals are
caught by wrapping builtins.open with a lookup table.
"""
import builtins
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

# Paths referenced as inline string literals (not module-level constants)
# inside dashboard.py functions — must be caught via the open() wrapper.
INLINE_HARDCODED_PATHS = {
    "/home/ubuntu/secops/soc_config.json": "soc_config.json",
    "/home/ubuntu/secops/soc_health.json": "soc_health.json",
    "/home/ubuntu/secops/annotations.json": "annotations.json",
}


@pytest.fixture
def secops_fixtures(tmp_path):
    """Minimal valid fixture files standing in for /home/ubuntu/secops/*."""
    json_files = {
        "soc_config.json": {
            "warn_cpu": 70, "crit_cpu": 85,
            "warn_ram": 75, "crit_ram": 90,
            "warn_disk": 75, "crit_disk": 88,
            "blocked_countries": [],
        },
        "soc_health.json": {"status": "OK", "checks": {}},
        "annotations.json": [],
        "ti_matches.json": {},
        "last_ai_summary.json": {},
        "geo_cache.json": {},
    }
    for name, content in json_files.items():
        (tmp_path / name).write_text(json.dumps(content), encoding="utf-8")

    (tmp_path / "audit_actions.csv").write_text("ts,ip,action,score,reason\n", encoding="utf-8")
    (tmp_path / "detector.log").write_text("", encoding="utf-8")
    (tmp_path / "metrics_history.csv").write_text("ts,cpu,ram,disk\n", encoding="utf-8")

    return tmp_path


@pytest.fixture
def dashboard(secops_fixtures, monkeypatch, tmp_path):
    """Import dashboard.py with every hardcoded path redirected to fixtures."""
    monkeypatch.setattr(os, "makedirs", lambda *a, **k: None)

    # os.uname() is POSIX-only; dashboard.py assumes it always exists (true
    # in production on Ubuntu). Stub it so the suite also runs on Windows.
    if not hasattr(os, "uname"):
        fake_uname = SimpleNamespace(
            sysname="Linux", nodename="test-host", release="", version="", machine=""
        )
        monkeypatch.setattr(os, "uname", lambda: fake_uname, raising=False)

    real_open = builtins.open

    def fake_open(file, *args, **kwargs):
        target = INLINE_HARDCODED_PATHS.get(str(file))
        if target:
            return real_open(secops_fixtures / target, *args, **kwargs)
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fake_open)

    sys.modules.pop("dashboard", None)
    import dashboard as dashboard_module

    dashboard_module.OUTPUT_FILE = str(tmp_path / "index.html")
    dashboard_module.MANIFEST_PATH = str(tmp_path / "manifest.json")
    dashboard_module.AUDIT_LOG = str(secops_fixtures / "audit_actions.csv")
    dashboard_module.DETECTOR_LOG = str(secops_fixtures / "detector.log")
    dashboard_module.AUTH_LOG = str(secops_fixtures / "detector.log")
    dashboard_module.AI_SUMMARY = str(secops_fixtures / "last_ai_summary.json")
    dashboard_module.METRICS_CSV = str(secops_fixtures / "metrics_history.csv")
    dashboard_module.GEO_CACHE = str(secops_fixtures / "geo_cache.json")
    dashboard_module.TI_MATCHES_FILE = str(secops_fixtures / "ti_matches.json")

    return dashboard_module
