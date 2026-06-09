#!/usr/bin/env python3
"""
ViaDigiTech SOC — Health Check automatique (toutes les 30 min via cron)
Vérifie que tous les composants du SOC fonctionnent correctement.
Écrit /home/ubuntu/secops/soc_health.json lu par le dashboard.
"""
import os
import json
import subprocess
import time
import requests
from datetime import datetime

HEALTH_FILE    = "/home/ubuntu/secops/soc_health.json"
DETECTOR_LOG   = "/home/ubuntu/secops/detector.log"
ABUSEIPDB_KEY  = os.environ.get("ABUSEIPDB_KEY", "")


def check_ollama():
    """Vérifie qu'Ollama répond sur son API (sans inférence = rapide)."""
    try:
        start = time.time()
        r = requests.get("http://localhost:11434/api/tags", timeout=5)
        latency_ms = int((time.time() - start) * 1000)
        return {"ok": r.status_code == 200, "latency_ms": latency_ms}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def check_fail2ban():
    try:
        r = subprocess.run(
            ["sudo", "fail2ban-client", "status"],
            capture_output=True, text=True, timeout=5
        )
        return {"ok": r.returncode == 0}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def check_disk_logs():
    try:
        stat = os.statvfs("/var/log")
        free_mb = stat.f_bavail * stat.f_frsize // (1024 * 1024)
        return {"ok": free_mb > 100, "free_mb": free_mb}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def check_detector_last_run():
    """Vérifie que detector.py s'est exécuté il y a moins de 20 minutes (via detector.log)."""
    try:
        if not os.path.exists(DETECTOR_LOG):
            return {"ok": False, "error": "detector.log introuvable"}
        age_minutes = int((time.time() - os.path.getmtime(DETECTOR_LOG)) / 60)
        return {"ok": age_minutes < 20, "minutes_ago": age_minutes}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def check_abuseipdb():
    if not ABUSEIPDB_KEY:
        return {"ok": True, "skipped": True}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": "1.1.1.1", "maxAgeInDays": "90"},
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            timeout=5
        )
        return {"ok": r.status_code == 200}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def check_soc_api():
    try:
        r = requests.get("http://localhost:8022/config", timeout=3)
        return {"ok": r.status_code in (200, 403)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def main():
    checks = {
        "ollama":    check_ollama(),
        "fail2ban":  check_fail2ban(),
        "disk_logs": check_disk_logs(),
        "detector":  check_detector_last_run(),
        "abuseipdb": check_abuseipdb(),
        "soc_api":   check_soc_api(),
    }

    critical = ["fail2ban", "detector", "soc_api"]
    warn     = ["ollama", "disk_logs"]

    crit_ko = [k for k in critical if not checks[k].get("ok", False) and not checks[k].get("skipped", False)]
    warn_ko = [k for k in warn     if not checks[k].get("ok", False) and not checks[k].get("skipped", False)]

    overall = "CRIT" if crit_ko else ("WARN" if warn_ko else "OK")

    result = {
        "ts":      datetime.now().strftime("%Y-%m-%d %H:%M"),
        "overall": overall,
        "checks":  checks,
    }

    with open(HEALTH_FILE, "w") as f:
        json.dump(result, f, indent=2)

    ko_list = crit_ko + warn_ko
    suffix  = f" — KO: {', '.join(ko_list)}" if ko_list else " — Tous les checks OK"
    print(f"[{datetime.now():%H:%M:%S}] SOC Health [{overall}]{suffix}")


if __name__ == "__main__":
    main()
