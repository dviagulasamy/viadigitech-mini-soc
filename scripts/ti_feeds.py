#!/usr/bin/env python3
"""
ViaDigiTech SOC — Threat Intelligence feeds
Feodo Tracker (gratuit, sans auth) + AlienVault OTX (optionnel, via OTX_KEY)
Cache local /tmp/soc_ti_cache.json, TTL 1h.
"""
import os
import json
import time
import requests
from datetime import datetime

CACHE_FILE = "/tmp/soc_ti_cache.json"
CACHE_TTL  = 3600   # 1 heure
FEODO_URL  = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
OTX_KEY    = os.environ.get("OTX_KEY", "")
TI_MATCHES_FILE = "/home/ubuntu/secops/ti_matches.json"


# ─────────────────────────────────────────
# Cache Feodo Tracker
# ─────────────────────────────────────────

def _load_cache():
    try:
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE) as f:
                data = json.load(f)
            if time.time() - data.get("ts", 0) < CACHE_TTL:
                return data
    except Exception:
        pass
    return None


def _save_cache(data):
    try:
        data["ts"] = time.time()
        with open(CACHE_FILE, "w") as f:
            json.dump(data, f)
    except Exception:
        pass


def _fetch_feodo():
    """Télécharge la blocklist Feodo Tracker (IPs C2 botnets connus)."""
    try:
        r = requests.get(FEODO_URL, timeout=10)
        ips = set()
        for line in r.text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                ip = line.split()[0]
                if ip:
                    ips.add(ip)
        return ips
    except Exception as e:
        print(f"[TI] Feodo Tracker fetch error: {e}")
        return set()


def _get_feodo_set():
    cache = _load_cache()
    if cache:
        return set(cache.get("feodo", []))
    feodo_ips = _fetch_feodo()
    _save_cache({"feodo": list(feodo_ips)})
    print(f"[TI] Feodo Tracker mis à jour : {len(feodo_ips)} IPs")
    return feodo_ips


# ─────────────────────────────────────────
# Lookup AlienVault OTX (optionnel)
# ─────────────────────────────────────────

def _check_otx(ip):
    """Retourne (pulse_count, tags[]) ou (0, []) si pas de clé / erreur."""
    if not OTX_KEY:
        return 0, []
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers={"X-OTX-API-KEY": OTX_KEY},
            timeout=5
        )
        if r.status_code == 200:
            data = r.json()
            pulses = data.get("pulse_info", {})
            count  = pulses.get("count", 0)
            tags   = []
            for p in pulses.get("pulses", [])[:3]:
                tags.extend(p.get("tags", []))
            return count, list(set(tags))[:5]
    except Exception:
        pass
    return 0, []


# ─────────────────────────────────────────
# API publique
# ─────────────────────────────────────────

def check_ip_ti(ip):
    """
    Vérifie une IP contre les feeds TI disponibles.
    Retourne {matched, sources, tags, score_bonus}
    score_bonus : points à ajouter au score composite
    """
    sources = []
    tags    = []

    feodo_set = _get_feodo_set()
    if ip in feodo_set:
        sources.append("Feodo Tracker")
        tags.extend(["botnet", "C2"])

    otx_count, otx_tags = _check_otx(ip)
    if otx_count > 0:
        sources.append(f"AlienVault OTX ({otx_count} pulses)")
        tags.extend(otx_tags)

    return {
        "matched":      bool(sources),
        "sources":      sources,
        "tags":         list(set(tags)),
        "score_bonus":  25 if sources else 0,
    }


def persist_ti_match(ip, ti_result):
    """Enregistre un match TI dans ti_matches.json pour affichage dashboard."""
    if not ti_result.get("matched"):
        return
    try:
        data = {}
        if os.path.exists(TI_MATCHES_FILE):
            with open(TI_MATCHES_FILE) as f:
                data = json.load(f)
        data[ip] = {
            "sources": ti_result["sources"],
            "tags":    ti_result["tags"],
            "ts":      datetime.now().strftime("%Y-%m-%d %H:%M"),
        }
        with open(TI_MATCHES_FILE, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[TI] persist error: {e}")


def load_ti_matches():
    """Charge le fichier des matchs TI persistés."""
    try:
        if os.path.exists(TI_MATCHES_FILE):
            with open(TI_MATCHES_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    return {}


if __name__ == "__main__":
    import sys
    ip = sys.argv[1] if len(sys.argv) > 1 else "194.165.16.72"
    result = check_ip_ti(ip)
    print(f"TI check {ip}: {result}")
