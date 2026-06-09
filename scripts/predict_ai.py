#!/usr/bin/env python3
"""
ViaDigiTech SOC — Analyse prédictive IA (lundi 07h00 via cron)
Analyse les patterns de la semaine passée, génère des recommandations proactives.
Stocke le résultat dans last_ai_summary.json sous la clé 'predictive'.
"""
import os
import csv
import json
import requests
from datetime import datetime, timedelta
from collections import Counter, defaultdict

AUDIT_LOG      = "/home/ubuntu/secops/audit_actions.csv"
AI_SUMMARY     = "/home/ubuntu/secops/last_ai_summary.json"
OLLAMA_URL     = "http://localhost:11434/api/generate"


def read_audit_7d():
    since = datetime.now() - timedelta(days=7)
    bans, watches = 0, 0
    ips  = Counter()
    countries = Counter()
    hours = Counter()

    if not os.path.exists(AUDIT_LOG):
        return {}

    with open(AUDIT_LOG) as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 4 or row[0] == "timestamp":
                continue
            try:
                ts = datetime.fromisoformat(row[0][:19])
            except Exception:
                continue
            if ts < since:
                continue
            ip, action, reason = row[1].strip(), row[2].strip(), row[4] if len(row) > 4 else ""
            if "BAN" in action:
                bans += 1
                ips[ip] += 1
                hours[ts.hour] += 1
                # Extraire pays depuis la raison si disponible
                for part in reason.split(","):
                    part = part.strip()
                    if len(part) == 2 and part.isupper():
                        countries[part] += 1
            elif "SURVEILLE" in action or "WATCH" in action:
                watches += 1

    return {
        "bans": bans,
        "watches": watches,
        "top_ips": ips.most_common(5),
        "top_countries": countries.most_common(5),
        "peak_hours": hours.most_common(3),
    }


def build_prompt(data):
    top3_ips = ", ".join(f"{ip}({n}x)" for ip, n in data.get("top_ips", [])[:3])
    top3_cc  = ", ".join(f"{cc}({n})" for cc, n in data.get("top_countries", [])[:3])
    peak_h   = ", ".join(f"{h}h({n}x)" for h, n in data.get("peak_hours", [])[:3])

    return (
        f"Tu es un expert en cybersécurité SOC. Analyse les données de la semaine passée:\n"
        f"- Total bans SSH: {data.get('bans', 0)}\n"
        f"- IPs surveillées: {data.get('watches', 0)}\n"
        f"- Top attaquants: {top3_ips or 'aucun'}\n"
        f"- Pays sources: {top3_cc or 'inconnu'}\n"
        f"- Heures de pointe: {peak_h or 'aucune tendance'}\n\n"
        f"Génère une analyse prédictive pour la semaine à venir:\n"
        f"1. Tendances et risques identifiés (1-2 phrases)\n"
        f"2. Vecteurs d'attaque émergents à surveiller (1-2 phrases)\n"
        f"3. 3 recommandations concrètes pour renforcer la posture de sécurité\n\n"
        f"Format: JSON valide avec les clés 'tendances', 'vecteurs', 'recommandations' (liste de 3 strings).\n"
        f"Réponds en français uniquement. Sois précis et actionnable."
    )


def main():
    now = datetime.now()
    print(f"[Predict] Analyse prédictive IA — {now.strftime('%d/%m/%Y %H:%M')}")

    data = read_audit_7d()
    if not data:
        print("[Predict] Pas de données audit disponibles.")
        return

    prompt = build_prompt(data)

    try:
        r = requests.post(OLLAMA_URL, json={
            "model": "qwen2.5:3b",
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {"num_predict": 400, "temperature": 0.4}
        }, timeout=120)

        if r.status_code == 200:
            raw = r.json().get("response", "").strip()
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = {
                    "tendances": raw[:200],
                    "vecteurs": "",
                    "recommandations": []
                }

            result = {
                "ts":       now.strftime("%Y-%m-%d %H:%M"),
                "week_bans": data.get("bans", 0),
                "week_watches": data.get("watches", 0),
                **parsed
            }
        else:
            result = {
                "ts": now.strftime("%Y-%m-%d %H:%M"),
                "error": f"Ollama HTTP {r.status_code}"
            }
    except Exception as e:
        print(f"[Predict] Ollama error: {e}")
        result = {"ts": now.strftime("%Y-%m-%d %H:%M"), "error": str(e)}

    # Merge dans last_ai_summary.json
    summary = {}
    if os.path.exists(AI_SUMMARY):
        try:
            with open(AI_SUMMARY) as f:
                summary = json.load(f)
        except Exception:
            pass

    summary["predictive"] = result

    with open(AI_SUMMARY, "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(f"[Predict] Résultat sauvegardé dans {AI_SUMMARY}")
    reco = result.get("recommandations", [])
    if reco:
        for i, r in enumerate(reco, 1):
            print(f"  {i}. {r}")


if __name__ == "__main__":
    main()
