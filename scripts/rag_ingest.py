#!/usr/bin/env python3
"""
ViaDigiTech SOC — Ingestion des rapports dans AnythingLLM (RAG)
Exécuté après report.py à 7h UTC pour alimenter la mémoire longue durée.
"""

import os
import re
import json
import requests
from datetime import datetime

ANYTHINGLLM_URL  = "http://localhost:3101"
ANYTHINGLLM_KEY  = os.environ.get("ANYTHINGLLM_KEY", "")
WORKSPACE_SLUG   = "viadigitech-soc"
AUDIT_LOG        = "/home/ubuntu/secops/audit_actions.csv"
DETECTOR_LOG     = "/home/ubuntu/secops/detector.log"
REPORT_HTML      = "/home/ubuntu/secops/last_report.html"

def api(method, path, **kwargs):
    r = getattr(requests, method)(
        f"{ANYTHINGLLM_URL}{path}",
        headers={"Authorization": f"Bearer {ANYTHINGLLM_KEY}", "Content-Type": "application/json"},
        timeout=30,
        **kwargs
    )
    return r.json()

def chat(message):
    """
    RAG manuel : récupère le contexte depuis AnythingLLM puis interroge Ollama directement.
    Contourne les timeouts Node.js internes d'AnythingLLM.
    """
    # Récupérer les documents du workspace comme contexte
    r = requests.get(
        f"{ANYTHINGLLM_URL}/api/v1/workspace/{WORKSPACE_SLUG}",
        headers={"Authorization": f"Bearer {ANYTHINGLLM_KEY}"},
        timeout=15
    )
    docs = r.json().get("workspace", [{}])[0].get("documents", [])
    context_parts = []
    for doc in docs[:5]:  # top 5 docs
        metadata = doc.get("metadata", "{}")
        try:
            meta = json.loads(metadata) if isinstance(metadata, str) else metadata
            title = meta.get("title", doc.get("filename", ""))
        except:
            title = doc.get("filename", "")
        if title:
            context_parts.append(f"[{title}]")

    # Contexte réduit — 10 lignes max pour rester rapide sur CPU
    context = ""
    if os.path.exists(AUDIT_LOG):
        with open(AUDIT_LOG) as f:
            lines = f.readlines()[-10:]
        context += "Audit:\n" + "".join(lines)
    if os.path.exists(DETECTOR_LOG):
        with open(DETECTOR_LOG) as f:
            lines = f.readlines()[-5:]
        context += "\nDetecteur:\n" + "".join(lines)

    prompt = f"SOC ViaDigiTech. Réponds en 3 phrases max en français.\n{context}\nQuestion: {message}"

    r = requests.post(
        "http://localhost:11434/api/generate",
        json={"model": "llama3.2:3b", "prompt": prompt, "stream": False},
        timeout=180
    )
    return r.json().get("response", "").strip()

def html_to_text(html):
    """Convertit HTML en texte brut pour l'ingestion RAG."""
    text = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL)
    text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL)
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def get_audit_summary():
    """Résumé textuel des actions d'audit des dernières 24h."""
    if not os.path.exists(AUDIT_LOG):
        return "Aucune action d'audit enregistrée."
    with open(AUDIT_LOG) as f:
        lines = f.readlines()[-50:]
    today = datetime.now().strftime("%Y-%m-%d")
    today_lines = [l for l in lines[1:] if l.startswith(today)]
    if not today_lines:
        return "Aucune action d'audit aujourd'hui."
    bans = [l for l in today_lines if "BAN" in l]
    return f"{len(today_lines)} actions aujourd'hui dont {len(bans)} bans automatiques.\n" + "".join(today_lines[:20])

def upload_document(title, content):
    """Upload un document texte dans AnythingLLM."""
    # Étape 1 : upload du fichier texte
    files = {
        "file": (f"{title}.txt", content.encode("utf-8"), "text/plain")
    }
    r = requests.post(
        f"{ANYTHINGLLM_URL}/api/v1/document/raw-text",
        headers={"Authorization": f"Bearer {ANYTHINGLLM_KEY}"},
        json={"textContent": content, "metadata": {"title": title}},
        timeout=60
    )
    if r.status_code != 200:
        print(f"[RAG] Erreur upload : {r.status_code} {r.text[:100]}")
        return None
    data = r.json()
    doc_location = data.get("documents", [{}])[0].get("location")
    return doc_location

def embed_in_workspace(doc_location):
    """Intègre le document dans le workspace SOC."""
    r = api("post", f"/api/v1/workspace/{WORKSPACE_SLUG}/update-embeddings",
            json={"adds": [doc_location], "deletes": []})
    return r

def main():
    if not ANYTHINGLLM_KEY:
        print("[RAG] ANYTHINGLLM_KEY manquant — arrêt.")
        return

    now = datetime.now()
    date_str = now.strftime("%Y-%m-%d")
    print(f"[{now:%H:%M:%S}] Ingestion RAG dans AnythingLLM...")

    documents = []

    # 1. Rapport HTML du jour (converti en texte)
    if os.path.exists(REPORT_HTML):
        with open(REPORT_HTML) as f:
            html = f.read()
        text = html_to_text(html)
        title = f"Rapport SOC {date_str}"
        documents.append((title, f"=== {title} ===\n\n{text}"))
        print(f"[RAG] Rapport HTML préparé ({len(text)} chars)")

    # 2. Résumé audit du jour
    audit_summary = get_audit_summary()
    documents.append((
        f"Audit actions {date_str}",
        f"=== Journal d'audit SOC {date_str} ===\n\n{audit_summary}"
    ))

    # 3. Log détecteur du jour
    if os.path.exists(DETECTOR_LOG):
        with open(DETECTOR_LOG) as f:
            det_lines = f.readlines()[-100:]
        today_det = [l for l in det_lines if now.strftime("%H:") in l or "BAN" in l or "Alerte" in l]
        if today_det:
            documents.append((
                f"Détecteur log {date_str}",
                f"=== Log détecteur {date_str} ===\n\n{''.join(today_det)}"
            ))

    # Upload et embedding
    success = 0
    for title, content in documents:
        print(f"[RAG] Upload : {title}...")
        loc = upload_document(title, content)
        if loc:
            result = embed_in_workspace(loc)
            print(f"[RAG] ✓ Intégré dans workspace '{WORKSPACE_SLUG}' : {title}")
            success += 1
        else:
            print(f"[RAG] ✗ Échec : {title}")

    print(f"[{now:%H:%M:%S}] RAG terminé — {success}/{len(documents)} documents ingérés.")

if __name__ == "__main__":
    main()
