# ViaDigiTech Mini-SOC — Roadmap V8.0
> Fonctionnalités avancées — Interface moderne

---

## Vision V8.0

Transformer le Mini-SOC d'un dashboard de monitoring statique en une **plateforme SecOps interactive temps réel**, avec une interface comparable à Datadog Security ou Splunk SIEM — mais légère, locale et IA-native.

---

## 🔴 P0 — Maintenance critique (à faire maintenant)

### 1. Logrotate des logs SOC
```
/home/ubuntu/secops/*.log {
    daily
    rotate 14
    compress
    missingok
    notifempty
}
```
**Impact :** Évite saturation disque (83% actuellement, seuil critique 88%)

### 2. Validation JS automatique post-génération
Dans `dashboard.py`, après écriture du fichier HTML :
```python
import subprocess
result = subprocess.run(['node', '--check', OUTPUT_FILE], capture_output=True)
if result.returncode != 0:
    print(f"[Dashboard] ERREUR JS : {result.stderr.decode()}")
```
**Impact :** Détecte les bugs JS avant la prochaine visite utilisateur

### 3. Fichier `.env` sécurisé (chmod 600)
Migrer les clés du crontab vers `/home/ubuntu/secops/.env` :
```bash
SOC_ACTIONS_KEY=...
ABUSEIPDB_KEY=...
ANYTHINGLLM_KEY=...
```
Et dans le crontab : `source /home/ubuntu/secops/.env`

---

## 🟠 P1 — Fonctionnalités haute valeur

### 4. Dashboard temps réel via SSE (Server-Sent Events)
**Actuellement :** Refresh complet toutes les 5 min (rechargement page entier)  
**Proposition :** Endpoint `/stream` dans actions.py qui pousse les updates en SSE

```python
@app.route("/stream")
def stream():
    def generate():
        while True:
            data = collect_live_metrics()
            yield f"data: {json.dumps(data)}\n\n"
            time.sleep(30)
    return Response(generate(), mimetype='text/event-stream')
```
Le dashboard JS se connecte au stream et met à jour uniquement les valeurs qui changent — **sans rechargement de page**.  
**Impact :** UX radicalement meilleure, perte de contexte éliminée

### 5. Alertes push Telegram / Slack
En complément du mail, envoyer les alertes critiques sur Telegram (bot gratuit) :
```python
requests.post(f"https://api.telegram.org/bot{TOKEN}/sendMessage",
    json={"chat_id": CHAT_ID, "text": f"🚨 BAN_AUTO {ip} — score {score}%", "parse_mode": "HTML"})
```
**Impact :** Alertes sur mobile en moins de 5 secondes, même sans email

### 6. Mode sombre / clair + thème personnalisable
Toggle CSS dans le dashboard (classes `theme-dark` / `theme-light` sur `body`).  
Stocké en `localStorage`. Variables CSS déjà en place (`--bg`, `--accent`...) — changement trivial.  
**Impact :** Confort utilisateur en conditions d'éclairage variées

### 7. Export CSV / JSON des données depuis le dashboard
Boutons d'export dans chaque tableau :
- Top IPs → `soc_top_ips_YYYYMMDD.csv`
- Audit log → `soc_audit_YYYYMMDD.csv`
- Timeline → `soc_timeline_YYYYMMDD.json`

```javascript
function exportTable(tableId, filename) {
    const rows = [...document.querySelectorAll(`#${tableId} tr`)];
    const csv = rows.map(r => [...r.cells].map(c => c.textContent).join(',')).join('\n');
    const blob = new Blob([csv], {type:'text/csv'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
    a.download = filename; a.click();
}
```
**Impact :** Facilite le reporting vers management / client

---

## 🟡 P2 — Interface moderne avancée

### 8. Vue "Analyst Workbench" — Écran d'investigation IP
Nouvel écran dédié à l'investigation d'une IP spécifique :
- Toutes les tentatives sur les 7 derniers jours
- Score AbuseIPDB en temps réel
- Géolocalisation détaillée + AS info
- Timeline des actions (BAN/UNBAN/WHITELIST)
- Bouton "Rapport IA sur cette IP" → `/analyze`
- Bouton Ban / Whitelist direct

**Déclenchement :** Clic sur n'importe quelle IP dans le dashboard → ouvre le workbench

### 9. Graphiques interactifs avec zoom et drill-down
Remplacer Chart.js par **Apache ECharts** (plus puissant, léger) :
- Zoom sur un segment de timeline en cliquant-glissant
- Drill-down heatmap : cliquer sur une cellule → voir les IPs de cette heure
- Graphique CPU : annoter les pics avec les événements correspondants (ban, alerte)
- **Tooltip enrichi** : hover sur une IP dans la carte → mini-card avec stats

### 10. Tableau de bord "KPI SOC" avec tendances
Section dédiée sur Vue globale :

| KPI | Valeur | Tendance 7j |
|-----|--------|-------------|
| MTTD (temps détection) | ~7.5 min | ↓ amélioration |
| Taux couverture ban | 63% | → stable |
| Faux positifs IA | 2% | ↓ |
| IPs récidivistes | 8% | ↑ attention |

Calculé depuis `audit_actions.csv` + `auth.log`.

### 11. Mode "Incident Response" — Vue urgence
Bouton `⚡ Mode IR` dans la topbar : réduit le dashboard à l'essentiel en plein écran :
- Threat score géant centré
- Top 5 IPs actives avec boutons ban en un clic
- Timeline des 30 dernières minutes
- Fond rouge si menace ÉLEVÉE
- Idéal sur TV/grand écran en salle SOC

### 12. Annotations sur les graphiques
Permettre à l'opérateur d'ajouter des notes sur la timeline :
```json
{ "ts": "2026-06-08T14:30", "note": "Maintenance programmée", "author": "David" }
```
Stockées dans `annotations.json`, affichées comme marqueurs verticaux sur les graphiques.

### 13. Recherche globale ⌘K / Ctrl+K
Barre de recherche universelle style Spotlight :
- Rechercher une IP dans tous les écrans
- Naviguer vers un écran par nom
- Lancer une analyse IA directement
- Shortcut clavier `Ctrl+K`

```javascript
document.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        openGlobalSearch();
    }
});
```

---

## 🔵 P3 — Évolutions stratégiques

### 14. Multi-serveur : fédération SOC
Surveiller plusieurs VPS depuis un dashboard unique.  
Chaque serveur expose un endpoint `/metrics` JSON.  
Le dashboard central agrège et compare :
- Carte géo des attaques multi-serveur
- Détection d'attaques coordonnées (même /24 sur plusieurs serveurs)
- Score de menace global vs par serveur

### 15. IA Adaptive — Mémoire des patterns
Actuellement : chaque run d'Ollama est sans contexte.  
Proposition : constituer un fichier `threat_patterns.json` enrichi au fil du temps :
```json
{
  "45.148.10.0/24": { "first_seen": "2026-04-05", "bans": 47, "label": "scanner industriel" },
  "port_22_brute": { "pattern": "Invalid user root|admin|ubuntu", "frequency": "high" }
}
```
L'IA Ollama reçoit ce contexte dans son prompt → **décisions plus précises, moins de faux positifs**.

### 16. Rapport hebdomadaire + mensuel
Compléter le rapport quotidien avec :
- **Hebdo (lundi 7h)** : comparatif semaine N vs N-1, top 10 IPs, tendances
- **Mensuel (1er du mois)** : bilan complet, graphiques d'évolution, recommandations IA
- Format PDF optionnel via `weasyprint`

### 17. API publique documentée (Swagger UI)
Documenter l'API actions.py avec Flask-RESTX ou Flasgger :
- Interface Swagger auto-générée sur `/action/docs`
- Permet intégration n8n, scripts externes, webhooks
- Rate limiting par clé API (flask-limiter)

### 18. Progressive Web App (PWA)
Transformer le dashboard en PWA installable sur mobile :
```json
// manifest.json
{
  "name": "ViaDigiTech SOC",
  "short_name": "SOC",
  "theme_color": "#0d1117",
  "display": "standalone",
  "start_url": "/soc/"
}
```
+ Service Worker pour cache offline  
→ Dashboard installable sur l'écran d'accueil iPhone/Android, notification push natives

---

## Priorités recommandées

```
MAINTENANT    → P0 : logrotate, validation JS, .env
CETTE SEMAINE → P1 : SSE temps réel, Telegram, export CSV
CE MOIS       → P2 : Workbench IP, recherche Ctrl+K, KPIs SOC
TRIMESTRE     → P3 : multi-serveur, IA adaptive, PWA
```

---

## Effort estimé par feature

| Feature | Effort | Valeur |
|---------|--------|--------|
| Logrotate | 15 min | ★★★★★ |
| Validation JS auto | 10 min | ★★★★★ |
| Telegram alertes | 1h | ★★★★★ |
| Export CSV | 2h | ★★★★ |
| SSE temps réel | 4h | ★★★★★ |
| Workbench IP | 3h | ★★★★★ |
| Recherche Ctrl+K | 2h | ★★★★ |
| KPIs SOC | 3h | ★★★★ |
| Mode IR plein écran | 2h | ★★★★ |
| ECharts + zoom | 4h | ★★★ |
| Annotations | 3h | ★★★ |
| PWA | 2h | ★★★ |
| Multi-serveur | 8h+ | ★★★ |
| IA adaptive | 6h+ | ★★★ |
