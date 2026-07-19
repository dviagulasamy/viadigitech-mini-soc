# Audit UX/UI & alignement fonctionnel — Dashboard SOC (`scripts/dashboard.py`)

> Artefact BMAD — planning-artifacts. Complète `project-analysis.md` (audit d'architecture générale) par un audit ciblé frontend, mené via agent Explore + grille de lecture design (typographie, couleur/thème, motion, composition spatiale, arrière-plans/détails visuels, accessibilité).

## Résumé exécutif

Les 7 écrans documentés existent réellement et sont richement fonctionnels (jauge SVG, glassmorphism, skeleton loading, playbooks IR, SSE mobile-aware — tout confirmé en code). Le vrai problème n'est pas l'absence de fonctionnalités mais **trois angles morts** :
1. **Alignement doc/code** : une feature phare (export SIEM/CEF) et un mécanisme documenté (geo-blocking via `/countries`, `/block|unblock/country`) ne sont jamais appelés depuis le frontend — 6 endpoints sur 27 sont orphelins.
2. **Accessibilité quasi absente** : 0 attribut `aria-`/`role=` sur tout le fichier, navigation en `<div onclick>` non focusable au clavier — écart net avec le niveau de finition visuelle.
3. **Dette de maintenabilité frontend** : une fonction Python de ~2740 lignes génère tout le HTML/CSS/JS en f-strings, avec 303 attributs `style=` inline et des couleurs hexadécimales dupliquées en dur (cassent le theming clair/sombre par endroits).

## 1. Écarts documentation ↔ code (à corriger ou re-documenter)

| Écart | Détail | Impact |
|---|---|---|
| Export SIEM/CEF (F12) | Endpoint `actions.py:579` existe, documenté comme livré (README:41, PROJECT_STATE:115), **jamais appelé** depuis `dashboard.py` | Feature invisible pour l'utilisateur final malgré doc "livrée" |
| Geo-blocking F14 — mécanisme | `/countries`, `/block/country`, `/unblock/country` documentés comme le chemin F14 ; le dashboard utilise en réalité `POST /action/config` avec `blocked_countries` en payload générique | Doc technique incorrecte, 3 endpoints dédiés orphelins |
| `/health`, `/fail2ban/status` | Jamais appelés — le badge santé topbar semble lire `soc_health.json` statique plutôt que l'API live | À clarifier : voulu (cohérent avec archi statique) ou oubli |
| PWA "installable" | Manifest généré et lié, **aucun service worker** — critère d'installabilité standard non rempli sur la plupart des navigateurs | Doc surestime la feature |
| Nav desktop vs bottom-nav | Ordre des écrans diffère légèrement (non documenté, mineur) | Cosmétique |

## 2. Observations UX/UI (grille : typographie / couleur / motion / composition / accessibilité)

- **Typographie** : choix délibéré et cohérent — `JetBrains Mono` pour toute donnée technique (IPs, scores, logs), pile système pour le texte courant. Identité "terminal SOC" assumée, mais le corps de texte reste une pile système générique sans caractère propre.
- **Couleur/thème** : variables CSS bien structurées (`--bg`, `--accent`, `--red/orange/green`) avec un vrai mode clair complet. Point faible : les fragments HTML générés côté Python (tableaux, badges) codent les couleurs en hexadécimal dur plutôt qu'en `var(--accent)` → ne réagissent pas au thème clair par endroits.
- **Motion** : bien fourni et cohérent avec l'ambition "SecOps premium" — gauge animée, compteurs incrémentaux, skeleton shimmer, glow sur alertes critiques, bannière IR défilante.
- **Composition spatiale** : densité d'info logique par écran (Vue globale/Sécurité/Infra denses, Timeline aérée). Bonne prise en compte mobile (drawer, bottom-nav, breakpoints 900/600/400px, safe-area iOS).
- **Identité visuelle** : dark theme indigo + sémantique rouge/orange/vert, glassmorphism au login, glow sur menace — exécution soignée mais de patterns communs au genre "dashboard SecOps 2023-2025", pas un design system distinctif en soi.
- **Accessibilité (angle mort)** : 0 `aria-`/`role=` sur tout le fichier ; navigation construite en `<div onclick>` (non focusable clavier, non annoncée lecteur d'écran) ; focus-visible limité aux champs `<input>`, absent sur boutons/nav/cartes cliquables ; contrastes de texte secondaire (gris moyens sur fond très sombre, 9-12px) probablement sous le seuil WCAG AA par endroits. Rappel : les standards Digital Factory exigent WCAG 2.1 AA minimum — c'est aujourd'hui le plus grand écart du dashboard vis-à-vis de vos propres standards.

## 3. Dette technique frontend

- `build_html()` : fonction monolithique de ~2740 lignes générant HTML+CSS+JS en f-strings imbriquées — difficile à diff/reviewer/éditer.
- Duplication de pattern : 5-6 blocs de construction de tableaux HTML quasi-identiques sans fonction de rendu partagée.
- 303 attributs `style=` inline en plus de la feuille globale (~380 lignes) — pas de classes réutilisables pour les fragments Python.
- Pas de composants JS réutilisables (pas de framework) — cohérent avec le choix "HTML statique + SSE léger", mais chaque nouvel écran impose de dupliquer la logique de nav à 3 endroits (desktop/drawer/bottom-nav) + `showScreen()` — déjà source d'un bug passé (correctif B4 documenté).

## 4. Recommandations priorisées

| # | Action | Catégorie | Effort |
|---|---|---|---|
| 1 | Brancher ou retirer l'export SIEM/CEF côté UI (décider : feature abandonnée ou bouton manquant) | Alignement | Faible |
| 2 | Corriger la doc F14 (remplacer les 3 endpoints dédiés documentés par le mécanisme réel `/action/config`, ou brancher réellement `/countries`+`/block`+`/unblock`) | Alignement | Faible |
| 3 | Convertir la nav (`<div onclick>` → `<button>`/`<nav>`/`role="tablist"`) avec focus-visible sur tous les éléments interactifs | Accessibilité (WCAG AA — standard Digital Factory) | Moyen |
| 4 | Auditer les contrastes de texte secondaire (gris sur fond sombre) avec un outil automatisé (axe-core, Lighthouse) | Accessibilité | Faible |
| 5 | Remplacer les couleurs hex dupliquées en dur (fragments Python) par les variables CSS existantes | Maintenabilité / theming | Moyen |
| 6 | Extraire une fonction `render_table_row()` partagée pour les 5-6 blocs de tableaux dupliqués | Maintenabilité | Moyen |
| 7 | Ajouter un service worker minimal si la PWA installable doit rester une feature revendiquée | Alignement | Moyen |
| 8 | (Plus lourd, hors urgence) Découper `build_html()` en sous-fonctions par écran, voire évaluer un templating (Jinja2) pour sortir le HTML des f-strings Python | Maintenabilité | Élevé |

## Statut
Audit uniquement — aucune modification de code effectuée. À transformer en epics/stories BMAD (`bmad-create-epics-and-stories`) si tu veux passer à l'implémentation, en commençant probablement par #1-#4 (faible effort, gains alignement + conformité WCAG AA déjà exigée par vos standards).
