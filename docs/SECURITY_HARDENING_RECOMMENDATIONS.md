# Recommandations de protection — 2026-07-17

## Contexte
- Le serveur SOC a été inspecté en direct après une séquence d’attaques SSH/scan observées via les logs du détecteur et Fail2Ban.
- Les données observées montrent une activité de reconnaissance et de brute-force significative, avec plus de 500 IP actuellement bannies dans le jail sshd.

## Observations clés
- Santé globale du SOC : OK
- Services principaux actifs : detector, dashboard, API actions, honeypot
- Fail2Ban : OK
- Détecteur : plusieurs auto-bans récents déclenchés sur des IP externes
- Dashboard : génération OK, sortie JS valide

## Recommandations prioritaires

### P0 — durcissement immédiat
1. Protéger SSH strictement
   - Désactiver l’authentification par mot de passe
   - Interdire la connexion root
   - N’autoriser que l’authentification par clé SSH
   - Garder Fail2Ban actif et vérifier le jail sshd

2. Réduire la surface d’exposition
   - Ouvrir uniquement les ports nécessaires (22/80/443 si requis)
   - Limiter l’accès admin à VPN, IP de confiance ou réseau privé
   - Éviter d’exposer des ports de gestion/services non essentiels sur Internet

3. Appliquer une politique réseau minimale
   - UFW/iptables avec politique par défaut deny
   - Autoriser uniquement les ports et adresses nécessaires

### P1 — renforcement opérationnel
4. Mettre à jour le serveur et les paquets
   - apt update && apt upgrade
   - Vérifier les paquets obsolètes et les services non utilisés

5. Supprimer les accès inutiles
   - Désactiver les comptes inutilisés
   - Vérifier la présence de clés SSH non utilisées
   - Revue des comptes sudo

6. Ajouter de la surveillance proactive
   - Alertes sur nouveaux bannissements massifs
   - Journalisation centralisée des échecs d’authentification
   - Vérification automatique de la santé du SOC

### P2 — niveau pro / hardening avancé
7. Ajouter une couche de protection supplémentaire
   - WAF/proxy inverse si des services web sont exposés
   - CrowdSec ou règles Fail2Ban additionnelles
   - Limitation du taux d’accès sur les services exposés

## Conclusion
Le risque principal n’est pas l’absence de monitoring, mais l’exposition de l’infrastructure SSH et des services accessibles au public. La priorité absolue est de verrouiller SSH, réduire la surface d’attaque et conserver un monitoring actif sur les tentatives répétées.
