# Reprise de conversation — accès serveur et analyse

## Contexte
- Projet : viadigitech-mini-soc
- Objectif : se connecter au serveur distant via SSH/VS Code et analyser l’état du VPS.
- Date de la session : 2026-07-16

## Ce qui a été fait
- Configuration locale SSH Windows pour l’hôte `mon-vps`.
- Utilisation de la clé privée `C:\Users\david\.ssh\id_ed25519`.
- Connexion réussie au serveur distant avec l’utilisateur `ubuntu` et l’adresse `51.38.188.1`.
- Vérification de l’état du serveur :
  - hostname : `vps-23de4a3d`
  - OS : Ubuntu 22.04.5 LTS
  - mémoire : ~45% utilisée
  - disque : ~84% utilisé
  - services actifs : SSH, Fail2Ban, Docker, Glances, dashboard SOC, API actions, honeypot
  - ports ouverts observés : 22, 80, 443, 2222, 8022, 8088
- Vérification du dashboard local : `curl -I http://127.0.0.1:8088/` -> `HTTP/1.0 200 OK`

## Informations importantes
- Le serveur est en ligne et stable.
- Les services SOC sont actifs.
- Le dashboard semble accessible.
- La session SSH a pu être ouverte depuis le terminal et utilisée pour analyser le serveur.

## Prochaines étapes possibles
- Vérifier les logs des services SOC.
- Inspecter les tentatives d’attaque SSH et Fail2Ban.
- Ouvrir l’URL du dashboard dans le navigateur si nécessaire.
- Continuer le travail sur le projet via le serveur distant.
