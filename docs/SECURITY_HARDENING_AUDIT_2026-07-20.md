# Audit sécurité live — 2026-07-20

> Suite BMAD à `SECURITY_HARDENING_RECOMMENDATIONS.md` (2026-07-17). Audit mené en session interactive (Claude Code + accès SSH direct au VPS) suite à un incident de ban Fail2Ban sur l'IP de l'opérateur.

## Contexte
Un ban Fail2Ban sur l'IP de l'opérateur (tentative avec un mauvais utilisateur SSH) a déclenché une inspection plus large de la posture de sécurité du serveur, au-delà du seul incident.

## Constats

### Incident initial (résolu)
- IP `176.134.132.129` bannie par Fail2Ban (tentative SSH avec `user=david` au lieu de `ubuntu`)
- Débannie manuellement, puis `176.134.132.129` et `176.134.132.124` ajoutées durablement à `ignoreip` dans `/etc/fail2ban/jail.local`

### Drift de code prod/repo (résolu)
- `actions.py`, `detector.py`, `soc_db.py` divergeaient entre le serveur et le repo Git (migration SQLite de `threat_patterns` jamais commitée) — réconcilié et commité (`4c02777`)

### Bug de configuration SSH (identifié, non corrigé)
- `PasswordAuthentication` est effectif à `yes` malgré une intention contraire dans `sshd_config` (ligne 57 : `no`) et `60-cloudimg-settings.conf` (`no`)
- Cause : `Include /etc/ssh/sshd_config.d/*.conf` (ligne 12) est traité avant la ligne 57 ; dans le glob, `50-cloud-init.conf` (`PasswordAuthentication yes`) est lu avant `60-cloudimg-settings.conf` — OpenSSH garde la première valeur rencontrée
- Le compte `ubuntu` a un mot de passe actif (`/etc/shadow` non verrouillé)
- Auth par clé déjà validée fonctionnelle en standalone (`PreferredAuthentications=publickey`)

### Mises à jour système (identifié, non corrigé)
- `unattended-upgrades` actif mais `Allowed-Origins` n'inclut pas `jammy-updates` — seul `jammy-security`/ESM est auto-appliqué
- 26 paquets en attente depuis ~2,5 mois (dernière trace `apt/history.log` : 2026-05-01), dont noyau Linux (173.161 → 174.162), Docker (27.5.1 → 28.2.2), containerd, apparmor, ldap
- `caddy`, `mongodb-mongosh`, `nodejs` (dépôts tiers) hors périmètre unattended-upgrades quel que soit le fix

### Autres écarts identifiés
- Pas de jail `recidive` Fail2Ban (un seul jail actif : `sshd`)
- Port SSH par défaut (22) — volume de bruit non réduit
- Port `3030` ouvert en UFW à `Anywhere` sans commentaire explicatif (contrairement aux autres règles)
- `subnet_ban_enabled: false` dans `soc_config.json` malgré la fonctionnalité F14 déjà codée
- Pas de MFA/2FA SSH, `auditd` inactif — jugés P2/optionnels vu la couverture déjà assurée par le SOC maison

## Liste priorisée (risque × effort)

| # | Action | Statut |
|---|---|---|
| 1 | Fix `PasswordAuthentication` (override cloud-init) | ✅ fait |
| 2 | Verrouiller le mot de passe du compte `ubuntu` | ✅ fait |
| 3 | Appliquer les 26 paquets en attente (+ reboot planifié) | ⏸ différé |
| 4 | Jail `recidive` Fail2Ban | ✅ fait |
| 5 | Revue des clés SSH autorisées (`coolify-generated-ssh-key`, `viadigitech-pc`) | ⏸ différé |
| 6 | Activer `subnet_ban_enabled` | ⏸ différé |
| 7 | Changer le port SSH | ⏸ différé |
| 8 | Justifier/fermer le port `3030` en UFW | ⏸ différé |
| 9 | MFA/2FA SSH | ⏸ différé (P2) |
| 10 | `auditd` | ⏸ différé (P2) |
| 11 | WAF/CrowdSec/rate-limiting web | ⏸ différé (P2) |

## Décision
Traitement des points 1, 2 et 4 en session live, un par un avec vérification (nouvelle connexion SSH testée) entre chaque étape avant de passer à la suivante. Points 3, 5-11 différés à une session ultérieure planifiée.

## Détail des actions réalisées (2026-07-20)

### 1 — Fix PasswordAuthentication
- Backup : `/etc/ssh/sshd_config.bak-<timestamp>`
- Ajout de `PasswordAuthentication no` dans `/etc/ssh/sshd_config`, avant la ligne `Include /etc/ssh/sshd_config.d/*.conf` (ligne 12) — gagne sur l'override `50-cloud-init.conf` grâce à l'ordre de lecture d'OpenSSH (première valeur rencontrée conservée)
- Validé : `sshd -t` OK, `systemctl reload ssh`, `sshd -T | grep passwordauthentication` → `no`
- Vérifié sur une connexion SSH neuve après application

### 2 — Verrouillage du mot de passe `ubuntu`
- `sudo passwd -l ubuntu` → statut `L` confirmé via `passwd -S ubuntu`
- Vérifié : accès par clé toujours fonctionnel après verrouillage

### 4 — Jail Fail2Ban `recidive`
- Backup : `/etc/fail2ban/jail.local.bak-<timestamp>`
- Ajout de `[recidive]\nenabled = true` en fin de `/etc/fail2ban/jail.local` (hérite de `bantime=1w`, `findtime=1d`, `banaction=allports` du template `jail.conf`)
- `ignoreip` du `[DEFAULT]` confirmé hérité par `recidive` (protège `176.134.132.129` et `176.134.132.124`)
- 2 jails actifs après reload : `sshd`, `recidive`

Aucune interruption d'accès SSH constatée sur l'ensemble des 3 actions.
