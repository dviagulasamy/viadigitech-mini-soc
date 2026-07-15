
# ACCESS_VSCODE_CLAUDE_CODE.md — Connexion au VPS via VSCode + Claude Code

---

## 📌 Prérequis

- Un accès SSH par clé publique au serveur (voir `INSTALL.md` pour le déploiement du serveur lui-même)
- [VSCode](https://code.visualstudio.com/) installé en local
- [Claude Code](https://docs.claude.com/claude-code) installé côté serveur (via Node.js/NVM)

---

## 1️⃣ Configuration SSH locale

Éditer (ou créer) `~/.ssh/config` sur ta machine :

```
Host mon-vps
    HostName <IP_OU_DOMAINE_DU_SERVEUR>
    User <utilisateur_ssh>
    IdentityFile ~/.ssh/<ta_cle_privee>
    IdentitiesOnly yes
```

La clé publique correspondante doit être présente dans `~/.ssh/authorized_keys` sur le serveur.

Tester la connexion :

```bash
ssh mon-vps
```

⚠️ Privilégier systématiquement l'authentification par clé — désactiver `PasswordAuthentication` dans `/etc/ssh/sshd_config` (et vérifier qu'aucun fichier dans `/etc/ssh/sshd_config.d/*.conf` ne le réactive : `Include` étant placé en tête de `sshd_config`, la **première** occurrence d'une directive gagne. Vérifier la valeur effective avec `sudo sshd -T | grep passwordauthentication`).

---

## 2️⃣ VSCode — extension Remote-SSH

1. Installer l'extension **Remote - SSH** (Microsoft) dans VSCode.
2. `Ctrl+Shift+P` → **Remote-SSH: Connect to Host…** → choisir l'entrée définie dans `~/.ssh/config` (`mon-vps`).
3. Une fois connecté, ouvrir le dossier de travail souhaité sur le serveur (ex. le clone de ce repo, ou le répertoire des scripts SOC).
4. Le terminal intégré (`` Ctrl+` ``) s'exécute directement sur le serveur distant.

Extensions utiles à réinstaller côté remote (VSCode le propose automatiquement) : Python, Pylance.

---

## 3️⃣ Claude Code CLI côté serveur

Installation (si pas déjà fait), via NVM :

```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
nvm install --lts
npm install -g @anthropic-ai/claude-code
```

Authentification (une seule fois) :

```bash
claude
/login
```

Les identifiants sont stockés localement (`~/.claude/.credentials.json`) et persistent entre les sessions — pas besoin de relancer `/login` à chaque connexion.

### Utilisation depuis le terminal intégré de VSCode (Remote-SSH)

```bash
cd /chemin/vers/le/projet
claude
```

Comme la session est déjà authentifiée côté serveur, ouvrir un terminal via VSCode Remote-SSH puis lancer `claude` suffit.

---

## 🔒 Rappels sécurité

- Ne jamais committer de clés privées, tokens, mots de passe ou IP/ports réels dans ce repo (public).
- Garder les fichiers contenant des informations d'accès réelles (IP, identifiants) en local, hors du contrôle de version, ou dans un repo privé dédié.
- Vérifier régulièrement la config SSH effective (`sshd -T`) pour s'assurer qu'aucun hardening n'a été silencieusement écrasé par un fichier de conf (cloud-init, etc.).
