# Installation ViadigiTech Mini-SOC

## 1. Préparation serveur (Ubuntu 22.04 / 24.04)

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv curl jq mutt mailutils
2. Créer l'environnement Python isolé
bash
Copier
Modifier
python3 -m venv /home/ubuntu/viadigitech-env
source /home/ubuntu/viadigitech-env/bin/activate
pip install numpy==1.26.4 matplotlib pandas
deactivate
3. Créer les répertoires de logs
bash
Copier
Modifier
sudo mkdir -p /var/log/viadigitech-monitoring
sudo chown -R root:root /var/log/viadigitech-monitoring
4. Copier les fichiers de script et les rendre exécutables
bash
Copier
Modifier
chmod +x *.sh
5. Ajouter la tâche planifiée cron (root)
bash
Copier
Modifier
sudo crontab -e
Et insérer :

bash
Copier
Modifier
0 7 * * * /home/ubuntu/viadigitech-monitoring-v4-enterprise-patched.sh
6. Tester manuellement le SOC
bash
Copier
Modifier
sudo /home/ubuntu/viadigitech-monitoring-v4-enterprise-patched.sh
yaml
Copier
Modifier

---

## 3️⃣ `CHANGELOG.md`

```markdown
# Changelog ViadigiTech Mini-SOC

## V1.0 (2025-06-16)

- Stabilisation complète sous Ubuntu 22.04
- Gestion Fail2Ban root
- Correction numpy version
- Virtualenv propre
- Historisation CSV & PNG
- Envoi mail automatisé avec géolocalisation
- Full packaging GitHub

4️⃣ LICENSE
(tu peux utiliser la licence MIT standard, à copier depuis le template officiel de GitHub)