#!/bin/bash

echo "Installation ViadigiTech Mini-SOC"

sudo apt update
sudo apt install -y python3 python3-pip python3-venv curl jq mutt mailutils

python3 -m venv /home/ubuntu/viadigitech-env
source /home/ubuntu/viadigitech-env/bin/activate
pip install numpy==1.26.4 matplotlib pandas
deactivate

sudo mkdir -p /var/log/viadigitech-monitoring
sudo chown -R root:root /var/log/viadigitech-monitoring

echo "Installation complète. Pensez à configurer le cron :"
echo "sudo crontab -e"
echo "0 7 * * * /home/ubuntu/viadigitech-monitoring-v4-enterprise-patched.sh"
