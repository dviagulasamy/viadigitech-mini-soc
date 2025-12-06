#!/usr/bin/env bash
set -euo pipefail

# ================================
# ViaDigiTech SOC IA V5.3 – Shell
# ================================
WORKDIR="/home/ubuntu/viadigitech-soc-v5-3"
SCRIPT="$WORKDIR/viadigitech-monitoring-v5-ia-analyzer.py"

MODE="${1:-production}"
if [[ "$MODE" == "test" ]]; then
  echo "MODE TEST ACTIVE : FORCING REPORT"
else
  echo "MODE PRODUCTION ACTIVE"
fi

# Lancement de l’analyse et envoi d’email intégrés au Python
python3 "$SCRIPT" "$MODE"
