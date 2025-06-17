#!/usr/bin/env bash
set -euo pipefail

# ================================
# ViaDigiTech SOC IA V5.3 – Shell
# ================================
WORKDIR="$(dirname "$0")"
SCRIPT="$WORKDIR/viadigitech-monitoring-v5-ia-analyzer.py"

MODE="${1:-production}"
if [[ "$MODE" == "test" ]]; then
  echo "MODE TEST ACTIVÉ : FORCING REPORT"
else
  echo "MODE PRODUCTION ACTIVÉ"
fi

python3 "$SCRIPT" "$MODE"
