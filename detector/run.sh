#!/usr/bin/env bash
# Pull device logs and run The Docket.
# Usage:
#   ./run.sh                  # adb logcat -d  → docket.json
#   ./run.sh path/to.log      # file           → docket.json
#   ./run.sh --clear          # adb logcat -c only
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DETECTOR="$ROOT/detector/docket.py"
OUT="${DOCKET_OUT:-$ROOT/docket.json}"
ADB="${ADB:-adb}"
PYTHON="${PYTHON:-python3}"

if [[ "${1:-}" == "--clear" ]]; then
  "$ADB" logcat -c
  echo "logcat buffer cleared"
  exit 0
fi

if [[ $# -ge 1 && "$1" != "-" ]]; then
  echo "Scanning log file: $1"
  "$PYTHON" "$DETECTOR" --input "$1" --output "$OUT"
else
  echo "Pulling adb logcat -d ..."
  "$ADB" logcat -d | "$PYTHON" "$DETECTOR" --input - --output "$OUT"
fi
