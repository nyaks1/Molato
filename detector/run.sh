#!/usr/bin/env bash
# Pull device logs and run The Docket.
# Usage:
#   ./run.sh                  # adb logcat -d  → docket.json + DOCKET.md
#   ./run.sh path/to.log      # file           → docket.json + DOCKET.md
#   ./run.sh --clear          # adb logcat -c only
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DETECTOR="$ROOT/detector/docket.py"
OUT="${DOCKET_OUT:-$ROOT/docket.json}"
MD_OUT="${DOCKET_MD_OUT:-$ROOT/DOCKET.md}"
PYTHON="${PYTHON:-python3}"

find_adb() {
  if [[ -n "${ADB:-}" ]]; then
    echo "$ADB"
    return 0
  fi
  if command -v adb >/dev/null 2>&1; then
    command -v adb
    return 0
  fi
  # Windows platform-tools via WSL mount (Flutter/AS live on Windows)
  local win_adb="/mnt/c/Users/${WINUSER:-$USER}/AppData/Local/Android/Sdk/platform-tools/adb.exe"
  if [[ ! -x "$win_adb" && ! -f "$win_adb" ]]; then
    win_adb="/mnt/c/Users/User/AppData/Local/Android/Sdk/platform-tools/adb.exe"
  fi
  if [[ -f "$win_adb" ]]; then
    echo "$win_adb"
    return 0
  fi
  # Windows path when run from PowerShell/Git-Bash
  if [[ -f "/c/Users/User/AppData/Local/Android/Sdk/platform-tools/adb.exe" ]]; then
    echo "/c/Users/User/AppData/Local/Android/Sdk/platform-tools/adb.exe"
    return 0
  fi
  return 1
}

if ! ADB_BIN="$(find_adb)"; then
  echo "error: adb not found." >&2
  echo "  Set ADB=/full/path/to/adb  or  install platform-tools on PATH." >&2
  echo "  Windows default: C:\\Users\\<you>\\AppData\\Local\\Android\\Sdk\\platform-tools\\adb.exe" >&2
  echo "  Offline proof still works:  bash detector/selftest.sh" >&2
  exit 1
fi

if [[ "${1:-}" == "--clear" ]]; then
  "$ADB_BIN" logcat -c
  echo "logcat buffer cleared"
  exit 0
fi

if [[ $# -ge 1 && "$1" != "-" ]]; then
  echo "Scanning log file: $1"
  "$PYTHON" "$DETECTOR" --input "$1" --output "$OUT" --md-output "$MD_OUT"
else
  echo "Pulling logcat via: $ADB_BIN"
  # Capture first so a failed adb never silently feed an empty docket.
  LOG_TMP="$(mktemp)"
  if ! "$ADB_BIN" logcat -d >"$LOG_TMP"; then
    echo "error: adb logcat failed. Is the phone connected? Try: adb devices" >&2
    rm -f "$LOG_TMP"
    exit 1
  fi
  if [[ ! -s "$LOG_TMP" ]]; then
    echo "error: logcat buffer empty. Trigger login / send money / logout, then re-run." >&2
    rm -f "$LOG_TMP"
    exit 1
  fi
  echo "Captured $(wc -l <"$LOG_TMP") lines — scanning..."
  "$PYTHON" "$DETECTOR" --input "$LOG_TMP" --output "$OUT" --md-output "$MD_OUT"
  rm -f "$LOG_TMP"
fi
