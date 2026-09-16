#!/bin/bash
set -euo pipefail

HOMES_BASE="${HOMES_BASE:-/homes}"
SYNC_INTERVAL="${SYNC_INTERVAL:-300}"
CONFIG_DIR="/config"
STATE_DIR="/state"
TRIGGER_FILE="${CONFIG_DIR}/.sync_now"

echo "[sync] Home-Mail-Bridge Sync-Service gestartet"
echo "[sync] Interval: ${SYNC_INTERVAL}s | Homes: ${HOMES_BASE}"

# Warte kurz, bis Config da ist
sleep 5

run_sync() {
  echo "[sync] $(date '+%Y-%m-%d %H:%M:%S') – Starte Sync-Lauf"

  if [ -d "$CONFIG_DIR" ]; then
    # Alle .mbsyncrc Dateien durchgehen (ohne versteckte Trigger-Datei)
    find "$CONFIG_DIR" -maxdepth 1 -name "*.mbsyncrc" -type f | while read -r cfg; do
      user=$(basename "$cfg" .mbsyncrc)
      echo "[sync] → Sync für User: $user"
      if mbsync -c "$cfg" -a 2>&1; then
        echo "[sync]   OK: $user"
      else
        echo "[sync]   FEHLER bei $user (siehe Logs)"
      fi
    done
  else
    echo "[sync] Keine Config-Verzeichnis gefunden – warte auf GUI"
  fi
}

while true; do
  run_sync

  # Auf nächsten regulären Lauf oder manuellen Trigger warten
  # Alle 5 Sekunden prüfen, ob .sync_now existiert
  elapsed=0
  while [ "$elapsed" -lt "$SYNC_INTERVAL" ]; do
    if [ -f "$TRIGGER_FILE" ]; then
      echo "[sync] Manueller Trigger erkannt – sofortiger Sync"
      rm -f "$TRIGGER_FILE"
      break
    fi
    sleep 5
    elapsed=$((elapsed + 5))
  done
done
