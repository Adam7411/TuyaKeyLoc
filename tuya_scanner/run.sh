#!/bin/sh
set -e

CONFIG=/data/options.json

if [ -f "$CONFIG" ]; then
    SCAN_INTERVAL=$(python3 -c "import json;d=json.load(open('$CONFIG'));print(d.get('scan_interval',3600))")
    SCAN_DURATION=$(python3 -c "import json;d=json.load(open('$CONFIG'));print(d.get('scan_duration',18))")
    AUTO_SCAN=$(python3 -c "import json;d=json.load(open('$CONFIG'));print('1' if d.get('auto_scan', False) else '0')")
    QR_SCHEME=$(python3 -c "import json;d=json.load(open('$CONFIG'));print(d.get('qr_scheme','smartlife') or 'smartlife')")
else
    SCAN_INTERVAL=3600
    SCAN_DURATION=18
    AUTO_SCAN=0
    QR_SCHEME=smartlife
fi

export SCAN_INTERVAL
export SCAN_DURATION
export AUTO_SCAN
export QR_SCHEME
export QR_SESSION_FILE="/data/qr_session.json"
export QR_DEVICES_CACHE_FILE="/data/qr_devices_cache.json"
export DATA_FILE="/data/devices.json"
export WIZARD_FILE="/data/wizard_devices.json"
export EXPORT_DIR="/data/exports"
export CREDENTIALS_FILE="/data/tinytuya.json"
export RAW_CLOUD_FILE="/data/tuya-raw.json"
export SUPERVISOR_TOKEN="${SUPERVISOR_TOKEN:-}"

echo "[TuyaKeyLoc] Start — interwał: ${SCAN_INTERVAL}s, czas skanu: ${SCAN_DURATION}s, auto_scan: ${AUTO_SCAN}, qr_scheme: ${QR_SCHEME}"
echo "[TuyaKeyLoc] DATA_FILE = ${DATA_FILE}"
echo "[TuyaKeyLoc] WIZARD_FILE = ${WIZARD_FILE}"
echo "[TuyaKeyLoc] EXPORT_DIR = ${EXPORT_DIR}"

exec python3 /scanner.py
