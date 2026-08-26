#!/usr/bin/env python3
"""TuyaKeyLoc — HA Addon Backend"""

import ipaddress
import json, logging, os, re, subprocess, sys, threading, time
from datetime import datetime
from pathlib import Path

import requests
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [TuyaKeyLoc] %(levelname)s: %(message)s"
)
log = logging.getLogger(__name__)

SCAN_DURATION = int(os.environ.get("SCAN_DURATION", 18))
SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", 3600))
AUTO_SCAN = os.environ.get("AUTO_SCAN", "0") in ("1", "true", "True", "yes")
DATA_FILE = os.environ.get("DATA_FILE", "/data/devices.json")
WIZARD_FILE = os.environ.get("WIZARD_FILE", "/data/wizard_devices.json")
WWW_DIR = "/var/www"
PORT = 7080
EXPORT_DIR = os.environ.get("EXPORT_DIR", "/data/exports")
LATEST_EXPORT = os.path.join(EXPORT_DIR, "latest.json")
MAX_EXPORTS = 30
CREDENTIALS_FILE = os.environ.get("CREDENTIALS_FILE", "/data/tinytuya.json")
RAW_CLOUD_FILE = os.environ.get("RAW_CLOUD_FILE", "/data/tuya-raw.json")
SUPERVISOR_TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")
QR_SCHEME = os.environ.get("QR_SCHEME", "smartlife")
HA_BASE = "http://supervisor/core/api"
HA_HEADERS = {
    "Authorization": f"Bearer {SUPERVISOR_TOKEN}",
    "Content-Type": "application/json",
}
# HA config mounted read-only via map: homeassistant_config:ro
HA_STORAGE = Path("/homeassistant/.storage/core.config_entries")
# Fallback paths seen on some HAOS layouts
HA_STORAGE_CANDIDATES = [
    HA_STORAGE,
    Path("/config/.storage/core.config_entries"),
    Path("/homeassistant/config/.storage/core.config_entries"),
]

app = Flask(__name__, static_folder=WWW_DIR)
# In HA Ingress/browser contexts preflight requests are common.
# Keep CORS permissive for addon-local API endpoints.
CORS(
    app,
    resources={r"/api/*": {"origins": "*"}},
    supports_credentials=False,
    methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
)


@app.after_request
def add_headers(response):
    if request.path.startswith("/api/"):
        response.headers["Content-Type"] = "application/json"
        origin = request.headers.get("Origin")
        response.headers["Access-Control-Allow-Origin"] = origin or "*"
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = (
            "Content-Type, Authorization, X-Requested-With"
        )
    return response


state = {
    "scanning": False,
    "devices": [],
    "last_scan": None,
    "log": [],
    "progress": 0,
    "wizard_running": False,
    "wizard_log": [],
    "wizard_devices": [],
    "last_force_cidrs": [],
    "last_export": None,
    "ha_entries": [],
    "ha_synced_at": None,
}

# ── persistence ───────────────────────────────────────────────


def _is_lan_ip(ip):
    """True only for usable local addresses (not Tuya cloud WAN / CGNAT public)."""
    ip = (ip or "").strip()
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
        return False
    # RFC1918 / link-local / ULA — OK for tuya-local host
    if addr.is_private or addr.is_link_local:
        return True
    # IPv6 unique local
    if getattr(addr, "is_private", False):
        return True
    return False


def _lan_ip_or_empty(ip):
    return (ip or "").strip() if _is_lan_ip(ip) else ""


# (scanner.py continues unchanged...) 
