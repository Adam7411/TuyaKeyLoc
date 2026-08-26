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


def _sanitize_device_ips(devices, persist=False):
    """Drop public/cloud IPs from device rows (QR sharing API often returns WAN)."""
    changed = False
    for d in devices or []:
        raw = (d.get("ip") or "").strip()
        if not raw:
            continue
        if _is_lan_ip(raw):
            continue
        # Keep for diagnostics, never as local host
        if not d.get("cloud_ip"):
            d["cloud_ip"] = raw
        d["ip"] = ""
        if d.get("status") == "online" and not d.get("ip"):
            d["status"] = "cloud-only"
            d["online"] = False
        elif d.get("status") == "offline" and not d.get("ip"):
            d["status"] = "cloud-only"
        changed = True
        log.info(
            "Stripped non-LAN IP %s from device %s (kept as cloud_ip)",
            raw,
            (d.get("id") or d.get("gwId") or "")[:12],
        )
    if changed and persist:
        _save()
    return changed


def _load():
    log.info("DATA_FILE = %s  exists = %s", DATA_FILE, os.path.exists(DATA_FILE))
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE) as f:
                saved = json.load(f)
            state["devices"] = saved.get("devices", [])
            state["last_scan"] = saved.get("last_scan")
            log.info("Loaded %d devices", len(state["devices"]))
            if _sanitize_device_ips(state["devices"], persist=True):
                log.info("Sanitized non-LAN IPs after load")
        except Exception as e:
            log.warning("Read error: %s", e)
    if os.path.exists(WIZARD_FILE):
        try:
            with open(WIZARD_FILE) as f:
                state["wizard_devices"] = json.load(f)
            log.info("Loaded %d devices from wizard cache", len(state["wizard_devices"]))
        except:
            pass
    if os.path.exists(LATEST_EXPORT):
        try:
            with open(LATEST_EXPORT) as f:
                latest = json.load(f)
            state["last_export"] = {
                "path": LATEST_EXPORT,
                "latest": LATEST_EXPORT,
                "at": latest.get("exported_at"),
                "reason": latest.get("reason"),
                "count": latest.get("count"),
            }
            # If runtime cache empty (e.g. after rebuild), hydrate from latest export
            if not state.get("devices") and isinstance(latest.get("devices"), list):
                state["devices"] = latest["devices"]
                state["last_scan"] = latest.get("last_scan") or state.get("last_scan")
                log.info("Hydrated %d devices from latest export", len(state["devices"]))
            if not state.get("wizard_devices") and isinstance(
                latest.get("wizard_devices"), list
            ):
                state["wizard_devices"] = latest["wizard_devices"]
                log.info(
                    "Hydrated %d wizard devices from latest export",
                    len(state["wizard_devices"]),
                )
        except Exception as e:
            log.warning("Could not load latest export: %s", e)


def _save():
    try:
        os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
        with open(DATA_FILE, "w") as f:
            json.dump(
                {"devices": state["devices"], "last_scan": state["last_scan"]},
                f,
                indent=2,
            )
        log.info("Saved %d devices to %s", len(state["devices"]), DATA_FILE)
    except Exception as e:
        log.warning("Write error: %s", e)


def _build_export_payload(reason="manual"):
    devices = state.get("devices") or []
    wizard = state.get("wizard_devices") or []
    return {
        "format": "tuyakeyloc_export",
        "version": 1,
        "reason": reason,
        "exported_at": datetime.now().isoformat(timespec="seconds"),
        "last_scan": state.get("last_scan"),
        "count": {
            "devices": len(devices),
            "wizard_devices": len(wizard),
            "with_key": sum(
                1
                for d in devices
                if d.get("localKey") or d.get("key")
            )
            or sum(1 for d in wizard if d.get("key")),
        },
        "devices": devices,
        "wizard_devices": wizard,
    }


def _prune_exports():
    try:
        files = sorted(
            (
                f
                for f in os.listdir(EXPORT_DIR)
                if f.startswith("tuya_backup_") and f.endswith(".json")
            ),
            reverse=True,
        )
        for old in files[MAX_EXPORTS:]:
            try:
                os.remove(os.path.join(EXPORT_DIR, old))
            except Exception:
                pass
    except Exception:
        pass


def _save_export(reason="manual", snapshot=True):
    """Persist devices+keys to /data/exports (latest + optional timestamped snapshot)."""
    if not (state.get("devices") or state.get("wizard_devices")):
        return None
    payload = _build_export_payload(reason)
    os.makedirs(EXPORT_DIR, exist_ok=True)
    with open(LATEST_EXPORT, "w") as f:
        json.dump(payload, f, indent=2)
    path = LATEST_EXPORT
    if snapshot:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(EXPORT_DIR, f"tuya_backup_{stamp}.json")
        with open(path, "w") as f:
            json.dump(payload, f, indent=2)
        _prune_exports()
    state["last_export"] = {
        "path": path,
        "latest": LATEST_EXPORT,
        "at": payload["exported_at"],
        "reason": reason,
        "count": payload["count"],
    }
    log.info(
        "Export saved (%s): %s devices, %s with keys → %s",
        reason,
        payload["count"]["devices"],
        payload["count"]["with_key"],
        path,
    )
    return state["last_export"]


def _list_exports():
    os.makedirs(EXPORT_DIR, exist_ok=True)
    items = []
    if os.path.exists(LATEST_EXPORT):
        try:
            with open(LATEST_EXPORT) as f:
                data = json.load(f)
            items.append(
                {
                    "name": "latest.json",
                    "path": LATEST_EXPORT,
                    "at": data.get("exported_at"),
                    "reason": data.get("reason"),
                    "count": data.get("count"),
                    "is_latest": True,
                }
            )
        except Exception:
            pass
    for name in sorted(os.listdir(EXPORT_DIR), reverse=True):
        if not (name.startswith("tuya_backup_") and name.endswith(".json")):
            continue
        fpath = os.path.join(EXPORT_DIR, name)
        try:
            with open(fpath) as f:
                data = json.load(f)
            items.append(
                {
                    "name": name,
                    "path": fpath,
                    "at": data.get("exported_at"),
                    "reason": data.get("reason"),
                    "count": data.get("count"),
                    "is_latest": False,
                }
            )
        except Exception:
            items.append({"name": name, "path": fpath, "is_latest": False})
    return items


def _restore_export(name="latest.json"):
    name = os.path.basename(name or "latest.json")
    if name == "latest.json":
        path = LATEST_EXPORT
    else:
        if not (name.startswith("tuya_backup_") and name.endswith(".json")):
            raise ValueError("Invalid backup name")
        path = os.path.join(EXPORT_DIR, name)
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    with open(path) as f:
        data = json.load(f)
    devices = data.get("devices")
    wizard = data.get("wizard_devices")
    if devices is None and isinstance(data, list):
        devices = data
        wizard = []
    if not isinstance(devices, list):
        devices = []
    if not isinstance(wizard, list):
        wizard = []
    state["devices"] = devices
    state["wizard_devices"] = wizard
    state["last_scan"] = data.get("last_scan") or datetime.now().isoformat()
    _save()
    try:
        with open(WIZARD_FILE, "w") as f:
            json.dump(wizard, f, indent=2)
    except Exception:
        pass
    _save_export(reason="restore", snapshot=False)
    return {
        "devices": len(devices),
        "wizard_devices": len(wizard),
        "with_key": sum(1 for d in devices if d.get("localKey")),
        "source": name,
    }


def _load_saved_credentials():
    if not os.path.exists(CREDENTIALS_FILE):
        return None
    try:
        with open(CREDENTIALS_FILE) as f:
            creds = json.load(f)
        return {
            "region": creds.get("apiRegion") or "eu",
            "apiKey": creds.get("apiKey") or "",
            "apiSecret": creds.get("apiSecret") or "",
            "deviceId": creds.get("apiDeviceID") or "",
        }
    except Exception:
        return None


def _log(msg, level="info"):
    state["log"].append(
        {"t": datetime.now().strftime("%H:%M:%S"), "msg": msg, "level": level}
    )
    state["log"] = state["log"][-100:]
    getattr(log, {"found": "info", "warn": "warning"}.get(level, level))(msg)


def _wlog(msg, level="info"):
    state["wizard_log"].append(
        {"t": datetime.now().strftime("%H:%M:%S"), "msg": msg, "level": level}
    )
    state["wizard_log"] = state["wizard_log"][-200:]
    log.info("[Wizard] %s", msg)


# ── parser ────────────────────────────────────────────────────

RE_DEV = re.compile(r"(Unknown|Known)\s+v([\d.]+)\s+Device\s+Product ID\s*=\s*(\S+)")
RE_ADDR = re.compile(
    r"Address\s*=\s*([\d.]+)\s+Device ID\s*=\s*(\S+)\s+\(\w+:\d+\)\s+"
    r"Local Key\s*=\s*(\S*)\s+Version\s*=\s*([\d.]+)(?:.*?MAC\s*=\s*(\S*))?"
)


def _parse(lines):
    devices, last = {}, {}
    for line in lines:
        line = line.strip()
        m1 = RE_DEV.search(line)
        if m1:
            last = {"known": m1.group(1) == "Known", "productKey": m1.group(3)}
            continue
        m2 = RE_ADDR.search(line)
        if m2:
            gwId = m2.group(2)
            devices[gwId] = {
                "ip": m2.group(1),
                "gwId": gwId,
                "id": gwId,
                "localKey": (m2.group(3) or "").strip(),
                "version": m2.group(4),
                "mac": (m2.group(5) or "").strip(),
                "productKey": last.get("productKey", ""),
                "known": last.get("known", False),
            }
    return list(devices.values())


def _pick_product_key(payload):
    """Normalize product id/key from different Tuya payload variants."""
    return (
        payload.get("productKey")
        or payload.get("product_id")
        or payload.get("productId")
        or payload.get("pid")
        or ""
    )


def _find_device(dev_id):
    for d in state.get("devices") or []:
        if d.get("id") == dev_id or d.get("gwId") == dev_id:
            return d
    return None


def _wizard_mapping_for(dev_id):
    for w in state.get("wizard_devices") or []:
        wid = w.get("id") or w.get("gwId") or ""
        if wid == dev_id and w.get("mapping"):
            return w.get("mapping")
    return None


def _make_tuya_device(dev, timeout=4, retries=2):
    import tinytuya

    return tinytuya.Device(
        dev_id=dev.get("id") or dev.get("gwId"),
        address=dev.get("ip"),
        local_key=dev.get("localKey"),
        version=float(dev.get("version") or 3.3),
        connection_timeout=timeout,
        connection_retry_limit=retries,
        connection_retry_delay=1,
    )


def _enrich_dps(dps, mapping):
    """Attach human-readable DP names from cloud mapping when available."""
    if not isinstance(dps, dict):
        return {}
    out = {}
    mapping = mapping or {}
    for code, value in dps.items():
        key = str(code)
        meta = mapping.get(key) or mapping.get(code) or {}
        name = ""
        if isinstance(meta, dict):
            name = meta.get("code") or meta.get("name") or meta.get("dp_name") or ""
        elif isinstance(meta, str):
            name = meta
        out[key] = {
            "value": value,
            "name": name or f"dp_{key}",
            "raw_code": key,
        }
    return out


def _localtuya_entries(only_with_key=True, ids=None):
    id_set = None
    if ids is not None:
        id_set = {str(x).strip() for x in ids if str(x).strip()}
    entries = []
    for d in state.get("devices") or []:
        did = d.get("id") or d.get("gwId") or ""
        if id_set is not None and did not in id_set:
            continue
        key = d.get("localKey") or ""
        if only_with_key and not key:
            continue
        if not d.get("ip") and only_with_key:
            # still export cloud-known keys without IP for reference
            pass
        entries.append(
            {
                "friendly_name": d.get("name") or d.get("productName") or d.get("id"),
                "host": _lan_ip_or_empty(d.get("ip") or ""),
                "device_id": did,
                "local_key": key,
                "protocol_version": str(d.get("version") or "3.3"),
                "mac": d.get("mac") or "",
                "product_id": d.get("productKey") or "",
                "status": d.get("status") or "",
            }
        )
    return entries


def _tuya_local_push_rows(ids=None):
    """Selected devices + HA presence for one-shot tuya-local setup."""
    entries = _localtuya_entries(only_with_key=True, ids=ids)
    ha_by_id = {}
    for e in state.get("ha_entries") or []:
        did = (e.get("device_id") or "").strip()
        if did:
            ha_by_id[did] = e
    rows = []
    for e in entries:
        did = e["device_id"]
        ha = ha_by_id.get(did)
        configured = (ha or {}).get("host") or ""
        host = e.get("host") or ""
        rows.append(
            {
                **e,
                "in_ha": bool(ha),
                "entry_id": (ha or {}).get("entry_id") or "",
                "configured_host": configured,
                "ip_mismatch": bool(
                    ha and host and configured and host != configured
                ),
                "ha_title": (ha or {}).get("title") or "",
            }
        )
    return rows


def _tuya_local_yaml(entries):
    lines = ["# Generated by TuyaKeyLoc — for make-all/tuya-local reference", "devices:"]
    for e in entries:
        lines.append(f"  - name: \"{e['friendly_name']}\"")
        lines.append(f"    device_id: \"{e['device_id']}\"")
        lines.append(f"    local_key: \"{e['local_key']}\"")
        if e.get("host"):
            lines.append(f"    host: \"{e['host']}\"")
        lines.append(f"    protocol_version: {e['protocol_version']}")
    return "\n".join(lines) + "\n"


def _localtuya_yaml(entries):
    lines = ["# Generated by TuyaKeyLoc — LocalTuya-style list", "localtuya:"]
    for e in entries:
        lines.append(f"  - friendly_name: \"{e['friendly_name']}\"")
        lines.append(f"    host: \"{e['host']}\"")
        lines.append(f"    device_id: \"{e['device_id']}\"")
        lines.append(f"    local_key: \"{e['local_key']}\"")
        lines.append(f"    protocol_version: \"{e['protocol_version']}\"")
    return "\n".join(lines) + "\n"


REGION_FALLBACKS = {
    "eu": ["eu-w"],
    "eu-w": ["eu"],
    "us": ["us-e"],
    "us-e": ["us"],
}


def _is_region_or_auth_error(err):
    text = str(err).lower()
    if _is_iot_core_expired(err):
        return False
    needles = (
        "token",
        "sign",
        "1106",
        "1004",
        "invalid",
        "region",
        "permission deny",
        "1010",
        "clientid",
        "secret",
    )
    return any(n in text for n in needles)


def _cloud_connect(api_region, api_key, api_secret, device_id):
    """Connect to Tuya Cloud; auto-retry sibling region on auth/region errors."""
    import tinytuya

    tried = []
    regions = [api_region] + [
        r for r in REGION_FALLBACKS.get(api_region, []) if r != api_region
    ]
    last_err = None
    for region in regions:
        tried.append(region)
        _wlog(f"Connecting to Tuya Cloud (region={region}) ...", "info")
        creds = {
            "apiKey": api_key,
            "apiSecret": api_secret,
            "apiRegion": region,
            "apiDeviceID": device_id,
        }
        try:
            os.makedirs(os.path.dirname(CREDENTIALS_FILE), exist_ok=True)
            with open(CREDENTIALS_FILE, "w") as f:
                json.dump(creds, f, indent=2)
        except Exception as e:
            _wlog(f"Could not save credentials: {e}", "warn")

        cloud = tinytuya.Cloud(
            apiRegion=region,
            apiKey=api_key,
            apiSecret=api_secret,
            apiDeviceID=device_id,
            configFile=CREDENTIALS_FILE,
        )
        if getattr(cloud, "error", None):
            err = cloud.error
            payload = err.get("Payload", err) if isinstance(err, dict) else err
            last_err = payload
            _wlog(f"Cloud auth error ({region}): {payload}", "warn")
            if _is_iot_core_expired(payload):
                return None, region, payload
            if _is_region_or_auth_error(payload) and region != regions[-1]:
                nxt = REGION_FALLBACKS.get(region, [None])[0]
                if nxt:
                    _wlog(f"REGION_RETRY: Trying alternate region {nxt} ...", "warn")
                continue
            return None, region, payload

        devices = cloud.getdevices(
            False, oldlist=state.get("wizard_devices") or [], include_map=True
        )
        if not isinstance(devices, list):
            err = (
                devices.get("Payload", devices)
                if isinstance(devices, dict)
                else devices
            )
            last_err = err
            _wlog(f"Cloud getdevices error ({region}): {err}", "warn")
            if _is_iot_core_expired(err):
                return None, region, err
            if _is_region_or_auth_error(err) and region != regions[-1]:
                nxt = REGION_FALLBACKS.get(region, [None])[0]
                if nxt:
                    _wlog(f"REGION_RETRY: Trying alternate region {nxt} ...", "warn")
                continue
            return None, region, err

        if region != api_region:
            _wlog(
                f"REGION_OK: Region {region} worked (selected was {api_region}). "
                "Credentials updated.",
                "found",
            )
        return cloud, region, devices

    return None, api_region, last_err


# ── Home Assistant / tuya_local sync ──────────────────────────


def _ha_storage_path():
    for p in HA_STORAGE_CANDIDATES:
        if p.exists():
            return p
    return HA_STORAGE_CANDIDATES[0]


def _read_entry_config():
    """entry_id -> host/local_key/protocol/device_id from HA storage (secrets not in REST)."""
    path = _ha_storage_path()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        log.warning("Cannot read HA config_entries (%s): %s", path, e)
        return {}
    out = {}
    for e in raw.get("data", {}).get("entries", []):
        if e.get("domain") != "tuya_local":
            continue
        merged = {**(e.get("data") or {}), **(e.get("options") or {})}
        out[e.get("entry_id")] = {
            "host": str(merged.get("host") or ""),
            "local_key": str(merged.get("local_key") or ""),
            "protocol_version": str(merged.get("protocol_version") or ""),
            "poll_only": bool(merged.get("poll_only", False)),
            "device_id": str(merged.get("device_id") or ""),
        }
    return out


def _ha_list_entries_rest():
    if not SUPERVISOR_TOKEN:
        raise RuntimeError(
            "Brak SUPERVISOR_TOKEN — włącz homeassistant_api / hassio_api w addonie i przebuduj."
        )
    r = requests.get(
        f"{HA_BASE}/config/config_entries/entry",
        headers=HA_HEADERS,
        timeout=20,
    )
    if r.status_code == 404:
        raise RuntimeError("Endpoint config_entries niedostępny na tej wersji HA")
    r.raise_for_status()
    return r.json()


def ha_refresh_entries():
    """Load tuya_local config entries into state."""
    entries_raw = _ha_list_entries_rest()
    cfg = _read_entry_config()
    out = []
    for e in entries_raw:
        if e.get("domain") != "tuya_local":
            continue
        if e.get("source") == "ignore" or e.get("disabled_by"):
            continue
        c = cfg.get(e.get("entry_id"), {})
        out.append(
            {
                "entry_id": e.get("entry_id"),
                "title": e.get("title") or "",
                "state": e.get("state") or "",
                "host": c.get("host", ""),
                "local_key": c.get("local_key", ""),
                "protocol_version": c.get("protocol_version", ""),
                "poll_only": c.get("poll_only", False),
                "device_id": c.get("device_id", ""),
            }
        )
    state["ha_entries"] = out
    state["ha_synced_at"] = datetime.now().isoformat()
    return out


def _ha_want_ips():
    ips = []
    for e in state.get("ha_entries") or []:
        host = (e.get("host") or "").strip()
        if not host or host.lower() == "auto":
            continue
        # skip hostnames; only literal IPs for wantips
        try:
            ipaddress.ip_address(host)
            ips.append(host)
        except ValueError:
            continue
    return sorted(set(ips))


def build_ha_mismatches():
    """Diff scanned devices vs tuya_local configured hosts."""
    devices = state.get("devices") or []
    by_id = {}
    by_ip = {}
    for d in devices:
        did = d.get("id") or d.get("gwId") or ""
        ip = _lan_ip_or_empty(d.get("ip") or "")
        if did:
            by_id[did] = d
        if ip:
            by_ip[ip] = d

    wizard_by_id = {}
    for w in state.get("wizard_devices") or []:
        wid = w.get("id") or w.get("gwId") or ""
        if wid:
            wizard_by_id[wid] = w

    rows = []
    for e in state.get("ha_entries") or []:
        configured = (e.get("host") or "").strip()
        dev_id = e.get("device_id") or ""
        scanned = by_id.get(dev_id) if dev_id else None
        if not scanned and configured:
            scanned = by_ip.get(configured)
        # also try match by title==name
        if not scanned:
            title = (e.get("title") or "").strip().lower()
            if title:
                for d in devices:
                    name = (d.get("name") or d.get("productName") or "").strip().lower()
                    if name and name == title:
                        scanned = d
                        if not dev_id:
                            dev_id = d.get("id") or d.get("gwId") or ""
                        break
        scanned_ip = _lan_ip_or_empty((scanned or {}).get("ip") or "")
        cloud_ip = ((scanned or {}).get("cloud_ip") or "").strip()
        cloud_key = ""
        if scanned and scanned.get("localKey"):
            cloud_key = scanned.get("localKey") or ""
        elif dev_id and wizard_by_id.get(dev_id):
            cloud_key = wizard_by_id[dev_id].get("key") or ""
        ha_key = e.get("local_key") or ""
        mismatch = bool(scanned_ip and configured and scanned_ip != configured)
        key_mismatch = bool(cloud_key and ha_key and cloud_key != ha_key)
        rows.append(
            {
                "entry_id": e.get("entry_id"),
                "title": e.get("title"),
                "state": e.get("state"),
                "configured_host": configured,
                "scanned_ip": scanned_ip,
                "cloud_ip": cloud_ip,
                "device_id": dev_id or (scanned or {}).get("id") or (scanned or {}).get("gwId") or "",
                "protocol_version": e.get("protocol_version") or "",
                "poll_only": bool(e.get("poll_only")),
                "local_key": ha_key,
                "cloud_key": cloud_key,
                "mismatch": mismatch,
                "key_mismatch": key_mismatch,
                "fixable": bool(mismatch and scanned_ip and _is_lan_ip(scanned_ip)),
                "discovery": (scanned or {}).get("discovery") or "",
            }
        )
    return rows


def ha_fix_host(entry_id, new_host):
    """Update tuya_local entry host via options flow (preserve other fields)."""
    if not SUPERVISOR_TOKEN:
        raise RuntimeError("Brak SUPERVISOR_TOKEN")
    new_host = (new_host or "").strip()
    if not new_host:
        raise RuntimeError("Brak nowego IP")
    if not _is_lan_ip(new_host):
        raise RuntimeError(
            f"Odrzucono IP {new_host} — to nie jest adres LAN (QR podaje IP z chmury Tuya). "
            "Najpierw uruchom skan sieci lokalnej."
        )

    entry = next(
        (e for e in (state.get("ha_entries") or []) if e.get("entry_id") == entry_id),
        None,
    )
    if not entry:
        # refresh once
        ha_refresh_entries()
        entry = next(
            (e for e in (state.get("ha_entries") or []) if e.get("entry_id") == entry_id),
            None,
        )
    if not entry:
        raise RuntimeError("Nie znaleziono wpisu tuya_local")

    protocol_version = entry.get("protocol_version") or "3.3"
    try:
        if str(protocol_version).lower() != "auto":
            protocol_version = float(protocol_version)
    except (TypeError, ValueError):
        pass

    fallbacks = {
        "host": new_host,
        "local_key": entry.get("local_key") or "",
        "protocol_version": protocol_version,
        "poll_only": bool(entry.get("poll_only")),
    }

    r = requests.post(
        f"{HA_BASE}/config/config_entries/options/flow",
        headers=HA_HEADERS,
        json={"handler": entry_id, "show_advanced_options": True},
        timeout=30,
    )
    if r.status_code >= 400:
        raise RuntimeError(f"options flow init failed: {r.text[:300]}")
    flow = r.json()
    flow_id = flow.get("flow_id")
    if not flow_id:
        raise RuntimeError("Brak flow_id z options flow")

    user_input = {}
    for field in flow.get("data_schema") or []:
        name = field.get("name")
        if not name:
            continue
        desc = field.get("description") or {}
        if name == "host":
            user_input[name] = new_host
        elif "suggested_value" in desc:
            user_input[name] = desc["suggested_value"]
        elif "default" in field:
            user_input[name] = field["default"]
        elif name in fallbacks:
            user_input[name] = fallbacks[name]

    if "host" not in user_input:
        user_input["host"] = new_host

    r2 = requests.post(
        f"{HA_BASE}/config/config_entries/options/flow/{flow_id}",
        headers=HA_HEADERS,
        json=user_input,
        timeout=30,
    )
    if r2.status_code >= 400:
        raise RuntimeError(f"options flow rejected: {r2.text[:300]}")
    result = r2.json()
    if result.get("type") == "form":
        errs = result.get("errors") or {}
        if errs:
            raise RuntimeError(f"options flow errors: {errs}")
        raise RuntimeError(
            f"options flow needs another step ({result.get('step_id')}) — dokończ w UI HA"
        )

    # refresh local cache
    try:
        ha_refresh_entries()
    except Exception as e:
        log.warning("Post-fix HA refresh failed: %s", e)
    return result


def _devices_from_tinytuya_map(found, want_ips):
    """Convert tinytuya.scanner.devices() result to our device list."""
    want = set(want_ips or [])
    out = []
    for ip, raw in (found or {}).items():
        if not isinstance(raw, dict):
            continue
        gw = raw.get("gwId") or raw.get("id") or raw.get("devId") or ""
        # tuyasync-style: no Device ID after direct probe => probe badge
        if not gw:
            discovery = "probe"
        elif ip in want:
            discovery = "scan"
        else:
            discovery = "broadcast"
        out.append(
            {
                "ip": ip,
                "gwId": gw,
                "id": gw,
                "version": str(raw.get("version") or raw.get("ver") or ""),
                "productKey": raw.get("productKey") or raw.get("product_key") or "",
                "mac": raw.get("mac") or "",
                "name": raw.get("name") or "",
                "localKey": raw.get("key") or raw.get("localKey") or "",
                "discovery": discovery,
                "online": True,
                "status": "online",
            }
        )
    return out


# ── scan ──────────────────────────────────────────────────────


def run_scan(duration=None, force_cidrs=None):
    if state["scanning"]:
        return
    duration = duration or SCAN_DURATION
    force_cidrs = force_cidrs or []
    state["last_force_cidrs"] = force_cidrs
    state.update(scanning=True, log=[], progress=0)

    # refresh HA hosts for wantips (best-effort)
    want_ips = []
    try:
        if SUPERVISOR_TOKEN:
            if not state.get("ha_entries"):
                ha_refresh_entries()
            want_ips = _ha_want_ips()
    except Exception as e:
        log.warning("HA wantips unavailable: %s", e)
        _log(f"HA refresh skipped: {e}", "warn")

    _log(
        f"Starting scan ({duration}s)"
        + (f", force={','.join(force_cidrs)}" if force_cidrs else "")
        + (f", probe HA IPs={len(want_ips)}" if want_ips else ""),
        "info",
    )
    _log(
        "Uwaga: skan UDP 6666/6667 może chwilowo kolidować z tuya-local. "
        "Auto-skan jest wyłączony domyślnie — skanuj ręcznie gdy potrzeba. "
        "Po odświeżeniu HA dopytywane są też znane IP (force-probe).",
        "warn",
    )

    start = time.time()

    def tick():
        while state["scanning"]:
            state["progress"] = min(
                90, int(100 * (time.time() - start) / (duration + 2))
            )
            time.sleep(1)

    threading.Thread(target=tick, daemon=True).start()

    try:
        scanned = []
        used_lib = False
        try:
            import tinytuya
            from tinytuya import scanner as tuya_scanner

            # Enrich names/keys from wizard cache.
            # tinytuya reads devices.json from CWD — use a dedicated workdir
            # (never overwrite DATA_FILE which has a different schema).
            work = Path("/data/scan_workdir")
            work.mkdir(parents=True, exist_ok=True)
            devices_json = work / "devices.json"
            try:
                if state.get("wizard_devices"):
                    devices_json.write_text(
                        json.dumps(state["wizard_devices"], indent=2), encoding="utf-8"
                    )
            except Exception:
                pass
            prev = os.getcwd()
            try:
                os.chdir(str(work))
                force_arg = False
                if force_cidrs:
                    force_arg = force_cidrs
                found = tuya_scanner.devices(
                    verbose=False,
                    color=False,
                    scantime=duration,
                    wantips=want_ips or None,
                    show_timer=False,
                    assume_yes=True,
                    forcescan=force_arg,
                    poll=False,
                )
            finally:
                try:
                    os.chdir(prev)
                except Exception:
                    pass
            if isinstance(found, dict):
                scanned = _devices_from_tinytuya_map(found, want_ips)
                used_lib = True
                for d in scanned:
                    label = d.get("discovery") or "scan"
                    _log(
                        f"[{label}] {d.get('ip')}  id={(d.get('id') or '—')[:16]}  v{d.get('version') or '?'}",
                        "found",
                    )
        except Exception as e:
            log.warning("Library scan failed, fallback to CLI: %s", e)
            _log(f"Library scan fallback: {e}", "warn")

        if not used_lib:
            cmd = [sys.executable, "-m", "tinytuya", "scan", str(duration)]
            if force_cidrs:
                cmd += ["-force"] + force_cidrs
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            raw = proc.stdout.read()
            proc.wait()
            lines = re.split(r"[\r\n]+", raw.decode("utf-8", errors="ignore"))
            for line in lines:
                s = line.strip()
                if "Address" in s and "Device ID" in s:
                    _log(s, "found")
                elif "Found" in s or "Complete" in s:
                    _log(s, "info")
            scanned = _parse(lines)
            for d in scanned:
                d["discovery"] = d.get("discovery") or "broadcast"

        # Pobierz dane z wizarda - indeksowane po device id
        wizard_data = {}
        for w in state.get("wizard_devices", []):
            dev_id = w.get("id") or w.get("gwId") or w.get("deviceId", "")
            if dev_id:
                wizard_data[dev_id] = w

        # Poprzednio zapisane urządzenia (fallback dla MAC/nazwy/itp.)
        prev_by_id = {}
        for p in state.get("devices", []):
            pid = p.get("id") or p.get("gwId", "")
            if pid:
                prev_by_id[pid] = p

        # Scal dane - skaner nadaje IP/wersję/MAC, wizard nadaje nazwę/klucz
        merged = []

        scanned_ids = set()
        for d in scanned:
            dev_id = d.get("id") or d.get("gwId", "")
            if dev_id:
                scanned_ids.add(dev_id)
            w = wizard_data.get(dev_id, {}) if dev_id else {}
            p = prev_by_id.get(dev_id, {}) if dev_id else {}

            # Match HA entry by IP for probe-only rows (no gwId yet)
            if not w and d.get("ip"):
                for e in state.get("ha_entries") or []:
                    if e.get("host") == d.get("ip") and e.get("device_id"):
                        w = wizard_data.get(e["device_id"], {})
                        if not dev_id and e.get("device_id"):
                            dev_id = e["device_id"]
                            d["id"] = dev_id
                            d["gwId"] = dev_id
                            scanned_ids.add(dev_id)
                        if not d.get("name") and e.get("title"):
                            d["name"] = e["title"]
                        break

            d["name"] = d.get("name") or w.get("name", "")
            d["productName"] = (
                w.get("productName")
                or w.get("product_name")
                or w.get("name", "")
                or d.get("productName", "")
            )
            d["productKey"] = _pick_product_key(w) or d.get("productKey", "")
            d["localKey"] = d.get("localKey") or w.get("key", "") or p.get("localKey", "")
            d["mac"] = d.get("mac") or w.get("mac", "") or p.get("mac", "")
            if w.get("mapping"):
                d["mapping"] = w.get("mapping")
            d["online"] = True
            d["status"] = "online"
            d["discovery"] = d.get("discovery") or "broadcast"

            if not d.get("name"):
                d["name"] = w.get("productName", p.get("name", f"Device {(dev_id or d.get('ip') or '?')[:8]}"))

            merged.append(d)

        # Dodaj urządzenia z wizarda których nie znaleziono w sieci
        for wdev in state.get("wizard_devices", []):
            wid = wdev.get("id") or wdev.get("gwId") or wdev.get("deviceId", "")
            if wid and wid not in scanned_ids:
                p = prev_by_id.get(wid, {})
                merged.append(
                    {
                        "ip": p.get("ip", ""),
                        "gwId": wid,
                        "id": wid,
                        "name": wdev.get(
                            "name", wdev.get("productName", p.get("name", f"Device {wid[:8]}"))
                        ),
                        "productName": wdev.get("productName", wdev.get("product_name", "")),
                        "productKey": _pick_product_key(wdev),
                        "localKey": wdev.get("key", p.get("localKey", "")),
                        "version": p.get("version", ""),
                        "mac": wdev.get("mac", "") or p.get("mac", ""),
                        "mapping": wdev.get("mapping") or p.get("mapping"),
                        "online": False,
                        "status": "cloud-only",
                        "discovery": "",
                    }
                )

        for d in merged:
            if not d.get("online"):
                if d.get("ip"):
                    d["status"] = "offline"
                else:
                    d["status"] = "cloud-only"

        state["devices"] = merged
        state["last_scan"] = datetime.now().isoformat()
        _save()
        with_key = sum(1 for d in merged if d.get("localKey"))
        if with_key:
            info = _save_export(reason="scan", snapshot=False)
            if info:
                _log(
                    f"Backup updated (/data/exports/latest.json) — {with_key} devices with Local Key",
                    "info",
                )
        v33 = sum(1 for d in scanned if str(d.get("version", "")).startswith("3.3"))
        v34 = sum(1 for d in scanned if str(d.get("version", "")).startswith("3.4"))
        probe_n = sum(1 for d in scanned if d.get("discovery") == "probe")
        _log(
            f"Completed — {len(scanned)} devices (v3.3:{v33} v3.4:{v34}, probe:{probe_n})",
            "info",
        )
    except Exception as e:
        _log(f"Error: {e}", "warn")
        log.exception("Details:")
    finally:
        state["scanning"] = False
        state["progress"] = 100


# ── wizard / cloud keys ───────────────────────────────────────


def _pick_device_id(explicit=None):
    """Cloud API needs any registered Device ID to resolve the account UID."""
    if explicit and str(explicit).strip():
        return str(explicit).strip()

    for d in state.get("devices") or []:
        did = d.get("id") or d.get("gwId") or ""
        if did:
            return did

    for w in state.get("wizard_devices") or []:
        did = w.get("id") or w.get("gwId") or w.get("deviceId") or ""
        if did:
            return did

    if os.path.exists(CREDENTIALS_FILE):
        try:
            with open(CREDENTIALS_FILE) as f:
                saved = json.load(f)
            did = (saved.get("apiDeviceID") or "").strip()
            if did:
                return did
        except Exception:
            pass
    return ""


def _is_iot_core_expired(err):
    text = str(err).lower()
    return (
        "28841002" in text
        or "iot core" in text
        or ("subscription" in text and "expired" in text)
        or "cloud development plan has expired" in text
    )


def _emit_cloud_error_help(err):
    """Log actionable, localizable help for common Tuya Cloud failures."""
    if _is_iot_core_expired(err):
        _wlog(
            "IOTCORE_EXPIRED: IoT Core subscription has expired (Tuya error 28841002). "
            "Local Keys cannot be fetched until renewed.",
            "warn",
        )
        _wlog("IOTCORE_STEP1: 1) Open https://iot.tuya.com and log in", "warn")
        _wlog(
            "IOTCORE_STEP2: 2) Go to Cloud → Cloud Services "
            "(not the paid Enterprise Subscribe page)",
            "warn",
        )
        _wlog(
            "IOTCORE_STEP3: 3) Find IoT Core → View details → Extend / Renew trial period",
            "warn",
        )
        _wlog(
            "IOTCORE_STEP4: 4) Form tips: Extension Period = longest free option (e.g. 6 months); "
            "Developer Identity = Individual Developer; Estimated Devices = Less than 50; "
            "Project Overview = personal Home Assistant / local keys (non-commercial); "
            "Contact Person/Info = your name + same email as Tuya account",
            "warn",
        )
        _wlog(
            "IOTCORE_STEP5: 5) Submit, wait for approval (often ~1 business day), "
            "then re-run Get keys in this add-on",
            "warn",
        )
        _wlog(
            "IOTCORE_NOTE: Do not buy the expensive commercial plan — use free trial extension.",
            "warn",
        )
        return

    text = str(err).lower()
    if "token" in text or "sign" in text or "1106" in text or "1004" in text:
        _wlog(
            "Hint: check API Key/Secret and Region (eu vs eu-w, us vs us-e).",
            "warn",
        )
        return

    if "permission" in text or "1010" in text:
        _wlog(
            "Hint: check API permissions, Link Tuya App Account, and IoT Core status.",
            "warn",
        )
        return

    _wlog(
        "Also verify: Devices → Link Tuya App Account, and IoT Core API is enabled.",
        "warn",
    )


def _merge_wizard_into_devices():
    """Apply cloud Local Keys / names onto the current device table without a LAN scan."""
    wizard_data = {}
    for w in state.get("wizard_devices") or []:
        wid = w.get("id") or w.get("gwId") or w.get("deviceId") or ""
        if wid:
            wizard_data[wid] = w
    if not wizard_data:
        return 0

    applied = 0
    existing_ids = set()
    for d in state.get("devices") or []:
        did = d.get("id") or d.get("gwId") or ""
        if not did:
            continue
        existing_ids.add(did)
        w = wizard_data.get(did)
        if not w:
            continue
        key = w.get("key") or ""
        if key and d.get("localKey") != key:
            d["localKey"] = key
            applied += 1
        elif key and not d.get("localKey"):
            d["localKey"] = key
            applied += 1
        if w.get("name"):
            d["name"] = w.get("name")
        d["productName"] = (
            w.get("productName") or w.get("product_name") or d.get("productName", "")
        )
        pk = _pick_product_key(w)
        if pk:
            d["productKey"] = pk
        if w.get("mac") and not d.get("mac"):
            d["mac"] = w.get("mac")
        if w.get("mapping"):
            d["mapping"] = w.get("mapping")

    # Cloud-only devices not seen on LAN yet
    for wid, w in wizard_data.items():
        if wid in existing_ids:
            continue
        state["devices"].append(
            {
                "ip": "",
                "gwId": wid,
                "id": wid,
                "name": w.get("name", w.get("productName", f"Device {wid[:8]}")),
                "productName": w.get("productName", w.get("product_name", "")),
                "productKey": _pick_product_key(w),
                "localKey": w.get("key", ""),
                "version": "",
                "mac": w.get("mac", ""),
                "mapping": w.get("mapping"),
                "online": False,
                "status": "cloud-only",
            }
        )
        if w.get("key"):
            applied += 1

    state["last_scan"] = state.get("last_scan") or datetime.now().isoformat()
    _save()
    return applied


def run_wizard(api_region, api_key, api_secret, api_device_id=None):
    """Fetch Local Keys via tinytuya.Cloud (same path as upstream wizard)."""
    if state["wizard_running"]:
        return
    state["wizard_running"] = True
    state["wizard_log"] = []
    _wlog("Starting Tuya Cloud key retrieval ...", "info")
    _wlog(f"Region: {api_region}  |  API Key: {api_key[:8]}…", "info")
    start_scan_after = False

    try:
        import tinytuya

        device_id = _pick_device_id(api_device_id)
        if not device_id:
            _wlog(
                "Missing Device ID. Run a network scan first, or paste any Device ID "
                "from iot.tuya.com (Devices list).",
                "warn",
            )
            return

        _wlog(f"Using Device ID: {device_id[:12]}… (needed to resolve cloud UID)", "info")

        cloud, used_region, result = _cloud_connect(
            api_region, api_key, api_secret, device_id
        )
        if cloud is None:
            _emit_cloud_error_help(result)
            return

        tuyadevices = result
        with_key = sum(1 for d in tuyadevices if d.get("key"))
        _wlog(
            f"Cloud returned {len(tuyadevices)} devices ({with_key} with Local Key) "
            f"[region={used_region}]",
            "found",
        )
        for d in tuyadevices[:30]:
            name = d.get("name") or d.get("id", "?")
            key = d.get("key") or ""
            if key:
                _wlog(f"📱 {name}  key={key[:6]}…", "found")
            else:
                _wlog(f"📱 {name}  (no key)", "info")

        try:
            raw = getattr(cloud, "getdevices_raw", None)
            if raw is not None:
                with open(RAW_CLOUD_FILE, "w") as f:
                    json.dump(raw, f, indent=2)
                _wlog(f"Raw cloud response saved to {RAW_CLOUD_FILE}", "info")
        except Exception as e:
            _wlog(f"Could not save raw cloud file: {e}", "warn")

        state["wizard_devices"] = tuyadevices
        try:
            with open(WIZARD_FILE, "w") as f:
                json.dump(tuyadevices, f, indent=2)
            _wlog(f"Saved {len(tuyadevices)} devices to {WIZARD_FILE}", "found")
        except Exception as e:
            _wlog(f"Could not save wizard cache: {e}", "warn")

        applied = _merge_wizard_into_devices()
        _wlog(
            f"Done — {len(tuyadevices)} cloud devices, {applied} Local Keys applied to table",
            "found",
        )
        info = _save_export(reason="cloud", snapshot=True)
        if info:
            _wlog(
                f"BACKUP_SAVED: Snapshot saved to {info.get('path')} "
                f"(also /data/exports/latest.json)",
                "found",
            )
        start_scan_after = True

    except Exception as e:
        _wlog(f"Wizard error: {e}", "warn")
        _emit_cloud_error_help(e)
        log.exception("Wizard error:")
    finally:
        state["wizard_running"] = False

    if start_scan_after and not state["scanning"]:
        _wlog("Refreshing network scan to merge IP + keys ...", "info")
        run_scan(force_cidrs=state.get("last_force_cidrs") or None)


# ── auto-scan ─────────────────────────────────────────────────


def auto_scan_loop():
    if not AUTO_SCAN:
        log.info("Auto-scan disabled (auto_scan=false) — only manual scans")
        return
    time.sleep(15)
    while True:
        run_scan()
        time.sleep(SCAN_INTERVAL)


# ── Flask ─────────────────────────────────────────────────────


@app.route("/")
def index():
    return send_from_directory(WWW_DIR, "index.html")


@app.route("/tuya-help.svg")
def tuya_help_svg():
    return send_from_directory(WWW_DIR, "tuya-help.svg", mimetype="image/svg+xml")


@app.route("/tuya-help.html")
def tuya_help_html():
    return send_from_directory(WWW_DIR, "tuya-help.html", mimetype="text/html")


@app.route("/ProjectManagement.png")
def project_management_png():
    return send_from_directory(WWW_DIR, "ProjectManagement.png", mimetype="image/png")


@app.route("/AccessIDSecret.png")
def access_id_secret_png():
    return send_from_directory(WWW_DIR, "AccessIDSecret.png", mimetype="image/png")


@app.route("/favicon.ico")
def favicon():
    fav = os.path.join(WWW_DIR, "favicon.png")
    if os.path.exists(fav):
        return send_from_directory(WWW_DIR, "favicon.png", mimetype="image/png")
    icon = os.path.join(WWW_DIR, "icon.png")
    if os.path.exists(icon):
        return send_from_directory(WWW_DIR, "icon.png", mimetype="image/png")
    return "", 204


# API routes - must be BEFORE the catch-all static route
@app.route("/api/status")
def api_status():
    devs = state["devices"]
    log.info(
        "API /api/status called - devices: %d, scanning: %s",
        len(devs),
        state["scanning"],
    )
    mismatches = build_ha_mismatches() if state.get("ha_entries") else []
    qr_logged_in = False
    qr_cache = {"cached": False}
    try:
        import qr_auth

        qr_logged_in = qr_auth.is_logged_in()
        qr_cache = qr_auth.cache_meta()
    except Exception:
        pass
    # Opportunistic cleanup if QR previously stored WAN IPs
    if _sanitize_device_ips(state.get("devices") or [], persist=True):
        mismatches = build_ha_mismatches() if state.get("ha_entries") else []
    result = {
        "scanning": state["scanning"],
        "devices": devs,
        "last_scan": state["last_scan"],
        "log": state["log"][-40:],
        "progress": state["progress"],
        "scan_interval": SCAN_INTERVAL,
        "auto_scan": AUTO_SCAN,
        "wizard_running": state["wizard_running"],
        "wizard_log": state["wizard_log"][-40:],
        "wizard_devices": state["wizard_devices"],
        "last_force_cidrs": state.get("last_force_cidrs", []),
        "last_export": state.get("last_export"),
        "ha_entries": state.get("ha_entries") or [],
        "ha_synced_at": state.get("ha_synced_at"),
        "ha_mismatches": mismatches,
        "ha_mismatch_count": sum(1 for m in mismatches if m.get("mismatch")),
        "ha_available": bool(SUPERVISOR_TOKEN),
        "qr_logged_in": qr_logged_in,
        "qr_scheme": QR_SCHEME,
        "qr_cache": qr_cache,
        "count": {
            "total": len(devs),
            "v33": sum(1 for d in devs if str(d.get("version", "")).startswith("3.3")),
            "v34": sum(1 for d in devs if str(d.get("version", "")).startswith("3.4")),
            "with_key": sum(1 for d in devs if d.get("localKey")),
            "with_mac": sum(1 for d in devs if d.get("mac")),
            "with_product_id": sum(1 for d in devs if d.get("productKey")),
            "online": sum(1 for d in devs if d.get("status") == "online"),
            "offline": sum(1 for d in devs if d.get("status") == "offline"),
            "cloud_only": sum(1 for d in devs if d.get("status") == "cloud-only"),
            "probe": sum(1 for d in devs if d.get("discovery") == "probe"),
        },
    }
    log.info(
        "API /api/status returning: scanning=%s, total=%d", state["scanning"], len(devs)
    )
    return jsonify(result)


@app.route("/api/ha/refresh", methods=["POST", "OPTIONS"])
def api_ha_refresh():
    if request.method == "OPTIONS":
        return ("", 204)
    try:
        entries = ha_refresh_entries()
        mismatches = build_ha_mismatches()
        return jsonify(
            {
                "ok": True,
                "count": len(entries),
                "entries": entries,
                "mismatches": mismatches,
                "mismatch_count": sum(1 for m in mismatches if m.get("mismatch")),
                "synced_at": state.get("ha_synced_at"),
            }
        )
    except Exception as e:
        log.exception("api_ha_refresh error")
        return jsonify({"ok": False, "msg": str(e)}), 500


@app.route("/api/ha/mismatches", methods=["GET"])
def api_ha_mismatches():
    try:
        if not state.get("ha_entries") and SUPERVISOR_TOKEN:
            ha_refresh_entries()
        mismatches = build_ha_mismatches()
        return jsonify(
            {
                "ok": True,
                "mismatches": mismatches,
                "mismatch_count": sum(1 for m in mismatches if m.get("mismatch")),
                "ha_synced_at": state.get("ha_synced_at"),
            }
        )
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)}), 500


@app.route("/api/ha/fix", methods=["POST", "OPTIONS"])
def api_ha_fix():
    if request.method == "OPTIONS":
        return ("", 204)
    data = request.json or {}
    entry_id = (data.get("entry_id") or "").strip()
    new_host = (data.get("host") or data.get("new_host") or "").strip()
    if not entry_id or not new_host:
        return jsonify({"ok": False, "msg": "Required: entry_id and host"}), 400
    try:
        ha_fix_host(entry_id, new_host)
        mismatches = build_ha_mismatches()
        return jsonify(
            {
                "ok": True,
                "msg": f"Updated host → {new_host}",
                "mismatches": mismatches,
                "mismatch_count": sum(1 for m in mismatches if m.get("mismatch")),
            }
        )
    except Exception as e:
        log.exception("api_ha_fix error")
        return jsonify({"ok": False, "msg": str(e)}), 500


@app.route("/api/scan", methods=["POST", "OPTIONS"])
def api_scan():
    if request.method == "OPTIONS":
        return ("", 204)
    log.info("API /api/scan called")
    if state["scanning"]:
        return jsonify({"ok": False, "msg": "Scan already running"}), 409
    dur = SCAN_DURATION
    force_cidrs = []
    if request.is_json and request.json:
        dur = int(request.json.get("duration", SCAN_DURATION))
        raw_force = request.json.get("forceCidrs", "")
        if isinstance(raw_force, str):
            force_cidrs = [c.strip() for c in raw_force.split(",") if c.strip()]
        elif isinstance(raw_force, list):
            force_cidrs = [str(c).strip() for c in raw_force if str(c).strip()]
    valid_cidrs = []
    for c in force_cidrs:
        try:
            ipaddress.ip_network(c, strict=False)
            valid_cidrs.append(c)
        except Exception:
            _log(f"Skipping invalid CIDR: {c}", "warn")
    log.info("Starting scan with duration: %s", dur)
    threading.Thread(target=run_scan, args=(dur, valid_cidrs), daemon=True).start()
    return jsonify(
        {
            "ok": True,
            "msg": f"Scan started ({dur}s)",
            "forceCidrs": valid_cidrs,
        }
    )


@app.route("/api/device/<dev_id>/dps", methods=["GET"])
def api_device_dps(dev_id):
    try:
        dev = _find_device(dev_id)
        if not dev:
            return jsonify({"ok": False, "msg": "Device not found"}), 404
        if not dev.get("ip"):
            return jsonify({"ok": False, "msg": "Device is not online (missing IP)"}), 400
        if not dev.get("localKey"):
            return jsonify({"ok": False, "msg": "Missing Local Key for device"}), 400

        tdev = _make_tuya_device(dev)
        payload = tdev.status() or {}
        dps = payload.get("dps", {}) if isinstance(payload, dict) else {}
        mapping = dev.get("mapping") or _wizard_mapping_for(
            dev.get("id") or dev.get("gwId")
        )
        return jsonify(
            {
                "ok": True,
                "device": {
                    "id": dev.get("id") or dev.get("gwId"),
                    "name": dev.get("name", ""),
                    "ip": dev.get("ip", ""),
                    "version": dev.get("version", ""),
                },
                "payload": payload,
                "dps": dps,
                "dps_named": _enrich_dps(dps, mapping),
                "mapping": mapping or {},
            }
        )
    except Exception as e:
        log.exception("api_device_dps error")
        return jsonify({"ok": False, "msg": str(e)}), 500


@app.route("/api/device/<dev_id>/probe", methods=["GET", "POST", "OPTIONS"])
def api_device_probe(dev_id):
    if request.method == "OPTIONS":
        return ("", 204)
    started = time.time()
    try:
        dev = _find_device(dev_id)
        if not dev:
            return jsonify({"ok": False, "result": "missing", "msg": "Device not found"}), 404
        if not dev.get("ip"):
            return jsonify(
                {
                    "ok": False,
                    "result": "no_ip",
                    "msg": "Missing IP — device offline or cloud-only",
                }
            ), 400
        if not dev.get("localKey"):
            return jsonify(
                {"ok": False, "result": "no_key", "msg": "Missing Local Key"}
            ), 400

        tdev = _make_tuya_device(dev, timeout=3, retries=1)
        payload = tdev.status() or {}
        ms = int((time.time() - started) * 1000)
        if isinstance(payload, dict) and payload.get("Error"):
            return jsonify(
                {
                    "ok": False,
                    "result": "error",
                    "msg": str(payload.get("Error") or payload),
                    "latency_ms": ms,
                    "payload": payload,
                }
            )
        dps = payload.get("dps", {}) if isinstance(payload, dict) else {}
        mapping = dev.get("mapping") or _wizard_mapping_for(
            dev.get("id") or dev.get("gwId")
        )
        return jsonify(
            {
                "ok": True,
                "result": "ok",
                "msg": "Local connection OK",
                "latency_ms": ms,
                "dps": dps,
                "dps_named": _enrich_dps(dps, mapping),
                "payload": payload,
            }
        )
    except Exception as e:
        ms = int((time.time() - started) * 1000)
        log.exception("api_device_probe error")
        return jsonify(
            {
                "ok": False,
                "result": "fail",
                "msg": str(e),
                "latency_ms": ms,
            }
        ), 500


@app.route("/api/device/<dev_id>/monitor", methods=["GET"])
def api_device_monitor(dev_id):
    """Poll local status a few times (lightweight live monitor)."""
    try:
        seconds = min(20, max(3, int(request.args.get("seconds", 8))))
        samples = min(10, max(2, int(request.args.get("samples", 4))))
        dev = _find_device(dev_id)
        if not dev:
            return jsonify({"ok": False, "msg": "Device not found"}), 404
        if not dev.get("ip"):
            return jsonify({"ok": False, "msg": "Missing IP"}), 400
        if not dev.get("localKey"):
            return jsonify({"ok": False, "msg": "Missing Local Key"}), 400

        tdev = _make_tuya_device(dev, timeout=3, retries=1)
        mapping = dev.get("mapping") or _wizard_mapping_for(
            dev.get("id") or dev.get("gwId")
        )
        interval = seconds / samples
        history = []
        for i in range(samples):
            t0 = time.time()
            try:
                payload = tdev.status() or {}
                dps = payload.get("dps", {}) if isinstance(payload, dict) else {}
                history.append(
                    {
                        "t": datetime.now().strftime("%H:%M:%S"),
                        "ok": True,
                        "latency_ms": int((time.time() - t0) * 1000),
                        "dps": dps,
                        "dps_named": _enrich_dps(dps, mapping),
                        "error": payload.get("Error")
                        if isinstance(payload, dict)
                        else None,
                    }
                )
            except Exception as e:
                history.append(
                    {
                        "t": datetime.now().strftime("%H:%M:%S"),
                        "ok": False,
                        "latency_ms": int((time.time() - t0) * 1000),
                        "dps": {},
                        "error": str(e),
                    }
                )
            if i < samples - 1:
                time.sleep(interval)
        ok_n = sum(1 for h in history if h.get("ok") and not h.get("error"))
        return jsonify(
            {
                "ok": ok_n > 0,
                "device": {
                    "id": dev.get("id") or dev.get("gwId"),
                    "name": dev.get("name", ""),
                    "ip": dev.get("ip", ""),
                    "version": dev.get("version", ""),
                },
                "samples": history,
                "summary": f"{ok_n}/{len(history)} OK",
            }
        )
    except Exception as e:
        log.exception("api_device_monitor error")
        return jsonify({"ok": False, "msg": str(e)}), 500


@app.route("/api/export/integration", methods=["GET", "POST", "OPTIONS"])
def api_export_integration():
    """Export devices for LocalTuya / tuya-local."""
    if request.method == "OPTIONS":
        return ("", 204)
    ids = None
    if request.method == "POST":
        body = request.json or {}
        ids = body.get("ids")
        fmt = (body.get("format") or request.args.get("format") or "json").lower()
        only_key = body.get("only_key", True)
        if isinstance(only_key, str):
            only_key = only_key != "0"
    else:
        fmt = (request.args.get("format") or "json").lower()
        only_key = request.args.get("only_key", "1") != "0"
        raw_ids = request.args.get("ids") or ""
        if raw_ids:
            ids = [x.strip() for x in raw_ids.split(",") if x.strip()]
    entries = _localtuya_entries(only_with_key=only_key, ids=ids)
    if fmt == "localtuya":
        body = _localtuya_yaml(entries)
        return app.response_class(body, mimetype="text/yaml")
    if fmt == "tuya_local" or fmt == "tuya-local":
        body = _tuya_local_yaml(entries)
        return app.response_class(body, mimetype="text/yaml")
    return jsonify(
        {
            "ok": True,
            "count": len(entries),
            "localtuya": entries,
            "yaml_localtuya": _localtuya_yaml(entries),
            "yaml_tuya_local": _tuya_local_yaml(entries),
        }
    )


@app.route("/api/export/tuya_local_push", methods=["POST", "OPTIONS"])
def api_tuya_local_push():
    """Selected devices → YAML + HA presence for tuya-local add/fix flow."""
    if request.method == "OPTIONS":
        return ("", 204)
    try:
        data = request.json or {}
        ids = data.get("ids")
        if ids is not None and not isinstance(ids, list):
            return jsonify({"ok": False, "msg": "ids must be a list"}), 400
        # Refresh HA map when possible so in_ha is current
        if SUPERVISOR_TOKEN and data.get("refresh_ha", True):
            try:
                ha_refresh_entries()
            except Exception as e:
                log.warning("HA refresh for push skipped: %s", e)
        rows = _tuya_local_push_rows(ids=ids)
        yaml_body = _tuya_local_yaml(
            [
                {
                    "friendly_name": r["friendly_name"],
                    "host": r["host"],
                    "device_id": r["device_id"],
                    "local_key": r["local_key"],
                    "protocol_version": r["protocol_version"],
                }
                for r in rows
            ]
        )
        return jsonify(
            {
                "ok": True,
                "count": len(rows),
                "in_ha": sum(1 for r in rows if r.get("in_ha")),
                "new": sum(1 for r in rows if not r.get("in_ha")),
                "ip_mismatches": sum(1 for r in rows if r.get("ip_mismatch")),
                "devices": rows,
                "yaml_tuya_local": yaml_body,
            }
        )
    except Exception as e:
        log.exception("tuya_local_push failed")
        return jsonify({"ok": False, "msg": str(e)}), 500


@app.route("/api/wizard", methods=["POST", "OPTIONS"])
def api_wizard():
    if request.method == "OPTIONS":
        return ("", 204)
    log.info("API /api/wizard called")
    if state["wizard_running"]:
        return jsonify({"ok": False, "msg": "Wizard already running"}), 409
    data = request.json or {}
    region = (data.get("region") or "eu").strip().lower()
    key = (data.get("apiKey") or "").strip()
    secret = (data.get("apiSecret") or "").strip()
    device_id = (data.get("deviceId") or data.get("apiDeviceID") or "").strip()
    if not key or not secret:
        return jsonify({"ok": False, "msg": "Required: apiKey and apiSecret"}), 400
    if not device_id and not _pick_device_id():
        return jsonify(
            {
                "ok": False,
                "msg": "Required: deviceId (or run network scan first so a Device ID is known)",
            }
        ), 400
    log.info(
        "Starting cloud key fetch: region=%s key=%s*** device=%s",
        region,
        key[:8],
        (device_id or _pick_device_id())[:12],
    )
    threading.Thread(
        target=run_wizard, args=(region, key, secret, device_id or None), daemon=True
    ).start()
    return jsonify({"ok": True, "msg": "Pobieranie kluczy z Tuya Cloud uruchomione"})


@app.route("/api/credentials", methods=["GET"])
def api_credentials():
    creds = _load_saved_credentials()
    if not creds:
        return jsonify({"ok": True, "saved": False})
    return jsonify({"ok": True, "saved": True, **creds})


@app.route("/api/export/save", methods=["POST", "OPTIONS"])
def api_export_save():
    if request.method == "OPTIONS":
        return ("", 204)
    if not (state.get("devices") or state.get("wizard_devices")):
        return jsonify({"ok": False, "msg": "No devices to save"}), 400
    info = _save_export(reason="manual", snapshot=True)
    return jsonify({"ok": True, "msg": "Backup saved", "export": info})


@app.route("/api/exports", methods=["GET"])
def api_exports():
    return jsonify({"ok": True, "exports": _list_exports()})


@app.route("/api/export/download", methods=["GET"])
def api_export_download():
    name = request.args.get("name", "latest.json")
    name = os.path.basename(name)
    if name == "latest.json":
        path = LATEST_EXPORT
    elif name.startswith("tuya_backup_") and name.endswith(".json"):
        path = os.path.join(EXPORT_DIR, name)
    else:
        return jsonify({"ok": False, "msg": "Invalid name"}), 400
    if not os.path.exists(path):
        # Build on the fly if latest missing but memory has data
        if name == "latest.json" and (state.get("devices") or state.get("wizard_devices")):
            _save_export(reason="download", snapshot=False)
        if not os.path.exists(path):
            return jsonify({"ok": False, "msg": "Backup not found"}), 404
    return send_from_directory(
        os.path.dirname(path),
        os.path.basename(path),
        as_attachment=True,
        download_name=name if name != "latest.json" else "tuya_devices_latest.json",
    )


@app.route("/api/export/restore", methods=["POST", "OPTIONS"])
def api_export_restore():
    if request.method == "OPTIONS":
        return ("", 204)
    data = request.json or {}
    name = data.get("name") or "latest.json"
    try:
        result = _restore_export(name)
        return jsonify({"ok": True, "msg": "Backup restored", **result})
    except FileNotFoundError:
        return jsonify({"ok": False, "msg": "Backup not found"}), 404
    except Exception as e:
        log.exception("restore error")
        return jsonify({"ok": False, "msg": str(e)}), 400


def _merge_qr_devices(qr_devices):
    """Merge QR-fetched keys/names into wizard_devices + devices table.

    QR sharing API often returns public WAN IPs (not LAN) — never use those as host.
    """
    if not qr_devices:
        return 0
    by_id = {}
    for w in state.get("wizard_devices") or []:
        wid = w.get("id") or w.get("gwId") or ""
        if wid:
            by_id[wid] = dict(w)
    for q in qr_devices:
        qid = q.get("id") or q.get("gwId") or ""
        if not qid:
            continue
        prev = by_id.get(qid, {})
        # Merge metadata, but handle IP carefully
        q_clean = {k: v for k, v in q.items() if v not in (None, "", {}, []) and k != "ip"}
        merged = {**prev, **q_clean}
        merged["id"] = qid
        merged["gwId"] = qid
        raw_ip = (q.get("ip") or "").strip()
        if _is_lan_ip(raw_ip):
            # Only set LAN IP if we don't already have a better LAN address
            if not _is_lan_ip(merged.get("ip") or ""):
                merged["ip"] = raw_ip
        elif raw_ip:
            merged["cloud_ip"] = raw_ip
            # Never keep public IP as local host
            if not _is_lan_ip(merged.get("ip") or ""):
                merged["ip"] = ""
        if q.get("key"):
            merged["key"] = q["key"]
            merged["localKey"] = q["key"]
        by_id[qid] = merged
    state["wizard_devices"] = list(by_id.values())
    try:
        with open(WIZARD_FILE, "w", encoding="utf-8") as f:
            json.dump(state["wizard_devices"], f, indent=2)
    except Exception as e:
        log.warning("Could not save wizard cache after QR: %s", e)

    # Apply keys onto current LAN/cloud table
    updated = 0
    devices = list(state.get("devices") or [])
    idx = { (d.get("id") or d.get("gwId") or ""): i for i, d in enumerate(devices) }
    for qid, w in by_id.items():
        key = w.get("key") or w.get("localKey") or ""
        lan_ip = _lan_ip_or_empty(w.get("ip") or "")
        cloud_ip = (w.get("cloud_ip") or "").strip()
        if qid in idx:
            d = devices[idx[qid]]
            if key:
                d["localKey"] = key
            if w.get("name") and not d.get("name"):
                d["name"] = w["name"]
            if w.get("productName"):
                d["productName"] = w["productName"]
            if w.get("productKey") and not d.get("productKey"):
                d["productKey"] = w["productKey"]
            if w.get("mapping"):
                d["mapping"] = w["mapping"]
            if cloud_ip:
                d["cloud_ip"] = cloud_ip
            # Never overwrite a good LAN IP with empty/cloud
            if lan_ip and not _is_lan_ip(d.get("ip") or ""):
                d["ip"] = lan_ip
            elif d.get("ip") and not _is_lan_ip(d.get("ip") or ""):
                if not d.get("cloud_ip"):
                    d["cloud_ip"] = d["ip"]
                d["ip"] = ""
                d["status"] = "cloud-only"
                d["online"] = False
            updated += 1
        else:
            devices.append(
                {
                    "ip": lan_ip,
                    "cloud_ip": cloud_ip,
                    "gwId": qid,
                    "id": qid,
                    "name": w.get("name") or w.get("productName") or f"Device {qid[:8]}",
                    "productName": w.get("productName") or "",
                    "productKey": w.get("productKey") or "",
                    "localKey": key,
                    "version": "",
                    "mac": "",
                    "mapping": w.get("mapping"),
                    "online": bool(lan_ip and w.get("online")),
                    "status": "online" if lan_ip else "cloud-only",
                    "discovery": "qr",
                }
            )
            updated += 1
    state["devices"] = devices
    _sanitize_device_ips(devices)
    _save()
    with_key = sum(1 for d in devices if d.get("localKey"))
    if with_key:
        _save_export(reason="qr", snapshot=False)
    return updated


@app.route("/api/qr/state", methods=["GET"])
def api_qr_state():
    try:
        import qr_auth

        return jsonify(
            {
                "ok": True,
                "logged_in": qr_auth.is_logged_in(),
                "scheme": QR_SCHEME,
                "available": True,
                "cache": qr_auth.cache_meta(),
            }
        )
    except Exception as e:
        return jsonify({"ok": False, "available": False, "msg": str(e)}), 500


@app.route("/api/qr/start", methods=["POST", "OPTIONS"])
def api_qr_start():
    if request.method == "OPTIONS":
        return ("", 204)
    try:
        import qr_auth

        data = request.json or {}
        user_code = (data.get("user_code") or data.get("userCode") or "").strip()
        scheme = (data.get("scheme") or QR_SCHEME or "smartlife").strip()
        result = qr_auth.start_login(user_code, scheme=scheme)
        return jsonify({"ok": True, **result})
    except Exception as e:
        # LoginError or import / network
        log.exception("QR start failed")
        code = 400 if "User Code" in str(e) or "user code" in str(e).lower() or "logowania" in str(e) else 502
        return jsonify({"ok": False, "msg": str(e)}), code


@app.route("/api/qr/poll", methods=["POST", "OPTIONS"])
def api_qr_poll():
    if request.method == "OPTIONS":
        return ("", 204)
    try:
        import qr_auth

        data = request.json or {}
        token = (data.get("token") or "").strip()
        if not token:
            return jsonify({"ok": False, "msg": "Missing token"}), 400
        result = qr_auth.poll_pending(token)
        return jsonify({"ok": True, **result})
    except Exception as e:
        log.exception("QR poll failed")
        return jsonify({"ok": False, "msg": str(e)}), 500


@app.route("/api/qr/fetch", methods=["POST", "OPTIONS"])
def api_qr_fetch():
    if request.method == "OPTIONS":
        return ("", 204)
    try:
        import qr_auth

        if not qr_auth.is_logged_in():
            return jsonify({"ok": False, "msg": "not_logged_in"}), 401
        body = request.json or {}
        force = bool(body.get("force") or body.get("refresh"))
        devices, meta = qr_auth.fetch_devices(force=force)
        n = _merge_qr_devices(devices)
        with_key = sum(1 for d in devices if d.get("key"))
        return jsonify(
            {
                "ok": True,
                "count": len(devices),
                "with_key": with_key,
                "merged": n,
                "devices": devices,
                "from_cache": bool(meta.get("from_cache")),
                "cache_age_s": meta.get("age_s"),
                "cache_fetched_at": meta.get("fetched_at"),
                "cache_ttl_s": meta.get("ttl_s"),
            }
        )
    except Exception as e:
        msg = str(e)
        log.exception("QR fetch failed")
        if "sesji" in msg.lower() or "session" in msg.lower() or "token" in msg.lower():
            try:
                import qr_auth

                qr_auth.clear_session()
            except Exception:
                pass
            return jsonify({"ok": False, "msg": "session_invalid", "detail": msg}), 401
        return jsonify({"ok": False, "msg": msg}), 502


@app.route("/api/qr/logout", methods=["POST", "OPTIONS"])
def api_qr_logout():
    if request.method == "OPTIONS":
        return ("", 204)
    try:
        import qr_auth

        qr_auth.clear_session()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)}), 500


@app.route("/api/devices")
def api_devices():
    return jsonify(state["devices"])


# Catch-all for static files - must be AFTER API routes
@app.route("/<path:filename>")
def static_files(filename):
    # Explicit MIME for SVG under Ingress (some proxies mishandle guess_type)
    if str(filename).lower().endswith(".svg"):
        return send_from_directory(WWW_DIR, filename, mimetype="image/svg+xml")
    if str(filename).lower().endswith(".png"):
        return send_from_directory(WWW_DIR, filename, mimetype="image/png")
    return send_from_directory(WWW_DIR, filename)


if __name__ == "__main__":
    _load()
    threading.Thread(target=auto_scan_loop, daemon=True).start()
    if SUPERVISOR_TOKEN:
        try:
            ha_refresh_entries()
            log.info("Loaded %d tuya_local entries from HA", len(state.get("ha_entries") or []))
        except Exception as e:
            log.warning("Initial HA refresh failed: %s", e)
    else:
        log.warning("SUPERVISOR_TOKEN missing — HA sync / Fix IP disabled until rebuild with APIs")
    log.info("Flask started on port %d (auto_scan=%s)", PORT, AUTO_SCAN)
    app.run(host="0.0.0.0", port=PORT, threaded=True)
