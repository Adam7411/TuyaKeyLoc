#!/usr/bin/env python3
"""QR login for Smart Life / Tuya Smart via tuya-device-sharing-sdk.

Uses Home Assistant's public device-sharing app credentials (same as the
official HA Tuya integration and tuya-local-key). No IoT Core / Access ID needed.
"""

from __future__ import annotations

import base64
import io
import json
import logging
import os
import stat
import tempfile
import threading
import time
from types import SimpleNamespace

log = logging.getLogger(__name__)

# Published HA device-sharing client (not a secret — in HA / tuya-local source).
CLIENT_ID = "HA_3y9q4ak7g4ephrvke"
SCHEMA = "haauthorize"
TOKEN_FIELDS = ("t", "uid", "expire_time", "access_token", "refresh_token")
REQUEST_TIMEOUT_SECONDS = 60
PENDING_TTL = 180

SESSION_FILE = os.environ.get("QR_SESSION_FILE", "/data/qr_session.json")
DEVICES_CACHE_FILE = os.environ.get(
    "QR_DEVICES_CACHE_FILE", "/data/qr_devices_cache.json"
)
DEFAULT_SCHEME = os.environ.get("QR_SCHEME", "smartlife")
CACHE_TTL_SECONDS = int(os.environ.get("QR_CACHE_TTL", str(24 * 3600)))

_session_lock = threading.Lock()
_pending_lock = threading.Lock()
_pending = {}  # token -> {user_code, created_at, scheme}


class LoginError(Exception):
    """QR login could not be started (bad user code, etc.)."""


def load_session(path=None):
    path = path or SESSION_FILE
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def save_session(session, path=None):
    path = path or SESSION_FILE
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    with _session_lock:
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".qr-session-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(session, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            try:
                os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
            os.replace(tmp, path)
        except BaseException:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise


def clear_devices_cache(path=None):
    path = path or DEVICES_CACHE_FILE
    try:
        os.remove(path)
    except OSError:
        pass


def load_devices_cache(path=None):
    path = path or DEVICES_CACHE_FILE
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict) or not isinstance(data.get("devices"), list):
            return None
        return data
    except (OSError, json.JSONDecodeError):
        return None


def save_devices_cache(devices, path=None):
    path = path or DEVICES_CACHE_FILE
    payload = {
        "fetched_at": time.time(),
        "fetched_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "count": len(devices or []),
        "devices": devices or [],
    }
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    with _session_lock:
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".qr-devices-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            try:
                os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
            os.replace(tmp, path)
        except BaseException:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise
    return payload


def cache_meta(cache=None):
    cache = cache if cache is not None else load_devices_cache()
    if not cache:
        return {"cached": False, "age_s": None, "fetched_at": None, "ttl_s": CACHE_TTL_SECONDS}
    fetched = float(cache.get("fetched_at") or 0)
    age = max(0, int(time.time() - fetched)) if fetched else None
    fresh = age is not None and age < CACHE_TTL_SECONDS
    return {
        "cached": True,
        "fresh": fresh,
        "age_s": age,
        "fetched_at": cache.get("fetched_at_iso"),
        "ttl_s": CACHE_TTL_SECONDS,
        "count": cache.get("count") or len(cache.get("devices") or []),
    }


def clear_session(path=None):
    path = path or SESSION_FILE
    clear_devices_cache()
    try:
        os.remove(path)
    except OSError:
        pass
    with _pending_lock:
        _pending.clear()


class _SessionSaver:
    def __init__(self, path, session):
        self.path = path
        self.session = session

    def update_token(self, token_info):
        self.session["token_info"] = {k: token_info.get(k) for k in TOKEN_FIELDS}
        save_session(self.session, self.path)


def mint_qr_token(user_code):
    from tuya_sharing import LoginControl

    resp = LoginControl().qr_code(CLIENT_ID, SCHEMA, user_code)
    if not resp.get("success"):
        raise LoginError(
            f"Nie udało się rozpocząć logowania [{resp.get('code')}]: {resp.get('msg')}"
        )
    return resp["result"]["qrcode"]


def qr_png_data_url(content):
    import qrcode

    buf = io.BytesIO()
    qrcode.make(content).save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"


def _session_from_info(info, user_code):
    return {
        "client_id": CLIENT_ID,
        "user_code": user_code,
        "terminal_id": info.get("terminal_id"),
        "endpoint": info.get("endpoint") or info.get("end_point"),
        "token_info": {k: info.get(k) for k in TOKEN_FIELDS},
    }


def poll_login(token, user_code):
    from tuya_sharing import LoginControl

    try:
        ok, result = LoginControl().login_result(token, CLIENT_ID, user_code)
    except Exception:
        return None
    return _session_from_info(result, user_code) if ok else None


def _cleanup_pending(now=None):
    now = now or time.time()
    dead = [
        t
        for t, info in _pending.items()
        if now - info.get("created_at", 0) > PENDING_TTL
    ]
    for t in dead:
        _pending.pop(t, None)


def start_login(user_code, scheme=None):
    """Start QR login. Returns {token, qr data-url, scheme}."""
    user_code = (user_code or "").strip()
    if not user_code:
        raise LoginError("Podaj User Code z aplikacji Smart Life.")
    scheme = (scheme or DEFAULT_SCHEME or "smartlife").strip()
    if scheme not in ("smartlife", "tuyaSmart"):
        scheme = "smartlife"

    token = mint_qr_token(user_code)
    with _pending_lock:
        _cleanup_pending()
        _pending[token] = {
            "user_code": user_code,
            "scheme": scheme,
            "created_at": time.time(),
        }
    qr_payload = f"{scheme}--qrLogin?token={token}"
    return {
        "token": token,
        "qr": qr_png_data_url(qr_payload),
        "scheme": scheme,
        "expires_in": PENDING_TTL,
    }


def poll_pending(token):
    """Returns status: pending | confirmed | expired."""
    token = (token or "").strip()
    with _pending_lock:
        _cleanup_pending()
        info = _pending.get(token)
        user_code = info["user_code"] if info else None
    if not user_code:
        return {"status": "expired"}

    session = poll_login(token, user_code)
    if session:
        save_session(session)
        with _pending_lock:
            _pending.pop(token, None)
        return {"status": "confirmed"}
    return {"status": "pending"}


def _apply_request_timeout():
    try:
        import tuya_sharing.customerapi as customerapi
        import tuya_sharing.user as user

        customerapi.DEFAULT_TIMEOUT = user.DEFAULT_TIMEOUT = REQUEST_TIMEOUT_SECONDS
    except (ImportError, AttributeError):
        pass


def build_manager(session, path=None):
    from tuya_sharing import Manager

    path = path or SESSION_FILE
    _apply_request_timeout()
    saver = _SessionSaver(path, session)
    return Manager(
        session.get("client_id", CLIENT_ID),
        session["user_code"],
        session["terminal_id"],
        session["endpoint"],
        session["token_info"],
        saver,
    )


def _plain(value):
    if isinstance(value, SimpleNamespace):
        value = vars(value)
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value


def device_to_wizard(device):
    """Normalize SDK device into our wizard_devices shape."""
    did = getattr(device, "id", None) or ""
    key = getattr(device, "local_key", None) or ""
    name = getattr(device, "name", None) or ""
    product_id = getattr(device, "product_id", None) or ""
    product_name = getattr(device, "product_name", None) or name
    ip = getattr(device, "ip", None) or ""
    uuid = getattr(device, "uuid", None) or ""
    mapping = {}
    # local_strategy: {dp_id: {code, ...}} — useful for DPS names
    strategy = getattr(device, "local_strategy", None) or {}
    if isinstance(strategy, dict):
        for dp_id, meta in strategy.items():
            meta = _plain(meta) if not isinstance(meta, dict) else meta
            if isinstance(meta, dict):
                mapping[str(dp_id)] = {
                    "code": meta.get("code") or meta.get("statusCode") or "",
                    "name": meta.get("code") or meta.get("statusCode") or f"dp_{dp_id}",
                }
    # Sharing API often returns public WAN IP — keep separately, not as LAN host
    try:
        import ipaddress as _ipaddress

        def _is_private(addr):
            try:
                a = _ipaddress.ip_address(str(addr).split("%")[0])
                return bool(a.is_private or a.is_link_local)
            except ValueError:
                return False

        lan_ip = ip if _is_private(ip) else ""
        cloud_ip = "" if lan_ip else (ip or "")
    except Exception:
        lan_ip, cloud_ip = "", ip or ""
    return {
        "id": did,
        "gwId": did,
        "name": name,
        "key": key,
        "localKey": key,
        "productName": product_name,
        "productKey": product_id,
        "product_id": product_id,
        "ip": lan_ip,
        "cloud_ip": cloud_ip,
        "uuid": uuid,
        "category": getattr(device, "category", None) or "",
        "online": bool(getattr(device, "online", False)),
        "mapping": mapping,
        "source": "qr",
    }


def fetch_devices(session=None, path=None, force=False):
    """Return wizard-shaped devices; use 24h disk cache unless force=True.

    Returns (devices, meta) where meta describes cache hit/miss.
    """
    path = path or SESSION_FILE
    session = session or load_session(path)
    if not session:
        raise LoginError("Brak sesji QR — zaloguj się ponownie.")

    if not force:
        cache = load_devices_cache()
        meta = cache_meta(cache)
        if cache and meta.get("fresh"):
            return list(cache.get("devices") or []), {
                **meta,
                "from_cache": True,
            }

    manager = build_manager(session, path)
    manager.update_device_cache()
    devices = [device_to_wizard(d) for d in manager.device_map.values()]
    saved = save_devices_cache(devices)
    meta = cache_meta(saved)
    meta["from_cache"] = False
    return devices, meta


def is_logged_in():
    return bool(load_session())
