
<img width="436" height="79" alt="Screenshot" src="https://github.com/user-attachments/assets/2d6b7edb-fcad-4df2-a3c4-63fd70abe5b0" />

# TuyaKeyLoc (Home Assistant Add-on)

TuyaKeyLoc discovers Tuya devices on your local network, retrieves Local Keys (Smart Life QR login or IoT Cloud), and merges everything into one diagnostic table — with IP sync helpers for tuya-local.

---

## What This Add-on Does

1. **Scan local network** for Tuya devices (IP, Device ID, protocol version, MAC when available)
2. **Fetch Local Keys** via **Smart Life / Tuya Smart QR login** (no IoT Core) **or** classic Access ID / Secret
3. **Merge everything into one table** for diagnostics and automation preparation

---

## Features

- Local Tuya device discovery (UDP/TCP scan)
- Optional **forced subnet scan (CIDR)** for harder network layouts
- **QR login** (Smart Life / Tuya Smart) — no `iot.tuya.com` / IoT Core required
  - Auto-fetch keys right after QR confirm
  - 24h device-list cache (`/data/qr_devices_cache.json`) with manual cloud refresh
- Classic Tuya Cloud key retrieval (Access ID / Secret + IoT Core)
- **Push to tuya-local**: select devices → YAML + HA status (new / already added / Fix IP)
- Unified device table with:
  - Name, IP, MAC, Version, Device ID, Product ID, Local Key, Status
- Data quality summary (online, keys, MAC, product ID)
- Per-device DPS diagnostics
- Persistent backups in `/data/exports`
- Export helpers for **LocalTuya** and **tuya-local** YAML
- Per-device **Probe** and short **Monitor**
- Multi-language UI (EN / PL / DE / FR)

---

## Installation

### 1) Add this repository to Home Assistant

1. Open Home Assistant
2. Go to **Settings -> Add-ons -> Add-on Store**
3. Click the menu icon (top-right, three dots) -> **Repositories**
4. Add your repository URL:

```text
https://github.com/Adam7411/tuya_scanner
```

### 2) Install the add-on

1. Find **TuyaKeyLoc** in the Add-on Store
2. Click **Install**
3. Start the add-on
4. Open the Web UI

---

## Local Keys — Method A (QR login, recommended)

1. In Smart Life (or Tuya Smart): **Me → ⚙️ → Account and Security → User Code**
2. In the add-on: paste User Code → choose app → **Show QR and log in**
3. In the app: **+ → Scan** the QR → confirm login
4. Keys are fetched automatically (or use **Fetch keys / Refresh from cloud**)

Option `qr_scheme`: `smartlife` (default) or `tuyaSmart`.

---

## Local Keys — Method B (iot.tuya.com / IoT Core)

1. Log in to [iot.tuya.com](https://iot.tuya.com)
2. Create or open a Cloud project
3. Copy Access ID / Secret from Overview
4. Run cloud-key retrieval in the add-on UI

---

## Recommended Workflow

1. Run **Network Scan**
2. Fetch keys via **QR login** (or classic Cloud credentials)
3. Review the merged table / **Push tuya-local**

---

## Troubleshooting

- **No devices found in local scan** — try forced CIDR (e.g. `192.168.100.0/24`)
- **Missing Local Keys** — prefer QR if IoT Core expired (`28841002`)
- **Public 185.x IPs after QR** — those are cloud WAN addresses; LAN IP comes only from network scan
- **Device cloud-only** — known in cloud but not reachable locally

---

## Disclaimer

Scanning, protocol behavior, and cloud/key access depend on Tuya platform availability and your local network.
