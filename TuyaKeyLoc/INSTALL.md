# Instalacja TuyaKeyLoc

## Lokalny add-on (folder `/addons`)

1. Utwórz folder: `/addons/tuya_scanner/` (slug folderu zostaje — nie zmieniaj nazwy katalogu)
2. Skopiuj pliki addonu do tego folderu
3. W HA: **Ustawienia → System → Dodatki → sklep → ⋮ → Sprawdź aktualizacje**
4. Pojawi się sekcja **Lokalne dodatki** → **TuyaKeyLoc**
5. Zainstaluj, uruchom, otwórz panel (**TuyaKeyLoc** w menu HA)

```bash
mkdir -p /addons/tuya_scanner/www
```

Panel: Ingress (lewe menu HA → TuyaKeyLoc) lub port `7080`.

## Konfiguracja

W HA → Ustawienia → Dodatki → TuyaKeyLoc → Konfiguracja:

- `scan_interval` — interwał auto-skanu (gdy `auto_scan: true`)
- `scan_duration` — czas skanu UDP
- `auto_scan` — domyślnie `false` (unikaj kolizji z tuya-local)
- `qr_scheme` — `smartlife` lub `tuyaSmart`
