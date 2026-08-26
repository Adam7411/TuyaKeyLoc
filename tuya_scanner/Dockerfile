FROM python:3.11-slim

# Use Debian-based slim image to avoid Alpine compilation issues for cryptography
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    libjpeg-dev \
    zlib1g-dev \
    cargo \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
      tinytuya \
      requests \
      flask \
      flask-cors \
      "tuya-device-sharing-sdk>=0.2.15" \
      "qrcode[pil]>=7.4" \
      "cryptography>=41.0"

COPY run.sh /run.sh
COPY scanner.py /scanner.py
COPY qr_auth.py /qr_auth.py
COPY www/ /var/www/

VOLUME ["/data"]

RUN chmod +x /run.sh

ENTRYPOINT ["/run.sh"]
