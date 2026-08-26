FROM python:3.11-slim

# Install build deps to compile Python packages that require native extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    libssl-dev \
    libffi-dev \
    libjpeg-dev \
    zlib1g-dev \
    cargo \
    rustc \
    pkg-config \
    git \
  && rm -rf /var/lib/apt/lists/*

# Ensure latest pip/setuptools/wheel
RUN pip install --upgrade pip setuptools wheel

# Install Python dependencies
RUN pip install --no-cache-dir \
      tinytuya \
      requests \
      flask \
      flask-cors \
      "tuya-device-sharing-sdk>=0.2.15" \
      "qrcode[pil]>=7.4" \
      "cryptography>=41.0"

# Copy addon files
COPY run.sh /run.sh
COPY scanner.py /scanner.py
COPY qr_auth.py /qr_auth.py
COPY www/ /var/www/

VOLUME ["/data"]

# Ensure entrypoint is executable
RUN chmod +x /run.sh

ENTRYPOINT ["/run.sh"]
