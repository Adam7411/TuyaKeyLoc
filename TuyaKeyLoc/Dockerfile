FROM python:3.11-alpine

RUN apk add --no-cache gcc musl-dev libffi-dev openssl-dev jpeg-dev zlib-dev && \
    pip install --no-cache-dir \
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
