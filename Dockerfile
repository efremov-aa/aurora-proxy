# Aurora — собственный VPN-прокси (VLESS Reality + Telegram WS)
# Образ: python + xray.v26.9.9 (бинар+геофайлы).
FROM python:3.12-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iproute2 \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Xray: конфиг собирает Aurora, поэтому нужны бинарь + геофайлы.
ARG XRAY_VER=v26.9.9
ARG XRAY_URL="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VER}/Xray-linux-64.zip"
RUN curl -fsSL -o /tmp/xray.zip "${XRAY_URL}" \
    && python3 - <<'EOF'
import zipfile, os, shutil
os.makedirs('/usr/local/lib/xray', exist_ok=True)
with zipfile.ZipFile('/tmp/xray.zip') as z:
    for name in ('xray', 'geoip.dat', 'geosite.dat'):
        with z.open(name) as src, open('/usr/local/lib/xray/' + name, 'wb') as dst:
            shutil.copyfileobj(src, dst)
os.chmod('/usr/local/lib/xray/xray', 0o755)
EOF
RUN ln -s /usr/local/lib/xray/xray /usr/local/bin/xray && rm -f /tmp/xray.zip

WORKDIR /app
COPY . /app

ENV XRAY_MANAGE=proc \
    AURORA_HOST=0.0.0.0 \
    AURORA_WHITE_IP=

RUN mkdir -p /app/data && python3 -m compileall -q /app || true

EXPOSE 8890 8899 8897 1443 8443
VOLUME ["/app/data"]

CMD ["python3", "/app/run.py"]