#!/bin/bash
# Aurora: запуск Telegram WS-прокси. Секрет в data/tg_secret.txt (генерится при первом запуске).
# Порт по умолчанию 443 (привилегированный — нужен net.ipv4.ip_unprivileged_port_start=0
# либо запуск от root; 1443 блокировался РКН снаружи).
DIR="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$DIR/data"
TGWS_PORT="${TGWS_PORT:-443}"
SECRET=$(cat "$DIR/data/tg_secret.txt" 2>/dev/null)
if [ -z "$SECRET" ]; then
  SECRET=$(python3 -c "import secrets; print(secrets.token_hex(16))")
  echo "$SECRET" > "$DIR/data/tg_secret.txt"
fi
exec python3 -m proxy.tg_ws_proxy --host 0.0.0.0 --port "$TGWS_PORT" --secret "$SECRET"
