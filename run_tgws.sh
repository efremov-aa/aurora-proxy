#!/bin/bash
# Aurora: запуск Telegram WS-прокси. Секрет в data/tg_secret.txt (генерится при первом запуске).
DIR="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$DIR/data"
SECRET=$(cat "$DIR/data/tg_secret.txt" 2>/dev/null)
if [ -z "$SECRET" ]; then
  SECRET=$(python3 -c "import secrets; print(secrets.token_hex(16))")
  echo "$SECRET" > "$DIR/data/tg_secret.txt"
fi
exec python3 -m proxy.tg_ws_proxy --host 0.0.0.0 --port 1443 --secret "$SECRET"