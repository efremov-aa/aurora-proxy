#!/bin/bash
set -euo pipefail
umask 077
DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="${AURORA_DATA_DIR:-$DIR/data}"
RUNTIME_DIR="${AURORA_TGWS_RUNTIME_DIR:-${XDG_RUNTIME_DIR:-/tmp}/aurora-tgws-runtime}"
mkdir -p "$DATA_DIR" "$RUNTIME_DIR"
chmod 700 "$RUNTIME_DIR"
export AURORA_DATA_DIR="$DATA_DIR"
RUNTIME_SECRET="$(mktemp "$RUNTIME_DIR/secret.XXXXXX")"
trap 'rm -f "$RUNTIME_SECRET"' EXIT HUP INT TERM
PYTHONPATH="$DIR${PYTHONPATH:+:$PYTHONPATH}" python3 - "$RUNTIME_SECRET" <<'PY'
import os
import sys
import tgws

path = sys.argv[1]
value = tgws._get_secret()
fd = os.open(path, os.O_WRONLY | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="ascii", newline="\n") as stream:
    stream.write(value + "\n")
    stream.flush()
    os.fsync(stream.fileno())
PY
exec 3< "$RUNTIME_SECRET"
rm -f "$RUNTIME_SECRET"
trap - EXIT HUP INT TERM
cd "$DIR"
export PYTHONPATH="$DIR${PYTHONPATH:+:$PYTHONPATH}"
TGWS_PORT="${AURORA_TGWS_PORT:-${TGWS_PORT:-443}}"
exec python3 -m proxy.tg_ws_proxy --host 0.0.0.0 --port "$TGWS_PORT" --secret-fd 3 -v
