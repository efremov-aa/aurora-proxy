# Aurora v1.3.0 — безопасность панели: admin-токен, rate-limit, защита файлов данных.
# Токен: env AURORA_ADMIN_TOKEN либо data/admin_secret.json (генерится при enable).
# Все POST /api/* без валидного Bearer-токена получают 401, когда токен установлен.

import hashlib
import hmac
import json
import os
import secrets
import threading
import time

import config

_SECRET_FILE = os.path.join(config.DATA_DIR, "admin_secret.json")
_TOKEN = {"value": ""}          # "" = авторизация выключена
_LOCK = threading.Lock()

# --- rate-limit: 10 неудачных попыток авторизации с одного IP за 60с ---
_RL_WINDOW_S = 60.0
_RL_MAX_FAILS = 10
_RL = {}                        # {ip: [ts_fail, ...]}
_RL_LOCK = threading.Lock()


def _load_secret():
    """Читает токен из env или файла (env имеет приоритет)."""
    env_tok = (os.environ.get("AURORA_ADMIN_TOKEN") or "").strip()
    if env_tok:
        return env_tok
    try:
        with open(_SECRET_FILE, "r", encoding="utf-8") as f:
            return (json.load(f).get("admin_token") or "").strip()
    except (OSError, ValueError):
        return ""


def init():
    """Загружает токен при старте, chmod на data/ (Linux)."""
    _TOKEN["value"] = _load_secret()
    if _TOKEN["value"]:
        config.log("security: admin-token активен (auth=required)")
    else:
        config.log("security: admin-token не задан (auth=off)")
    protect_files()


def enabled():
    return bool(_TOKEN["value"])


def status():
    """Маскированное состояние авторизации для UI (без полного токена)."""
    tok = _TOKEN["value"] or ""
    masked = ""
    if len(tok) >= 8:
        masked = "%s…%s" % (tok[:4], tok[-4:])
    elif tok:
        masked = "…%s" % tok[-4:]
    return {"enabled": bool(tok), "masked": masked}


def _rate_ok(ip):
    now = time.time()
    with _RL_LOCK:
        fails = [t for t in _RL.get(ip, []) if now - t < _RL_WINDOW_S]
        _RL[ip] = fails
        return len(fails) < _RL_MAX_FAILS


def _rate_fail(ip):
    with _RL_LOCK:
        _RL.setdefault(ip, []).append(time.time())


def check(headers, client_ip=""):
    """Проверка Authorization: Bearer <token>. True=ок (или auth выключен)."""
    if not enabled():
        return True
    if not _rate_ok(client_ip or "?"):
        return False
    auth = ""
    for k, v in (headers or {}).items():
        if k.lower() == "authorization":
            auth = v
            break
    got = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    if got and hmac.compare_digest(got.encode(), _TOKEN["value"].encode()):
        return True
    _rate_fail(client_ip or "?")
    return False


def rotate():
    """Генерирует новый токен в data/admin_secret.json. Возвращает токен."""
    new_tok = secrets.token_hex(24)
    with _LOCK:
        payload = {"admin_token": new_tok, "created_at": int(time.time())}
        tmp = _SECRET_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        os.replace(tmp, _SECRET_FILE)
        if os.name != "nt":
            try:
                os.chmod(_SECRET_FILE, 0o600)
            except OSError:
                pass
        _TOKEN["value"] = new_tok
    config.log("security: admin-token ротирован")
    return new_tok


def protect_files():
    """chmod 700 data/ и 600 *.json (Linux best-effort)."""
    if os.name == "nt":
        return
    try:
        os.chmod(config.DATA_DIR, 0o700)
    except OSError:
        pass
    try:
        for name in os.listdir(config.DATA_DIR):
            if name.endswith(".json"):
                try:
                    os.chmod(os.path.join(config.DATA_DIR, name), 0o600)
                except OSError:
                    pass
    except OSError:
        pass
