# Aurora A-121 «Кот-диспетчер» — TG-уведомления владельцу.
#
# Опциональный бот (НЕ TG-WS-прокси): токен и chat_id берутся из env
# AURORA_TG_BOT_TOKEN / AURORA_TG_CHAT_ID или из шифрованных настроек
# панели. Токен никогда не пишется в журнал и не отдаётся в API.
# Анти-спам: одно событие одного вида не чаще COOLDOWN_S.

import json
import os
import threading
import time
import urllib.request

import config

_LOCK = threading.RLock()
_LOG_MAX = 20
_LOG = []
_LAST_SENT = {}
COOLDOWN_S = 600
SEND_TIMEOUT_S = 10
API_BASE = "https://api.telegram.org"


def _now():
    return int(time.time())


def _log(msg):
    with _LOCK:
        _LOG.append({"ts": _now(), "msg": str(msg)[:200]})
        del _LOG[:max(0, len(_LOG) - _LOG_MAX)]


def _creds():
    token = str(config.get("notify_tg_token", "") or "").strip() \
        or os.environ.get("AURORA_TG_BOT_TOKEN", "").strip()
    chat = str(config.get("notify_tg_chat", "") or "").strip() \
        or os.environ.get("AURORA_TG_CHAT_ID", "").strip()
    return token, chat


def configured():
    token, chat = _creds()
    return bool(token and chat)


def enabled():
    return bool(config.get("notify_enabled", False)) and configured()


def send(text):
    """Отправить сообщение. Возвращает (ok, error). Токен не логируется."""
    token, chat = _creds()
    if not token or not chat:
        return False, "бот не настроен"
    body = json.dumps({"chat_id": chat, "text": str(text)[:3500],
                       "disable_web_page_preview": True}).encode("utf-8")
    req = urllib.request.Request(API_BASE + "/bot" + token + "/sendMessage",
                                 data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=SEND_TIMEOUT_S) as r:
            answer = json.loads(r.read().decode("utf-8"))
        if answer.get("ok"):
            return True, ""
        return False, str(answer.get("description") or "telegram отказал")[:160]
    except Exception as e:
        # В ошибке может оказаться URL с токеном — вычищаем его.
        msg = str(e).replace(token, "***") if token else str(e)
        return False, msg[:160]


def event(kind, msg):
    """Событие с анти-спамом. Отправка в фоне, канал не блокируется."""
    if not enabled():
        return False
    kind = str(kind or "event")[:40]
    with _LOCK:
        last = _LAST_SENT.get(kind, 0)
        if _now() - last < COOLDOWN_S:
            return False
        _LAST_SENT[kind] = _now()
    text = "🐾 Aurora: %s" % str(msg)[:3000]

    def _run():
        ok, err = send(text)
        _log(("отправлено: " if ok else "ошибка: ") + (str(msg)[:120] if ok else err))

    threading.Thread(target=_run, daemon=True).start()
    return True


def test():
    """Проверочное сообщение (кнопка в панели), без кулдауна."""
    if not configured():
        return {"ok": False, "error": "бот не настроен: нужен токен и chat_id"}
    ok, err = send("🐾 Aurora: проверка уведомлений — связь есть, мяу!")
    _log("тест: " + ("ок" if ok else err))
    return {"ok": ok, "error": err}


def status():
    """Состояние для панели. Секреты не отдаём никогда."""
    with _LOCK:
        log = list(reversed(_LOG))
    return {
        "ok": True,
        "enabled": bool(config.get("notify_enabled", False)),
        "configured": configured(),
        "cooldown_s": COOLDOWN_S,
        "log": log,
    }
