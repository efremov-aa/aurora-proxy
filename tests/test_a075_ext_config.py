# -*- coding: utf-8 -*-
"""A075 — контракт браузерного расширения: GET /api/ext/config."""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import api
import config
import subs

failures = []


def check(cond, message):
    if not cond:
        failures.append(message)


class Req:
    """Минимальный запрос: путь + перехват ответа."""

    def __init__(self, path):
        self.path = path
        self.status = None
        self.body = None

    def _send(self, status, ctype, body):
        self.status = status
        self.body = body


def call(path, sub=None, state=None):
    old_lookup = subs.by_token_status
    old_state = subs.access_state
    subs.by_token_status = lambda token: (sub, 200) if sub is not None else (None, 404)
    subs.access_state = lambda s: state or {"ok": True, "status": 200, "reason": "active"}
    try:
        req = Req(path)
        api._ext_config(req)
        return req
    finally:
        subs.by_token_status = old_lookup
        subs.access_state = old_state


import json

# 1) конфиг в состоянии config.py
check(bool(getattr(config, "BUY_URL", "")), "config.BUY_URL пуст")
check(isinstance(getattr(config, "RULES_VERSION", ""), str) and config.RULES_VERSION, "config.RULES_VERSION пуст")
check(isinstance(getattr(config, "RU_BYPASS", None), bool), "config.RU_BYPASS не bool")
host = config.ext_proxy_host()
check(isinstance(host, str) and host and "0.0.0.0" not in host, "ext_proxy_host() некорректен: %r" % host)

# 2) маршрут есть в обоих зеркалах и живёт в публичном блоке (до _access_allowed)
for name in ("api.py", "windows/api.py"):
    text = (ROOT / name).read_text(encoding="utf-8-sig")
    check('"/api/ext/config"' in text, "%s: нет маршрута /api/ext/config" % name)
    route = text.index('if path == "/api/ext/config"')
    gate = text.index("if not _access_allowed(self)")
    check(route < gate, "%s: маршрут ext/config после гейта доступа" % name)
    check("_TRANSPORT_EXEMPT = (\"/api/ext/config\"" in text, "%s: маршрут не в _TRANSPORT_EXEMPT" % name)
    check("def _ext_config(req):" in text, "%s: нет функции _ext_config" % name)
    check("Access-Control-Allow-Origin" not in text, "%s: CORS не должен выставляться" % name)

# 3) формат ответа
sub = {"uid": "u1", "plan": "basic", "expires": 4102444800, "used_bytes": 1234,
       "limit_bytes": 107374182400, "enabled": True, "blocked_until": 0}
req = call("/api/ext/config?token=abc", sub=sub)
check(req.status == 200, "200 ожидался, получено %s" % req.status)
data = json.loads(req.body.decode("utf-8"))
for key in ("proxy", "mode", "ru_bypass", "blocked", "plan", "expires", "used", "limit",
            "buy_url", "rules_version"):
    check(key in data, "в ответе нет %s" % key)
check(data["proxy"]["port"] == config.XRAY_PORT, "порт прокси не совпал с XRAY_PORT")
check(data["proxy"]["host"] == host, "хост прокси не совпал с ext_proxy_host()")
check(data["mode"] in ("vpn", "direct"), "mode вне vpn/direct: %r" % data["mode"])
check(data["blocked"] is False, "blocked должен быть False")
check(data["plan"] == "basic" and data["used"] == 1234, "план/трафик не отдались")

# 4) блокировка и режим direct
req = call("/api/ext/config?token=abc", sub=dict(sub, enabled=False))
check(json.loads(req.body.decode("utf-8"))["blocked"] is True, "enabled=False должен давать blocked=True")
req = call("/api/ext/config?token=abc", sub=dict(sub, blocked_until=4102444800))
check(json.loads(req.body.decode("utf-8"))["blocked"] is True, "blocked_until в будущем должен давать blocked=True")

# 5) истёкшая подписка: мастер-код + buy_url + «купить»
for reason, status in (("expired", 410), ("traffic_exhausted", 429), ("disabled", 403)):
    req = call("/api/ext/config?token=abc", sub=sub,
               state={"ok": False, "status": status, "reason": reason})
    body = json.loads(req.body.decode("utf-8"))
    check(req.status == status, "%s: код %s ожидался, получено %s" % (reason, status, req.status))
    check(body.get("buy") is True, "%s: нет флага buy" % reason)
    check(body.get("buy_url") == config.BUY_URL, "%s: нет buy_url" % reason)
    check(bool(body.get("message")), "%s: нет текста с предложением купить" % reason)
    check("proxy" not in body, "%s: при отказе не отдаём прокси" % reason)

# 6) неизвестный токен и мусорный вход
req = call("/api/ext/config?token=nope", sub=None)
check(req.status == 404, "404 ожидался, получено %s" % req.status)
req = call("/api/ext/config", sub=sub)
check(req.status == 400, "400 без токена ожидался, получено %s" % req.status)
req = call("/api/ext/config?token=" + ("x" * 300), sub=sub)
check(req.status == 400, "400 для слишком длинного токена ожидался, получено %s" % req.status)

if failures:
    for line in failures:
        print("FAIL:", line)
    raise SystemExit(1)
print("A075_EXT_CONFIG_OK")
