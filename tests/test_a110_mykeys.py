# -*- coding: utf-8 -*-
"""A-110 (P0): устройство = ключ - инструкция подключения и честные счётчики."""
import hashlib
import io
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import config  # noqa: E402
import subs  # noqa: E402

I18N = ["myk.head", "myk.hint", "myk.until", "myk.traffic", "myk.devices",
        "myk.how", "myk.copy", "myk.copy-ok", "myk.empty", "myk.unlim",
        "dev.conn", "nav.conn", "nav.keys-proxy"]


def read(p):
    with io.open(str(p), encoding="utf-8") as f:
        return f.read()


def md5(p):
    return hashlib.md5(read(p).encode("utf-8")).hexdigest()


def check(cond, name):
    if not cond:
        raise AssertionError(name)
    print("ok", name)


# --- нормализация платформы
check(subs.normalize_platform("iOS") == "iphone", "platform iphone")
check(subs.normalize_platform("Windows") == "pc", "platform pc")
check(subs.normalize_platform("android") == "android", "platform android")
check(subs.normalize_platform("") == "pc", "platform default")

# --- инструкция: ПК -> vless://, телефон -> ссылка подписки, без happ://crypt5
# внешний вход в тестовой сборке выключен, поэтому подменяем только провайдеры
# параметров ссылки и адреса подписки (config.vless_public() читает env/секреты)
_old_params = subs._vless_params
_old_ext = config.external_link_host
PARAMS = {"host": "10.1.136.56", "port": 8443, "pbk": "x" * 43, "sid": "ab12cd34",
          "sni": "www.microsoft.com", "flow": "xtls-rprx-vision"}
subs._vless_params = lambda: dict(PARAMS)
config.external_link_host = lambda: "10.1.136.56"
sub = {"uid": "u1", "name": "Test", "plan": "basic", "token": "tok-1",
       "used_bytes": 10, "limit_bytes": 1000,
       "keys": [{"id": "11111111-2222-3333-4444-555555555555", "created": 1,
                 "remark": ""}]}
pc = subs.device_instructions(sub, "pc")
check(pc["ok"] and pc["platform"] == "pc", "pc ok")
check(pc["vless"].startswith("vless://"), "pc vless link")
check("security=reality" in pc["vless"], "pc reality params")
check(pc["link_ready"] is True, "pc link_ready")
check("v2rayN" in pc["app"], "pc app name")
check("happ://crypt5" not in pc["text"], "pc no happ payload")
ph = subs.device_instructions(sub, "iphone")
check(ph["mobile"] and ph["platform"] == "iphone", "iphone mobile")
check("Happ" in ph["text"] and "App Store" in ph["text"], "iphone happ text")
# happ://crypt5/... не выдаём как ссылку для вставки - только упоминаем в пояснении
check("happ://crypt5" not in (ph["vless"] or "") and
      "happ://crypt5" not in (ph["sub_url"] or "") and
      "happ://crypt5" not in (ph["qr"] or ""), "iphone no happ link")
check("не вставляем" in ph["text"], "iphone explains happ payload")
check(ph["sub_url"].startswith("http"), "iphone sub url")
check(bool(ph["qr"]), "qr payload")
check(subs.device_instructions({"keys": []}, "pc")["vless"] == "", "no key -> empty link")
check(subs.device_instructions(None)["ok"] is False, "bad record")
# внешний вход выключен - инструкция честная, а не пустая
subs._vless_params = lambda: {}
off = subs.device_instructions(sub, "pc")
check(off["ok"] is True and off["link_ready"] is False, "no vless -> ok but no link")
check("внешний вход" in off["text"], "hint about external access")
subs._vless_params = _old_params
config.external_link_host = _old_ext

# --- роут и хендлер в api.py
for tree in ("", os.path.join("windows", "")):
    a = read(ROOT / tree / "api.py")
    tag = tree or "linux/"
    check('"/api/subs/device/instructions": self._subs_device_instructions,' in a,
          "route %s" % tag)
    check("def _subs_device_instructions(self, data):" in a, "handler %s" % tag)
    check('"devices": dev_count' in a and '"devices_limit": dev_limit' in a,
          "subs_safe counters %s" % tag)
    s = read(ROOT / tree / "subs.py")
    check("def device_instructions(sub" in s, "subs.device_instructions %s" % tag)
    check("def normalize_platform(value):" in s, "subs.normalize_platform %s" % tag)
    check("happ://crypt5" in s, "mascot note about happ payload %s" % tag)

# --- роут не попал в админские (клиентская операция)
a = read(ROOT / "api.py")
check("device/instructions" not in a.split("SUBS_ADMIN_POSTS = ")[1].split(")")[0],
      "instructions not admin-only")

# --- UI
app = read(ROOT / "ui" / "app.js")
check("function renderMyKeys(j)" in app, "renderMyKeys")
check("$('mykeys-list')" in app, "mykeys-list box")
check("postJSON('/api/subs/device/instructions'" in app, "instructions request")
check("'sub-how': function (t) { window.subHow(t); }," in app, "act sub-how")
check("'sub-copy': function (t) { subCopy(t.getAttribute('data-copy-what') || 'link'); },"
      in app, "act sub-copy")
check("renderMyKeys(j);" in app, "renderMyKeys call in loadSubs")
for key in I18N:
    check(len(re.findall(r"'" + re.escape(key) + r"':", app)) == 10, "i18n %s x10" % key)

html = read(ROOT / "ui" / "index.html")
for needle in ('id="mykeys-list"', 'id="mykeys-count"', 'data-i18n="myk.head"',
               'data-i18n="dev.conn"', 'data-i18n="nav.keys-proxy"'):
    check(needle in html, "html %s" % needle)

# --- зеркала windows
check(md5(ROOT / "ui" / "app.js") == md5(ROOT / "windows" / "ui" / "app.js"),
      "app.js parity")
check(md5(ROOT / "ui" / "index.html") == md5(ROOT / "windows" / "ui" / "index.html"),
      "index.html parity")
check("function renderMyKeys(j)" in read(ROOT / "windows" / "ui" / "app.js"),
      "windows renderMyKeys")

check(config.VERSION == "1.9.3", "version unchanged")
print("A110_MYKEYS_OK")
