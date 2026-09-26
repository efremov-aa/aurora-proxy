# -*- coding: utf-8 -*-
"""A-111 (P1): лицензионный гейт PRO-функций - модуль extgate и его контракты."""
import io
import os
import re
import shutil
import stat
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import config  # noqa: E402
import extgate  # noqa: E402

I18N = ["ext.head", "ext.locked", "ext.pro", "ext.expired",
        "ext.na", "ext.buy", "ext.offline"]


def read(p):
    with io.open(str(p), encoding="utf-8") as f:
        return f.read()


def check(cond, name):
    if not cond:
        raise AssertionError(name)
    print("ok", name)


def reset():
    # фоновые чеки из state() могут быть в полёте - дожидаемся, иначе
    # single-flight вернёт None и сценарий проверит чужой результат
    deadline = time.time() + 5
    while extgate._INFLIGHT is not None and time.time() < deadline:
        time.sleep(0.05)
    extgate._CACHE = {}
    extgate._SNAPSHOT = {}
    extgate._LAST_CHECK = 0.0
    extgate._INFLIGHT = None
    extgate._BG_STARTED = False


# --- изолируем кэш в temp, чтобы не писать в репозиторий
_TMP = tempfile.mkdtemp(prefix="aurora_ext_")
_OLD_FILE = extgate.LICENSE_FILE
extgate.LICENSE_FILE = os.path.join(_TMP, "ext_license.json")

# --- логика PRO: всё, что не free
os.environ.pop("AURORA_EXT_PRO_PLANS", None)
check(extgate.is_pro("prem") is True, "is_pro prem")
check(extgate.is_pro("basic") is True, "is_pro basic")
check(extgate.is_pro("free") is False, "is_pro free")
check(extgate.is_pro("") is False, "is_pro empty")
check(extgate.is_pro(None) is False, "is_pro none")

# --- явный список PRO-планов (значение читается из config при импорте)
_OLD_PRO = config.EXT_PRO_PLANS
config.EXT_PRO_PLANS = "basic,prem"
check(extgate.is_pro("basic") is True, "allowlist basic")
check(extgate.is_pro("vip") is False, "allowlist deny vip")
config.EXT_PRO_PLANS = _OLD_PRO

# --- адрес мастера и интервалы заданы конфигом
check(config.EXT_MASTER_URL.startswith("http"), "master url")
check(config.EXT_MASTER_URL.endswith("8890"), "master port")
check(int(config.EXT_CHECK_INTERVAL_S) >= 60, "check interval")
check(int(config.EXT_OFFLINE_MAX_S) >= 3600, "offline max")

# --- сценарии HTTP: подменяем транспорт и идентичность
_OLD_FETCH = extgate._fetch
_OLD_ID = extgate.identity
extgate.identity = lambda: ("test-token", "test-credential")


def fake(payload, code):
    # так же, как настоящий _fetch: 4xx без тела = заглушка с кодом
    if payload is None and isinstance(code, int) and code >= 400:
        payload = {"error": "http-%s" % code}

    def _f(token, credential, timeout=None):
        return (payload, code)
    return _f


# --- пустое состояние (ни кэша, ни мастера) не ломает панель
# проверяем через _rebuild без фонового чека, чтобы не поймать single-flight
reset()
empty = extgate._rebuild()
check(isinstance(empty, dict), "state is dict")
check(empty.get("is_pro") is False, "empty state not pro")
check(bool(empty.get("state")), "empty state label")


def run_case(payload, code, plan_expect=None, state_expect=None, pro_expect=None):
    s = {}
    for _ in range(5):
        reset()
        extgate._fetch = fake(payload, code)
        extgate.check(force=True)
        s = extgate.state()
        if state_expect is None or s.get("state") == state_expect:
            break
        time.sleep(0.2)
    if state_expect is not None:
        check(s.get("state") == state_expect, "http %s state=%s" % (code, state_expect))
    if plan_expect is not None:
        check(s.get("plan") == plan_expect, "http %s plan" % code)
    if pro_expect is not None:
        check(s.get("is_pro") is pro_expect, "http %s is_pro" % code)
    return s


ok_body = {"ok": True, "plan": "prem", "status": "active",
           "expires": int(time.time()) + 86400, "used_bytes": 10,
           "limit_bytes": 100, "device_count": 1, "limit_devices": 3,
           "rules_version": "1", "buy_url": "https://t.me/aurorahomevpn_bot"}
s = run_case(ok_body, 200, plan_expect="prem", state_expect="ok", pro_expect=True)
check(s.get("buy_url", "").find("t.me") > 0, "buy url from master")
check(os.path.exists(extgate.LICENSE_FILE), "cache file written")
if os.name != "nt":
    mode = stat.S_IMODE(os.stat(extgate.LICENSE_FILE).st_mode)
    check(mode == 0o600, "cache mode 0600")

free_body = dict(ok_body)
free_body["plan"] = "free"
run_case(free_body, 200, plan_expect="free", state_expect="free", pro_expect=False)

run_case(None, 403, state_expect="blocked", pro_expect=False)
run_case(None, 404, state_expect="unknown", pro_expect=False)
# 410 = подписка истекла: панель обязана показать честный экран с buy_url
expired = run_case({"ok": False, "buy_url": "https://t.me/aurorahomevpn_bot"},
                   410, state_expect="expired", pro_expect=False)
check(expired.get("buy_url", "").find("t.me") > 0, "expired keeps buy_url")
run_case(None, 429, state_expect="slow_down")

# --- без токена сеть не трогаем, но и не падаем
reset()
extgate._fetch = lambda *a, **k: (_ for _ in ()).throw(AssertionError("network used"))
extgate.identity = lambda: ("", "")
extgate.check(force=True)
check(extgate.state().get("is_pro") is False, "no token not pro")

# --- офлайн: старый кэш честно помечается просроченным
reset()
extgate._fetch = _OLD_FETCH
extgate.identity = _OLD_ID
extgate._CACHE = {"plan": "prem", "state": "ok", "token": "t",
                  "credential": "c", "buy_url": "https://t.me/aurorahomevpn_bot",
                  "checked_at": int(time.time()) - int(config.EXT_OFFLINE_MAX_S) - 60}
extgate._rebuild()
off = extgate.state()
check(off.get("state") == "expired", "offline expired")
check(bool(off.get("last_error")), "offline last_error")
check(off.get("is_pro") is False, "offline not pro")

# --- свежий кэш без сети: PRO остаётся открытым, но с пометкой offline
reset()
extgate._CACHE = {"plan": "prem", "state": "ok", "token": "t", "credential": "c",
                  "checked_at": int(time.time()) - 60}
extgate._rebuild(offline_reason="offline")
fresh = extgate.state()
check(fresh.get("is_pro") is True, "cached pro")

# --- feature()/require()
check(extgate.feature("whitelist") is True, "feature pro on")
check(extgate.feature("no-such-feature") is False, "feature unknown off")
check(extgate.require("whitelist") is None, "require open")
reset()
extgate._CACHE = {"plan": "free", "state": "ok", "checked_at": int(time.time())}
extgate._rebuild()
check(extgate.feature("adblock") is False, "feature free off")
req = extgate.require("adblock")
check(isinstance(req, dict) and req.get("ok") is False, "require closed dict")
check("buy_url" in req, "require buy_url")
check(isinstance(extgate.require(" vpn "), dict), "require unknown fail-closed")

# --- статические контракты деревьев
api_l = read(ROOT / "api.py")
api_w = read(ROOT / "windows" / "api.py")
for tag, txt in (("linux", api_l), ("windows", api_w)):
    check("import extgate" in txt, tag + " import extgate")
    check('st["ext"]' in txt, tag + " state ext")
    check('"/api/ext/license"' in txt, tag + " route license")

run_l = read(ROOT / "run.py")
run_w = read(ROOT / "windows" / "run.py")
for tag, txt in (("linux", run_l), ("windows", run_w)):
    check("extgate.start_background()" in txt, tag + " start_background")

cfg_l = read(ROOT / "config.py")
cfg_w = read(ROOT / "windows" / "config.py")
for tag, txt in (("linux", cfg_l), ("windows", cfg_w)):
    check("EXT_MASTER_URL" in txt, tag + " EXT_MASTER_URL")
    check("EXT_OFFLINE_MAX_S" in txt, tag + " EXT_OFFLINE_MAX_S")
    check("EXT_PRO_PLANS" in txt, tag + " EXT_PRO_PLANS")

# --- UI: гейт, карточка и переводы
app = read(ROOT / "ui" / "app.js")
check("PRO-GATE" in app, "ui pro-gate block")
# A-112: витрина PRO не прячется целиком (клиент должен видеть прайс и кнопку
# «Купить»), поэтому признак data-gh="hide" у карточек убран - гейт работает
# по data-ext-feature и вешает pro-lock с бейджем.
check("data-gh" not in app, "ui data-gh не прячет витрину (A-112)")
check("pro-lock" in app, "ui pro-lock метка вместо скрытия")
check('class="pro-tag"' in app or "pro-tag" in app, "ui pro-tag бейдж PRO")
check("data-ext-feature" in app, "ui data-ext-feature")
check("applyExtGate" in app, "ui applyExtGate")
check("/api/ext/license" in app, "ui license fetch")
check("loadExt()" in app, "ui loadExt call")
check("'ext-buy'" in app, "ui ext-buy action")
html = read(ROOT / "ui" / "index.html")
check('id="ext-card"' in html, "ui ext-card")
check('data-act="ext-buy"' in html, "ui ext-buy markup")
css = read(ROOT / "ui" / "style.css")
check(".ext-card" in css, "ui ext-card css")
for key in I18N:
    check(len(re.findall(r"'" + re.escape(key) + r"':", app)) == 10,
          "i18n x10 " + key)

# --- зеркала windows
for name in ("app.js", "index.html", "style.css"):
    check(read(ROOT / "ui" / name) == read(ROOT / "windows" / "ui" / name),
          "mirror ui/" + name)
check(read(ROOT / "extgate.py") == read(ROOT / "windows" / "extgate.py"),
      "mirror extgate.py")
check(config.VERSION == "1.9.3", "version contract")

# --- чистим temp
extgate.LICENSE_FILE = _OLD_FILE
shutil.rmtree(_TMP, ignore_errors=True)

print("A111_EXTGATE_OK")
