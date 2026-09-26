# -*- coding: utf-8 -*-
"""A-161: браузерное расширение как PRO-фича (архив, гейт, кнопка «Скачать»)."""
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

FAILED = []


def read(rel):
    return io.open(os.path.join(ROOT, rel), "r", encoding="utf-8", newline="").read()


def check(cond, name):
    if cond:
        print("ok", name)
    else:
        FAILED.append(name)
        print("FAIL", name)


# 1. архивы расширения лежат в assets/ и читаются git
assets = os.path.join(ROOT, "assets")
for name in ("aurora-extension-chrome-0.1.0.zip", "aurora-extension-edge-0.1.0.zip"):
    p = os.path.join(assets, name)
    check(os.path.isfile(p) and os.path.getsize(p) > 2000, "assets %s present" % name)
gi = read(".gitignore")
check("!assets/" in gi and "!assets/aurora-extension-*.zip" in gi, "gitignore allows extension zips")

# 2. config: путь и белый список имён
for tree in ("", os.path.join("windows")):
    cfg = read(os.path.join(tree, "config.py") if tree else "config.py")
    check("EXT_ASSETS_DIR" in cfg, "config %s EXT_ASSETS_DIR" % (tree or "linux"))
    check('"chrome": "aurora-extension-chrome-0.1.0.zip"' in cfg, "config %s EXT_PACKAGES chrome" % (tree or "linux"))
    check('"edge": "aurora-extension-edge-0.1.0.zip"' in cfg, "config %s EXT_PACKAGES edge" % (tree or "linux"))

# 3. api: эндпоинт скачивания под гейтом, имя файла только из белого списка
for tree in ("", "windows"):
    api = read(os.path.join(tree, "api.py"))
    tag = tree or "linux"
    check('if path == "/api/ext/download":' in api, "api %s route" % tag)
    check('extgate.require("extension")' in api, "api %s gated by require" % tag)
    check("def _send_binary(" in api, "api %s _send_binary" % tag)
    check('"application/zip"' in api, "api %s zip ctype" % tag)
    check("Content-Disposition" in api, "api %s content-disposition" % tag)
    check("os.path.basename(_name)" in api, "api %s basename-only path" % tag)
    # эндпоинт не должен быть публичным/exempt
    _a = api.find("_TRANSPORT_EXEMPT")
    _b = api.find("def _tls_env")
    _block = api[_a:_b] if (_a >= 0 and _b > _a) else ""
    check(_block and "/api/ext/download" not in _block, "api %s download not exempt" % tag)
    # роут стоит рядом с защищённым license, а не в публичном блоке
    check(api.index('if path == "/api/ext/download":') > api.index("trusted = _trusted_read(self)"), "api %s after auth gate" % tag)

# 4. extgate: триал открывает extension/adblock, но не whitelist/unlimited
eg = read("extgate.py")
check('TRIAL_FEATURES = ("extension", "adblock")' in eg, "extgate TRIAL_FEATURES")
check("def trial_ok():" in eg, "extgate trial_ok")
check("if key in TRIAL_FEATURES and trial_ok():" in eg, "extgate feature honours trial")
check(eg.count("TRIAL_FEATURES") >= 2, "extgate TRIAL_FEATURES used")
check(read(os.path.join("windows", "extgate.py")) == eg, "extgate mirror bit-for-bit")

# 5. UI: кнопка скачивания, триал в гейте, карточка статуса
app = read(os.path.join("ui", "app.js"))
check("data-ext-download" in app, "ui download buttons")
check("'ext-download': function (t)" in app, "ui ACTS ext-download")
check("function extDownload(target)" in app and "window.extDownload = extDownload" in app, "ui extDownload")
check("var trial = !pro && !!e.ok && (e.state === 'ok' || e.state === 'free');" in app, "ui trial detection")
check("var card = $('ext-card');" in app, "ui ext-card filled again")
check("_t('ext.trial')" in app, "ui uses ext.trial")
check("/api/ext/download?target=" in app, "ui hits download endpoint")
for key in ("ext.trial", "ext.dl-chrome", "ext.dl-edge"):
    n = len(re.findall(r"'%s':" % re.escape(key), app))
    check(n == 10, "i18n %s x10 (%d)" % (key, n))

# 6. зеркала UI бит-в-бит
for n in ("app.js", "index.html", "style.css"):
    check(read(os.path.join("ui", n)) == read(os.path.join("windows", "ui", n)), "mirror ui/%s" % n)

# 7. в index.html кнопка PRO-карточки на месте
html = read(os.path.join("ui", "index.html"))
check('id="ext-card"' in html and 'data-act="ext-buy"' in html, "html ext-card + ext-buy")

if FAILED:
    print("A161 FAILED:", FAILED)
    sys.exit(1)
print("A161_EXT_PACKAGE_OK")
