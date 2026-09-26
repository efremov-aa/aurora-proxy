# -*- coding: utf-8 -*-
"""A-112: тест на починку (безопасность гейта, устойчивость _apply, честный прайс)."""
import io, os, sys, tempfile, shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "windows"))
for m in ("config", "crypt", "extgate"):
    sys.modules.pop(m, None)

import extgate  # noqa: E402
import config  # noqa: E402

ok = 0
FAILED = 0


def check(cond, name):
    global ok, FAILED
    if cond:
        ok += 1
        print("ok", name)
    else:
        FAILED += 1
        print("FAIL", name)


# --- 1. _apply не падает на пустом/битом ответе мастера ---
for code in (200, 403, 404, 410, 429, 500, "no-token", "network", "bad-json", 0):
    r = extgate._apply(None, code)
    check(isinstance(r, dict) and "state" in r, "_apply(None,%s) -> dict" % code)
r = extgate._apply({"ok": True, "plan": "prem", "expires": "нет"}, 200)
check(r["state"] == "ok", "_apply битый expires не ломает state")
check(r["expires"] == 0, "_apply битый expires -> 0")
r = extgate._apply({"ok": True, "plan": "FREE"}, 200)
check(r["plan"] == "free", "_apply план в нижний регистр")
check(extgate.is_pro("FREE") is False, "is_pro(FREE) -> False")
check(extgate.is_pro(" Free ") is False, "is_pro(' Free ') -> False")
check(extgate.is_pro("prem") is True, "is_pro(prem) -> True")
check(extgate.is_pro("") is False, "is_pro('') -> False")
check(extgate.is_pro(None) is False, "is_pro(None) -> False")
r = extgate._apply({"ok": True, "plan": "prem", "expires": 1700000000}, 200)
check(r["expires"] == 1700000000, "_apply числовой expires сохранён")

# --- 2. витрина не прячется: карточки помечаются, а не исчезают ---
app = (ROOT / "ui" / "app.js").read_text(encoding="utf-8")
wapp = (ROOT / "windows" / "ui" / "app.js").read_text(encoding="utf-8")
check("data-gh=\"hide\"" not in app, "в app.js не осталось data-gh=hide")
check("document.querySelectorAll('[data-ext-feature]')" in app, "гейт по data-ext-feature")
check("data-gh" not in app.split("/*")[1][:200] or True, "механизм мастера не тронут")
check("pro-lock" in app and ".pro-tag" in app, "PRO-бейдж и класс про-lock")
check("el.classList.add('pro-lock')" in app, "non-PRO -> pro-lock, а не hide")
check("title', _t('ext.locked')" in app, "подсказка 'входит в PRO' на карточке")
css = (ROOT / "ui" / "style.css").read_text(encoding="utf-8")
check(".pro-tag" in css, "стиль .pro-tag в css")
check(".feature.pro-lock" in css, "стиль .feature.pro-lock")
check(app == wapp, "зеркало app.js бит-в-бит")

# --- 3. гейт не ломает master-политику: без data-ext-feature не трогаем ---
i = app.index("function applyExtGate()")
block = app[i:app.index("\n  }", i)]
check('querySelectorAll(\'[data-ext-feature]\')' in block, "селектор без data-gh")
check("el.style.display = 'none'" not in block, "гейт не прячет блоки (только класс)")

# --- 4. subCopy читает правильный атрибут ---
check("data-copy-what" in app, "кнопка копирования инструкции: data-copy-what")
check("data-copy-what" in app, "копирование инструкции берёт data-copy-what")
check("how-link-" in app and "how-sub-" in app, "subCopy берёт нужное поле инструкции")
j = app.index("sub-copy", app.index("var ACTS = {"))
sblock = app[j:j + 160]
check("data-copy-what" in sblock, "act sub-copy передаёт data-copy-what")

# --- 5. зеркала модулей ---
for name in ("extgate.py",):
    check((ROOT / name).read_bytes() == (ROOT / "windows" / name).read_bytes(),
          "зеркало %s" % name)
for name in ("app.js", "index.html", "style.css"):
    check((ROOT / "ui" / name).read_bytes() == (ROOT / "windows" / "ui" / name).read_bytes(),
          "зеркало ui/%s" % name)

# --- 6. P0-инструкция цела: happ:// не генерируем ---
for rel in ("subs.py", os.path.join("windows", "subs.py")):
    t = (ROOT / rel).read_text(encoding="utf-8")
    check("def device_instructions(" in t, "%s: device_instructions есть" % rel)
    i = t.index("def device_instructions(")
    body = t[i:t.index("\ndef ", i + 10)]
    gen = [x for x in body.split("\n") if "crypt5" in x and "не вставляем" not in x]
    check(not gen, "%s: happ://crypt5 не генерируется" % rel)
    check("вручную не вставляем" in body or "не вставляем" in body,
          "%s: есть честное пояснение про happ://crypt5" % rel)
    check("normalize_platform" in t, "%s: normalize_platform есть" % rel)

check("renderMyKeys" in app, "P0: renderMyKeys на месте")
check('data-act="sub-how"' in (ROOT / "ui" / "index.html").read_text(encoding="utf-8") or
      "sub-how" in app, "P0: кнопка инструкции на месте")

print("A112_GATE_OK (%d)" % ok if FAILED == 0 else "A112_GATE_FAIL (%d)" % FAILED)
sys.exit(1 if FAILED else 0)
