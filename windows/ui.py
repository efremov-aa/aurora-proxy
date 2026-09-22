# Aurora v1.0 — панель: разбитая на ui/index.html + ui/style.css + ui/app.js.
# Модуль-загрузчик: подтягивает реальные файлы папки ui/ при импорте.

import os

_BASE = os.path.dirname(os.path.abspath(__file__))
_UI = os.path.join(_BASE, "ui")


def _load(name):
    try:
        with open(os.path.join(_UI, name), "r", encoding="utf-8") as f:
            return f.read()
    except OSError as e:
        return "<h1>UI: %s не найден (%s)</h1>" % (name, e)


PAGE = _load("index.html")    # разметка вкладок Aurora
STYLE = _load("style.css")    # дизайн-система Neko (темы/адаптив/котики)
APP = _load("app.js")         # вся логика панели (api/refresh/render/...)
QJS = _load("qr.js")          # локальный генератор QR (без внешнего api.qrserver.com)
