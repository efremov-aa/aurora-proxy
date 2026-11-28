# -*- coding: utf-8 -*-
"""Публичная сборка: все возможности включены сразу.

Лицензий, планов и внешнего сервера нет. Функции-проверки всегда отвечают
«разрешено», а локальные пользовательские маршруты продолжают работать как
обычное хранилище настроек (без всяких прав и подписей).
"""

import config

_HANDLERS = ("external_vless", "mesh_tunnel", "no_profile_cap",
             "custom_routes", "ext_config", "display_only")
EFFECT_CODES = _HANDLERS

ROUTE_ACTIONS = ("proxy", "direct", "block")
_MAX_ROUTES = 200


def active_codes():
    """Все коды доступны в публичной сборке."""
    return list(_HANDLERS)


def key_cap():
    """0 = без ограничения числа ключей."""
    return 0


def cap_removed():
    return True


def set_key_cap(value):
    """Лимит снят навсегда; вызов оставлен для совместимости."""
    return True


def custom_routes():
    """Проверка возможности: маршруты доступны всегда."""
    return True


def external_vless():
    return True


def mesh_tunnel():
    return True


def no_profile_cap():
    return True


def apply(force=False):
    """Применять нечего: всё уже включено."""
    return None


def status():
    return {"effects": list(_HANDLERS), "done": list(_HANDLERS),
            "blocked": [], "cap_removed": True, "custom_routes": len(routes()),
            "unknown": []}


def reason(code):
    return ""


def _vless_ready():
    return True


def _enable_mesh_tunnel():
    return True


def _routes_file():
    import os
    return os.path.join(config.DATA_DIR, "custom_routes.json")


def routes():
    """Локальные правила маршрутизации: [{domain, action}]."""
    import crypt
    try:
        raw = crypt.load_json(_routes_file(), []) or []
    except Exception:
        return []
    out = []
    for row in raw if isinstance(raw, list) else []:
        if not isinstance(row, dict):
            continue
        domain = str(row.get("domain") or "").strip().lower()[:253]
        action = str(row.get("action") or "").strip().lower()
        if not domain or action not in ROUTE_ACTIONS:
            continue
        out.append({"domain": domain, "action": action})
        if len(out) >= _MAX_ROUTES:
            break
    return out


def set_custom_routes(rows):
    """Сохранить локальные правила (только известные действия)."""
    import crypt
    clean = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        domain = str(row.get("domain") or "").strip().lower()[:253]
        action = str(row.get("action") or "").strip().lower()
        if not domain or action not in ROUTE_ACTIONS:
            continue
        clean.append({"domain": domain, "action": action})
        if len(clean) >= _MAX_ROUTES:
            break
    try:
        crypt.save_json(_routes_file(), clean)
    except Exception:
        return False
    return True


def xray_rules():
    """Правила для core.build_xray_config(): применяются всегда, без проверок."""
    out = []
    for row in routes():
        out.append({"type": "field", "domain": [row["domain"]],
                    "outboundTag": row["action"] if row["action"] != "block" else "block"})
    return out
