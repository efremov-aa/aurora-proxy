# -*- coding: utf-8 -*-
"""Публичная сборка: все возможности доступны сразу.

Модуль сохранён как совместимая заглушка: сетевых запросов, лицензий,
планов и внешнего головного сервера здесь нет. Любая проверка возможностей
всегда разрешает доступ, фоновый запуск ничего не делает.
"""

FEATURES = ("whitelist", "unlimited", "adblock", "extension")
TRIAL_FEATURES = ("extension", "adblock")

EFFECT_CODES = ("external_vless", "mesh_tunnel", "no_profile_cap",
                "custom_routes", "ext_config", "display_only")


def master_url():
    """Совместимость со старыми вызывающими: внешнего сервера нет."""
    return ""


def identity():
    """Совместимость: device-ссылки больше нет."""
    return "", ""


def pro_plans():
    """Все планы считаются разрешёнными."""
    return set()


def is_pro(plan=None):
    return True


def feature(name):
    return True


def require(name):
    """Гейт всегда пропускает: в публичной сборке всё открыто."""
    return True


def trial_ok():
    return True


def check(force=False, timeout=None):
    return state()


def apply_tunnel_license(value):
    """Совместимость со старыми кадрами туннеля: лицензия не нужна."""
    return True


def state():
    """Снимок для панели: всё включено, ничего не проверяется."""
    return {
        "ok": True,
        "pro": True,
        "active": True,
        "state": "ok",
        "plan": "pro",
        "is_pro": True,
        "trial": False,
        "features": FEATURES,
        "effects": list(EFFECT_CODES),
        "addons": [],
        "addons_detail": [],
        "addon_effects": {},
        "addon_effects_legend": {},
        "addon_unknown": [],
        "expires": 0,
        "expires_in_days": 0,
        "used_bytes": 0,
        "limit_bytes": 0,
        "device_count": 0,
        "limit_devices": 0,
        "rules_version": None,
        "checked_at": 0,
        "age_s": 0,
        "offline": False,
        "offline_reason": "",
        "last_error": "",
    }


def start_background():
    """Фоновая проверка не нужна: кажать нечего."""
    return None
