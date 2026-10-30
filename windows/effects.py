# Aurora v1.10.13 - исполнение купленных возможностей.
# A-945: узел исполняет РОВНО то, что прислал мастер в addon_effects, и не решает
# за него. Код, которого нет в легенде, показывается человеку и не включается.
#
# Здесь нет «угадывания»: если возможность куплена, а включить её на узле нечем
# (нет ключей, нет настройки), узел так и говорит и ничего молча не ломает.

import threading
import time

import config
import extgate

# Что узел умеет исполнить своими руками. Всё остальное честно помечается
# как «нужна настройка владельцем» - молчаливый включитель хуже отказа.
_HANDLERS = ("external_vless", "mesh_tunnel", "no_profile_cap",
             "custom_routes", "ext_config", "display_only")

_LOCK = threading.RLock()
_LAST = {}
_REASON = {
    "external_vless": "нужна настройка владельцем: внешний вход VLESS Reality",
    "mesh_tunnel": "",
    "no_profile_cap": "",
    "custom_routes": "",
    "ext_config": "",
    "display_only": "",
}


def _log(text):
    try:
        config.log("addon: %s" % text)
    except Exception:
        pass


def active_codes():
    """Коды, которые мастер разрешил исполнить прямо сейчас.

    display_only - не действие: такую позицию показываем, включать нечего.
    Позиция без известного кода НЕ считается включённой.
    """
    snapshot = extgate.state() or {}
    active = set()
    effects = snapshot.get("addon_effects") or {}
    for name in snapshot.get("addons") or []:
        for code in effects.get(name) or []:
            if code in _HANDLERS and code != "display_only":
                active.add(code)
    with _LOCK:
        _LAST["effects"] = sorted(active)
    return sorted(active)


def _vless_ready():
    """Внешний вход реально сконфигурирован? Молча генерировать ключи нельзя:
    это открытие порта наружу, такое делает владелец, не узел по своему."""
    try:
        vln = config.vless_public() or {}
    except Exception:
        return False
    return bool(vln.get("enabled") and vln.get("uuid"))


def apply(force=False):
    """Привести узел к тому, что куплено. Вызывается после проверки лицензии.

    Возвращает отчёт для панели: что включено, что нечем включить и почему.
    """
    codes = active_codes()
    report = {
        "at": int(time.time()),
        "effects": codes,
        "done": [],
        "blocked": [],
        "cap_removed": False,
        "custom_routes": 0,
        "unknown": [],
    }
    snapshot = extgate.state() or {}
    report["unknown"] = list(snapshot.get("addon_unknown") or [])

    if "no_profile_cap" in codes:
        report["cap_removed"] = set_key_cap(0)
        (report["done"] if report["cap_removed"] else report["blocked"]).append(
            "no_profile_cap")

    if "mesh_tunnel" in codes:
        ok = _enable_mesh_tunnel()
        (report["done"] if ok else report["blocked"]).append("mesh_tunnel")

    if "custom_routes" in codes:
        report["custom_routes"] = len(custom_routes())
        report["done"].append("custom_routes")

    if "ext_config" in codes:
        report["done"].append("ext_config")

    if "external_vless" in codes:
        if _vless_ready():
            report["done"].append("external_vless")
        else:
            # Ключи и Reality-параметры задаёт владелец. Узел не открывает
            # наружу ничего сам и не выдумывает uuid/ключи.
            report["blocked"].append("external_vless")
            _REASON["external_vless"] = (
                "нужна настройка владельцем: внешний вход VLESS Reality "
                "(uuid и Reality-параметры задаёт владелец, узел сам не открывает "
                "порт наружу)")

    if "display_only" in codes:
        report["done"].append("display_only")

    with _LOCK:
        _LAST["report"] = report
    return dict(report)


def status():
    with _LOCK:
        return dict(_LAST.get("report") or {})


def reason(code):
    return str(_REASON.get(code) or "")


# --- no_profile_cap: лимит профилей должен сниматься на ходу, а не константой ---

def key_cap():
    """Действующий потолок ключей. 0 = без ограничения (купленная nolimit).

    Настройки key_cap может не быть - тогда действует штатный
    config.MAX_USER_KEYS. Отличать «не задано» от «0» обязательно: 0 это
    снятый лимит, а не отсутствие настройки."""
    try:
        raw = config.get("key_cap", None)
    except Exception:
        raw = None
    if isinstance(raw, bool) or not isinstance(raw, int):
        try:
            raw = int(config.MAX_USER_KEYS)
        except Exception:
            raw = 0
    return raw if raw >= 0 else 0


def cap_removed():
    """Снят ли лимит профилей (куплена позиция nolimit)."""
    return key_cap() == 0


def set_key_cap(value):
    """Снять или вернуть лимит. Возвращает фактический результат."""
    try:
        value = int(value)
    except (TypeError, ValueError):
        return False
    if value < 0 or value > 100000:
        return False
    try:
        config.set("key_cap", value)
        config.save_settings()
    except Exception as e:
        _log("не удалось сохранить лимит профилей: %s" % e)
        return False
    _log("лимит профилей: %s" % ("без ограничения" if not value else str(value)))
    return key_cap() == value


# --- mesh_tunnel: включение без перезапуска ------------------------------------

def _enable_mesh_tunnel():
    try:
        import meshtunnel
    except Exception:
        return False
    try:
        if meshtunnel.enabled() and meshtunnel.status().get("running"):
            return True
        return bool(meshtunnel.start())
    except Exception as e:
        _log("меш-туннель не поднялся: %s" % e)
        return False


# --- custom_routes: свои правила маршрутизации ---------------------------------
# Семантику НЕ выдумываем: у каждого правила человек сам выбирает действие.
# Позиция whitelist лишь разрешает этот список правил.

ROUTE_ACTIONS = ("proxy", "direct", "block")
_MAX_ROUTES = 200


def _routes_file():
    import os
    return os.path.join(config.DATA_DIR, "custom_routes.json")


def custom_routes():
    """Список правил: [{domain, action}], только белым списком."""
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
    """Сохранить правила. Принимает только белый список, лишнее отбрасывает."""
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
    except Exception as e:
        _log("правила маршрутизации не сохранены: %s" % e)
        return False
    return True


def xray_rules():
    """Правила для core.build_xray_config(): домен -> действие.

    Правила идут ПЕРВЫМИ, до штатных: человек описал свой маршрут - он главный.
    """
    out = []
    for row in custom_routes():
        rule = {"type": "field", "domain": [row["domain"]],
                "outboundTag": row["action"]}
        if row["action"] == "block":
            rule = {"type": "field", "domain": [row["domain"]],
                    "outboundTag": "block"}
        out.append(rule)
    return out