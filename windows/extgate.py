# -*- coding: utf-8 -*-
"""A-111: лицензионный гейт PRO-функций (котик на связи, но аккуратно).

Клиентская сборка сама не решает, что открыто: она спрашивает головной сервер
`GET /api/ext/config` по своей device-ссылке и берёт оттуда план. Логика PRO:
`plan != "free"` (список исключений задаётся env `AURORA_EXT_PRO_PLANS`).

Прокси при этом НИКОГДА не падает: если мастер молчит или сеть легла, работаем
на последнем успешном ответе — но не дольше `AURORA_EXT_OFFLINE_MAX_S` (72 ч),
дальше честно показываем «подписку надо продлить».

Правила (маскот):
* прокси/ключи/подписка открыты ВСЕГДА — сервер для пользователя бесплатный;
* закрыты только PRO-фичи: обход «Белого списка», безлимитные устройства и
  трафик, блок рекламы/трекеров, части расширения;
* в лог не пишем токены — только план и флаг PRO.
"""

import json
import os
import re
import threading
import time

import config
import mesh

LICENSE_FILE = os.path.join(config.DATA_DIR, "ext_license.json")

MAX_BODY = 64 * 1024          # ответ мастера больше 64 КБ — считаем мусором
ATTEMPTS = 3                  # попытки при сети/мастере
BACKOFF_S = 0.7               # пауза между попытками, растёт
STATE_LOCK = threading.RLock()
FEATURES = ("whitelist", "unlimited", "adblock", "extension")

# A-945: коды эффектов, которые мастер кладёт в addon_effects. Узел исполняет
# ровно то, что прислал мастер, и не решает сам. Код, которого нет в легенде,
# показывается человеку как «неизвестная возможность» и молча не включается.
EFFECT_CODES = ("external_vless", "mesh_tunnel", "no_profile_cap",
                "custom_routes", "ext_config", "display_only")
MAX_ADDONS = 32
ADDON_ID_RE = re.compile(r"^[a-z0-9_-]{1,40}$")


def _valid_addon_id(value):
    return isinstance(value, str) and bool(ADDON_ID_RE.fullmatch(value))


def _parse_addons(value):
    """Что куплено: id действующих позиций + подробности.

    Просроченные и отменённые мастер не присылает. Поле может отсутствовать
    (старый мастер) - это «ничего не куплено», а не ошибка.
    """
    ids, detail = [], []
    raw = value.get("addons")
    if isinstance(raw, list):
        for item in raw:
            if _valid_addon_id(item) and item not in ids:
                ids.append(item)
            if len(ids) >= MAX_ADDONS:
                break
    rows = value.get("addons_detail")
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict) or not _valid_addon_id(row.get("id")):
                continue
            period = str(row.get("period") or "").strip().lower()
            detail.append({
                "id": str(row.get("id")),
                "name": str(row.get("name") or "")[:120],
                "price": _int(row.get("price"), 0),
                "period": period if period in ("once", "month") else "",
                "until": _int(row.get("until"), 0),
                "forever": bool(row.get("forever")),
            })
            if len(detail) >= MAX_ADDONS:
                break
    return ids[:MAX_ADDONS], detail


def _parse_effects(value, ids):
    """Карта «позиция -> что включить» от мастера. Решать за мастера нельзя."""
    effects, legend, unknown = {}, {}, []
    raw = value.get("addon_effects")
    if isinstance(raw, dict):
        # Неизвестные коды собираем ВСЕГДА, даже под невалидным id позиции:
        # человек должен увидеть, что мастер прислал то, чего узел не умеет.
        for codes in raw.values():
            if not isinstance(codes, list):
                continue
            for code in codes:
                code = str(code or "").strip().lower()
                if code and code not in EFFECT_CODES and code not in unknown:
                    unknown.append(code)
        for key, codes in raw.items():
            if not _valid_addon_id(key) or not isinstance(codes, list):
                continue
            out = []
            for code in codes:
                code = str(code or "").strip().lower()
                if code in EFFECT_CODES and code not in out:
                    out.append(code)
            if out:
                effects[key] = out
    rows = value.get("addon_effects_legend")
    if isinstance(rows, dict):
        for key, text in rows.items():
            legend[str(key)[:40]] = str(text or "")[:200]
    return effects, legend, unknown


def _effects_known(snapshot):
    """Коды, которые мастер разрешил исполнить прямо сейчас.

    display_only - не действие: такую позицию показываем, но включать нечего.
    Позиция без известного кода НЕ считается включённой.
    """
    active = set()
    for name in snapshot.get("addons") or []:
        for code in (snapshot.get("addon_effects") or {}).get(name) or []:
            if code in EFFECT_CODES and code != "display_only":
                active.add(code)
    return active

_CACHE = {}          # последний успешный ответ мастера (сырой)
_SNAPSHOT = {}       # что отдаём наружу
_LAST_CHECK = 0.0
_INFLIGHT = False
_BG_STARTED = False


# ------------------------------------------------------------------ помощники
def _int_env(name, default):
    try:
        value = int(str(os.environ.get(name, "") or default).strip())
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def master_url():
    """Адрес головного сервера (env AURORA_EXT_MASTER)."""
    return str(getattr(config, "EXT_MASTER_URL", "") or "http://10.1.0.238:8890").rstrip("/")


def identity():
    """Своя device-ссылка: token + credential (env, никогда не в лог)."""
    return (str(getattr(config, "EXT_TOKEN", "") or "").strip(),
            str(getattr(config, "EXT_CREDENTIAL", "") or "").strip())


def pro_plans():
    """Список планов с PRO. Пусто — все, кроме free (правило ТЗ)."""
    raw = str(getattr(config, "EXT_PRO_PLANS", "") or "")
    out = set()
    for part in raw.replace(";", ",").split(","):
        value = part.strip().lower()
        if value:
            out.add(value)
    return out


def is_pro(plan):
    """PRO = платный план. Пустой plan — не PRO (честно)."""
    name = str(plan or "").strip().lower()
    if not name or name == "free":
        return False
    allowed = pro_plans()
    if allowed and name not in allowed:
        return False
    return True


def _int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# --------------------------------------------------------------------- кэш
def _load_cache():
    global _CACHE
    try:
        import crypt
        raw = crypt.load_bytes(LICENSE_FILE)
        value = json.loads(raw.decode("utf-8")) if raw else None
        if isinstance(value, dict):
            _CACHE = value
    except Exception as e:
        config.log("ext-gate: кэш лицензии не прочитан: %s" % e)
    return dict(_CACHE)


def _save_cache():
    """Атомарно и 0600 — в кэше лежит device-ссылка."""
    try:
        import crypt
        crypt.save_json(LICENSE_FILE, _CACHE)
    except Exception as e:
        config.log("ext-gate: кэш лицензии не сохранён: %s" % e)


# ------------------------------------------------------------------ запрос
def _fetch(token, credential, timeout):
    """Одна попытка спросить мастера. Возвращает (dict|None, код|str)."""
    if not token:
        return None, "no-token"
    from urllib.error import HTTPError
    from urllib.parse import urlencode
    from urllib.request import ProxyHandler, Request, build_opener
    query = urlencode({"token": token, "credential": credential})
    request = Request("%s/api/ext/config?%s" % (master_url(), query),
                      headers={"X-Aurora-Request": "1"})
    opener = build_opener(ProxyHandler({}))   # без системного прокси
    code = 0
    try:
        with opener.open(request, timeout=timeout) as response:
            code = _int(getattr(response, "status", 200) or 200, 200)
            body = response.read(MAX_BODY + 1)
    except HTTPError as e:
        # Мастер отвечает 403/404/410/429 с телом (в нем buy_url).
        # Без этого HTTPError отказ был бы в общий "network",
        # и истекая подписка ("expired") невозможна.
        code = _int(getattr(e, "code", 0) or 0, 0)
        try:
            body = e.read(MAX_BODY + 1)
        except Exception:
            body = b""
    except Exception:
        return None, "network"
    if len(body) > MAX_BODY:
        return None, "too-big"
    try:
        value = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        value = None
    if not isinstance(value, dict):
        if not code or code == 200:
            # A-263: 200 с не-JSON телом - это НЕ ответ лицензии.
            # Раньше такой ответ затирал хороший кэш (state=unknown,
            # plan=""), и панель показывала «подписки нет» при живой
            # подписке. Теперь считаем его «мастер не ответил» и
            # продолжаем работать на кэше.
            return None, "bad-json"
        # Отказ без тела — код остаётся, чтобы панель сказала
        # правдильную причину (blocked/expired/slow_down).
        return {"error": "http-%s" % code}, str(code)
    return value, code


def _apply(value, code):
    """Разбор ответа мастера: 200 — лицензия, 4xx — причина отказа.
    A-112: пустой/битый ответ мастера не должен ронять панель - чиним в dict."""
    if not isinstance(value, dict):
        value = {}
    plan = str(value.get("plan") or "").strip().lower()
    status = str(value.get("status") or "").strip().lower()
    if code == 200 and value.get("ok"):
        state = "ok"
    elif code in (403, 404, 410, 429):
        state = {"403": "blocked", "404": "unknown",
                 "410": "expired", "429": "slow_down"}.get(str(code), "blocked")
    else:
        state = status or "unknown"
    # A-945: покупки видны только в успешном ответе. При отказе (код >= 400)
    # мастер не присылает ни addons, ни эффекты - это «ничего не куплено».
    ids, detail = ([], [])
    effects, legend, unknown = ({}, {}, [])
    if code == 200 and value.get("ok"):
        ids, detail = _parse_addons(value)
        effects, legend, unknown = _parse_effects(value, ids)
    return {
        "state": state,
        "plan": plan,
        "status": status or state,
        "expires": _int(value.get("expires"), 0),
        "expires_in_days": 0,
        "used_bytes": _int(value.get("used_bytes"), 0),
        "limit_bytes": _int(value.get("limit_bytes"), 0),
        "device_count": _int(value.get("device_count"), 0),
        "limit_devices": _int(value.get("limit_devices"), 0),
        "rules_version": value.get("rules_version"),
        "buy_url": str(value.get("buy_url") or getattr(config, "BUY_URL", "") or "").strip(),
        "addons": ids,
        "addons_detail": detail,
        "addon_effects": effects,
        "addon_effects_legend": legend,
        "addon_unknown": unknown,
        "checked_at": int(time.time()),
        "code": code,
    }


# ------------------------------------------------------------------- цикл
def check(force=False, timeout=None):
    """Проверить лицензию у мастера. Никогда не бросает и не роняет прокси."""
    global _CACHE, _LAST_CHECK, _INFLIGHT
    with STATE_LOCK:
        if _INFLIGHT:
            return dict(_SNAPSHOT)
        interval = _int_env("AURORA_EXT_CHECK_INTERVAL",
                            _int(getattr(config, "EXT_CHECK_INTERVAL_S", 3600), 3600))
        if not force and (_LAST_CHECK and (time.time() - _LAST_CHECK) < interval):
            return state()
        if not force and not _LAST_CHECK and _SNAPSHOT:
            return dict(_SNAPSHOT)
        _INFLIGHT = True
        token, credential = identity()
        cached = dict(_CACHE) if _CACHE else _load_cache()
    timeout = _int(timeout, _int(getattr(config, "EXT_TIMEOUT", 10), 10))
    result = None
    reason = "no-token"
    try:
        for attempt in range(ATTEMPTS):
            value, info = _fetch(token, credential, timeout)
            if value is not None:
                result = _apply(value, info if isinstance(info, int) else 200)
                break
            reason = info if isinstance(info, str) else "network"
            if attempt + 1 < ATTEMPTS:
                time.sleep(BACKOFF_S * (attempt + 1))
    except Exception as e:
        reason = "error"
        config.log("ext-gate: проверка упала: %s" % e)
    with STATE_LOCK:
        _INFLIGHT = False
        _LAST_CHECK = time.time()
        if result is not None:
            _CACHE = dict(cached)
            _CACHE.update({
                "token": token, "credential": credential,
                "plan": result["plan"], "status": result["status"],
                "expires": result["expires"], "rules_version": result.get("rules_version"),
                "buy_url": result["buy_url"], "checked_at": result["checked_at"],
                "state": result["state"],
                # A-262: счётчики подписки тоже в кэш - без них панель
                # показывала трафик и устройства как 0/0 при живой лицензии.
                "used_bytes": result["used_bytes"],
                "limit_bytes": result["limit_bytes"],
                "device_count": result["device_count"],
                "limit_devices": result["limit_devices"],
                # A-945: покупки переживают офлайн вместе с тарифом, иначе при
                # недоступном мастере панель показывала бы «ничего не куплено»
                # у человека, который всё купил.
                "addons": result["addons"],
                "addons_detail": result["addons_detail"],
                "addon_effects": result["addon_effects"],
                "addon_effects_legend": result["addon_effects_legend"],
                "addon_unknown": result["addon_unknown"],
            })
            _save_cache()
            previous = (_SNAPSHOT or {}).get("plan")
            if previous != result["plan"]:
                config.log("ext-gate: plan=%s is_pro=%d" % (
                    result["plan"] or "-", 1 if is_pro(result["plan"]) else 0))
        else:
            config.log("ext-gate: мастер не ответил (%s) — работаем на кэше" % reason)
        _rebuild(offline_reason=reason if result is None else None)
        _apply_effects()
        return dict(_SNAPSHOT)


def _apply_effects():
    """A-945: после проверки лицензии - привести узел к тому, что куплено.

    Импорт ленивый: effects ходит в extgate.state(), обратный импорт на
    уровне модуля дал бы цикл. Ошибка применения не должна ронять проверку."""
    try:
        import effects
        return effects.apply()
    except Exception as e:
        try:
            config.log("addon: применение эффектов не удалось: %s" % e)
        except Exception:
            pass
        return {}


def _rebuild(offline_reason=None):
    """Собираем снимок из кэша: план, PRO, остаток дней, офлайн-состояние."""
    global _SNAPSHOT
    with STATE_LOCK:
        cache = _CACHE or _load_cache()
        now = int(time.time())
        checked = _int(cache.get("checked_at"), 0)
        age = max(0, now - checked) if checked else None
        limit_s = _int_env("AURORA_EXT_OFFLINE_MAX_S",
                           _int(getattr(config, "EXT_OFFLINE_MAX_S", 72 * 3600), 72 * 3600))
        expired_cache = bool(age is not None and age > limit_s)
        plan = str(cache.get("plan") or "")
        state = str(cache.get("state") or "unknown")
        offline = offline_reason is not None
        if state == "ok" and expired_cache:
            state = "expired"
        expires = _int(cache.get("expires"), 0)
        days = max(0, (expires - now) // 86400) if expires else 0
        pro = is_pro(plan) and state == "ok"
        if state == "ok" and not is_pro(plan):
            state = "free"
        _SNAPSHOT = {
            "ok": state == "ok" and is_pro(plan),
            # A-277: "active" - подписка жива (в т.ч. бесплатный уровень close),
            # независимо от PRO. Раньше trial_ok() требовал "ok", а "ok" по
            # определению false без PRO, поэтому бесплатный уровень не получал
            # extension/adblock (конъюнкция была невыполнима).
            # A-945: триала больше нет - бесплатный уровень это close (0 ₽,
            # бессрочно), а не пробный период.
            "active": state in ("ok", "free"),
            "state": state,
            "plan": plan,
            "is_pro": bool(pro),
            "expires": expires,
            "expires_in_days": days,
            "used_bytes": _int(cache.get("used_bytes"), 0),
            "limit_bytes": _int(cache.get("limit_bytes"), 0),
            "device_count": _int(cache.get("device_count"), 0),
            "limit_devices": _int(cache.get("limit_devices"), 0),
            "rules_version": cache.get("rules_version"),
            "buy_url": str(cache.get("buy_url") or getattr(config, "BUY_URL", "") or "").strip(),
            "master": master_url(),
            "checked_at": checked,
            "age_s": age,
            "offline": offline,
            "offline_reason": offline_reason or "",
            "last_error": "" if (checked and not expired_cache) else (offline_reason or "no-data"),
            # A-945: купленные позиции и что каждая включает. Поля могут быть
            # пустыми - это честное «ничего не куплено».
            "addons": list(cache.get("addons") or [])[:MAX_ADDONS],
            "addons_detail": list(cache.get("addons_detail") or [])[:MAX_ADDONS],
            "addon_effects": dict(cache.get("addon_effects") or {}),
            "addon_effects_legend": dict(cache.get("addon_effects_legend") or {}),
            "addon_unknown": list(cache.get("addon_unknown") or [])[:MAX_ADDONS],
            # A-945/M16: узлы с правом на меш из подписанной политики мастера.
            "mesh_entitlements": mesh.policy_entitlements(),
        }
        _SNAPSHOT["effects"] = sorted(_effects_known(_SNAPSHOT))
        return dict(_SNAPSHOT)


def apply_tunnel_license(value):
    """A-307: license received in the mesh tunnel, applied as a 200 answer.

    The same _apply() path as the HTTP answer - no second source of truth.
    """
    return _apply(value, 200)


def state():
    """Снимок для панели. Раз в интервал поднимает фоновую проверку."""
    with STATE_LOCK:
        interval = _int_env("AURORA_EXT_CHECK_INTERVAL",
                            _int(getattr(config, "EXT_CHECK_INTERVAL_S", 3600), 3600))
        due = (not _LAST_CHECK) or (time.time() - _LAST_CHECK) >= interval
        if not _SNAPSHOT:
            _rebuild()
        if due and not _INFLIGHT:
            thread = threading.Thread(target=check, kwargs={"force": True}, daemon=True)
            thread.start()
        return dict(_SNAPSHOT)


# A-161: фичи, открытые уже на триале (7 дней) - по ТЗ продукта:
# расширение браузера и блок рекламы доступны без PRO,
# а обход "Белого списка" и безлимиты - только PRO.
TRIAL_FEATURES = ("extension", "adblock")


def trial_ok():
    """Подписка активна (в т.ч. триал free), но PRO ещё не куплен."""
    with STATE_LOCK:
        snap = dict(_SNAPSHOT) if _SNAPSHOT else _rebuild()
    # A-277: брать признак "подписка жива" из снимка, а не из "ok"
    # (ok == state=="ok" and is_pro(plan), то есть для бесплатного уровня
    # всегда False). A-945: триала нет, бесплатный уровень - это close.
    if "active" in snap:
        return bool(snap.get("active")) and not is_pro(str(snap.get("plan") or ""))
    st = str(snap.get("state") or "")
    return st == "free" and not is_pro(str(snap.get("plan") or ""))


def feature(name):
    """Открыта ли PRO-фича (whitelist/unlimited/adblock/extension)."""
    key = str(name or "").strip().lower()
    if key not in FEATURES:
        return False
    if key in TRIAL_FEATURES and trial_ok():
        return True
    with STATE_LOCK:
        if not _SNAPSHOT:
            _rebuild()
        return bool(_SNAPSHOT.get("is_pro"))


def require(name):
    """Гейт для сервера: None — можно, иначе честный экран с buy_url."""
    key = str(name or "").strip().lower()
    if key in FEATURES and feature(key):
        return None
    with STATE_LOCK:
        snap = dict(_SNAPSHOT) if _SNAPSHOT else _rebuild()
    return {
        "ok": False,
        "error": "ext: это входит в PRO",
        "feature": key,
        "state": snap.get("state", "unknown"),
        "plan": snap.get("plan", ""),
        "expires": snap.get("expires", 0),
        "buy_url": snap.get("buy_url") or getattr(config, "BUY_URL", ""),
    }


def _loop():
    while True:
        time.sleep(_int_env("AURORA_EXT_CHECK_INTERVAL",
                            _int(getattr(config, "EXT_CHECK_INTERVAL_S", 3600), 3600)))
        try:
            check(force=True)
        except Exception:
            pass


def start_background():
    """Фоновый цикл проверки лицензии (идемпотентно)."""
    global _BG_STARTED
    with STATE_LOCK:
        if _BG_STARTED:
            return False
        _BG_STARTED = True
    threading.Thread(target=_loop, daemon=True).start()
    threading.Thread(target=check, kwargs={"force": True}, daemon=True).start()
    return True
