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
import threading
import time

import config

LICENSE_FILE = os.path.join(config.DATA_DIR, "ext_license.json")

MAX_BODY = 64 * 1024          # ответ мастера больше 64 КБ — считаем мусором
ATTEMPTS = 3                  # попытки при сети/мастере
BACKOFF_S = 0.7               # пауза между попытками, растёт
STATE_LOCK = threading.RLock()
FEATURES = ("whitelist", "unlimited", "adblock", "extension")

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
        # Отказ без тела — но код остаться, чтобы панель
        # сказала правдильную причину (blocked/unknown/
        # expired/slow_down), а не молчалива без причины.
        return ({"error": "http-%s" % code} if code else None), (str(code) if code else "bad-json")
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
            })
            _save_cache()
            previous = (_SNAPSHOT or {}).get("plan")
            if previous != result["plan"]:
                config.log("ext-gate: plan=%s is_pro=%d" % (
                    result["plan"] or "-", 1 if is_pro(result["plan"]) else 0))
        else:
            config.log("ext-gate: мастер не ответил (%s) — работаем на кэше" % reason)
        _rebuild(offline_reason=reason if result is None else None)
        return dict(_SNAPSHOT)


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
        pro = is_pro(plan) and state in ("ok", "free")
        if state == "ok" and not is_pro(plan):
            state = "free"
        _SNAPSHOT = {
            "ok": state == "ok" and is_pro(plan),
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
        }
        return dict(_SNAPSHOT)


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
    """Подписка активна (в т. ч. триал free), но PRO ещё не куплен."""
    with STATE_LOCK:
        snap = dict(_SNAPSHOT) if _SNAPSHOT else _rebuild()
    st = str(snap.get("state") or "")
    return bool(snap.get("ok")) and st in ("ok", "free")

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
