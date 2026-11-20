# Aurora A-1040 «Кот-смотритель» — автопроверка пула ключей по расписанию.
#
# Владелец включает autoprovерку и выбирает интервал (минуты). Фоновый тред
# раз в 30 с смотрит, пора ли гонять source.check_all(bg=True), и пишет событие
# в журнал (последние 40). Проверка идёт в фоне, панель только показывает
# прогресс через уже существующее поле check_progress.

import threading
import time

import config

_LOCK = threading.RLock()
_TICK_S = 30
_LOG_MAX = 40
_LAST_RUN = 0
_LOG = []
_RUNNING = False
_STARTED = False


def _now():
    return int(time.time())


def _log(msg):
    with _LOCK:
        _LOG.append({"ts": _now(), "msg": str(msg)[:200]})
        del _LOG[:max(0, len(_LOG) - _LOG_MAX)]


def _interval_min():
    try:
        value = int(config.get("keycheck_interval_min", 0) or 0)
    except (TypeError, ValueError):
        return 0
    return max(0, min(10080, value))


def enabled():
    return bool(config.get("keycheck_enabled", False)) and _interval_min() > 0


def status():
    with _LOCK:
        log = list(reversed(_LOG))
        last = _LAST_RUN
    interval = _interval_min()
    next_ts = 0
    if enabled():
        next_ts = last + interval * 60 if last else _now()
    return {
        "ok": True,
        "enabled": enabled(),
        "interval_min": interval,
        "last_ts": last,
        "next_ts": next_ts,
        "log": log,
    }


def run_now(reason="ручной запуск"):
    """Немедленный запуск проверки (кнопка «Проверить сейчас»)."""
    return _start_check(reason)


def _start_check(reason):
    global _LAST_RUN
    import source
    result = source.check_all(bg=True)
    if result.get("ok"):
        with _LOCK:
            _LAST_RUN = _now()
        _log("%s: проверка запущена" % reason)
        threading.Thread(target=_watch_done, daemon=True).start()
    else:
        _log("%s: проверка уже идёт или недоступна" % reason)
    return {"ok": bool(result.get("ok")),
            "msg": str(result.get("msg") or "")[:160]}


def _watch_done():
    """Ждём завершения фоновой проверки и пишем итог в журнал."""
    import pool
    deadline = time.time() + 900
    while time.time() < deadline:
        st = (config.get_state().get("check_progress") or {})
        if st.get("state") != "running":
            break
        time.sleep(5)
    total = 0
    alive = 0
    try:
        keys = pool.get_keys()
        total = len(keys)
        for key in keys:
            status_row = pool.get_status(key.get("uri", "")) or {}
            if status_row.get("status") in ("ok", "slow"):
                alive += 1
    except Exception:
        pass
    _log("проверка завершена: живых %d из %d" % (alive, total))


def tick():
    """Один шаг планировщика. Вызывается из loop() каждые _TICK_S."""
    if not enabled():
        return False
    interval = _interval_min()
    with _LOCK:
        due = (_LAST_RUN == 0 or _now() - _LAST_RUN >= interval * 60)
    if not due:
        return False
    _start_check("автопроверка")
    return True


def loop():
    global _RUNNING
    with _LOCK:
        if _RUNNING:
            return
        _RUNNING = True
    while True:
        try:
            tick()
        except Exception as e:
            config.log("autocheck: ошибка тика: %s" % e)
        time.sleep(_TICK_S)


def start():
    """Фоновый тред планировщика (идемпотентно)."""
    global _STARTED
    with _LOCK:
        if _STARTED:
            return False
        _STARTED = True
    threading.Thread(target=loop, daemon=True).start()
    return True
