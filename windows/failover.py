# Aurora A-120 «Кот-диспетчер» — авто-переключение резерва канала.
#
# Владелец включает диспетчер, и фоновый тред раз в N секунд оценивает
# здоровье каналов: VLESS-пул -> MASQUE -> WARP. Если основной канал умер,
# а резерв жив — final уходит на резерв без ручного выбора; когда основной
# ожил — возвращается обратно. Ручной выбор канала ставит паузу (hold),
# чтобы диспетчер не спорил с владельцем. Все переключения — в журнал.
#
# Принцип: диспетчер НИКОГДА не роняет канал в direct, если жив хоть один
# резерв, и не трогает ручной режим WARP "on" (A-890).

import threading
import time

import config

_LOCK = threading.RLock()
_LOG_MAX = 40
_LOG = []
_STARTED = False
_RUNNING = False
_HOLD_UNTIL = 0.0
# Последнее решение диспетчера: channel = vless | reserve | direct | "".
_DECISION = {"channel": "", "ts": 0, "health": {}}
# Порядок приоритета: основной пул, затем MASQUE, затем чистый WARP.
ORDER = ("vless", "masque", "warp")


def _now():
    return int(time.time())


def _log(msg):
    with _LOCK:
        _LOG.append({"ts": _now(), "msg": str(msg)[:200]})
        del _LOG[:max(0, len(_LOG) - _LOG_MAX)]


def enabled():
    return bool(config.get("failover_enabled", False))


def interval_s():
    try:
        value = int(config.get("failover_interval_s", 60) or 60)
    except (TypeError, ValueError):
        value = 60
    return max(30, min(3600, value))


def hold(seconds=1800):
    """Пауза после ручного выбора канала: диспетчер не спорит с владельцем."""
    global _HOLD_UNTIL
    with _LOCK:
        _HOLD_UNTIL = time.time() + max(0, int(seconds))


def held():
    with _LOCK:
        return time.time() < _HOLD_UNTIL


def health(probe=False):
    """Здоровье каналов. probe=True разрешает одноразовую живую пробу резерва.

    Без probe смотрим только на сохранённые факты (быстро, для sync):
    MASQUE/WARP живы, если включены, конфиг загружен и известен свежий egress.
    """
    import masque
    import pool
    import warp
    h = {}
    try:
        final_key = pool.pick_final()
        h["vless"] = {"ok": bool(final_key),
                      "detail": "живой ключ пула" if final_key else "живых ключей нет"}
    except Exception:
        h["vless"] = {"ok": False, "detail": "пул недоступен"}
    try:
        st = masque.status()
        ok = bool(st.get("enabled") and st.get("loaded"))
        egress = str(st.get("egress") or "-")
        fresh = (_now() - int(st.get("egress_ts") or 0)) <= 2 * int(masque.AUTO_INTERVAL)
        alive = ok and egress not in ("", "-") and fresh
        if ok and not alive and probe:
            r = masque.probe(timeout=15)
            alive = bool(r.get("ok"))
            egress = str(r.get("egress") or egress)
        h["masque"] = {"ok": bool(alive), "egress": egress,
                       "detail": "MASQUE жив" if alive else "MASQUE молчит"}
    except Exception:
        h["masque"] = {"ok": False, "detail": "masque недоступен"}
    try:
        st = warp.status()
        ok = bool(st.get("loaded")) and st.get("mode") != "off"
        egress = str(st.get("egress") or "-")
        fresh = (_now() - int(st.get("egress_ts") or 0)) <= 1800
        alive = ok and egress not in ("", "-") and fresh
        if ok and not alive and probe:
            r = warp.probe(timeout=15)
            alive = bool(r.get("ok"))
            egress = str(r.get("egress") or egress)
        h["warp"] = {"ok": bool(alive), "egress": egress,
                     "detail": "WARP жив" if alive else "WARP молчит"}
    except Exception:
        h["warp"] = {"ok": False, "detail": "warp недоступен"}
    return h


def decide(h):
    """Выбрать канал по приоритету. reserve = MASQUE или WARP (тег warp)."""
    if (h.get("vless") or {}).get("ok"):
        return "vless"
    if (h.get("masque") or {}).get("ok") or (h.get("warp") or {}).get("ok"):
        return "reserve"
    return "direct"


def override_tag():
    """Подсказка для core._sync_impl: 'reserve' или None.

    None = обычная логика выбора (пул / ручной WARP). Диспетчер вмешивается
    только когда включён, не на паузе и его решение — резерв.
    """
    if not enabled() or held():
        return None
    with _LOCK:
        channel = _DECISION["channel"]
    if channel == "reserve":
        return "reserve"
    return None


def status():
    with _LOCK:
        log = list(reversed(_LOG))
        decision = dict(_DECISION)
        hold_left = max(0, int(_HOLD_UNTIL - time.time()))
    return {
        "ok": True,
        "enabled": enabled(),
        "interval_s": interval_s(),
        "held": held(),
        "hold_left_s": hold_left,
        "decision": decision,
        "log": log,
    }


def run_now(reason="ручной запуск"):
    """Немедленная оценка и переключение (кнопка в панели)."""
    return _tick(reason, force=True)


def _tick(reason="диспетчер", force=False):
    if not enabled() and not force:
        return {"ok": False, "msg": "диспетчер выключен"}
    if held() and not force:
        return {"ok": False, "msg": "пауза после ручного выбора"}
    h = health(probe=True)
    want = decide(h)
    with _LOCK:
        prev = _DECISION["channel"]
        _DECISION.update({"channel": want, "ts": _now(), "health": h})
    if want == prev and not force:
        return {"ok": True, "channel": want, "changed": False}
    # Решение изменилось (или ручной запуск) — пересобираем канал.
    import core
    ok, final = core.sync()
    msg = "%s: канал %s -> %s (final=%s)" % (reason, prev or "—", want, final)
    _log(msg)
    config.log("failover: " + msg)
    try:
        import notify
        notify.event("failover", msg)
    except Exception:
        pass
    return {"ok": bool(ok), "channel": want, "changed": want != prev, "final": final}


def tick():
    """Один шаг планировщика (вызывается из loop())."""
    if not enabled():
        return False
    _tick()
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
            config.log("failover: ошибка тика: %s" % e)
        time.sleep(interval_s())


def start():
    """Фоновый тред диспетчера (идемпотентно)."""
    global _STARTED
    with _LOCK:
        if _STARTED:
            return False
        _STARTED = True
    threading.Thread(target=loop, daemon=True).start()
    return True
