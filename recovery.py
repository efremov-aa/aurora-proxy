# Aurora v1.0 — авто-восстановление: лимит/регион/соединение.
# Recovery: VPN ON -> ротация vless; VPN OFF -> пропустить.

import json
import os
import threading
import time

import config
import core

RECOVERY_LOCK = threading.RLock()
RECOVERY_IN_PROGRESS = False
RECOVERY_COUNT = 0
RECOVERY_LOG = []

# A-102: журнал не должен умирать вместе с рестартом службы.
RECOVERY_LOG_FILE = os.path.join(config.DATA_DIR, "recovery_log.json")
_LOG_LOADED = False
BOOT_MSG = ("котик на связи: слежу за ключами (лимит, регион, соединения) - "
            "если ключ отвалится или упрётся в лимит, переключу канал сам")


def _fmt_ts(ts):
    try:
        return time.strftime("%d.%m.%Y %H:%M:%S", time.localtime(int(ts)))
    except (TypeError, ValueError, OSError):
        return "-"


def _log_boot():
    """Стартовая запись: лента не должна выглядеть вечно мёртвой."""
    entry = {"kind": "info", "ts": int(time.time()), "msg": BOOT_MSG}
    RECOVERY_LOG.append(entry)
    del RECOVERY_LOG[:-50]
    config.log("recovery info: %s" % BOOT_MSG)


def _load():
    """Поднимаем прошлый журнал и дописываем стартовую запись."""
    global _LOG_LOADED, RECOVERY_COUNT
    with RECOVERY_LOCK:
        if _LOG_LOADED:
            return
        _LOG_LOADED = True
        data = None
        try:
            with open(RECOVERY_LOG_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            data = None
        except Exception:
            data = None
        items = data.get("log") if isinstance(data, dict) else data
        if isinstance(items, list):
            for item in items:
                if not isinstance(item, dict) or not isinstance(item.get("msg"), str):
                    continue
                RECOVERY_LOG.append({
                    "kind": str(item.get("kind") or "info")[:24],
                    "ts": int(item.get("ts") or 0),
                    "msg": item["msg"][:300],
                })
            del RECOVERY_LOG[:-50]
            if isinstance(data, dict):
                try:
                    RECOVERY_COUNT = max(RECOVERY_COUNT, int(data.get("count") or 0))
                except (TypeError, ValueError):
                    pass
        if not RECOVERY_LOG:
            _log_boot()
        _save()


def _save():
    """Атомарно сохраняем журнал в data/ (0600, tmp + replace)."""
    try:
        payload = {
            "count": RECOVERY_COUNT,
            "log": [dict(item) for item in RECOVERY_LOG[-50:]],
        }
        tmp = RECOVERY_LOG_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, RECOVERY_LOG_FILE)
    except Exception:
        # Журнал не должен ронять службу: молча продолжаем в памяти.
        pass


def _flap_guard(kind):
    """Анти-трепетание: не чаще раза в 90с на один тип."""
    with RECOVERY_LOCK:
        now = time.time()
        for item in RECOVERY_LOG[-5:]:
            if item.get("kind") == kind and now - item.get("ts", 0) < 90:
                return True
    return False


def _log(kind, msg):
    global RECOVERY_COUNT
    with RECOVERY_LOCK:
        RECOVERY_COUNT += 1
        entry = {"kind": kind, "ts": int(time.time()), "msg": msg}
        RECOVERY_LOG.append(entry)
        if len(RECOVERY_LOG) > 50:
            del RECOVERY_LOG[:-50]
        _save()
    config.log("recovery %s: %s" % (kind, msg))


def note(msg, kind="info"):
    """A-102: запись в ленту recovery без ротации ключа.

    Так лента наполняется реальными событиями (старт службы, смена канала),
    а не молчит вечным "восстановлений не было".
    """
    text = str(msg or "").strip()
    if not text:
        return
    _load()
    _log(kind, text[:200])


def _run_recovery(kind, reason, automatic=False):
    global RECOVERY_IN_PROGRESS
    with RECOVERY_LOCK:
        if automatic and not config.get("auto_recovery", True):
            return {"ok": False, "msg": "automatic recovery disabled"}
        if RECOVERY_IN_PROGRESS:
            return {"ok": False, "msg": "recovery in progress", "in_progress": True}
        if automatic and _flap_guard(kind):
            _log(kind, "skipped (flap guard) for %s: %s" % (kind, reason))
            return {"ok": False, "msg": "flap guard"}
        RECOVERY_IN_PROGRESS = True
    try:
        if config.get("vpn_mode", True):
            tag = core.rotate()
            if tag:
                _log(kind, "rotation -> %s (%s)" % (tag, reason))
                return {"ok": True, "tag": tag}
            _log(kind, "rotation failed for %s: %s" % (kind, reason))
            return {"ok": False, "msg": "no live key"}
        _log(kind, "vpn off - recovery skipped")
        return {"ok": False, "msg": "vpn off - recovery skipped"}
    finally:
        with RECOVERY_LOCK:
            RECOVERY_IN_PROGRESS = False


def run_limit(ip="", automatic=False):
    return _run_recovery("limit", ip or "limit report", automatic=automatic)


def run_region(reason="", automatic=False):
    return _run_recovery("region", reason or "region report", automatic=automatic)


def run_conn(host="", port=0, automatic=False):
    return _run_recovery("conn", "%s:%s" % (host, port) if host else "conn report", automatic=automatic)


def status():
    _load()
    with RECOVERY_LOCK:
        log = [dict(item) for item in RECOVERY_LOG]
    # Готовые строки для панели: "27.09.2026 12:00:00 · limit · rotation -> tag".
    lines = ["%s \u00b7 %s \u00b7 %s" % (_fmt_ts(i.get("ts")), i.get("kind") or "info",
                                          i.get("msg") or "")
             for i in log]
    return {
        "in_progress": RECOVERY_IN_PROGRESS,
        "count": RECOVERY_COUNT or len(log),
        "log": log,
        "lines": lines,
        "persisted": True,
    }


