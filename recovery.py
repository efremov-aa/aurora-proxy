# Aurora v1.0 — авто-восстановление: лимит/регион/соединение.
# Recovery: VPN ON -> ротация vless; VPN OFF -> пропустить.

import threading
import time

import config
import core

RECOVERY_LOCK = threading.RLock()
RECOVERY_IN_PROGRESS = False
RECOVERY_COUNT = 0
RECOVERY_LOG = []


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
    config.log("recovery %s: %s" % (kind, msg))


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
    with RECOVERY_LOCK:
        return {
            "in_progress": RECOVERY_IN_PROGRESS,
            "count": RECOVERY_COUNT,
            "log": [dict(item) for item in RECOVERY_LOG],
        }


