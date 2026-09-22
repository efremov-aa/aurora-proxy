# Aurora v1.0 — авто-восстановление: лимит/регион/соединение.
# Recovery: VPN ON -> ротация vless; VPN OFF -> пропустить.

import threading
import time

import config
import core

RECOVERY_LOCK = threading.Lock()
RECOVERY_IN_PROGRESS = False
RECOVERY_COUNT = 0
RECOVERY_LOG = []


def _flap_guard(kind):
    """Анти-трепетание: не чаще раза в 90с на один тип."""
    now = time.time()
    for item in RECOVERY_LOG[-5:]:
        if item.get("kind") == kind and now - item.get("ts", 0) < 90:
            return True
    return False


def _log(kind, msg):
    global RECOVERY_COUNT
    RECOVERY_COUNT += 1
    entry = {"kind": kind, "ts": int(time.time()), "msg": msg}
    RECOVERY_LOG.append(entry)
    if len(RECOVERY_LOG) > 50:
        del RECOVERY_LOG[:-50]
    config.log("recovery %s: %s" % (kind, msg))


def _run_recovery(kind, reason):
    global RECOVERY_IN_PROGRESS
    if _flap_guard(kind):
        _log(kind, "skipped (flap guard) for %s: %s" % (kind, reason))
        return {"ok": False, "msg": "flap guard"}
    with RECOVERY_LOCK:
        RECOVERY_IN_PROGRESS = True
        try:
            if config.get("vpn_mode", True):
                tag = core.rotate()
                if tag:
                    _log(kind, "rotation -> %s (%s)" % (tag, reason))
                    return {"ok": True, "tag": tag}
                _log(kind, "rotation failed for %s: %s" % (kind, reason))
                return {"ok": False, "msg": "no live key"}
            else:
                _log(kind, "vpn off - recovery skipped")
                return {"ok": False, "msg": "vpn off - recovery skipped"}
        finally:
            RECOVERY_IN_PROGRESS = False


def run_limit(ip=""):
    return _run_recovery("limit", ip or "limit report")


def run_region(reason=""):
    return _run_recovery("region", reason or "region report")


def run_conn(host="", port=0):
    return _run_recovery("conn", "%s:%s" % (host, port) if host else "conn report")


def status():
    return {
        "in_progress": RECOVERY_IN_PROGRESS,
        "count": RECOVERY_COUNT,
        "log": list(RECOVERY_LOG),
    }


