# Aurora A-123 «Кот-диспетчер» — плановый бэкап по расписанию.
#
# Образец — autocheck.py: фоновый тред раз в 30 с смотрит, пора ли делать
# архив. Архив собирается тем же backup.export (ZIP + пароль владельца),
# кладётся в data/backups/ и ротируется: храним N последних копий.
# Пароль расписания лежит в шифрованных настройках панели и в архив
# восстановления НЕ попадает (BACKUP_SETTINGS его не содержит).

import os
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
BACKUP_DIRNAME = "backups"


def _now():
    return int(time.time())


def _log(msg):
    with _LOCK:
        _LOG.append({"ts": _now(), "msg": str(msg)[:200]})
        del _LOG[:max(0, len(_LOG) - _LOG_MAX)]


def _interval_h():
    try:
        value = int(config.get("backup_interval_h", 24) or 24)
    except (TypeError, ValueError):
        return 24
    return max(1, min(168, value))


def _keep():
    try:
        value = int(config.get("backup_keep", 7) or 7)
    except (TypeError, ValueError):
        return 7
    return max(1, min(60, value))


def enabled():
    return bool(config.get("backup_schedule_enabled", False)) \
        and bool(config.get("backup_password", ""))


def backup_dir():
    return os.path.join(config.DATA_DIR, BACKUP_DIRNAME)


def list_files():
    """Список архивов (новые первыми), без чтения содержимого."""
    out = []
    try:
        d = backup_dir()
        for name in os.listdir(d):
            if not name.startswith("aurora-backup-") or not name.endswith(".zip"):
                continue
            p = os.path.join(d, name)
            if os.path.isfile(p):
                out.append({"name": name, "bytes": os.path.getsize(p),
                            "ts": int(os.path.getmtime(p))})
    except OSError:
        pass
    out.sort(key=lambda x: x["ts"], reverse=True)
    return out


def _rotate():
    keep = _keep()
    files = list_files()
    dropped = 0
    for item in files[keep:]:
        try:
            os.remove(os.path.join(backup_dir(), item["name"]))
            dropped += 1
        except OSError:
            pass
    return dropped


def run_now(reason="ручной запуск"):
    """Сделать архив сейчас. Возвращает отчёт для панели."""
    global _LAST_RUN
    import backup
    password = str(config.get("backup_password", "") or "")
    if len(password) < backup.MIN_PASSWORD_LEN:
        return {"ok": False, "error": "задайте пароль расписания (минимум 8 символов)"}
    try:
        blob, name = backup.export(password)
        d = backup_dir()
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, name)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(blob)
    except (backup.BackupError, OSError, ValueError) as e:
        _log("%s: ошибка: %s" % (reason, str(e)[:120]))
        return {"ok": False, "error": str(e)[:200]}
    with _LOCK:
        _LAST_RUN = _now()
    dropped = _rotate()
    msg = "%s: архив %s (%d байт), удалено старых: %d" % (reason, name, len(blob), dropped)
    _log(msg)
    config.log("autobackup: " + msg)
    try:
        import notify
        notify.event("backup", msg)
    except Exception:
        pass
    return {"ok": True, "name": name, "bytes": len(blob), "dropped": dropped}


def read_file(name):
    """Отдать архив по имени (с защитой от выхода из папки)."""
    name = str(name or "")
    if not name.startswith("aurora-backup-") or not name.endswith(".zip") \
            or "/" in name or "\\" in name or ".." in name:
        return None
    path = os.path.join(backup_dir(), name)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return None


def status():
    with _LOCK:
        log = list(reversed(_LOG))
        last = _LAST_RUN
    interval = _interval_h()
    next_ts = 0
    if enabled():
        next_ts = last + interval * 3600 if last else _now()
    return {
        "ok": True,
        "enabled": enabled(),
        "interval_h": interval,
        "keep": _keep(),
        "has_password": bool(config.get("backup_password", "")),
        "last_ts": last,
        "next_ts": next_ts,
        "files": list_files(),
        "log": log,
    }


def tick():
    if not enabled():
        return False
    interval = _interval_h()
    with _LOCK:
        due = (_LAST_RUN == 0 or _now() - _LAST_RUN >= interval * 3600)
    if not due:
        return False
    run_now("плановый бэкап")
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
            config.log("autobackup: ошибка тика: %s" % e)
        time.sleep(_TICK_S)


def start():
    global _STARTED
    with _LOCK:
        if _STARTED:
            return False
        _STARTED = True
    threading.Thread(target=loop, daemon=True).start()
    return True
