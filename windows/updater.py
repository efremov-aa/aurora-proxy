# Aurora v1.3.1 — авто-обновление: сверка версии с GitHub Releases, скачивание,
# sha256-проверка, бэкап текущих файлов, замена модулей, перезапуск.
# Источник сборки фиксирован в config.UPDATE_REPO, отключить нельзя.
# Windows-сборка: без security.py, статика включает qr.js, ассет релиза — windows.zip.

import hashlib
import json
import os
import shutil
import tarfile
import threading
import time
import urllib.request
import zipfile

import config

_REPO = (getattr(config, "UPDATE_REPO", "") or "").strip()
_API = "https://api.github.com/repos/"
_RAW = "https://raw.githubusercontent.com/"

# файлы, которые обновляются из windows-сборки релиза
_MODULES = [
    "config.py", "pool.py", "source.py", "core.py", "telemetry.py",
    "tgws.py", "recovery.py", "rusegment.py", "api.py", "ui.py", "run.py",
    "updater.py",
]
_STATIC = ["ui/index.html", "ui/app.js", "ui/style.css", "ui/qr.js"]

_LOCK = threading.Lock()
_STATE = {"state": "idle", "msg": "", "ts": 0.0}  # idle/checking/ready/applying/done/error


def _set_state(st, msg=""):
    with _LOCK:
        _STATE["state"] = st
        _STATE["msg"] = msg
        _STATE["ts"] = int(time.time())
    if msg:
        config.log("update: %s" % msg)


def status():
    with _LOCK:
        s = dict(_STATE)
    s["enabled"] = bool(_REPO)
    s["current"] = config.VERSION
    s["repo"] = _REPO
    return s


def _http_json(url, timeout=15):
    req = urllib.request.Request(url, headers={
        "User-Agent": "Aurora/" + config.VERSION,
        "Accept": "application/vnd.github+json",
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def _http_bytes(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": "Aurora/" + config.VERSION})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def _ver_tuple(v):
    parts = []
    for p in str(v).strip().lstrip("v").split("."):
        n = ""
        for ch in p:
            if ch.isdigit():
                n += ch
            else:
                break
        parts.append(int(n) if n else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def check():
    """Сверяет VERSION с releases/latest. Возвращает {ok, current, latest, update}."""
    if not _REPO:
        return {"ok": False, "error": "AURORA_UPDATE_REPO не задан"}
    _set_state("checking", "запрос releases/latest")
    try:
        rel = _http_json(_API + _REPO + "/releases/latest")
        latest = str(rel.get("tag_name") or "").lstrip("v")
        update = _ver_tuple(latest) > _ver_tuple(config.VERSION)
        _set_state("ready" if update else "done",
                   ("доступно: v%s" % latest) if update else ("актуально: v%s" % config.VERSION))
        return {"ok": True, "current": config.VERSION, "latest": latest, "update": update}
    except Exception as e:
        _set_state("error", "check: %s" % e)
        return {"ok": False, "error": str(e)}


def _backup_current(tag):
    """Тар-бэкап обновляемых файлов в data/backup_update_<tag>.tar.gz."""
    bk = os.path.join(config.DATA_DIR, "backup_update_%s.tar.gz" % tag.replace("/", "_"))
    with tarfile.open(bk, "w:gz") as tar:
        for rel in _MODULES + _STATIC:
            p = os.path.join(config.BASE_DIR, rel)
            if os.path.isfile(p):
                tar.add(p, arcname=rel)
    return bk


def _download_release_zip():
    """Скачивает zip-ассет релиза (windows.zip) или source-архив при отсутствии → bytes."""
    rel = _http_json(_API + _REPO + "/releases/latest")
    for a in rel.get("assets") or []:
        name = a.get("name") or ""
        if name.endswith(".zip") and "windows" in name.lower():
            return _http_bytes(a.get("browser_download_url")), name, ""
    # фолбэк: source zip
    url = rel.get("zipball_url")
    if url:
        return _http_bytes(url), "source.zip", ""
    raise RuntimeError("нет zip в релизе")


def _verify_sha256(data, expected):
    if not expected:
        return True
    got = hashlib.sha256(data).hexdigest()
    return hmac_compare(got, expected)


def hmac_compare(a, b):
    import hmac as _h
    return _h.compare_digest(str(a).lower().encode(), str(b).lower().encode())


def apply():
    """Полное обновление: check → download → sha256 → backup → замена файлов.
    Не перезапускает процесс — рестарт делает вызывающая сторона (NSSM)."""
    if not _REPO:
        return {"ok": False, "error": "AURORA_UPDATE_REPO не задан"}
    if not _LOCK.acquire(blocking=False):
        return {"ok": False, "error": "обновление уже идёт"}
    try:
        chk = check()
        if not chk.get("ok"):
            return chk
        if not chk.get("update"):
            return {"ok": True, "msg": "уже актуально", "current": config.VERSION}
        _set_state("applying", "скачивание zip")
        data, name, _ = _download_release_zip()
        _set_state("applying", "бэкап текущих файлов")
        bk = _backup_current(chk["latest"])
        _set_state("applying", "распаковка и замена")
        replaced = _extract_and_replace(data, name)
        _set_state("done", "обновлено до v%s (заменено %d файлов, бэкап %s)"
                   % (chk["latest"], len(replaced), os.path.basename(bk)))
        return {"ok": True, "latest": chk["latest"], "replaced": replaced,
                "backup": os.path.basename(bk),
                "restart_required": True}
    except Exception as e:
        _set_state("error", "apply: %s" % e)
        return {"ok": False, "error": str(e)}
    finally:
        _LOCK.release()


def _extract_and_replace(zip_bytes, name):
    """Распаковывает zip во временную папку и заменяет _MODULES/_STATIC.
    sha256 zip (если задан в data/update_sha256.txt) сверяется заранее."""
    import tempfile
    replaced = []
    want = set(_MODULES) | set(_STATIC)
    # сверка sha256, если рядом лежит файл с ожидаемым хэшем
    sha_file = os.path.join(config.DATA_DIR, "update_sha256.txt")
    if os.path.isfile(sha_file):
        expected = open(sha_file, "r", encoding="utf-8").read().strip()
        if not _verify_sha256(zip_bytes, expected):
            raise RuntimeError("sha256 релиза не совпал — обновление отменено")
    tmpd = tempfile.mkdtemp(prefix="aurora_upd_")
    try:
        zp = os.path.join(tmpd, "r.zip")
        with open(zp, "wb") as f:
            f.write(zip_bytes)
        with zipfile.ZipFile(zp) as z:
            # внутри source-zip/github-ассета обычно корень-папка с префиксом
            for info in z.infolist():
                if info.is_dir():
                    continue
                rel = info.filename.split("/", 1)[-1] if "/" in info.filename else info.filename
                if rel not in want:
                    continue
                dst = os.path.join(config.BASE_DIR, rel)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                with z.open(info) as src, open(dst + ".new", "wb") as out:
                    shutil.copyfileobj(src, out)
                os.replace(dst + ".new", dst)
                replaced.append(rel)
        if not replaced:
            raise RuntimeError("в архиве не найдено ни одного нашего файла")
        return replaced
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)


AUTO_INTERVAL = getattr(config, "UPDATE_CHECK_INTERVAL", 15 * 60)


def _restart_after_apply():
    """Перезапуск процесса после применения обновления (NSSM поднимет заново)."""
    config.log("update: перезапуск после обновления")
    time.sleep(1)
    try:
        os._exit(0)
    except Exception:
        pass


def auto_update():
    """Обязательный фоновый цикл: автоматическое применение обновлений.
    Запускается безусловно при старте, отключение/обход не предусмотрен."""
    def _bg():
        while True:
            try:
                r = apply()
                if not r.get("ok"):
                    config.log("update: %s" % (r.get("error") or r.get("msg") or "?"))
                elif r.get("restart_required"):
                    config.log("update: применено v%s, перезапуск" % r.get("latest"))
                    _restart_after_apply()
                else:
                    config.log("update: актуально (v%s)" % config.VERSION)
            except Exception as e:
                config.log("update: ошибка цикла: %s" % e)
            time.sleep(AUTO_INTERVAL)
    threading.Thread(target=_bg, daemon=True).start()