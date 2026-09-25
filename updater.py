# Aurora v1.3.1 — авто-обновление: сверка версии с GitHub Releases, скачивание,
# sha256-проверка, бэкап текущих файлов, замена модулей, перезапуск.
# Источник сборки фиксирован в config.UPDATE_REPO, отключить нельзя.

import errno
import hashlib
import io
import json
import os
import re
import shutil
import tarfile
import tempfile
import threading
import time
import urllib.request
import zipfile

import config
import release_sign

_REPO = (getattr(config, "UPDATE_REPO", "") or "").strip()
_API = "https://api.github.com/repos/"
_RAW = "https://raw.githubusercontent.com/"

# файлы, которые обновляются из linux-сборки релиза
_MODULES = [
    "config.py", "pool.py", "source.py", "core.py", "telemetry.py",
    "tgws.py", "recovery.py", "rusegment.py", "api.py", "ui.py", "run.py",
    "security.py", "updater.py", "mesh.py", "subs.py", "crypt.py", "release_sign.py",
    "proxy/__init__.py", "proxy/_aes.py", "proxy/balancer.py", "proxy/bridge.py",
    "proxy/config.py", "proxy/fake_tls.py", "proxy/pool.py", "proxy/raw_websocket.py",
    "proxy/stats.py", "proxy/tg_ws_proxy.py", "proxy/utils.py",
]
_STATIC = ["ui/index.html", "ui/app.js", "ui/style.css", "ui/qr.js", "run_tgws.sh", "tg-ws-proxy.service"]

_MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
_MAX_UNPACKED_BYTES = 64 * 1024 * 1024
_MAX_ENTRY_BYTES = 16 * 1024 * 1024
_MAX_ENTRIES = 512
_MAX_SIGNATURE_BYTES = 64 * 1024

_LOCK = threading.RLock()
_STATE = {"state": "idle", "msg": "", "ts": 0.0}  # idle/checking/ready/applying/done/error


def _pubkey():
    """Публичный ключ подписи: config.UPDATE_PUBKEY имеет приоритет над окружением."""
    configured = str(getattr(config, "UPDATE_PUBKEY", "") or "").strip()
    if configured:
        return release_sign.parse_pubkey(configured)
    return release_sign.load_pubkey()


def _asset_url(assets, name):
    for a in assets or []:
        if (a.get("name") or "") == name:
            url = a.get("browser_download_url")
            if not url:
                raise RuntimeError("у ассета %s отсутствует URL" % name)
            return url
    raise RuntimeError("в релизе отсутствует ассет %s" % name)


def _verify_signature(data, name, version, signature):
    return release_sign.verify_release(data, signature, pubkey=_pubkey(),
                                        repo=_REPO, version=str(version), asset=name)


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
    s["latest"] = _STATE.get("latest", "")
    s["update"] = bool(_STATE.get("update", False))
    try:
        key = _pubkey()
    except Exception as e:
        key = b""
        s["pubkey_error"] = str(e)
    s["signature_required"] = True
    s["signed"] = bool(key)
    s["pubkey"] = release_sign.fingerprint(key) if key else ""
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
        with _LOCK:
            _STATE["latest"] = latest
            _STATE["update"] = update
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


def _archive_rel(name, want):
    name = str(name or "").replace("\\", "/")
    if not name or name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        return None
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        return None
    if any(p.lower() in ("linux", "windows") for p in parts):
        return None
    rel = "/".join(parts)
    if rel in want:
        return rel
    if len(parts) > 1:
        rel = "/".join(parts[1:])
        if rel in want:
            return rel
    return None


def _digest(value):
    value = str(value or "").strip().lower()
    if value.startswith("sha256:"):
        value = value[7:]
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise RuntimeError("у релиза отсутствует корректный sha256 digest")
    return value


def _download_release_zip():
    rel = _http_json(_API + _REPO + "/releases/latest")
    assets = rel.get("assets") or []
    for a in assets:
        name = a.get("name") or ""
        if not (name.endswith(".zip") and "linux" in name.lower()):
            continue
        url = a.get("browser_download_url")
        if not url:
            raise RuntimeError("у zip-ассета отсутствует URL")
        signature = _http_bytes(_asset_url(assets, name + ".sig"))
        return _http_bytes(url), name, _digest(a.get("digest")), signature
    raise RuntimeError("нет linux zip в релизе")

def _verify_sha256(data, expected):
    expected = _digest(expected)
    got = hashlib.sha256(data).hexdigest()
    return hmac_compare(got, expected)


def _validate_staged(staged, expected_version):
    for rel, path in staged.items():
        if not rel.endswith(".py"):
            continue
        with open(path, "r", encoding="utf-8-sig") as f:
            compile(f.read(), rel, "exec")
    config_path = staged.get("config.py")
    if not config_path:
        raise RuntimeError("в архиве отсутствует config.py")
    with open(config_path, "r", encoding="utf-8-sig") as f:
        match = re.search(r"^\s*VERSION\s*=\s*['\"]([^'\"]+)['\"]", f.read(), re.M)
    if not match or match.group(1) != str(expected_version):
        raise RuntimeError("версия config.py не совпадает с релизом")


def _install_file(src, dst):
    try:
        os.replace(src, dst)
    except OSError as e:
        if getattr(e, "errno", None) != errno.EXDEV:
            raise
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(dst), suffix=".aurora-new")
        os.close(fd)
        try:
            shutil.copy2(src, tmp)
            os.replace(tmp, dst)
        except Exception:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
        try:
            os.unlink(src)
        except OSError:
            pass


def _replace_staged(staged, rollback_dir):
    history = []
    try:
        for rel, src in sorted(staged.items()):
            dst = os.path.join(config.BASE_DIR, *rel.split("/"))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            backup = os.path.join(rollback_dir, *rel.split("/"))
            os.makedirs(os.path.dirname(backup), exist_ok=True)
            had_old = os.path.isfile(dst)
            if had_old:
                shutil.copy2(dst, backup)
            history.append((dst, backup, had_old))
            _install_file(src, dst)
    except Exception:
        for dst, backup, had_old in reversed(history):
            try:
                if had_old:
                    shutil.copy2(backup, dst)
                elif os.path.exists(dst):
                    os.unlink(dst)
            except OSError:
                pass
        raise
    return sorted(staged)


def hmac_compare(a, b):
    import hmac as _h
    return _h.compare_digest(str(a).lower().encode(), str(b).lower().encode())


def apply():
    """Полное обновление: check → download → sha256 → backup → замена файлов.
    Не перезапускает процесс — рестарт делает вызывающая сторона (systemd/Docker)."""
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
        data, name, digest, signature = _download_release_zip()
        _set_state("applying", "бэкап текущих файлов")
        bk = _backup_current(chk["latest"])
        _set_state("applying", "распаковка и замена")
        replaced = _extract_and_replace(data, name, digest, chk["latest"], signature)
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


def _extract_and_replace(zip_bytes, name, digest, expected_version, signature=b""):
    if len(zip_bytes) > _MAX_ARCHIVE_BYTES:
        raise RuntimeError("архив обновления слишком большой")
    signed = _verify_signature(zip_bytes, name, expected_version, signature)
    if not _verify_sha256(zip_bytes, digest):
        raise RuntimeError("sha256 релиза не совпал — обновление отменено")
    if signed and not hmac_compare(signed["digest"], _digest(digest)):
        raise RuntimeError("подпись и метаданные релиза расходятся — обновление отменено")
    want = set(_MODULES) | set(_STATIC)
    with tempfile.TemporaryDirectory(prefix="aurora_upd_") as tmpd:
        stage = os.path.join(tmpd, "stage")
        rollback = os.path.join(tmpd, "rollback")
        os.makedirs(stage, exist_ok=True)
        os.makedirs(rollback, exist_ok=True)
        staged = {}
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
            infos = z.infolist()
            if len(infos) > _MAX_ENTRIES:
                raise RuntimeError("слишком много файлов в архиве обновления")
            total_size = 0
            for info in infos:
                if info.is_dir():
                    continue
                if info.file_size < 0 or info.file_size > _MAX_ENTRY_BYTES:
                    raise RuntimeError("файл обновления слишком большой")
                total_size += info.file_size
            if total_size > _MAX_UNPACKED_BYTES:
                raise RuntimeError("распакованный архив слишком большой")
            for info in infos:
                if info.is_dir():
                    continue
                mode = (info.external_attr >> 16) & 0o170000
                if mode == 0o120000:
                    raise RuntimeError("символические ссылки в обновлении запрещены")
                rel = _archive_rel(info.filename, want)
                if rel is None:
                    continue
                if rel in staged:
                    raise RuntimeError("дубликат файла в архиве обновления: %s" % rel)
                dst = os.path.join(stage, *rel.split("/"))
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                copied = 0
                with z.open(info) as src, open(dst, "wb") as out:
                    while True:
                        chunk = src.read(1024 * 1024)
                        if not chunk:
                            break
                        copied += len(chunk)
                        if copied > _MAX_ENTRY_BYTES:
                            raise RuntimeError("файл обновления слишком большой")
                        out.write(chunk)
                staged[rel] = dst
        if set(staged) != want:
            missing = sorted(want - set(staged))
            raise RuntimeError("неполный манифест обновления: %s" % ", ".join(missing))
        _validate_staged(staged, expected_version)
        return _replace_staged(staged, rollback)


AUTO_INTERVAL = getattr(config, "UPDATE_CHECK_INTERVAL", 15 * 60)


def _restart_after_apply():
    """Перезапуск процесса после применения обновления (systemd/docker/NSSM поднимут заново)."""
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
