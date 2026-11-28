# Aurora A-1040 «Кот-смотритель» — бэкап и восстановление настроек/ключей.
#
# Архив: ZIP с manifest.json и aurora-backup.bin. Полезная нагрузка зашифрована
# паролем владельца (crypt.seal_password, scrypt + ChaCha20-Poly1305), поэтому
# архив можно переносить между машинами с разным файлом-ключом data/.aurora_key.
# В бэкап не попадают порты и учётные данные панели: восстановление не должно
# менять способ доступа к серверу.

import io
import json
import threading
import time
import zipfile

import config
import crypt
import masque
import pool
import source
import warp

ARCHIVE_MAGIC = "AURORA-BACKUP"
ARCHIVE_VERSION = 1
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
MIN_PASSWORD_LEN = 8

# Только эти настройки переживают восстановление. Порты, токены, PIN и секреты
# меша намеренно исключены: иначе восстановление могло бы закрыть панель.
BACKUP_SETTINGS = (
    "server_name", "auto_refresh", "lan_only", "block_scanners", "rate_limit",
    "segment_title", "segment_regions", "segment_custom",
    "warp_mode", "masque_enabled", "tgws_enabled", "vless_enabled",
    "game_tun", "game_scenario", "mesh_id",
)


class BackupError(ValueError):
    pass


def _check_password(password):
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LEN:
        raise BackupError("пароль архива должен быть не короче %d символов"
                          % MIN_PASSWORD_LEN)


def collect():
    """Собрать снимок данных для архива (без шифрования)."""
    settings = {key: config.get(key) for key in BACKUP_SETTINGS}
    return {
        "magic": ARCHIVE_MAGIC,
        "version": ARCHIVE_VERSION,
        "app": config.VERSION,
        "exported_at": int(time.time()),
        "settings": settings,
        "keys": pool.get_keys(),
        "warp": warp.backup_snapshot(),
        "masque": masque.backup_snapshot(),
    }


def export(password):
    """Вернуть (bytes zip, имя файла) для скачивания."""
    _check_password(password)
    plain = json.dumps(collect(), ensure_ascii=False,
                       separators=(",", ":")).encode("utf-8")
    blob = crypt.seal_password(plain, password)
    manifest = {
        "magic": ARCHIVE_MAGIC,
        "version": ARCHIVE_VERSION,
        "app": config.VERSION,
        "exported_at": int(time.time()),
        "entries": ["manifest.json", "aurora-backup.bin"],
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo("manifest.json")
        info.external_attr = 0o600 << 16
        zf.writestr(info, json.dumps(manifest, ensure_ascii=False))
        info = zipfile.ZipInfo("aurora-backup.bin")
        info.external_attr = 0o600 << 16
        zf.writestr(info, blob)
    name = "aurora-backup-%s.zip" % time.strftime("%Y%m%d-%H%M%S")
    return buf.getvalue(), name


def _open_archive(data):
    if not isinstance(data, (bytes, bytearray)) or not data:
        raise BackupError("пустой архив")
    if len(data) > MAX_ARCHIVE_BYTES:
        raise BackupError("архив больше %d МБ" % (MAX_ARCHIVE_BYTES // 1048576))
    try:
        zf = zipfile.ZipFile(io.BytesIO(bytes(data)))
    except (zipfile.BadZipFile, OSError, ValueError) as e:
        raise BackupError("это не zip-архив: %s" % e) from e
    with zf:
        infos = zf.infolist()
        names = [info.filename for info in infos]
        if sorted(names) != ["aurora-backup.bin", "manifest.json"]:
            raise BackupError("неожиданное содержимое архива")
        if len(set(names)) != len(names):
            raise BackupError("дублирующиеся записи в архиве")
        for info in infos:
            if info.is_dir() or info.file_size > MAX_ARCHIVE_BYTES:
                raise BackupError("подозрительная запись в архиве")
        try:
            manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        except (OSError, UnicodeDecodeError, ValueError) as e:
            raise BackupError("манифест не читается: %s" % e) from e
        blob = zf.read("aurora-backup.bin")
    if not isinstance(manifest, dict) or manifest.get("magic") != ARCHIVE_MAGIC:
        raise BackupError("это не архив Aurora")
    if int(manifest.get("version") or 0) != ARCHIVE_VERSION:
        raise BackupError("неизвестная версия архива")
    return blob, manifest


def restore(data, password):
    """Восстановить данные из архива. Возвращает отчёт или бросает BackupError."""
    _check_password(password)
    blob, manifest = _open_archive(data)
    try:
        plain = crypt.open_password(blob, password)
    except crypt.BackupPasswordError as e:
        raise BackupError(str(e)) from e
    try:
        snapshot = json.loads(plain.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise BackupError("полезная нагрузка не читается: %s" % e) from e
    if not isinstance(snapshot, dict) or snapshot.get("magic") != ARCHIVE_MAGIC:
        raise BackupError("это не архив Aurora")
    if int(snapshot.get("version") or 0) != ARCHIVE_VERSION:
        raise BackupError("неизвестная версия архива")

    report = {"ok": True, "settings": 0, "keys_added": 0, "keys_exist": 0,
              "keys_bad": 0, "warp": 0, "masque": 0}

    settings = snapshot.get("settings")
    if not isinstance(settings, dict):
        raise BackupError("в архиве нет настроек")
    clean = {}
    for key in BACKUP_SETTINGS:
        if key in settings:
            clean[key] = settings[key]
    # fail-closed: неизвестный режим WARP из чужого/битого архива не принимаем
    if clean.get("warp_mode") not in warp.MODES:
        clean.pop("warp_mode", None)
    if not config.set_many(clean):
        raise BackupError("настройки из архива не приняты")
    report["settings"] = len(clean)

    keys = snapshot.get("keys")
    if not isinstance(keys, list):
        keys = []
    seen = set()
    existing = {k.get("uri", "") for k in pool.get_keys()}
    for item in keys:
        uri = str((item or {}).get("uri") or "").strip()
        if not uri or uri in seen:
            continue
        seen.add(uri)
        key = source._key_from_uri(uri)
        if not key:
            report["keys_bad"] += 1
            continue
        if uri in existing:
            report["keys_exist"] += 1
            continue
        result = pool.add_key(key, force=True)
        if result == "added":
            report["keys_added"] += 1
        elif result == "exists":
            report["keys_exist"] += 1
        else:
            report["keys_bad"] += 1

    ok, count, err = warp.restore_snapshot(snapshot.get("warp") or {})
    if ok:
        report["warp"] = count
    ok, count, err = masque.restore_snapshot(snapshot.get("masque") or {})
    if ok:
        report["masque"] = count

    try:
        import core
        threading.Thread(target=core.sync, daemon=True).start()
    except Exception:
        pass
    try:
        import tgws
        tgws.refresh_status()
    except Exception:
        pass
    config.log("backup: восстановлено настроек %d, ключей +%d"
               % (report["settings"], report["keys_added"]))
    return report
