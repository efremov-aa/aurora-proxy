# Aurora v1.0 — Telegram WS-прокси: контроль процесса, секрет, QR-ссылка.

import os
import socket
import subprocess
import threading
import time

import config

SECRET_FILE = os.path.join(config.DATA_DIR, "tg_secret.txt")
RUN_SCRIPT = os.path.join(config.BASE_DIR, "run_tgws.sh")
_SECRET_LOCK = threading.RLock()


def _get_secret():
    """Секрет из data/tg_secret.txt или генерация нового."""
    with _SECRET_LOCK:
        import crypt
        missing = object()
        try:
            raw = crypt.load_bytes(SECRET_FILE, default=missing)
        except crypt.StorageError as e:
            config.quarantine_file(SECRET_FILE)
            raise config.StorageDataError("tg_secret.txt: %s" % e) from e
        if raw is missing:
            import secrets
            value = secrets.token_hex(16)
            try:
                crypt.save_bytes(SECRET_FILE, value.encode("ascii"), exclusive=True)
            except FileExistsError:
                try:
                    raw = crypt.load_bytes(SECRET_FILE)
                    value = raw.decode("utf-8").strip()
                except (crypt.StorageError, UnicodeError, AttributeError) as e:
                    config.quarantine_file(SECRET_FILE)
                    raise config.StorageDataError("tg_secret.txt: %s" % e) from e
            except (crypt.StorageError, OSError) as e:
                config.quarantine_file(SECRET_FILE)
                raise config.StorageDataError("tg_secret.txt: %s" % e) from e
            return value
        try:
            value = raw.decode("utf-8").strip()
        except UnicodeError as e:
            config.quarantine_file(SECRET_FILE)
            raise config.StorageDataError("tg_secret.txt: %s" % e) from e
        if not value or len(value) > 256:
            config.quarantine_file(SECRET_FILE)
            raise config.StorageDataError("tg_secret.txt: invalid secret")
        try:
            crypt.save_bytes(SECRET_FILE, value.encode("utf-8"))
        except (crypt.StorageError, OSError) as e:
            config.quarantine_file(SECRET_FILE)
            raise config.StorageDataError("tg_secret.txt: %s" % e) from e
        return value


def port_open(timeout=1):
    try:
        s = socket.create_connection(("127.0.0.1", config.TGWS_PORT), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False


def running():
    """Статус процесса tg-ws-proxy (pgrep по точному имени python-модуля)."""
    try:
        out = subprocess.run(["pgrep", "-f", "proxy.tg_ws_proxy"],
                             capture_output=True, text=True, timeout=5).stdout
        return bool(out.strip())
    except Exception:
        return port_open()


def restart():
    """Перезапуск через юнит tg-ws-proxy.service (или скрипт)."""
    try:
        r = subprocess.run(["systemctl", "--user", "restart", "tg-ws-proxy"],
                           capture_output=True, text=True, timeout=20)
        return r.returncode == 0
    except Exception:
        pass
    try:
        subprocess.Popen(["bash", RUN_SCRIPT])
        return True
    except Exception:
        return False


def tgws_link():
    """Ссылка tg://proxy?... для QR."""
    import urllib.parse
    secret = _get_secret()
    host = config.external_link_host()
    if not secret or not host:
        return ""
    return "tg://proxy?%s" % urllib.parse.urlencode({
        "server": config._format_link_host(host),
        "port": config.TGWS_PORT,
        "secret": secret,
    })


def status(include_secret=False):
    data = {
        "running": running(),
        "port_open": port_open(),
        "port": config.TGWS_PORT,
        "secret_ok": bool(_get_secret()),
        "link": tgws_link(),
    }
    # Секрет отдаём только доверенному клиенту (панель владельца из LAN/loopback).
    if include_secret:
        data["secret"] = _get_secret() or ""
    return data


def refresh_status():
    config.update_state(tgws=status())
