# Aurora v1.0 — Telegram WS-прокси: контроль процесса, секрет, QR-ссылка.

import os
import socket
import subprocess
import threading
import time

import config

SECRET_FILE = os.path.join(config.BASE_DIR, "data", "tg_secret.txt")
RUN_SCRIPT = os.path.join(config.BASE_DIR, "run_tgws.sh")


def _get_secret():
    """Секрет из data/tg_secret.txt или генерация нового."""
    try:
        with open(SECRET_FILE, "r", encoding="utf-8") as f:
            s = f.read().strip()
        if s:
            return s
    except OSError:
        pass
    import secrets
    s = secrets.token_hex(16)
    try:
        with open(SECRET_FILE, "w", encoding="utf-8") as f:
            f.write(s)
    except OSError:
        pass
    return s


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
    """Ссылка tg://proxy?... для QR. host берём из VM_HOST."""
    secret = _get_secret()
    if not secret:
        return ""
    return "tg://proxy?server=%s&port=%d&secret=%s" % (config.VM_HOST, config.TGWS_PORT, secret)


def status():
    return {
        "running": running(),
        "port_open": port_open(),
        "port": config.TGWS_PORT,
        "secret_ok": bool(_get_secret()),
        "link": tgws_link(),
    }


def refresh_status():
    config.update_state(tgws=status())
