# Aurora v1.0 — Telegram WS-прокси: контроль процесса, секрет, QR-ссылка.

import os
import socket
import subprocess
import sys
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
    """Статус процесса tg-ws-proxy (pgrep на Linux / port_open на Windows)."""
    if os.name == "nt":
        return port_open()
    try:
        out = subprocess.run(["pgrep", "-f", "proxy.tg_ws_proxy"],
                             capture_output=True, text=True, timeout=5).stdout
        return bool(out.strip())
    except Exception:
        return port_open()


def restart():
    """Перезапуск tg-ws-proxy (юнит на Linux / subprocess на Windows)."""
    if os.name == "nt":
        secret = _get_secret()
        if not secret:
            return False
        # убить старый процесс, если держит порт (иначе новый не поднимется)
        try:
            out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True,
                                 timeout=10).stdout
            pids = []
            for ln in out.splitlines():
                if ":%d" % config.TGWS_PORT in ln and "LISTENING" in ln:
                    parts = ln.split()
                    if parts and parts[-1].isdigit() and parts[-1] not in pids:
                        pids.append(parts[-1])
            for pid in pids:
                subprocess.run(["taskkill", "/F", "/PID", pid],
                               capture_output=True, timeout=10)
        except Exception:
            pass
        try:
            subprocess.Popen(
                [sys.executable, "-m", "proxy.tg_ws_proxy",
                 "--host", "0.0.0.0", "--port", str(config.TGWS_PORT),
                 "--secret", secret],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception:
            return False
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
    """Ссылка tg://proxy?... для QR.

    host: явный env AURORA_TGWS_HOST, иначе внутренний IP ПК (config.VM_HOST).
    Публичный IP — только явный фолбэк, если локальный не найден.
    """
    secret = _get_secret()
    if not secret:
        return ""
    host = (os.environ.get("AURORA_TGWS_HOST", "") or "").strip()
    if not host:
        vm = config.VM_HOST if hasattr(config, "VM_HOST") else ""
        if vm and not str(vm).startswith("127."):
            host = str(vm)
        elif hasattr(config, "get_public_ip"):
            host = config.get_public_ip() or ""
    if not host:
        host = "127.0.0.1"
    return "tg://proxy?server=%s&port=%d&secret=%s" % (host, config.TGWS_PORT, secret)


def status():
    return {
        "running": running(),
        "port_open": port_open(),
        "secret_ok": bool(_get_secret()),
        "link": tgws_link(),
    }


def refresh_status():
    config.update_state(tgws=status())