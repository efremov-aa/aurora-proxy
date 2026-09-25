# Aurora v1.0 — Telegram WS-прокси: контроль процесса, секрет, QR-ссылка.

import os
import socket
import subprocess
import sys
import threading
import time

import config

SECRET_FILE = os.path.join(config.DATA_DIR, "tg_secret.txt")
RUN_SCRIPT = os.path.join(config.BASE_DIR, "run_tgws.sh")
_SECRET_LOCK = threading.RLock()


def resource_path(rel):
    """Путь к ресурсу: в PyInstaller-бандле — из _MEIPASS, иначе из BASE_DIR."""
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, rel)
    return os.path.join(config.BASE_DIR, rel)


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
            os.makedirs(os.path.dirname(SECRET_FILE) or ".", exist_ok=True)
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
                                 timeout=10, creationflags=config.HIDE_FLAG).stdout
            pids = []
            for ln in out.splitlines():
                if ":%d" % config.TGWS_PORT in ln and "LISTENING" in ln:
                    parts = ln.split()
                    if parts and parts[-1].isdigit() and parts[-1] not in pids:
                        pids.append(parts[-1])
            for pid in pids:
                subprocess.run(["taskkill", "/F", "/PID", pid],
                               capture_output=True, timeout=10,
                               creationflags=config.HIDE_FLAG)
        except Exception:
            pass
        try:
            if getattr(sys, "frozen", False):
                tgb = resource_path("bin/tg-ws-proxy.exe")
                cmd = [tgb, "--host", "0.0.0.0",
                       "--port", str(config.TGWS_PORT), "--secret-fd", "0"]
            else:
                cmd = [sys.executable, "-m", "proxy.tg_ws_proxy",
                       "--host", "0.0.0.0", "--port", str(config.TGWS_PORT),
                       "--secret-fd", "0"]
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=config.HIDE_FLAG,
            )
            try:
                proc.stdin.write((secret + "\n").encode("ascii"))
                proc.stdin.close()
            except (BrokenPipeError, OSError, ValueError):
                try:
                    proc.stdin.close()
                except OSError:
                    pass
                if proc.poll() is None:
                    proc.terminate()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    if proc.poll() is None:
                        proc.kill()
                return False
            end = time.time() + 15
            while time.time() < end:
                if proc.poll() is not None:
                    return False
                if port_open():
                    return True
                time.sleep(1)
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()
                    try:
                        proc.wait(timeout=5)
                    except Exception:
                        pass
            return False
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


def status():
    return {
        "running": running(),
        "port_open": port_open(),
        "secret_ok": bool(_get_secret()),
        "link": tgws_link(),
    }


def refresh_status():
    config.update_state(tgws=status())
