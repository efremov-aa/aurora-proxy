# Aurora v1.0 — ядро: сборка xray.json, старт/рестарт xray, ротация, watch.
# Принцип: final-тег — только живой ключ с реальным egress. VPN OFF -> direct.

import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from contextlib import contextmanager

import config
import crypt
import pool
import subs

XRAY_CONFIG_LOCK = threading.RLock()  # RLock: read-modify-write оборачивается этим локом целиком
EGRESS_LOCK = threading.Lock()
_ROTATE_LOCK = threading.Lock()
_MODE_LOCK = threading.Lock()  # сериализация sync/set_direct (гонка vpn ON->OFF)
_MODE_STATE_LOCK = threading.RLock()
_MODE_GENERATION = [0]
_EGRESS_CACHE = {"ip": "-", "ts": 0.0}
_LAST_ROTATE = [0.0]
_WATCH_STOP = threading.Event()
_XRAY_FILE_LOCK = threading.RLock()
_XRAY_FILE_STATE = {"handle": None, "depth": 0}


@contextmanager
def _cross_process_lock():
    with _XRAY_FILE_LOCK:
        if _XRAY_FILE_STATE["depth"] == 0:
            os.makedirs(config.DATA_DIR, exist_ok=True)
            path = os.path.join(config.DATA_DIR, ".xray-transaction.lock")
            handle = open(path, "a+", encoding="utf-8")
            try:
                if os.name == "nt":
                    import msvcrt
                    handle.seek(0, os.SEEK_END)
                    if handle.tell() == 0:
                        handle.write("0")
                        handle.flush()
                    deadline = time.monotonic() + 120.0
                    while True:
                        try:
                            handle.seek(0)
                            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                            break
                        except OSError:
                            if time.monotonic() >= deadline:
                                raise TimeoutError("xray transaction lock timeout")
                            time.sleep(0.05)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                    crypt.restrict_file(path)
            except Exception:
                handle.close()
                raise
            _XRAY_FILE_STATE["handle"] = handle
            _XRAY_FILE_STATE["depth"] = 1
        else:
            _XRAY_FILE_STATE["depth"] += 1
        try:
            yield
        finally:
            _XRAY_FILE_STATE["depth"] -= 1
            if _XRAY_FILE_STATE["depth"] == 0:
                handle = _XRAY_FILE_STATE["handle"]
                try:
                    if os.name == "nt":
                        import msvcrt
                        handle.seek(0)
                        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                finally:
                    handle.close()
                    _XRAY_FILE_STATE["handle"] = None

# Как управлять xray: "systemctl" (по умолчанию) или "proc" (в Docker: xray — подпроцесс).
XRAY_MANAGE = os.environ.get("XRAY_MANAGE", "systemctl")
_XRAY_PROC = [None]  # Popen (режим proc)


def _xray_bin():
    cands = [
        shutil.which("xray"),
        shutil.which("xray.exe"),
        os.path.join(os.path.expanduser("~"), "xray"),
        os.path.join(config.BASE_DIR, "xray"),
        "/usr/local/bin/xray",
    ]
    for c in cands:
        if c and os.path.exists(c):
            return c
    return None


def _master_source_ip():
    raw = str(config.get("master_addr", "") or "").strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "//" + raw
    try:
        host = urllib.parse.urlparse(raw).hostname
        return str(ipaddress.ip_address(host)) if host else None
    except ValueError:
        return None


# --- A-145: исходящий relay-туннель меш-сети (по подписке клиента) ---
def _mesh_outbound():
    """A-145: исходящий relay-туннель (SOCKS5 меш-релея на loopback).

    Выключено по умолчанию: пока mesh_tunnel выключен, конфиг xray
    не меняется ни на байт."""
    if not config.get("mesh_tunnel", False):
        return None
    try:
        import meshtunnel
    except Exception:
        return None
    try:
        if not meshtunnel.enabled():
            return None
        port = int(meshtunnel.MESH_PORT) + 1
    except Exception:
        return None
    if port <= 0 or port > 65535:
        return None
    return {"tag": "mesh", "protocol": "socks",
            "settings": {"servers": [{"address": "127.0.0.1", "port": port}]}}


def _vless_emails(cfg):
    """A-145: email-адреса клиентов VLESS (якорь для маршрутизации)."""
    out = []
    for inbound in (cfg.get("inbounds") or []):
        if not isinstance(inbound, dict) or inbound.get("tag") != "vless-in":
            continue
        clients = ((inbound.get("settings") or {}).get("clients") or [])
        for client in clients:
            if not isinstance(client, dict):
                continue
            email = str(client.get("email") or "").strip()
            if email and email not in out:
                out.append(email)
    return out[:64]


def _mesh_rule_position(rules):
    """Позиция для mesh-правила: после block/direct-правил, но до inboundTag
    (RU-байпас и http-правило идут в туннель)."""
    for idx, rule in enumerate(rules):
        if isinstance(rule, dict) and rule.get("inboundTag"):
            return idx
    return len(rules)


def build_xray_config(final_tag):
    """Полный xray-конфиг. outbounds: [пул vless..., direct, block]."""
    if final_tag == "direct":
        tag = "direct"
    else:
        tag = final_tag
    outbounds = []
    keys = pool.get_keys()
    used_tags = set()
    for k in keys:
        ob = pool.build_outbound(k)
        if not ob:
            continue
        if ob["tag"] in used_tags:
            ob["tag"] = pool._tag_from_uri(k.get("uri", ""), k.get("host", ""))
            while ob["tag"] in used_tags:
                ob["tag"] += "-x"
        used_tags.add(ob["tag"])
        outbounds.append(ob)
        # final-ключ при коллизии переименован — routing должен идти на новое имя
        if tag != "direct" and ob["tag"] != tag and tag == k.get("tag"):
            tag = ob["tag"]
    # гарантируем наличие актуального direct/block
    outbounds.append({"tag": "direct", "protocol": "freedom",
                      "settings": {"domainStrategy": "UseIP"}})
    outbounds.append({"tag": "block", "protocol": "blackhole", "settings": {}})

    # Routing: RU-домены -> direct ПЕРВЫМ (без inboundTag — get_vless_now
    # берёт первое правило с http-in, оно должно остаться под VPN-тегом);
    # затем http-in/vless-in -> активный тег.
    http_rule = {"type": "field", "inboundTag": ["http-in"],
                 "network": "tcp,udp", "outboundTag": tag}
    rules = [http_rule]
    ru_bypass = config.ru_domains()
    if ru_bypass:
        rules.insert(0, {"type": "field",
                         "domain": ["domain:" + d for d in ru_bypass],
                         "outboundTag": "direct"})
    # Торрент-трафик на GitHub-сборках ВСЕГДА напрямую (правило юзера):
    # публичные сборки не гонят битторрент через туннель. Правило первым.
    rules.insert(0, {"type": "field", "protocol": ["bittorrent"],
                     "outboundTag": "direct"})
    rules.insert(len(rules) - 1, {"type": "field", "protocol": ["quic"],
                                  "outboundTag": "block"})
    rules.insert(len(rules) - 1, {"type": "field", "network": "udp",
                                  "outboundTag": "block"})

    cfg = {
        "log": {"loglevel": "warning", "access": "", "error": ""},
        "api": {"tag": "api-in", "services": ["StatsService"]},
        "policy": {"levels": {"0": {"statsUserUplink": True,
                                    "statsUserDownlink": True}}},
        "inbounds": [
            {"tag": "http-in", "listen": "0.0.0.0", "port": config.XRAY_PORT,
             "protocol": "http", "sniffing": {"enabled": True}},
            {"tag": "api-in", "listen": "127.0.0.1", "port": config.XRAY_API_PORT,
             "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"}},
        ],
        "outbounds": outbounds,
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": rules},
    }
    # Внешний VLESS-Reality inbound для подключения к прокси ИЗВНЕ.
    # При замке master_only сервер не раскрывает наружу входящий VLESS:
    # просочиться в этот сервер извне нельзя, работает только локальный http-in.
    vln = config.vless_public()
    master_locked = config.get("master_only", False)
    if vln.get("enabled") and vln.get("uuid") and not master_locked:
        # мастер-uuid (владелец сервера) + все активные подписочные клиенты
        clients = [{
            "id": vln["uuid"],
            "flow": vln.get("flow", "xtls-rprx-vision"),
        }]
        for cuuid in subs.build_client_list():
            clients.append({
                "id": cuuid,
                "email": cuuid,
                "flow": vln.get("flow", "xtls-rprx-vision"),
            })
        cfg["inbounds"].insert(1, {
            "tag": "vless-in",
            "listen": "0.0.0.0",
            "port": int(vln.get("port", 8443)),
            "protocol": "vless",
            "sniffing": {"enabled": True},
            "settings": {
                "clients": clients,
                "decryption": "none",
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "dest": (vln.get("sni") or vln.get("host", "www.microsoft.com")) + ":443",
                    "serverNames": [vln.get("sni") or vln.get("host", "www.microsoft.com")],
                    "privateKey": vln.get("private_key", ""),
                    "shortIds": [vln.get("short_id") or ""],
                },
            },
        })
        # A-145: подписочные клиенты -> relay-туннель меш-сети (по email)
    mesh_ob = _mesh_outbound()
    if mesh_ob:
        mesh_emails = _vless_emails(cfg)
        if mesh_emails:
            cfg["outbounds"].append(mesh_ob)
            rules.insert(_mesh_rule_position(rules),
                         {"type": "field", "inboundTag": ["vless-in"],
                          "email": mesh_emails, "outboundTag": "mesh"})
    http_rule["inboundTag"] = ["http-in", "vless-in"]
    if master_locked:
        master_ip = _master_source_ip()
        if master_ip:
            rules.insert(0, {
                "type": "field",
                "sourceIP": [master_ip],
                "inboundTag": ["http-in"],
                "outboundTag": tag,
            })
            rules.insert(1, {
                "type": "field",
                "inboundTag": ["http-in"],
                "outboundTag": "block",
            })
        else:
            cfg["inbounds"][0]["listen"] = "127.0.0.1"
    return cfg


def _authoritative_config(cfg, target):
    import copy
    allowed = {k.get("tag", "") for k in pool.get_keys() if k.get("tag")}
    # A-146: релей-туннель меш-сети не считаем «чужим» outbound: иначе
    # автосинхронизация вычистит и outbound, и правило маршрутизации.
    allowed.add("mesh")
    # A-146: возвращаем outbound mesh, если правила по нему остались
    mesh_ob = _mesh_outbound()
    if mesh_ob and not any(isinstance(o, dict) and o.get("tag") == "mesh"
                           for o in (cfg.get("outbounds") or [])):
        cfg.setdefault("outbounds", []).append(mesh_ob)
    allowed.update(("direct", "block"))
    outbounds = []
    used = set()
    for ob in list(cfg.get("outbounds", []) or []):
        tag = ob.get("tag")
        if not isinstance(tag, str) or not tag or tag in used:
            continue
        if tag not in allowed:
            continue
        used.add(tag)
        outbounds.append(copy.deepcopy(ob))
    for tag in ("direct", "block"):
        if tag not in used:
            if tag == "direct":
                outbounds.append({
                    "protocol": "freedom", "tag": "direct",
                    "settings": {"domainStrategy": "UseIP"},
                })
            else:
                outbounds.append({"protocol": "blackhole", "tag": "block"})
            used.add(tag)
    if target not in used:
        target = "direct"
    result = copy.deepcopy(cfg)
    result["outbounds"] = outbounds
    for rule in result.get("routing", {}).get("rules", []) or []:
        outbound = rule.get("outboundTag")
        if outbound not in used:
            rule["outboundTag"] = "direct"
    if not any(rule.get("type") == "field" and rule.get("inboundTag") == ["http-in"]
               for rule in result.get("routing", {}).get("rules", []) or []):
        rules = result.setdefault("routing", {}).setdefault("rules", [])
        rules.insert(0, {
            "type": "field", "inboundTag": ["http-in"], "outboundTag": target,
        })
    return result, target


def _read_config():
    path = config.XRAY_CONFIG
    try:
        if os.path.islink(path) or os.path.getsize(path) > 16 * 1024 * 1024:
            return None
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _write_config(cfg):
    with XRAY_CONFIG_LOCK:
        path = os.path.abspath(config.XRAY_CONFIG)
        directory = os.path.dirname(path) or "."
        tmp = None
        try:
            os.makedirs(directory, exist_ok=True)
            fd, tmp = tempfile.mkstemp(
                prefix=".xray-", suffix=".tmp", dir=directory)
            crypt.restrict_file(tmp)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
            try:
                crypt.restrict_file(path)
            except OSError as e:
                config.log("core: chmod xray.json не удался: %s" % e)
            if os.name != "nt":
                dir_fd = os.open(directory, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            return True
        except OSError as e:
            config.log("core: запись xray.json не удалась: %s" % e)
            return False
        finally:
            if tmp and os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass


def _config_fingerprint(cfg):
    data = json.dumps(
        cfg, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _current_fingerprint():
    current = _read_config()
    return None if current is None else _config_fingerprint(current)


def _xray_config_valid(cfg):
    xbin = _xray_bin()
    if not xbin:
        return False
    directory = os.path.dirname(os.path.abspath(config.XRAY_CONFIG)) or "."
    tmp = None
    try:
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(
            prefix=".xray-test-", suffix=".json", dir=directory)
        crypt.restrict_file(tmp)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        kwargs = {"capture_output": True, "timeout": 10}
        if os.name == "nt":
            kwargs["creationflags"] = config.HIDE_FLAG
        result = subprocess.run(
            [xbin, "run", "-test", "-config", tmp], **kwargs)
        return result.returncode == 0
    except (OSError, TypeError, ValueError, subprocess.SubprocessError):
        return False
    finally:
        if tmp:
            crypt.unlink_quiet(tmp, "xray preflight")


def _restore_config_cas(expected, previous):
    if previous is None or _current_fingerprint() != expected:
        return False
    return _write_config(previous)


def _port_open(port, timeout=1):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False


def _xray_proc_start():
    """Запуск xray как подпроцесса (режим proc для Docker)."""
    xbin = _xray_bin()
    if not xbin:
        config.log("core: xray-бинаря нет (proc)")
        return False
    if _XRAY_PROC[0] and _XRAY_PROC[0].poll() is None:
        return True
    try:
        _XRAY_PROC[0] = subprocess.Popen(
            [xbin, "run", "-c", config.XRAY_CONFIG],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as e:
        config.log("core: proc-старт xray не удался: %s" % e)
        return False
    end = time.time() + 15
    while time.time() < end:
        if _port_open(config.XRAY_PORT):
            return True
        time.sleep(1)
    config.log("core: xray (proc) не поднял порт за 15с")
    return False


def _service_value(prop):
    try:
        result = subprocess.run(
            ["systemctl", "--user", "show", "xray", "-p", prop, "--value"],
            capture_output=True, timeout=3, text=True)
    except (OSError, subprocess.SubprocessError):
        return ""
    if result.returncode != 0:
        return ""
    return str(result.stdout or "").strip()


def _service_runtime_ok():
    active = _service_value("ActiveState")
    main_pid = _service_value("MainPID")
    if not active and not main_pid:
        return True
    return active in ("active", "activating") and main_pid.isdigit() and main_pid != "0"


def _restart_xray():
    """Внешний перезапуск xray. Режим systemctl — `systemctl --user restart xray`,
    режим proc (Docker) — подпроцесс. Ждёт порт до 15с."""
    if XRAY_MANAGE == "proc":
        if _XRAY_PROC[0] and _XRAY_PROC[0].poll() is None:
            _XRAY_PROC[0].terminate()
            try:
                _XRAY_PROC[0].wait(timeout=8)
            except Exception:
                _XRAY_PROC[0].kill()
        _XRAY_PROC[0] = None
        return _xray_proc_start()
    try:
        result = subprocess.run(
            ["systemctl", "--user", "restart", "xray"],
            capture_output=True, timeout=20)
        if result.returncode != 0:
            config.log("core: xray restart failed rc=%s" % result.returncode)
            return False
    except Exception as e:
        config.log("core: xray restart failed: %s" % e)
        return False
    end = time.time() + 15
    while time.time() < end:
        if _port_open(config.XRAY_PORT) and _service_runtime_ok():
            return True
        time.sleep(1)
    config.log("core: xray не поднял порт за 15с")
    return False


def request_mode(on):
    on = bool(on)
    with _MODE_STATE_LOCK:
        _MODE_GENERATION[0] += 1
        generation = _MODE_GENERATION[0]
        config.set("vpn_mode", on)

    def run():
        with _MODE_STATE_LOCK:
            if generation != _MODE_GENERATION[0] or config.get("vpn_mode", True) != on:
                return
        with _MODE_LOCK:
            with _MODE_STATE_LOCK:
                if generation != _MODE_GENERATION[0] or config.get("vpn_mode", True) != on:
                    return
            with _cross_process_lock():
                if on:
                    _sync_impl()
                else:
                    _set_direct_impl()

    threading.Thread(target=run, daemon=True).start()
    return generation


def sync():
    """Полная синхронизация: пул -> конфиг -> старт -> проверка egress.
    Возвращает (ok: bool, final: str). Под _MODE_LOCK: параллельный set_direct
    не может перезаписать результат после чтения vpn_mode."""
    with _MODE_LOCK, _cross_process_lock():
        return _sync_impl()


def _sync_impl():
    config.update_state(comm={"state": "syncing", "msg": "синхронизация с xray..."})
    pool.dedupe()
    vpn = config.get("vpn_mode", True)
    active_key = pool.pick_final() if vpn else None
    final_tag = "direct"
    if vpn:
        if active_key:
            final_tag = active_key.get("tag") or "direct"
        else:
            final_tag = "direct"

    previous = _read_config()
    cfg = build_xray_config(final_tag)
    cfg, final_tag = _authoritative_config(cfg, final_tag)
    if not _xray_config_valid(cfg):
        config.update_state(vless_now="-", final_mode="-", egress_ip="-",
                            comm={"state": "error", "msg": "xray config preflight failed"})
        return False, "direct"
    if not _write_config(cfg):
        config.update_state(vless_now="-", final_mode="-", egress_ip="-",
                            comm={"state": "error", "msg": "xray config write failed"})
        return False, "direct"
    expected = _config_fingerprint(cfg)
    if not _restart_xray() or _current_fingerprint() != expected:
        if previous is not None and _restore_config_cas(expected, previous):
            _restart_xray()
        config.update_state(vless_now="-", final_mode="-", egress_ip="-",
                            comm={"state": "error", "msg": "xray restart failed"})
        return False, "direct"

    # egress-проверка активного канала (4 попытки — cold start Reality >8с)
    ip = None
    if final_tag != "direct":
        for i in range(1, 5):
            ip = egress_probe(timeout=10)
            if ip:
                break
            config.log("core: sync final=%s egress probe %d/4 не дал IP" % (final_tag, i))
            time.sleep(3)
        if not ip:
            config.log("core: final=%s БЕЗ egress, откат на direct" % final_tag)
            final_tag = "direct"
            cfg = build_xray_config("direct")
            cfg, final_tag = _authoritative_config(cfg, final_tag)
            if not _xray_config_valid(cfg) or not _write_config(cfg):
                if previous is not None and _restore_config_cas(expected, previous):
                    _restart_xray()
                config.update_state(vless_now="-", final_mode="-", egress_ip="-",
                                    comm={"state": "error", "msg": "direct fallback failed"})
                return False, "direct"
            direct_expected = _config_fingerprint(cfg)
            if not _restart_xray() or _current_fingerprint() != direct_expected:
                if previous is not None and _restore_config_cas(direct_expected, previous):
                    _restart_xray()
                config.update_state(vless_now="-", final_mode="-", egress_ip="-",
                                    comm={"state": "error", "msg": "direct fallback failed"})
                return False, "direct"
            config.update_state(vless_now="direct", final_mode="direct", egress_ip=config.get_direct_ip() or "-",
                                comm={"state": "idle", "msg": ""})
            return False, "direct"

    n_keys = len(pool.get_keys())
    config.log("core: sync: outbounds=%d final=%s user_keys=%d" % (
        len(cfg["outbounds"]) - 2, final_tag, n_keys))
    # при коллизии тег в xray.json мог быть переименован (-x) — в state пишем фактический
    if final_tag != "direct":
        final_tag = get_vless_now() or final_tag
    config.update_state(vless_now=final_tag, final_mode=final_tag,
                        egress_ip=ip or config.WHITE_IP,
                        comm={"state": "idle", "msg": ""})
    return True, final_tag


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def egress_probe(timeout=10):
    """Фактический egress через живой порт xray. Возвращает IP или None.
    Только HTTP: HTTPS через CONNECT даёт SSL EOF (ложный провал)."""
    url = "http://api.ipify.org?format=json"
    try:
        handler = urllib.request.ProxyHandler({
            "http": "http://127.0.0.1:%d" % config.XRAY_PORT,
            "https": "http://127.0.0.1:%d" % config.XRAY_PORT,
        })
        opener = urllib.request.build_opener(handler, _NoRedirect())
        req = urllib.request.Request(url, headers={"User-Agent": "curl"})
        with opener.open(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="replace")
        ip = json.loads(body).get("ip", "")
        direct_ip = config.get_direct_ip()
        if direct_ip and ip not in ("", "-", direct_ip):
            return ip
    except Exception:
        return None
    return None


def egress_ip(force=False):
    """Кэш egress (TTL 60с)."""
    with EGRESS_LOCK:
        now = time.time()
        if force or now - _EGRESS_CACHE["ts"] > config.EGRESS_TTL_S:
            ip = egress_probe() or "-"
            _EGRESS_CACHE["ip"] = ip
            _EGRESS_CACHE["ts"] = now
        return _EGRESS_CACHE["ip"]


def get_vless_now():
    """Единственный источник правды активного тега — rule в xray.json."""
    cfg = _read_config()
    if not cfg:
        return "-"
    try:
        for rule in cfg.get("routing", {}).get("rules", []):
            if "http-in" in (rule.get("inboundTag") or []):
                return rule.get("outboundTag", "-")
    except Exception:
        pass
    return "-"


def set_direct():
    """Переключение final=direct (правки routing, vless-outbounds сохраняются).
    Под _MODE_LOCK: сериализация с sync при смене vpn_mode."""
    with _MODE_LOCK, _cross_process_lock():
        return _set_direct_impl()


def _set_direct_impl():
    config.update_state(comm={"state": "syncing", "msg": "переключение в прямой режим..."})
    with XRAY_CONFIG_LOCK:  # read-modify-write целиком под локом (TOCTOU)
        cfg = _read_config()
        if not cfg:
            config.update_state(comm={"state": "idle", "msg": ""})
            return False
        for rule in cfg.get("routing", {}).get("rules", []):
            if "http-in" in (rule.get("inboundTag") or []):
                rule["outboundTag"] = "direct"
        if not _write_config(cfg):
            config.update_state(comm={"state": "idle", "msg": ""})
            return False
    if not _restart_xray():
        config.update_state(comm={"state": "idle", "msg": ""})
        return False
    config.update_state(vless_now="direct", final_mode="direct", egress_ip=config.get_direct_ip() or "-",
                        comm={"state": "idle", "msg": ""})
    config.log("core: final=direct (прямой режим)")
    return True


def apply_sub_clients():
    """Перезаписывает clients inbound vless-in в существующем xray.json
    (мастер + все активные подписочные uuid) и рестартует xray.
    ТОЛЬКО правка clients — routing/outbounds не трогаются (безопасно вживую).
    Возвращает (ok: bool, msg: str)."""
    vln = config.vless_public()
    if not (vln.get("enabled") and vln.get("uuid")):
        return False, "внешний inbound не настроен"
    flow = vln.get("flow", "xtls-rprx-vision")
    clients = [{"id": vln["uuid"], "flow": flow}]
    try:
        for cuuid in subs.build_client_list():
            clients.append({"id": cuuid, "email": cuuid, "flow": flow})
    except Exception as e:
        config.log("core: subscription clients failed: %s" % e)
        return False, "clients unavailable"
    with _cross_process_lock():
        with XRAY_CONFIG_LOCK:
            previous = _read_config()
            if not previous:
                return False, "нет конфига"
            cfg, _target = _authoritative_config(previous, get_vless_now())
            target = None
            for inbound in cfg.get("inbounds", []) or []:
                if inbound.get("tag") == "vless-in":
                    target = inbound
                    break
            if target is None:
                return False, "vless-in не найден в xray.json"
            if target.setdefault("settings", {}).get("clients") == clients:
                return True, "clients %d" % len(clients)
            target["settings"]["clients"] = clients
            level = cfg.setdefault("policy", {}).setdefault("levels", {}).setdefault("0", {})
            level["statsUserUplink"] = True
            level["statsUserDownlink"] = True
            if not _xray_config_valid(cfg):
                return False, "config preflight failed"
            if not _write_config(cfg):
                return False, "write fail"
            expected = _config_fingerprint(cfg)
        if not _restart_xray():
            _restore_config_cas(expected, previous)
            return False, "restart fail"
    config.log("core: vless-in clients обновлены (%d всего)" % len(clients))
    return True, "clients %d" % len(clients)


def set_active_tag(tag):
    with _MODE_LOCK, _cross_process_lock():
        return _set_active_tag_impl(tag)


def _set_active_tag_impl(tag):
    """Переключение final на тег из xray.json (vless). Возвращает (ok, msg)."""
    config.update_state(comm={"state": "syncing", "msg": "переключение ключа..."})
    with XRAY_CONFIG_LOCK:  # read-modify-write целиком под локом (TOCTOU)
        cfg = _read_config()
        if not cfg:
            config.update_state(comm={"state": "idle", "msg": ""})
            return False, "нет конфига"
        tags = [o.get("tag") for o in cfg.get("outbounds", [])]
        if tag not in tags:
            config.update_state(comm={"state": "idle", "msg": ""})
            return False, "tag not in outbounds"
        prev = get_vless_now()
        if prev == tag:
            config.update_state(comm={"state": "idle", "msg": ""})
            return True, "already active"
        for rule in cfg.get("routing", {}).get("rules", []):
            if "http-in" in (rule.get("inboundTag") or []):
                rule["outboundTag"] = tag
        if not _write_config(cfg):
            config.update_state(comm={"state": "idle", "msg": ""})
            return False, "write fail"
    if not _restart_xray():
        config.update_state(comm={"state": "idle", "msg": ""})
        return False, "restart fail"
    ip = None
    for i in range(1, 5):  # 4 попытки, cold start Reality >8с
        ip = egress_probe(timeout=10)
        if ip:
            break
        time.sleep(3)
    if ip:
        with EGRESS_LOCK:
            _EGRESS_CACHE["ip"] = ip
            _EGRESS_CACHE["ts"] = time.time()
        config.update_state(vless_now=tag, final_mode=tag, egress_ip=ip,
                            comm={"state": "idle", "msg": ""})
        config.log("core: switch -> %s (egress %s)" % (tag, ip))
        return True, "egress %s" % ip
    # откат
    rollback = prev if prev in tags else "direct"
    with XRAY_CONFIG_LOCK:
        cfg = _read_config()  # перечитываем свежую версию (конфиг мог смениться)
        if cfg:
            for rule in cfg.get("routing", {}).get("rules", []):
                if "http-in" in (rule.get("inboundTag") or []):
                    rule["outboundTag"] = rollback
            _write_config(cfg)
    _restart_xray()
    config.update_state(vless_now=rollback, final_mode=rollback,
                        comm={"state": "idle", "msg": ""})
    config.log("core: no egress, rollback to %s" % rollback)
    return False, "no egress, rollback to %s" % rollback


def _rotate_guard():
    now = time.time()
    if now - _LAST_ROTATE[0] < config.ROTATE_COOLDOWN_S:
        return True  # в кулдауне — пропустить
    return False


def rotate():
    with _MODE_LOCK:
        with _cross_process_lock():
            return _rotate_impl()


def _rotate_impl():
    """Ротация: пробуем до 3 кандидатов с живым egress. Возвращает новый тег или None."""
    with _ROTATE_LOCK:
        if _rotate_guard():
            config.log("core: rotate cooldown, skip")
            return None
        _LAST_ROTATE[0] = time.time()
    cur = get_vless_now()
    pool.dedupe()
    keys = pool.get_keys()
    cands = []
    for k in keys:
        if k.get("tag") == cur or pool.blocked(k.get("uri", "")):
            continue
        st = pool.get_status(k.get("uri", ""))
        if pool._good_ip(st.get("exit_ip", "-")):
            cands.append(k)
    if not cands:
        cands = [k for k in keys if k.get("tag") != cur and not pool.blocked(k.get("uri", ""))]
    cands = cands[:3]
    for k in cands:
        tag = k.get("tag")
        if not tag:
            continue
        ok, msg = _set_active_tag_impl(tag)
        if ok:
            config.log("core: rotate -> %s (%s)" % (tag, msg))
            return tag
    config.log("core: rotate: кандидаты мертвы")
    return None

# --- watchdog final ---
def _final_watch():
    """Каждые 120с: проверяет живой ли final, при смерти — sync/rotate."""
    while not _WATCH_STOP.is_set():
        if _WATCH_STOP.wait(120):
            break
        tag = get_vless_now()
        # VPN OFF -> просто наблюдаем
        if not config.get("vpn_mode", True):
            continue
        if tag in ("", "-", "direct", None):
            if pool.pick_final():
                config.log("core: final=direct при VPN ON, попытка восстановления")
                sync()
            else:
                config.log("core: живых кандидатов нет")
            continue
        # есть тег: проверяем TCP до хоста
        label = re.sub(r"-\d+$", "", tag.replace("vless-", ""))
        host = port = None
        for k in pool.get_keys():
            kh = k.get("host", "")
            if kh == label or kh.split(".")[0] == label:
                host, port = kh, k.get("port", 443)
                break
        if host:
            import source
            if not source._tcp_ping(host, port, timeout=5):
                config.log("core: final %s dead, rotate" % tag)
                if _rotate_guard():
                    continue
                rotate()
                continue
        # устойчивый None: одна проба = ложный rotate (cold start/flap 5-14с)
        ip = None
        for _attempt in range(3):
            ip = egress_probe(timeout=8)
            if ip:
                break
            time.sleep(3)
        if not ip:
            config.log("core: final %s БЕЗ egress (3 пробы), rotate" % tag)
            # честный egress: канал реально не отдаёт IP — не показываем устаревший кэш
            config.update_state(egress_ip="-")
            if _rotate_guard():
                continue
            rotate()
            continue
        # egress фактом жив — обновляем в state (анти-устаревание при кулдауне ротации)
        if config.get_state().get("egress_ip") != ip:
            config.update_state(egress_ip=ip)


def start_watch():
    t = threading.Thread(target=_final_watch, daemon=True)
    t.start()
    return t