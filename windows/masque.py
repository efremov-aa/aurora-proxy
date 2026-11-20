"""A-MASQUE: резервный канал Cloudflare WARP через MASQUE (mihomo).

Зачем: в части сетей чистый WireGuard WARP блокируется (нет ответов на
handshake), а MASQUE (HTTP/3) проходит. Модуль умеет держать несколько
именованных MASQUE-конфигов, применять выбранный к mihomo и показывать
выходной IP. Конфиг берётся с https://warp-generation.github.io/ (кнопка
MASQUE) — это JSON с privKey/peer_pub/client_ipv4, либо Clash-YAML
с type: masque.
"""

import json
import os
import re
import subprocess
import sys
import threading
import time

import config

_AURORA_DIR = os.path.dirname(os.path.abspath(config.DATA_DIR)) or os.getcwd()


def _mihomo_dir():
    """Каталог mihomo: важен тот, который реально читает сервис.

    A-MASQUE-FIX: выведенное из DATA_DIR место и место systemd-юнита
    (WorkingDirectory) могут НЕ совпадать - старый код писал config.yaml
    мимо сервиса, а ensure_mihomo пытался скачать бинарь заново, и после
    перезапуска панели канал умирал. Берём первый уже существующий каталог
    с бинарём/конфигом, иначе - выведенный.
    """
    derived = os.path.join(_AURORA_DIR, "mihomo")
    cands = [derived]
    env = str(os.environ.get("AURORA_MIHOMO_DIR") or "").strip()
    if env:
        cands.insert(0, env)
    if not sys.platform.startswith("win"):
        try:
            r = subprocess.run(["systemctl", "--user", "show", "mihomo",
                                "-p", "WorkingDirectory"],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, timeout=5)
            text = r.stdout.decode("utf-8", "replace").strip()
            if text.startswith("WorkingDirectory="):
                wd = text.split("=", 1)[1].strip()
                if wd:
                    cands.append(wd)
        except Exception:
            pass
        cands.append(os.path.expanduser("~/mihomo"))
    for path in cands:
        if not path:
            continue
        if (os.path.isfile(os.path.join(path, "mihomo"))
                or os.path.isfile(os.path.join(path, "mihomo.exe"))
                or os.path.isfile(os.path.join(path, "config.yaml"))):
            return path
    return derived


MIHOMO_DIR = _mihomo_dir()
MIHOMO_BIN = os.path.join(MIHOMO_DIR, "mihomo.exe" if sys.platform.startswith("win") else "mihomo")
MIHOMO_CFG = os.path.join(MIHOMO_DIR, "config.yaml")
MIXED_PORT = 18808
PROBE_URL = "http://api.ipify.org"
STORE = os.path.join(config.DATA_DIR, "masque_configs.json")
MAX_CONFIGS = 32
MAX_CONFIG_BYTES = 256 * 1024
MAX_NAME_LEN = 40

# A-MASQUE-EP: эндпоинты MASQUE по порядку предпочтения.
# 162.159.198.2 (по умолчанию у генератора) с части хостов НЕ отвечает
# по UDP/QUIC - таймаут, канал молчит, панель пишет "no egress".
# Соседний 162.159.198.1 отвечает и даёт живой выход (проверено вживую).
MASQUE_ENDPOINTS = (
    ("162.159.198.1", 443),
    ("162.159.199.1", 443),
    ("162.159.203.1", 443),
    ("162.159.192.1", 443),
    ("162.159.198.2", 443),
)

_EP_CACHE = {"ip": "", "ts": 0.0}
_PROBE_LOCK = threading.Lock()
_AUTO = {"running": False, "ts": 0, "result": {}}
AUTO_INTERVAL = 300  # секунд между автопроверками MASQUE

try:
    import yaml
except Exception:  # PyYAML может отсутствовать в публичной сборке
    yaml = None

_LOCK = __import__("threading").RLock()
_LAST = {"ip": "-", "ts": 0.0, "reason": ""}
_NAME_RE = re.compile(r"^[A-Za-z0-9 _.\-]{1,%d}$" % MAX_NAME_LEN)
_B64_RE = re.compile(r"^[A-Za-z0-9+/=_-]{40,}$")


def clean_name(value, fallback=""):
    name = str(value or "").strip()
    name = re.sub(r"[^A-Za-z0-9 _.\-]+", " ", name).strip()
    name = re.sub(r"\s{2,}", " ", name)[:MAX_NAME_LEN].strip()
    if not name:
        name = str(fallback or "").strip() or "masque"
    return name


def _crypt_module():
    try:
        import crypt
        return crypt
    except Exception:
        return None


def _store_read(path):
    cr = _crypt_module()
    if cr is not None and hasattr(cr, "load_json"):
        try:
            value = cr.load_json(path, None)
        except Exception:
            value = None
        if value is not None:
            return value
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError, TypeError):
        return None


def _store_write(path, obj):
    cr = _crypt_module()
    if cr is not None and hasattr(cr, "save_json"):
        try:
            cr.save_json(path, obj)
        except Exception:
            pass
        else:
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            return True
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return True


def _read_store():
    try:
        with _LOCK:
            value = _store_read(STORE)
    except Exception:
        value = None
    if not isinstance(value, dict) or not isinstance(value.get("items"), dict):
        return {"active": "", "items": {}}
    return value


def _save_store(store):
    with _LOCK:
        _store_write(STORE, store)


def _unique_name(store, name):
    if name not in store["items"]:
        return name
    i = 2
    while ("%s %d" % (name, i)) in store["items"]:
        i += 1
    return "%s %d" % (name, i)


def _endpoint_alive(ip, port=443, timeout=3):
    """QUIC-эхо до эндпоинта. True - UDP доходит, False - таймаут, None - н/д.

    Сигнал простой: до живого адреса пакеты возвращаются за доли секунды
    (дальше TLS-ошибка на чужом SNI), до заблокированного - полный таймаут.
    Если curl без HTTP/3 - возвращаем None и не исключаем адрес.
    """
    curl = "curl.exe" if sys.platform.startswith("win") else "curl"
    r = _run([curl, "--http3", "-m", str(int(timeout)), "-sS", "-o", os.devnull,
              "-w", "%{http_code} %{time_total}",
              "https://%s:%d/" % (ip, int(port))],
             timeout=int(timeout) + 5)
    if r is None:
        return None
    parts = r.stdout.decode("utf-8", "replace").split()
    if len(parts) < 2:
        return None
    try:
        took = float(parts[1])
    except ValueError:
        return None
    return took < max(1.5, float(timeout) * 0.75)


def pick_endpoint(force=False, timeout=3, ttl=3600):
    """Первый доступный MASQUE-эндпоинт (кэш на час)."""
    now = time.time()
    if not force and _EP_CACHE["ip"] and now - _EP_CACHE["ts"] < ttl:
        return _EP_CACHE["ip"]
    chosen = ""
    for ip, port in MASQUE_ENDPOINTS:
        if _endpoint_alive(ip, port, timeout) is not False:
            chosen = ip
            break
    chosen = chosen or MASQUE_ENDPOINTS[0][0]
    _EP_CACHE["ip"] = chosen
    _EP_CACHE["ts"] = now
    return chosen


def set_endpoint(name, server, port=443):
    """Перевести существующий конфиг на другой эндпоинт (ключи те же)."""
    key = clean_name(name, "")
    store = _read_store()
    item = store["items"].get(key)
    if not isinstance(item, dict):
        return False
    m = item.get("masque")
    if not isinstance(m, dict):
        return False
    try:
        port = int(port or 443)
    except (TypeError, ValueError):
        port = 443
    m["server"] = str(server)
    m["port"] = port
    item["endpoint"] = "%s:%d" % (m["server"], m["port"])
    _save_store(store)
    return True


def _norm(priv, pub, ip, ipv6, server, port, sni):
    priv = str(priv or "").strip()
    pub = str(pub or "").strip()
    if not _B64_RE.match(priv) or not _B64_RE.match(pub):
        return None, "bad masque keys"
    server = str(server or pick_endpoint()).strip()
    try:
        port = int(port or 443)
    except (TypeError, ValueError):
        port = 443
    return {
        "privKey": priv, "peer_pub": pub,
        "ip": str(ip or "172.16.0.2").strip(),
        "ipv6": str(ipv6 or "").strip(),
        "server": server, "port": port, "sni": str(sni or "").strip(),
    }, ""


def extract(cfg):
    """Принимает JSON сайта (privKey/peer_pub) или Clash-YAML (type: masque)."""
    data = cfg
    if isinstance(cfg, (bytes, bytearray)):
        try:
            cfg = bytes(cfg).decode("utf-8")
        except UnicodeDecodeError:
            return None, "invalid encoding"
    if isinstance(cfg, str):
        if len(cfg.encode("utf-8", "ignore")) > MAX_CONFIG_BYTES:
            return None, "config too large"
        text = cfg.strip()
        if text.startswith("{"):
            try:
                data = json.loads(text)
            except ValueError:
                return None, "invalid json"
        elif yaml is not None:
            try:
                data = yaml.safe_load(text)
            except Exception:
                return None, "invalid yaml"
        else:
            return None, "yaml not supported (install PyYAML)"
    if not isinstance(data, dict):
        return None, "config must be an object"
    if data.get("privKey") and data.get("peer_pub"):
        # A-MASQUE-EP: генератор не отдаёт server - берём доступный эндпоинт,
        # а не зашитый по умолчанию 162.159.198.2 (с части хостов он молчит).
        return _norm(data.get("privKey"), data.get("peer_pub"),
                     data.get("client_ipv4"), data.get("client_ipv6"),
                     str(data.get("server") or "").strip() or pick_endpoint(),
                     443, "4pda.to")
    proxies = data.get("proxies")
    if isinstance(proxies, list):
        for p in proxies:
            if isinstance(p, dict) and str(p.get("type") or "").lower() == "masque":
                return _norm(p.get("private-key"), p.get("public-key"),
                             p.get("ip"), p.get("ipv6"),
                             p.get("server"), p.get("port"), p.get("sni"))
    return None, "no masque config found"


def render_config(m, mixed_port=None):
    port = MIXED_PORT if mixed_port is None else int(mixed_port)
    sni = "\n  sni: %s" % m["sni"] if m.get("sni") else ""
    ipv6 = "\n  ipv6: %s/128" % m["ipv6"] if m.get("ipv6") else ""
    return """mixed-port: %d
bind-address: 127.0.0.1
mode: rule
log-level: warning
ipv6: false
external-controller: 127.0.0.1:19090
proxies:
- name: "warp-masque"
  type: masque
  server: %s
  port: %d
  private-key: %s
  public-key: %s
  ip: %s/32%s%s
  mtu: 1280
  udp: true
  remote-dns-resolve: true
  dns: [1.1.1.1, 1.0.0.1]
proxy-groups:
- name: "WARP"
  type: select
  proxies: ["warp-masque"]
rules:
- MATCH,WARP
""" % (port, m["server"], m["port"], m["privKey"], m["peer_pub"],
       m["ip"], ipv6, sni)


def _run(cmd, timeout=30, shell=False):
    try:
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, shell=shell)
    except (OSError, subprocess.SubprocessError):
        return None


def _service_cmd(action):
    """Команда управления сервисом mihomo под платформу."""
    if sys.platform.startswith("win"):
        return ["net", action, "AuroraMasque"]
    return ["systemctl", "--user", action, "mihomo"]


def ensure_mihomo():
    """Проверить/скачать mihomo. Возвращает (ok, error)."""
    if os.path.isfile(MIHOMO_BIN):
        return True, ""
    os.makedirs(MIHOMO_DIR, exist_ok=True)
    arch = "amd64" if sys.maxsize > 2 ** 32 else "386"
    if sys.platform.startswith("win"):
        name = "mihomo-windows-%s-compatible.exe" % arch
        url = ("https://github.com/MetaCubeX/mihomo/releases/latest/download/"
               + name)
        dest = MIHOMO_BIN
    elif sys.platform == "darwin":
        name = "mihomo-darwin-%s-compatible.gz" % arch
        url = ("https://github.com/MetaCubeX/mihomo/releases/latest/download/"
               + name)
        dest = os.path.join(MIHOMO_DIR, "m.gz")
    else:
        name = "mihomo-linux-%s-compatible.gz" % arch
        url = ("https://github.com/MetaCubeX/mihomo/releases/latest/download/"
               + name)
        dest = os.path.join(MIHOMO_DIR, "m.gz")
    import urllib.request
    try:
        with urllib.request.urlopen(url, timeout=60) as r:
            data = r.read()
        with open(dest, "wb") as f:
            f.write(data)
        if dest.endswith(".gz"):
            import gzip
            with gzip.open(dest, "rb") as f:
                blob = f.read()
            with open(MIHOMO_BIN, "wb") as f:
                f.write(blob)
            try:
                os.remove(dest)
            except OSError:
                pass
        os.chmod(MIHOMO_BIN, 0o755)
        return True, ""
    except Exception as exc:
        return False, "mihomo download failed: %s" % str(exc)[:120]


def apply(name=""):
    """Записать конфиг mihomo и перезапустить сервис."""
    store = _read_store()
    key = clean_name(name, "") if name else (store.get("active") or "")
    item = store["items"].get(key)
    if not isinstance(item, dict):
        return {"ok": False, "error": "no such config"}
    m = item.get("masque")
    if not isinstance(m, dict):
        return {"ok": False, "error": "bad config"}
    ok, err = ensure_mihomo()
    if not ok:
        return {"ok": False, "error": err}
    try:
        os.makedirs(MIHOMO_DIR, exist_ok=True)
        tmp = MIHOMO_CFG + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(render_config(m))
        os.replace(tmp, MIHOMO_CFG)
        os.chmod(MIHOMO_CFG, 0o600)
    except OSError as exc:
        return {"ok": False, "error": "write failed: %s" % str(exc)[:100]}
    r = _run(_service_cmd("restart"))
    if r is None or (hasattr(r, "returncode") and r.returncode != 0):
        # Сервис может не быть установлен (публичная сборка) — запускаем mihomo.
        try:
            subprocess.Popen([MIHOMO_BIN, "-d", MIHOMO_DIR],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError):
            pass
    return {"ok": True, "name": key, "endpoint": "%s:%d" % (m["server"], m["port"])}


def enabled():
    """Внешний резервный канал включён? (A-118: выключатель из панели)."""
    return bool(config.get("masque_enabled", True))


def stop():
    """Погасить mihomo: внешний канал выключен (A-118)."""
    _run(_service_cmd("stop"))
    # Публичная сборка может не иметь юнита — гасим процесс mihomo напрямую.
    if sys.platform.startswith("win"):
        _run(["taskkill", "/F", "/IM", "mihomo.exe"])
    else:
        _run(["pkill", "-f", "mihomo"])
    return True


def set_enabled(value):
    """Включить/выключить внешний канал (A-118). Возвращает новый status()."""
    value = bool(value)
    config.set("masque_enabled", value)
    try:
        config.save_settings()
    except Exception:
        pass
    if value:
        if active_name():
            apply()
    else:
        stop()
    st = status()
    st["ok"] = True
    st["enabled"] = enabled()
    return st


def probe(timeout=20, name=""):
    """Поднять временный mihomo с выбранным конфигом и узнать выходной IP.

    Один пробник на процесс: порт 18809 общий, параллельный запуск дал бы
    ложный "no egress". Автопроверка в этом случае пропускает цикл.
    """
    if not _PROBE_LOCK.acquire(False):
        return {"ok": False, "busy": True, "error": "probe busy"}
    try:
        return _probe_impl(timeout, name)
    finally:
        try:
            _PROBE_LOCK.release()
        except Exception:
            pass


def _probe_impl(timeout=20, name=""):
    store = _read_store()
    key = clean_name(name, "") if name else (store.get("active") or "")
    item = store["items"].get(key)
    if not isinstance(item, dict):
        return {"ok": False, "error": "no such config"}
    m = item.get("masque")
    if not isinstance(m, dict):
        return {"ok": False, "error": "bad config"}
    ok, err = ensure_mihomo()
    if not ok:
        return {"ok": False, "error": err}
    tmp_dir = os.path.join(MIHOMO_DIR, "probe")
    try:
        os.makedirs(tmp_dir, exist_ok=True)
        cfg_path = os.path.join(tmp_dir, "config.yaml")
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write(render_config(m, 18809))
        os.chmod(cfg_path, 0o600)
    except OSError as exc:
        return {"ok": False, "error": "cfg: %s" % str(exc)[:100]}
    proc = None
    try:
        proc = subprocess.Popen([MIHOMO_BIN, "-d", tmp_dir],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ip = None
        deadline = time.time() + max(5, int(timeout))
        while time.time() < deadline:
            args = ["curl", "-sS", "-m", "8", "-x", "http://127.0.0.1:18809", PROBE_URL]
            if sys.platform.startswith("win"):
                args = ["curl.exe", "-sS", "-m", "8", "-x",
                        "http://127.0.0.1:18809", PROBE_URL]
            r = _run(args, timeout=12)
            if r is not None and getattr(r, "returncode", 1) == 0:
                text = r.stdout.decode("utf-8", "replace").strip()
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", text):
                    ip = text
                    break
            time.sleep(1.0)
        if ip:
            record_probe(ip, "probe", key)
            return {"ok": True, "egress": ip, "name": key}
        record_probe("-", "no egress", key)
        return {"ok": False, "error": "no egress"}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "error": str(exc)[:120]}
    finally:
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass


MSQUE_BACKEND = "https://masque-vercel.warp-api.cfd"


def fetch_default(name="MASQUE"):
    """Prijnat' svezhiy MASQUE-konfig s generatora (dlya mastera nastroyki)."""
    import urllib.request
    try:
        with urllib.request.urlopen(MSQUE_BACKEND, timeout=25) as r:
            data = json.loads(r.read().decode("utf-8"))
    except Exception as exc:
        return {"ok": False, "error": "fetch failed: %s" % str(exc)[:100]}
    if not isinstance(data, dict) or not data.get("privKey"):
        return {"ok": False, "error": "bad masque backend response"}
    return install(json.dumps(data), name)


def fetch_apply(name="MASQUE"):
    """A-MASQUE-FIX: свежий конфиг с генератора -> активный -> поднять -> проба.

    Такого вызова ждёт api._masque_fetch (/api/masque/fetch); без него кнопка
    «Получить конфиг с сайта» падала с AttributeError.
    """
    r = fetch_default(name)
    if not r.get("ok"):
        return r
    key = str(r.get("name") or "")
    sel = select(key)
    if not sel.get("ok"):
        return {"ok": False, "error": sel.get("error", "select failed")}
    ap = apply(key)
    if not ap.get("ok"):
        return {"ok": False, "name": key, "error": ap.get("error", "apply failed")}
    res = probe(30, key)
    out = {"ok": bool(res.get("ok")), "name": key,
           "endpoint": str(ap.get("endpoint") or "")}
    if res.get("ok"):
        out["egress"] = res.get("egress", "-")
        config.log("masque: fetch_apply: %s -> %s" % (key, out["egress"]))
    else:
        out["error"] = str(res.get("error") or "no egress")[:120]
        config.log("masque: fetch_apply: %s ne proshel probu (%s)"
                   % (key, out["error"]))
    return out


def install(raw, name=""):
    m, reason = extract(raw)
    if m is None:
        return {"ok": False, "error": reason or "bad masque config"}
    store = _read_store()
    key = clean_name(name or ("%s-%d" % (m["server"], m["port"])), "masque")
    if len(store["items"]) >= MAX_CONFIGS and key not in store["items"]:
        return {"ok": False, "error": "too many configs (max %d)" % MAX_CONFIGS}
    key = _unique_name(store, key)
    store["items"][key] = {
        "masque": m, "endpoint": "%s:%d" % (m["server"], m["port"]),
        "ts": int(time.time()), "egress": "-", "egress_ts": 0,
    }
    if not store.get("active") or store["active"] not in store["items"]:
        store["active"] = key
    _save_store(store)
    return {"ok": True, "name": key, "endpoint": "%s:%d" % (m["server"], m["port"]),
            "count": len(store["items"])}


def select(name):
    key = clean_name(name, "")
    if not key:
        return {"ok": False, "error": "empty name"}
    store = _read_store()
    if key not in store["items"]:
        return {"ok": False, "error": "no such config"}
    store["active"] = key
    _save_store(store)
    return {"ok": True, "name": key, "status": status()}


def remove(name):
    key = clean_name(name, "")
    if not key:
        return {"ok": False, "error": "empty name"}
    store = _read_store()
    if key not in store["items"]:
        return {"ok": False, "error": "no such config"}
    store["items"].pop(key, None)
    if store.get("active") == key:
        store["active"] = next(iter(store["items"]), "")
    if store["items"]:
        _save_store(store)
    else:
        try:
            os.remove(STORE)
        except OSError:
            pass
    return {"ok": True, "count": len(_read_store()["items"]), "status": status()}


def clear():
    try:
        os.remove(STORE)
    except OSError:
        pass
    return {"ok": True, "count": 0}


def active_name():
    store = _read_store()
    active = store.get("active") or ""
    return active if active in store["items"] else ""


def list_configs():
    store = _read_store()
    active = store.get("active") or ""
    out = []
    for name in sorted(store["items"]):
        item = store["items"][name]
        out.append({
            "name": name,
            "endpoint": str(item.get("endpoint") or ""),
            "ts": int(item.get("ts") or 0),
            "egress": str(item.get("egress") or "-"),
            "egress_ts": int(item.get("egress_ts") or 0),
            "active": name == active,
        })
    return out


# --- A-1040: снимок списка для бэкапа и восстановления ---
def backup_snapshot():
    """Полный слепок конфигов (включая приватные ключи) для архива."""
    store = _read_store()
    items = {}
    for name, entry in (store.get("items") or {}).items():
        if not isinstance(entry, dict):
            continue
        try:
            items[str(name)] = json.loads(json.dumps(entry))
        except (TypeError, ValueError):
            continue
    return {"active": str(store.get("active") or ""), "items": items}


def restore_snapshot(snapshot):
    """Восстановить список из слепка. Возвращает (ok, count, error)."""
    if not isinstance(snapshot, dict):
        return False, 0, "bad snapshot"
    raw_items = snapshot.get("items")
    if not isinstance(raw_items, dict) or not raw_items:
        return False, 0, "empty snapshot"
    items = {}
    for name, entry in raw_items.items():
        key = clean_name(str(name), "")
        if not key or not isinstance(entry, dict):
            continue
        if not str(entry.get("privKey") or "").strip():
            continue
        if not str(entry.get("server") or "").strip():
            continue
        try:
            items[key] = json.loads(json.dumps(entry))
        except (TypeError, ValueError):
            continue
    if not items:
        return False, 0, "no valid configs"
    active = clean_name(str(snapshot.get("active") or ""), "")
    if active not in items:
        active = sorted(items)[0]
    _save_store({"active": active, "items": items})
    with _LOCK:
        pass
    return True, len(items), ""


def record_probe(ip, reason="", name=""):
    key = clean_name(name, "") if name else active_name()
    with _LOCK:
        _LAST["ip"] = str(ip or "-")
        _LAST["ts"] = time.time()
        _LAST["reason"] = str(reason or "")
        _LAST["name"] = key
    if not key:
        return
    store = _read_store()
    if key in store["items"]:
        store["items"][key]["egress"] = str(ip or "-")
        store["items"][key]["egress_ts"] = int(time.time())
        _save_store(store)


def status():
    store = _read_store()
    with _LOCK:
        last_ip = _LAST["ip"]
        last_ts = _LAST["ts"]
        reason = _LAST["reason"]
    configs = list_configs()
    current = active_name()
    return {
        "loaded": bool(configs),
        "count": len(configs),
        "name": current,
        "configs": configs,
        "endpoint": str((store["items"].get(current) or {}).get("endpoint") or ""),
        "egress": last_ip,
        "egress_ts": int(last_ts),
        "reason": reason,
        "enabled": enabled(),
        "autocheck": autocheck_status(),
    }


# --- A-MASQUE-AUTO: автопроверка канала и перевыпуск мёртвого конфига ---
def autocheck_status():
    """Состояние автопроверки для панели (лежит в status())."""
    return {
        "interval": int(AUTO_INTERVAL),
        "running": bool(_AUTO["running"]),
        "last_ts": int(_AUTO["ts"] or 0),
        "last": dict(_AUTO["result"] or {}),
    }


def _prune(max_keep=8):
    """Не раздувать список: активный + самые свежие, остальные вон."""
    store = _read_store()
    items = store.get("items") or {}
    if len(items) <= max_keep:
        return 0
    active = store.get("active")

    def _ts(name):
        entry = items.get(name)
        return int(entry.get("ts") or 0) if isinstance(entry, dict) else 0

    dropped = 0
    for name in sorted(items, key=_ts):
        if len(items) <= max_keep:
            break
        if name == active:
            continue
        items.pop(name, None)
        dropped += 1
    if dropped:
        store["items"] = items
        _save_store(store)
    return dropped


def autocheck_once():
    """Одна проверка активного MASQUE-конфига.

    Жив - фиксируем egress. Мёртв - сначала пробуем СОСЕДНИЕ эндпоинты на тех
    же ключах (проба поднимает временный mihomo, сервис не трогаем), и только
    потом берём свежий конфиг с генератора. Так на мастере умер канал:
    162.159.198.2 перестал отвечать по UDP, а 162.159.198.1 - отвечает.
    """
    key = active_name()
    if not key:
        return {"ok": False, "action": "no-config"}
    if not enabled():
        return {"ok": True, "action": "disabled"}
    res = probe(20)
    if res.get("ok"):
        return {"ok": True, "action": "alive", "name": key,
                "egress": res.get("egress", "-")}
    if res.get("busy"):
        return {"ok": True, "action": "busy"}
    config.log("masque: autocheck: konfig %s mertv (%s)"
               % (key, str(res.get("error"))[:80]))

    # 1) другой эндпоинт на тех же ключах
    store = _read_store()
    m = (store["items"].get(key) or {}).get("masque")
    orig_srv = str((m or {}).get("server") or "")
    orig_port = int((m or {}).get("port") or 443)
    for ip, port in MASQUE_ENDPOINTS:
        if ip == orig_srv:
            continue
        if not set_endpoint(key, ip, port):
            break
        res = probe(20)
        if res.get("ok"):
            ap = apply(key)  # один перезапуск сервиса, только когда нашли живой
            if ap.get("ok"):
                config.log("masque: autocheck: endpoint %s ozhil" % ip)
                return {"ok": True, "action": "endpoint", "name": key,
                        "server": ip, "egress": res.get("egress", "-")}
    if orig_srv:
        set_endpoint(key, orig_srv, orig_port)  # откат, раз не помогло

    # 2) старый конфиг мёртв совсем - выпускаем новый
    _prune(8)
    got = fetch_default("MASQUE")
    if not got.get("ok"):
        config.log("masque: autocheck: vypusk konfiga ne udalsya: %s"
                   % str(got.get("error"))[:100])
        return {"ok": False, "action": "fetch-failed",
                "error": str(got.get("error"))[:120]}
    new_key = str(got.get("name") or "")
    select(new_key)
    apply(new_key)
    res = probe(25, new_key)
    if res.get("ok"):
        config.log("masque: autocheck: vypushchen novyy konfig %s (%s)"
                   % (new_key, res.get("egress")))
        return {"ok": True, "action": "reissued", "name": new_key,
                "egress": res.get("egress", "-")}
    config.log("masque: autocheck: novyy konfig %s tozhe mertv: %s"
               % (new_key, str(res.get("error"))[:80]))
    return {"ok": False, "action": "reissued-dead", "name": new_key,
            "error": str(res.get("error"))[:120]}


def autocheck_loop(interval=None):
    iv = max(60, int(interval or AUTO_INTERVAL))
    time.sleep(30)  # дать панели подняться до первого вскрытия канала
    while True:
        try:
            if not _AUTO["running"]:
                _AUTO["running"] = True
                try:
                    _AUTO["result"] = autocheck_once()
                    _AUTO["ts"] = int(time.time())
                finally:
                    _AUTO["running"] = False
        except Exception as exc:
            _AUTO["running"] = False
            _AUTO["result"] = {"ok": False, "error": str(exc)[:160]}
            config.log("masque: autocheck: %s" % str(exc)[:160])
        time.sleep(iv)


def start_autocheck(interval=None):
    """Запустить фоновую автопроверку MASQUE (один тред на процесс)."""
    if getattr(start_autocheck, "_started", False):
        return False
    start_autocheck._started = True
    threading.Thread(target=autocheck_loop, args=(interval,),
                     daemon=True, name="masque-autocheck").start()
    return True
