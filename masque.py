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
import time

import config

_AURORA_DIR = os.path.dirname(os.path.abspath(config.DATA_DIR)) or os.getcwd()
MIHOMO_DIR = os.path.join(_AURORA_DIR, "mihomo")
MIHOMO_BIN = os.path.join(MIHOMO_DIR, "mihomo.exe" if sys.platform.startswith("win") else "mihomo")
MIHOMO_CFG = os.path.join(MIHOMO_DIR, "config.yaml")
MIXED_PORT = 18808
PROBE_URL = "http://api.ipify.org"
STORE = os.path.join(config.DATA_DIR, "masque_configs.json")
MAX_CONFIGS = 32
MAX_CONFIG_BYTES = 256 * 1024
MAX_NAME_LEN = 40

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


def _norm(priv, pub, ip, ipv6, server, port, sni):
    priv = str(priv or "").strip()
    pub = str(pub or "").strip()
    if not _B64_RE.match(priv) or not _B64_RE.match(pub):
        return None, "bad masque keys"
    server = str(server or "162.159.198.2").strip()
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
        return _norm(data.get("privKey"), data.get("peer_pub"),
                     data.get("client_ipv4"), data.get("client_ipv6"),
                     "162.159.198.2", 443, "4pda.to")
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


def probe(timeout=20, name=""):
    """Поднять временный mihomo с выбранным конфигом и узнать выходной IP."""
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
    }
