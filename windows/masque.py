"""A-MASQUE: резервный канал Cloudflare WARP через MASQUE (mihomo).

Зачем: в части сетей чистый WireGuard WARP блокируется (нет ответов на
handshake), а MASQUE (HTTP/3) проходит. Модуль умеет держать несколько
именованных MASQUE-конфигов, применять выбранный к mihomo и показывать
выходной IP. Конфиг берётся с https://warp-generation.github.io/ (кнопка
MASQUE) — это JSON с privKey/peer_pub/client_ipv4, либо Clash-YAML
с type: masque.
"""

import base64
import datetime
import json
import os
import re
import secrets
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
# A-MASQUE-EGRESS: несколько источников IP — если один недоступен из-под
# туннеля, проба всё равно должна показать живой выход.
PROBE_URLS = (PROBE_URL, "https://api.ipify.org", "https://ifconfig.me/ip")
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

# A-MASQUE-CREATE: локальный выпуск конфига без сайта-генератора.
# Server EC P-256 public key (SubjectPublicKeyInfo DER), стабилен у Cloudflare;
# совпадает с peer_pub у https://masque-vercel.warp-api.cfd (проверено 3 запроса).
MASQUE_SERVER_PUB = (
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+"
    "/h4mcG7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w=="
)
CF_WARP_API = "https://api.cloudflareclient.com/v0i1909051800"

# secp256r1 (NIST P-256), параметры кривой — только stdlib, без cryptography.
_P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
_P256_A = _P256_P - 3
_P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
_P256_GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
_P256_GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
_P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
_OID_EC_PUBLIC_KEY = bytes.fromhex("06072a8648ce3d0201")
_OID_PRIME256V1 = bytes.fromhex("06082a8648ce3d030107")


def _der_len(value):
    if value < 128:
        return bytes((value,))
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(raw),)) + raw


def _der(tag, payload):
    return bytes((tag,)) + _der_len(len(payload)) + payload


def _der_int(value):
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _der(0x02, raw)


def _p256_inv(value):
    return pow(value, _P256_P - 2, _P256_P)


def _p256_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x1, y1 = a
    x2, y2 = b
    if x1 == x2:
        if (y1 + y2) % _P256_P == 0:
            return None
        slope = (3 * x1 * x1 + _P256_A) * _p256_inv(2 * y1) % _P256_P
    else:
        slope = (y2 - y1) * _p256_inv(x2 - x1) % _P256_P
    x3 = (slope * slope - x1 - x2) % _P256_P
    y3 = (slope * (x1 - x3) - y1) % _P256_P
    return x3, y3


def _p256_mul(scalar, point=None):
    """Скалярное умножение точки P-256 (double-and-add)."""
    if point is None:
        point = (_P256_GX, _P256_GY)
    result = None
    while scalar:
        if scalar & 1:
            result = _p256_add(result, point)
        point = _p256_add(point, point)
        scalar >>= 1
    return result


def _p256_keypair():
    """Свежая пара EC P-256: (priv DER/SEC1, pub DER/SPKI) в base64."""
    secret = secrets.randbelow(_P256_N - 1) + 1
    qx, qy = _p256_mul(secret)
    point = (b"\x04" + qx.to_bytes(32, "big") + qy.to_bytes(32, "big"))
    priv = _der(0x30,
                _der_int(1)
                + _der(0x04, secret.to_bytes(32, "big"))
                + _der(0xa0, _OID_PRIME256V1)
                + _der(0xa1, _der(0x03, b"\x00" + point)))
    spki = _der(0x30,
                _der(0x30, _OID_EC_PUBLIC_KEY + _OID_PRIME256V1)
                + _der(0x03, b"\x00" + point))
    return base64.b64encode(priv).decode(), base64.b64encode(spki).decode()


def _cf_api(method, path, payload=None, token=""):
    """Один вызов Cloudflare WARP API (A-MASQUE-CREATE)."""
    import urllib.error
    import urllib.request
    headers = {"User-Agent": "CloudflareWarp/1.0",
               "Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(CF_WARP_API + path, data=body,
                                 method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))


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


def _mihomo_release_tag():
    """A-MASQUE-FIX: свежий тег mihomo через redirect /releases/latest.

    Без GitHub API (там rate limit) и без хардкода версии: GitHub сам
    редиректит на /releases/tag/vX.Y.Z, откуда берём тег для имени ассета.
    """
    import urllib.request
    try:
        req = urllib.request.Request(
            "https://github.com/MetaCubeX/mihomo/releases/latest",
            headers={"User-Agent": "Aurora/" + str(config.VERSION)})
        with urllib.request.urlopen(req, timeout=15) as r:
            final_url = r.geturl()
        m = re.search(r"/tag/(v\d+\.\d+\.\d+)", final_url)
        return m.group(1) if m else ""
    except Exception:
        return ""


def ensure_mihomo():
    """Проверить/скачать mihomo. Возвращает (ok, error).

    A-MASQUE-FIX: раньше качали mihomo-windows-amd64-compatible.exe и
    mihomo-linux-amd64-compatible.gz. С v1.19.x ассеты переименованы:
    …-compatible-v1.19.34.zip (Windows) и …-compatible-v1.19.34.gz.
    Старые URL дают 404 — канал не поднимался на свежей установке.
    """
    if os.path.isfile(MIHOMO_BIN):
        return True, ""
    os.makedirs(MIHOMO_DIR, exist_ok=True)
    arch = "amd64" if sys.maxsize > 2 ** 32 else "386"
    is_win = sys.platform.startswith("win")
    is_mac = sys.platform == "darwin"
    plat = "windows" if is_win else ("darwin" if is_mac else "linux")
    ext = "zip" if is_win else "gz"
    import urllib.request
    tag = _mihomo_release_tag()
    # Новый формат имени ассета (с версией) + старый как запасной вариант.
    names = []
    if tag:
        names.append("mihomo-%s-%s-compatible-%s.%s" % (plat, arch, tag, ext))
    names.append("mihomo-%s-%s-compatible.%s" % (plat, arch, ext))
    if is_win:
        names.append("mihomo-windows-%s-compatible.exe" % arch)
    base = "https://github.com/MetaCubeX/mihomo/releases/"
    urls = [base + "download/" + tag + "/" + n for n in names if tag]
    if tag:
        urls.append(base + "latest/download/" + names[-1])
    else:
        urls = [base + "latest/download/" + n for n in names]
    last_err = ""
    for url in urls:
        try:
            with urllib.request.urlopen(url, timeout=60) as r:
                data = r.read()
            if len(data) < 100000:
                last_err = "too small: %d" % len(data)
                continue
            if url.endswith(".zip"):
                import io
                import zipfile
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    exe = next((n for n in z.namelist()
                                if n.lower().endswith(".exe")), "")
                    if not exe:
                        last_err = "no exe in zip"
                        continue
                    data = z.read(exe)
            elif url.endswith(".gz"):
                import gzip
                data = gzip.decompress(data)
            with open(MIHOMO_BIN, "wb") as f:
                f.write(data)
            os.chmod(MIHOMO_BIN, 0o755)
            return True, ""
        except Exception as exc:
            last_err = str(exc)[:100]
    return False, "mihomo download failed: %s" % last_err


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


def _probe_egress(port=18809, timeout=8):
    """A-MASQUE-EGRESS: узнать IP выхода через локальный mixed-port mihomo.

    Раньше проба звала внешний `curl` из PATH. На минимальных установках
    (в т.ч. на мастере) его нет — канал работает, а панель показывает
    "Выходной IP -". Теперь основной путь — чистый stdlib urllib через
    HTTP-прокси 127.0.0.1:<port>; curl остаётся только запасным вариантом.
    Возвращает IPv4-строку или "".
    """
    import urllib.request
    proxy = "http://127.0.0.1:%d" % int(port)
    attempt = max(2, min(int(timeout), 4))
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    for url in PROBE_URLS:
        try:
            with opener.open(url, timeout=attempt) as resp:
                text = resp.read(256).decode("utf-8", "replace").strip()
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", text):
                return text
        except Exception:
            continue
    # Запасной путь: системный curl (если есть), один адрес, короткий таймаут.
    curls = (["curl.exe"] if sys.platform.startswith("win") else ["curl"])
    r = _run(curls + ["-sS", "-m", str(attempt), "-x", proxy, PROBE_URLS[0]],
             timeout=attempt + 4)
    if r is not None and getattr(r, "returncode", 1) == 0:
        text = r.stdout.decode("utf-8", "replace").strip()
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", text):
            return text
    return ""


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
        ip = ""
        deadline = time.time() + max(5, int(timeout))
        while time.time() < deadline:
            ip = _probe_egress(18809, 8)
            if ip:
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


def create(name="", endpoint=None):
    """A-MASQUE-CREATE: СОЗДАТЬ MASQUE-конфиг локально, без сайта-генератора.

    Рецепт проверен вживую (egress 104.28.245.231):
      1) генерируем свежую пару EC P-256 (только stdlib, DER SEC1 + SPKI);
      2) регистрируем публичку через POST /reg (иначе нет egress — проверено);
      3) собираем JSON генератора: privKey/peer_pub/client_ipv4,
         эндпоинт подбираем сами, т.к. сайт его не отдаёт.
    Возвращает то же, что install(): {ok, name, endpoint, count}.
    """
    try:
        priv_b64, pub_b64 = _p256_keypair()
    except Exception as exc:
        return {"ok": False, "error": "keygen failed: %s" % str(exc)[:80]}

    now = datetime.datetime.now(datetime.timezone.utc).isoformat(
        timespec="milliseconds").replace("+00:00", "Z")
    try:
        reg = _cf_api("POST", "/reg", {
            "install_id": "", "tos": now, "key": pub_b64,
            "fcm_token": "", "type": "ios", "locale": "en_US",
        })
    except Exception as exc:
        return {"ok": False, "error": "warp reg failed: %s" % str(exc)[:100]}
    result = reg.get("result") if isinstance(reg, dict) else None
    if not isinstance(result, dict) or not result.get("id"):
        return {"ok": False, "error": "bad warp reg response"}

    # PATCH не обязателен для выхода, но даёт адреса интерфейса; best-effort.
    ip = "172.16.0.2"
    ipv6 = ""
    rid = str(result.get("id"))
    token = str(result.get("token") or "")
    if token:
        try:
            en = _cf_api("PATCH", "/reg/" + rid, {"warp_enabled": True}, token)
            cfg = (((en.get("result") or {}).get("config") or {})
                   .get("interface") or {}).get("addresses") or {}
            ip = str(cfg.get("v4") or ip)
            ipv6 = str(cfg.get("v6") or "")
        except Exception:
            pass

    payload = {"privKey": priv_b64, "peer_pub": MASQUE_SERVER_PUB,
               "client_ipv4": ip, "client_ipv6": ipv6,
               "server": str(endpoint or pick_endpoint()), "port": 443}
    out = install(json.dumps(payload), name or "Созданный")
    if out.get("ok"):
        config.log("masque: A-MASQUE-CREATE konfig sozdan localno: %s"
                   % str(out.get("name", ""))[:40])
    return out


def create_apply(name=""):
    """A-MASQUE-CREATE: создать локально -> активный -> поднять -> проба.

    Аналог fetch_apply(), но без обращения к сайту-генератору.
    """
    r = create(name)
    if not r.get("ok"):
        return r
    key = str(r.get("name") or "")
    sel = select(key)
    if not sel.get("ok"):
        return {"ok": False, "error": sel.get("error", "select failed")}
    ap = apply(key)
    if not ap.get("ok"):
        return {"ok": False, "name": key,
                "error": ap.get("error", "apply failed")}
    res = probe(30, key)
    out = {"ok": bool(res.get("ok")), "name": key,
           "endpoint": str(ap.get("endpoint") or "")}
    if res.get("ok"):
        out["egress"] = res.get("egress", "-")
        config.log("masque: create_apply: %s -> %s" % (key, out["egress"]))
    else:
        out["error"] = str(res.get("error") or "no egress")[:120]
        config.log("masque: create_apply: %s ne proshel probu (%s)"
                   % (key, out["error"]))
    return out


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
