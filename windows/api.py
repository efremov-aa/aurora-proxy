# Aurora v1.6.0 — HTTP API: /api/* + панель. Чистый ThreadingHTTPServer (без фреймворков).
# Порт эталона v1.4.0 (mesh/keys/routes/settings/security) на публичную
# сборку: станция отсутствует, сохранены авто-обновление (update), Bearer-токен
# (security.check) и admin-ротация API-токена (/api/security/rotate).

import hmac
import ipaddress
import json
import os
import re
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import autocheck
import autobackup  # A-123 «Кот-диспетчер»: плановый бэкап
import backup
import clientexport  # A-122: экспорт клиентских конфигов
import config
import crypt
import diag
import extgate
import effects
import failover  # A-120: авто-переключение резерва
import core
import mesh
import meshsignal
import notify  # A-121: TG-уведомления владельцу
import pool
import recovery
import rusegment
import security
import source
import warp  # A-WARP-PUB: rezervnyy kanal WARP
import masque  # A-MASQUE-PUB
import telemetry
import tgws
import ui
import updater

# origins, которым разрешены POST
_ALLOWED_ORIGINS = {"127.0.0.1", "localhost", config.VM_HOST, "::1"}

# опциональный токен: если settings.ui_token непустой, все /api/* требуют X-Auth
_UI_TOKEN = ""


def _load_ui_token():
    global _UI_TOKEN
    _UI_TOKEN = str(config.get("ui_token", "") or "")


def _json(data, status=200):
    body = json.dumps(data, ensure_ascii=False).encode("utf-8")
    return (status, "application/json; charset=utf-8", body)


def _extra_hosts():
    """A-835: dopolnitelnye hosty paneli cherez env (zapryataya, cherez ";").

    Zachem: server znaet tol'ko svoi adresa (VM_HOST/AURORA_HOST i sohranennyy
    v nastroykah "host"). Esli panel otkryvayut po drugomu adresu - naprimer po
    adresu Tailnet (100.x) ili po aliyas meny - server otdayot
    {"error": "host not allowed"} s kodom 421 i stranitsa vsego ne rabotaet.

    Spisok cherez ";" (a ne cherez zapryatuyu) - tak zapis chasto zagnayotsya v
    .env i systemd override, gde zapyataya mozhet slomatsya.
    Fail-closed: tol'ko hosty, kotorye vypisany yavno. Nichego ne rasshiryаetsya
    avtomaticheski - tol'ko to, chto vlinedil operator.
    """
    values = set()
    raw = str(os.environ.get("AURORA_EXTRA_HOSTS", "") or "")
    for item in re.split(r"[;,\s]+", raw):
        host = item.strip().lower().rstrip(".")
        if not host or len(host) > 253:
            continue
        # tol'ko imya/adres, bez portov, probelov i skhem
        if any(ch in host for ch in "/:@?#"):  
            continue
        try:
            values.add(str(ipaddress.ip_address(host)))
            continue
        except ValueError:
            pass
        if re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?"
                        r"(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*", host):
            values.add(host)
    return values


def _configured_hosts():
    values = {"127.0.0.1", "::1", "localhost"}
    # A-264: хост, сохранённый в настройках, тоже разрешён. Раньше гейт знал
    # только env (AURORA_HOST/VM_HOST), и панель по своему же адресу из
    # настроек отбивалась: GET 401, POST 403 cross-origin.
    for value in (config.VM_HOST, os.environ.get("AURORA_HOST", ""),
                  config.get("host", "")):
        host = str(value or "").strip().lower().rstrip(".")
        if host:
            values.add(host)
    # A-835: явно разрешённые доп. адреса (Tailnet, алиасы).
    values |= _extra_hosts()
    return values


def _host_allowed(host):
    host = str(host or "").strip().lower().rstrip(".")
    if not host:
        return False
    return host in _configured_hosts()

def _authority(value):
    try:
        parsed = urllib.parse.urlsplit("//" + str(value or ""))
        if (not parsed.netloc or parsed.username is not None
                or parsed.password is not None or parsed.path
                or parsed.query or parsed.fragment):
            return None
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except (TypeError, ValueError):
        return None
    if not host or not _host_allowed(host):
        return None
    return host, port


def _host_ok(self):
    values = self.headers.get_all("Host", []) if hasattr(self.headers, "get_all") else []
    if not values:
        value = self.headers.get("Host")
        values = [value] if value is not None else []
    if len(values) != 1:
        return False
    authority = _authority(values[0].strip())
    if authority is None:
        return False
    host, port = authority
    if port is None:
        if host not in ("localhost", "127.0.0.1", "::1"):
            return False
        port = config.UI_PORT
    return port == config.UI_PORT

def _origin_key(value):
    try:
        parsed = urllib.parse.urlsplit(str(value or ""))
        if (parsed.scheme not in ("http", "https") or not parsed.netloc
                or parsed.username is not None or parsed.password is not None
                or parsed.path or parsed.query or parsed.fragment):
            return None
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except (TypeError, ValueError):
        return None
    if not host or not _host_allowed(host):
        return None
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    return parsed.scheme, host, port


def _origin_ok(self):
    origins = self.headers.get_all("Origin", []) if hasattr(self.headers, "get_all") else []
    if len(origins) > 1:
        return False
    if not origins or not origins[0].strip():
        markers = self.headers.get_all("X-Aurora-Request", []) \
            if hasattr(self.headers, "get_all") else []
        return len(markers) == 1 and markers[0].strip() == "1"
    hosts = self.headers.get_all("Host", []) if hasattr(self.headers, "get_all") else []
    if len(hosts) != 1:
        return False
    host_authority = _authority(hosts[0].strip())
    if host_authority is None:
        return False
    host, host_port = host_authority
    if host_port is None:
        if host not in ("localhost", "127.0.0.1", "::1"):
            return False
        host_port = config.UI_PORT
    origin = _origin_key(origins[0].strip())
    if origin is None or origin[0] != "http" or origin[2] != config.UI_PORT:
        return False
    return (origin[1], origin[2]) == (host, host_port)

def _is_local(self):
    try:
        return ipaddress.ip_address(str(self.client_address[0])).is_loopback
    except (TypeError, ValueError):
        return False


def _instance_claimed():
    if config.get("setup_complete", False) or config.get("ui_token", ""):
        return True
    try:
        return bool(security.status().get("enabled"))
    except Exception:
        return False


def _ui_qr():
    """Содержимое ui/qr.js: из модуля ui или с диска (на старых ui.py QR нет)."""
    try:
        qr = getattr(ui, "QR", "") or ""
        if qr:
            return qr
    except Exception:
        pass
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui", "qr.js")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


# --- v1.4.0: защита панели (LAN-only, сканеры, rate-limit) ---
_RATE = {}
_RATE_LOCK = threading.Lock()
_PUBLIC_EVENTS = {}
_PUBLIC_LOCK = threading.Lock()


def _public_allowed(kind, ip, max_hits=10, window=60, backoff=0):
    now = time.time()
    with _PUBLIC_LOCK:
        item = _PUBLIC_EVENTS.setdefault((kind, ip), {"hits": [], "fails": []})
        item["hits"] = [t for t in item["hits"] if now - t < window]
        fails = [t for t in item["fails"] if now - t < 900]
        item["fails"] = fails
        if backoff and fails:
            delay = backoff * (2 ** min(len(fails) - 1, 6))
            if now - fails[-1] < delay:
                return False
        if len(item["hits"]) >= max_hits:
            return False
        item["hits"].append(now)
        return True


def _public_failed(kind, ip):
    with _PUBLIC_LOCK:
        item = _PUBLIC_EVENTS.setdefault((kind, ip), {"hits": [], "fails": []})
        item["fails"].append(time.time())


def _public_succeeded(kind, ip):
    with _PUBLIC_LOCK:
        _PUBLIC_EVENTS.pop((kind, ip), None)

_SCANNER_PATHS = (
    "/admin", "/login", "/wp-", "/.env", "/vendor", "/server-status",
    "/boaform", "/manager", "/cgi-bin", "/config.php", "/phpmyadmin",
    "/.git", "/shell", "/actuator", "/wp-login", "/xmlrpc.php",
)


def _scanner_path(path):
    return any(path == p or path.startswith(p + "/") for p in _SCANNER_PATHS)


def _host_in_lan(ip):
    try:
        client = ipaddress.ip_address(str(ip))
        # A-264: если env AURORA_HOST не задан, ориентир берём из сохранённого
        # адреса панели - иначе при VM_HOST=127.0.0.1 подсеть LAN не угадывалась
        # и владелец в своей сети получал 401 вместо доступа.
        anchor = str(config.VM_HOST or "").strip()
        if anchor in ("", "localhost", "127.0.0.1", "::1"):
            anchor = str(config.get("host", "") or "").strip() or anchor
        server = ipaddress.ip_address(anchor)
    except (TypeError, ValueError):
        return _is_local_value(ip)
    if client.is_loopback:
        return True
    if client.version != server.version:
        return False
    if server.version == 4:
        return client in ipaddress.ip_network(str(server) + "/16", strict=False)
    return client in ipaddress.ip_network(str(server) + "/64", strict=False)


def _is_local_value(ip):
    try:
        return ipaddress.ip_address(str(ip)).is_loopback
    except (TypeError, ValueError):
        return False


def _rate_allowed(ip, window=60, max_hits=600):
    """Слайдинг-окно req/min на не-loopback IP (демпфер сканирования)."""
    if not config.get("rate_limit", True):
        return True
    if ip in ("127.0.0.1", "::1"):
        return True
    now = time.time()
    with _RATE_LOCK:
        hits = [t for t in _RATE.get(ip, []) if now - t < window]
        if len(hits) >= max_hits:
            _RATE[ip] = hits
            return False
        hits.append(now)
        _RATE[ip] = hits
        return True


def _access_allowed(self):
    if not _rate_allowed(self.client_address[0]):
        return False
    if _is_local(self):
        return True
    if config.get("lan_only", False) and _host_in_lan(self.client_address[0]):
        return True
    if _panel_token_ok(self):
        return True
    return security.enabled() and security.check(
        self.headers, self.client_address[0])


def _twofa_ok(self):
    """2FA-пин: если включён, POST-запросы требуют X-2FA."""
    if not config.get("twofa", False):
        return True
    # Владелец в своей LAN-сети: доступ к панели уже выдан по lan_only,
    # поэтому 2FA-пин поверх не спрашиваем — иначе кнопки недоступны вовсе.
    if config.get("lan_only", False) and _host_in_lan(self.client_address[0]):
        return True
    pin = config.get("ui_pin", "")
    return bool(pin) and self.headers.get("X-2FA", "") == pin


def _as_bool(v):
    """Приведение значения к bool (для настроек из UI)."""
    if isinstance(v, bool):
        return v
    return str(v or "").strip().lower() in ("1", "true", "yes", "on")


_AUTO_REFRESH_STARTED = False


def _panel_token_ok(self):
    given = self.headers.get("X-Auth", "")
    if not given:
        given = (urllib.parse.parse_qs(self.path.split("?", 1)[-1]) or {}).get("token", [""])[0]
    return _token_matches(given, _UI_TOKEN)


def _token_matches(value, expected):
    return bool(value and expected and hmac.compare_digest(
        str(value).encode("utf-8"), str(expected).encode("utf-8")))


def _local_mesh_root():
    """A-274: root of its own subnet. Tunnel on = this node may issue
    and accept invites for ITS subnet without the master flag."""
    try:
        if config.get("mesh_tunnel", False):
            return True
    except Exception:
        pass
    try:
        import meshtunnel
        return bool(meshtunnel.enabled())
    except Exception:
        return False


def _mesh_post_allowed(path):
    """A-274: own-subnet paths stay open for a local root even when the
    master has not turned show_mesh on."""
    if path in ("/api/mesh/invite", "/api/mesh/regenerate", "/api/mesh/join"):
        return _local_mesh_root()
    return False


def _admin_ok(self):
    if _token_matches(self.headers.get("X-Auth", ""), _UI_TOKEN):
        return True
    if security.enabled() and security.check(
            self.headers, self.client_address[0]):
        return True
    # Владелец в своей LAN-сети: панель закрыта только снаружи (lan_only),
    # поэтому из LAN доступ к кнопкам (обновить/проверить/оплатить) разрешён.
    if config.get("lan_only", False) and _host_in_lan(self.client_address[0]):
        return True
    # A-264: если админ-токен вообще не настроен, панель была мертва для всех
    # POST (даже с localhost и из браузера владельца) — «не авторизовано».
    # Loopback и так доверен для чтения, поэтому до настройки токена
    # разрешаем и запись; как только токен задан, эта ветка больше не работает.
    if not _UI_TOKEN and _is_local(self):
        return True
    return False

def _read_auth_ok(self):
    if _is_local(self):
        return True
    if config.get("lan_only", False) and _host_in_lan(self.client_address[0]):
        return True
    if _panel_token_ok(self):
        return True
    return security.enabled() and security.check(
        self.headers, self.client_address[0])


def _trusted_read(self):
    if _is_local(self):
        return True
    if _panel_token_ok(self):
        return True
    if security.enabled() and security.check(
            self.headers, self.client_address[0]):
        return True
    # Владелец в LAN: логи, recovery и ссылка TG-WS доступны из своей сети.
    if config.get("lan_only", False) and _host_in_lan(self.client_address[0]):
        return True
    return False


def _valid_peer_host(value):
    host = str(value or "").strip()
    if not host or len(host) > 253:
        return False
    if any(ch.isspace() for ch in host) or any(ch in host for ch in "/\\@?#"):
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return bool(host) and all(ch.isalnum() or ch in ".-" for ch in host)
    if str(ip) in config.METADATA_HOSTS:
        return False
    return not (ip.is_unspecified or ip.is_loopback or ip.is_link_local or ip.is_multicast)


def _read_json_body(self, max_bytes=65536, required=True):
    if self.headers.get("Transfer-Encoding") is not None:
        return None, "transfer-encoding not allowed"
    lengths = self.headers.get_all("Content-Length", []) \
        if hasattr(self.headers, "get_all") else []
    if not lengths:
        raw_length = self.headers.get("Content-Length")
        if raw_length is not None:
            lengths = [raw_length]
    if len(lengths) != 1:
        if not lengths and not required:
            return {}, None
        return None, "content-length required"
    raw_length = str(lengths[0]).strip()
    if not raw_length.isdigit():
        return None, "bad content-length"
    length = int(raw_length)
    if length <= 0 or length > max_bytes:
        return None, "invalid body length"
    content_types = self.headers.get_all("Content-Type", []) \
        if hasattr(self.headers, "get_all") else []
    if not content_types:
        content_type = self.headers.get("Content-Type")
        if content_type is not None:
            content_types = [content_type]
    if len(content_types) != 1 or content_types[0].split(";", 1)[0].strip().lower() != "application/json":
        return None, "application/json required"
    body = self.rfile.read(length)
    if len(body) != length:
        return None, "incomplete body"
    try:
        data = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None, "invalid json body"
    if not isinstance(data, dict):
        return None, "json object required"
    return data, None


def _auth_ok(self):
    return _panel_token_ok(self)


def _vless_ext():
    """Внешняя vless-ссылка для подключения к домашнему прокси ИЗВНЕ.

    A-118: отдаём словарь всегда (даже выключен/не настроен), чтобы панель
    могла показать выключатель. configured — есть ли настройки вообще.
    """
    v = config.vless_public()
    host = config._format_link_host(v.get("host", ""))
    out = {
        "enabled": bool(v.get("enabled")),
        "configured": bool(v.get("configured")),
        "port": v.get("port") or 0,
        "host": v.get("host") or "",
        "uuid": v.get("uuid") or "",
        "sni": v.get("sni") or "",
        "pbk": v.get("public_key") or "",
        "sid": v.get("short_id") or "",
        "fp": "chrome",
        "link": "",
    }
    if not out["enabled"] or not out["uuid"] or not host:
        return out
    q = urllib.parse.urlencode({
        "encryption": "none",
        "security": "reality",
        "flow": v["flow"],
        "sni": v["sni"],
        "fp": "chrome",
        "pbk": v["public_key"],
        "sid": v["short_id"],
        "type": "tcp",
        "headerType": "none",
    })
    out["link"] = "vless://%s@%s:%d?%s#Aurora-Out" % (
        v["uuid"], host, v["port"], q)
    return out


_CSP = ("default-src 'self'; base-uri 'none'; object-src 'none'; "
        "frame-ancestors 'none'; frame-src 'none'; form-action 'self'; "
        "script-src 'self'; script-src-attr 'none'; "
        "style-src 'self'; style-src-attr 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'")


_TLS_ENABLED = False

_TRANSPORT_EXEMPT = ("/api/ext/config", "/api/rusegment/regions")


def _tls_env():
    """Пути cert/key из окружения; оба файла должны существовать."""
    cert = os.environ.get("AURORA_TLS_CERT", "").strip()
    key = os.environ.get("AURORA_TLS_KEY", "").strip()
    if not cert or not key:
        return "", ""
    if not os.path.isfile(cert) or not os.path.isfile(key):
        return "", ""
    return cert, key


def _enable_tls(httpd):
    """Опциональный TLS (TLS 1.2+); без cert/key остаётся plain HTTP."""
    global _TLS_ENABLED
    cert, key = _tls_env()
    if not cert:
        return False
    import ssl
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    _TLS_ENABLED = True
    return True


def _has_credentials(req):
    if req.headers.get("X-Auth") or req.headers.get("X-2FA"):
        return True
    if req.headers.get("Authorization"):
        return True
    return "token=" in str(req.path or "")


def _transport_ok(req):
    """Учётные данные не идут открытым текстом вне доверенного сегмента."""
    path = str(req.path or "").split("?", 1)[0]
    if _is_local(req):
        return True
    if _TLS_ENABLED:
        return True
    if any(path == item or path.startswith(item + "/") for item in _TRANSPORT_EXEMPT):
        return True
    if not _has_credentials(req):
        return True
    return _host_in_lan(req.client_address[0])


_FAVICON_SVG = ("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 32 32\">"
                "<text x=\"3\" y=\"26\" font-size=\"24\">&#128049;</text></svg>")


def _security_headers():
    headers = (("X-Content-Type-Options", "nosniff"),
               ("X-Frame-Options", "DENY"),
               ("Referrer-Policy", "no-referrer"),
               ("Content-Security-Policy", _CSP))
    if _TLS_ENABLED:
        headers = headers + (("Strict-Transport-Security", "max-age=31536000"),)
    return headers


def _ext_config(req):
    """GET /api/ext/config — конфиг браузерного расширения, открыт без токена."""
    req._send(*_json({
        "ok": True,
        "proxy": {"host": config.ext_proxy_host(),
                  "port": int(config.XRAY_PORT), "type": "http"},
        "mode": "vpn" if config.get("vpn_mode", True) else "direct",
        "ru_bypass": bool(config.RU_BYPASS),
        "blocked": False,
        "plan": "", "expires": 0, "used": 0, "limit": 0,
        "buy_url": "",
        "rules_version": config.RULES_VERSION,
    }, 200))


def _setup_reject(req, reason, status=400):
    route = str(getattr(req, "path", "") or "").split("?", 1)[0]
    config.log("api: setup rejected: %s (%s)" % (reason, route))
    req._send(*_json({"ok": False, "error": reason}, status))


def _project_state(state, trusted):
    if trusted:
        return state
    out = dict(state)
    comm = dict(out.get("comm") or {})
    comm["msg"] = ""
    out["comm"] = comm
    out["xray_api_port"] = 0
    out["xray_port"] = 0
    return out


def _project_security_status(trusted):
    status = security.status()
    if trusted:
        return status
    return {"ok": True, "enabled": bool(status.get("enabled"))}


def _project_update_status(trusted):
    status = updater.status()
    if trusted:
        return status
    out = {"ok": True}
    for key in ("enabled", "current", "latest", "state", "update"):
        if key in status:
            out[key] = status[key]
    return out


def _reserve_egress(st):
    """A-MASQUE-EGRESS: IP активного резерва, когда xray-канал молчит.

    MASQUE/WARP поднимаются отдельным процессом mihomo, поэтому
    core.egress_ip() о них не знает и отдаёт '-' — панель показывала
    «Выходной IP -» даже при работающем туннеле. Берём самый свежий
    результат пробы у активного канала (MASQUE или обычный WARP).
    """
    best = ("", 0)

    def _take(item):
        if not isinstance(item, dict):
            return
        ip = str(item.get("egress") or "").strip()
        if ip == "-" or not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            return
        try:
            ts = int(item.get("egress_ts") or 0)
        except (TypeError, ValueError):
            ts = 0
        nonlocal best
        if ts >= best[1]:
            best = (ip, ts)

    for key in ("masque", "warp"):
        ch = st.get(key) or {}
        if not isinstance(ch, dict) or not ch.get("active"):
            continue
        # Верхнее поле живёт в памяти и сбрасывается при рестарте панели,
        # а egress в configs[...] читается из файла — надёжнее.
        _take(ch)
        for item in (ch.get("configs") or []):
            if isinstance(item, dict) and (item.get("active")
                                           or item.get("name") == ch.get("name")):
                _take(item)
    return best[0]


def build_state(local=True):
    st = config.get_state()
    st["version"] = config.VERSION
    st["version_name"] = config.VERSION_NAME
    st["app"] = config.APP_NAME
    st["xray_port"] = config.XRAY_PORT
    st["ui_port"] = config.UI_PORT
    st["xray_api_port"] = config.XRAY_API_PORT
    st["tgws_port"] = config.TGWS_PORT
    st["vpn_mode"] = config.get("vpn_mode", True)
    # A-427: /api/state had no white_ip at all, so every panel view that reads
    # the shared state object showed an empty white IP.
    st["white_ip"] = config.WHITE_IP
    st["auto_recovery"] = config.get("auto_recovery", True)
    st["vless_now"] = core.get_vless_now() or "-"
    st["egress_ip"] = core.egress_ip()
    st["comm"] = st.pop("comm", {"state": "idle", "msg": ""})
    st["vless_ext"] = _vless_ext()
    # A-118: выключатель внешнего VLESS-«Входящего» :8443.
    try:
        st["vless_enabled"] = bool(config.vless_public().get("enabled"))
    except Exception:
        st["vless_enabled"] = False
    st["mesh_tunnel"] = _tunnel_status()
    st["game_tun"] = _game_tun_status()
    st["game"] = _game_status()
    st["mesh_nodes"] = mesh.node_count()
    st["invite_available"] = False
    st["server_name"] = config.get("server_name", "Home")
    st["show_mesh"] = config.get("show_mesh", False)
    st["lan_only"] = bool(config.get("lan_only", False))
    st["rate_limit"] = bool(config.get("rate_limit", True))
    st["block_scanners"] = bool(config.get("block_scanners", False))
    st["setup_token_required"] = bool(config.SETUP_TOKEN)
    try:
        st["warp"] = warp.status()
    except Exception:
        st["warp"] = {"loaded": False, "mode": "off", "active": False}
    try:
        st["masque"] = masque.status()
    except Exception:
        st["masque"] = {"loaded": False, "count": 0, "name": "",
                        "endpoint": "", "egress": "-"}
    # A-MASQUE-EGRESS: показать живой IP резерва, если xray не дал свой.
    # В windows-ветке блок `not local` уже очистил поле — не воскрешаем его.
    if local and st.get("egress_ip") in ("", "-", None):
        fallback = _reserve_egress(st)
        if fallback:
            st["egress_ip"] = fallback
    # A-118: выключатели внешнего канала и TG-WS — в состоянии панели.
    try:
        st["masque_enabled"] = masque.enabled()
    except Exception:
        st["masque_enabled"] = bool(config.get("masque_enabled", True))
    try:
        st["tgws_enabled"] = tgws.enabled()
    except Exception:
        st["tgws_enabled"] = bool(config.get("tgws_enabled", True))
    # Состояние расширения: всё открыто, без лицензии/мастера.
    ext = extgate.state()
    ext["packages"] = _ext_packages()
    st["ext"] = ext
    if not local:
        v = dict(st["vless_ext"])
        for sec in ("link", "uuid", "pbk", "sid", "host", "port", "sni", "fp"):
            v.pop(sec, None)
        st["vless_ext"] = v
        tg = dict(st.get("tgws") or {})
        tg.pop("link", None)
        st["tgws"] = tg
        st["vless_now"] = ""
        st["egress_ip"] = ""
        st["server_name"] = ""
        st["white_ip"] = ""
        st["bypass_domains"] = []
        if "white_ip" in st:
            st["white_ip"] = ""
    # ключи в пуле
    keys = pool.get_keys()
    vless_now = st["vless_now"]
    st["keys_total"] = len(keys)
    st["keys"] = []
    masked = not local
    for index, k in enumerate(keys):
        uri = k.get("uri", "")
        hs = pool.get_status(uri)
        st["keys"].append({
            "uri": "" if masked else uri,
            "tag": k.get("tag", "") if local else "key-%d" % index,
            "host": k.get("host", "") if local else "",
            "port": k.get("port", 443) if local else 0,
            "source": k.get("source", "manual") if local else "",
            "status": hs.get("status", "unchecked") if local else "masked",
            "ping_ms": hs.get("ping_ms", 0) if local else 0,
            "exit_ip": hs.get("exit_ip", "-") if local else "",
            "sites_ok": hs.get("sites_ok", 0) if local else 0,
            "dead": pool.dead_reason(uri) if local else "",
            "is_active": k.get("tag") == vless_now,
        })
    # --- политика сервиса и региональный сегмент ---
    st["segment_title"] = config.segment_title()
    st["segment_flag"] = config.segment_flag()
    st["segment_regions"] = config.segment_regions()
    st["regions"] = [{"id": k, "flag": v["flag"], "title": v["title"]}
                     for k, v in config.REGIONS.items()]
    st["white_ip"] = config.get_white_ip()
    st["bypass_domains"] = config.get_bypass_domains()
    if not local:
        st["white_ip"] = ""
        st["bypass_domains"] = []
    return st


def _sync_after_pool_change():
    try:
        core.sync()
    except Exception as e:
        config.log("api: pool change sync failed: %s" % e)


def _redact_log_line(value):
    text = str(value or "")
    text = re.sub(
        r"(?i)([?&](?:token|secret|password|pin|key|uuid|pbk|sid)=)[^&\s]+",
        r"\1<redacted>", text)
    text = re.sub(
        r"(?i)(Bearer\s+)[A-Za-z0-9._~-]+",
        r"\1<redacted>", text)
    text = re.sub(
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
        "<uuid>", text, flags=re.IGNORECASE)
    return re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<ip>", text)


class Handler(BaseHTTPRequestHandler):
    server_version = "Aurora/1.0"

    def log_message(self, *a):
        pass

    def _send_binary(self, status, ctype, body, filename):
        """A-161: отдача файла (архив расширения) с Content-Disposition."""
        try:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Disposition", 'attachment; filename="%s"' % filename)
            self.send_header("Cache-Control", "no-store")
            for _name, _value in _security_headers():
                self.send_header(_name, _value)
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            return

    def _send(self, status, ctype, body):
        try:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for _name, _value in _security_headers():
                self.send_header(_name, _value)
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            return

    def do_GET(self):
        if not _host_ok(self):
            self._send(*_json({"error": "host not allowed"}, 421))
            return
        if not _transport_ok(self):
            self._send(*_json({"error": "https required"}, 403))
            return
        try:
            self._do_get()
        except Exception as e:
            import traceback
            traceback.print_exc()
            config.log("api: %s failed: %s" % (self.path.split("?", 1)[0], e))
            self._send(*_json({"error": "internal"}, 500))

    def _do_get(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            if not ui.PAGE:
                self._send(*_json({"error": "ui index.html not found"}, 500))
                return
            self._send(200, "text/html; charset=utf-8", ui.PAGE.encode("utf-8"))
            return
        if path == "/style.css":
            if not ui.STYLE:
                self._send(*_json({"error": "ui style.css not found"}, 500))
                return
            self._send(200, "text/css; charset=utf-8", ui.STYLE.encode("utf-8"))
            return
        if path == "/app.js":
            if not ui.APP:
                self._send(*_json({"error": "ui app.js not found"}, 500))
                return
            self._send(200, "application/javascript; charset=utf-8", ui.APP.encode("utf-8"))
            return
        if path == "/qr.js":
            qr = _ui_qr()
            if not qr:
                self._send(*_json({"error": "ui qr.js not found"}, 500))
                return
            self._send(200, "application/javascript; charset=utf-8", qr.encode("utf-8"))
            return
        if path == "/api/ext/config" or path.startswith("/api/ext/config?"):
            _ext_config(self)
            return
        # --- публичная выдача подписки: без авторизации и без LAN-ограничений ---
        # --- публичная политика меша: любой узел опрашивает мастера без авторизации ---
        if path == "/favicon.ico":
            self._send(200, "image/svg+xml; charset=utf-8", _FAVICON_SVG.encode("utf-8"))
            return
        # --- публичная справка по региональному сегменту ---
        if path == "/api/rusegment/regions":
            self._send(*_json({"ok": True,
                               "regions": config.segment_regions(),
                               "title": config.segment_title(),
                               "flag": config.segment_flag(),
                               "custom": config.get("segment_custom", ""),
                               "all": [{"id": k, "flag": v["flag"], "title": v["title"]}
                                       for k, v in config.REGIONS.items()]}))
            return
        # --- API: аутентификация (если токен настроен) + секреты только локально ---
        if not _read_auth_ok(self):
            self._send(*_json({"error": "unauthorized"}, 401))
            return
        if config.get("block_scanners", False) and _scanner_path(path):
            self._send(*_json({"error": "forbidden"}, 403))
            return
        if not _access_allowed(self):
            self._send(*_json({"error": "outside lan"}, 403))
            return
        trusted = _trusted_read(self)
        if not trusted and path in ("/api/log", "/api/logs", "/api/recovery/log",
                                    "/api/routes", "/api/diag", "/api/speed",
                                    "/api/autocheck", "/api/failover", "/api/notify",
                                    "/api/autobackup", "/api/export/client"):
            self._send(*_json({"error": "management authentication required"}, 403))
            return
        # Меш и все остальные разделы доступны локально, без команды мастера.
        if path == "/api/state":
            self._send(*_json(_project_state(build_state(local=trusted), trusted)))
            return
        if path in ("/api/log", "/api/logs"):
            lines = config.log_tail()
            if not trusted:
                lines = [_redact_log_line(line) for line in lines]
            self._send(*_json({"lines": lines}))
            return
        if path == "/api/recovery/log":
            self._send(*_json(recovery.status()))
            return
        # A-1040 «Кот-смотритель»: диагностика, замер скорости, автопроверка.
        if path == "/api/diag":
            self._send(*_json(diag.status()))
            return
        if path == "/api/speed":
            self._send(*_json(diag.speed_status()))
            return
        if path == "/api/autocheck":
            self._send(*_json(autocheck.status()))
            return
        # A-120/A-121/A-122/A-123 «Кот-диспетчер»: новые приборы «Сервиса».
        if path == "/api/failover":
            self._send(*_json(failover.status()))
            return
        if path == "/api/notify":
            self._send(*_json(notify.status()))
            return
        if path == "/api/autobackup":
            self._send(*_json(autobackup.status()))
            return
        if path == "/api/export/client":
            qs = urllib.parse.parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
            fmt = (qs.get("format") or [""])[0]
            try:
                self._send(*_json(clientexport.build(fmt)))
            except ValueError as e:
                self._send(*_json({"ok": False, "error": str(e)[:200]}, 400))
            return
        if path == "/api/ext/download":
            # Архив браузерного расширения доступен без подписки.
            _target = ""
            _qs = self.path.split("?", 1)[1] if "?" in self.path else ""
            for _pair in _qs.split("&"):
                if _pair.startswith("target="):
                    try:
                        _target = urllib.parse.unquote(_pair[7:]).strip().lower()
                    except Exception:
                        _target = ""
            _name = (getattr(config, "EXT_PACKAGES", {}) or {}).get(_target, "")
            if not _name:
                self._send(*_json({"ok": False, "error": "ext: неизвестная сборка расширения"}, 400))
                return
            _path = os.path.join(getattr(config, "EXT_ASSETS_DIR", ""), os.path.basename(_name))
            try:
                with open(_path, "rb") as _fh:
                    _body = _fh.read(16 * 1024 * 1024 + 1)
            except OSError:
                self._send(*_json({"ok": False, "error": "ext: архив расширения не найден"}, 404))
                return
            if len(_body) > 16 * 1024 * 1024:
                self._send(*_json({"ok": False, "error": "ext: архив слишком большой"}, 400))
                return
            self._send_binary(200, "application/zip", _body, _name)
            return

        if path == "/api/ext/license":
            # A-111: снимок лицензии (план/PRO/до купки) - панель спрашивает
            # на старте и раз в час, гейт берёт решение на сервере.
            _lic = extgate.state()
            # A-164: перечень сборок расширения (пусто: раздаёт мастер).
            _lic["packages"] = _ext_packages()
            self._send(*_json(_lic))
            return
        if path == "/api/tgws/status":
            data = tgws.status(include_secret=trusted)
            if not trusted:
                data["link"] = ""
                data.pop("secret", None)
                data["secret_ok"] = False
            self._send(*_json(data))
            return
        if path == "/api/security/status":
            self._send(*_json(_project_security_status(trusted)))
            return
        if path == "/api/update/status":
            self._send(*_json(_project_update_status(trusted)))
            return
        if path == "/api/versions":
            # история версий для вкладки «Версии»: без дублей, с описанием
            self._send(*_json({"ok": True, "versions": _versions_list(),
                               "current": config.VERSION,
                               "chronicle": getattr(config, "VERSION_CHRONICLE", {}) or {}}))
            return

        if path == "/api/mesh":
            # A-101: показываем честную живость узла (пинг порта прокси,
            # при неудаче - порта панели), иначе все узлы выглядят мертвыми.
            nodes = [_node_alive(n) for n in mesh.all_nodes()]
            if not trusted:
                nodes = [dict(n) for n in nodes if isinstance(n, dict)]
                for node in nodes:
                    for key in ("secret", "invite", "host", "port", "ip", "address"):
                        node.pop(key, None)
            self._send(*_json({"ok": True, "invite": mesh.invite() if trusted else "",
                               "nodes": nodes,
                               "count": mesh.node_count()}))
            return
        if path == "/api/mesh/signal":
            # A-557: сигналинг меша (offer/answer/ICE) для клиентов чата и голоса.
            self._mesh_signal_get()
            return
        if path == "/api/nodes":
            # A-101: ping_all отдаёт ok/ping_ms, добавляем status/ping_port.
            nodes = [_alive_via_tunnel(_node_alive(n)) for n in mesh.ping_all()]
            if not trusted:
                nodes = [{k: v for k, v in node.items()
                          if k not in ("ip", "host", "port", "address", "secret", "invite")}
                         for node in nodes if isinstance(node, dict)]
            self._send(*_json({"ok": True, "tunnel": _tunnel_status(), "nodes": nodes}))
            return
        if path == "/api/routes":
            self._send(*_json(_routes()))
            return
        if path == "/api/settings":
            settings = _settings()
            if not trusted:
                settings["settings"]["server_name"] = ""
                settings["settings"]["mesh_id"] = ""
                settings["settings"].pop("host", None)
            self._send(*_json(settings))
            return
        if path == "/api/whitelist":
            self._send(*_json({"ok": True,
                               "white_ip": config.get_white_ip() if trusted else "",
                               "bypass_domains": config.get_bypass_domains() if trusted else []}))
            return
        if path == "/api/security":
            self._send(*_json(_sec(include_secrets=trusted)))
            return
        if path == "/api/game":
            # A-827: игровой контур — сценарий, сервер группы, права узлов.
            self._send(*_json({"ok": True, "game": _game_status()}))
            return
        if path == "/api/addons":
            # A-945: что куплено и что из этого узел включил. Применять эффекты
            # из панели нельзя - узел исполняет ровно то, что прислал мастер.
            _lic = extgate.state()
            self._send(*_json({
                "ok": True,
                "addons": _lic.get("addons") or [],
                "addons_detail": _lic.get("addons_detail") or [],
                "addon_effects": _lic.get("addon_effects") or {},
                "addon_effects_legend": _lic.get("addon_effects_legend") or {},
                "unknown": _lic.get("addon_unknown") or [],
                "effects": effects.status(),
                "routes": effects.routes(),
                "route_actions": list(effects.ROUTE_ACTIONS),
                "cap": pool._cap(),
                "mesh_entitlements": _lic.get("mesh_entitlements") or [],
            }))
            return
        self._send(*_json({"error": "unknown endpoint"}, 404))
        return

    def do_POST(self):
        if not _host_ok(self):
            self._send(*_json({"error": "host not allowed"}, 421))
            return
        if not _transport_ok(self):
            self._send(*_json({"error": "https required"}, 403))
            return
        try:
            self._do_post()
        except Exception as e:
            import traceback
            traceback.print_exc()
            config.log("api: %s failed: %s" % (self.path.split("?", 1)[0], e))
            self._send(*_json({"error": "internal"}, 500))

    def _do_post(self):
        # приём политики — публичный и без прочих auth-гейтов
        path = self.path.split("?", 1)[0]
        if not _origin_ok(self):
            self._send(*_json({"error": "cross-origin blocked"}, 403))
            return
        if path == "/api/setup/complete":
            setup_data, body_error = _read_json_body(self)
            if body_error:
                self._send(*_json({"error": body_error}, 400))
                return
            self._setup_complete(setup_data or {})
            return
        if path == "/api/setup/warp_test":
            test_data, body_error = _read_json_body(self)
            if body_error:
                self._send(*_json({"error": body_error}, 400))
                return
            self._setup_warp_test(test_data or {})
            return
        if not _admin_ok(self):
            self._send(*_json({"error": "unauthorized"}, 401))
            return
        if not _twofa_ok(self):
            self._send(*_json({"error": "2fa required"}, 401))
            return
        if not _access_allowed(self):
            self._send(*_json({"error": "outside lan"}, 403))
            return
        path = self.path.split("?", 1)[0]

        # A-1040: импорт архива — тело больше обычного (base64 ZIP до 8 МБ).
        if path == "/api/backup/import":
            data, body_error = _read_json_body(
                self, max_bytes=backup.MAX_ARCHIVE_BYTES * 2 + 65536)
        else:
            data, body_error = _read_json_body(self)
        if body_error:
            self._send(*_json({"ok": False, "error": body_error}, 400))
            return

        if path == "/api/backup/import":
            self._backup_import(data or {})
            return


        handler = {
            "/api/vpn_mode": self._vpn_mode,
            "/api/rotate": self._rotate,
            "/api/warp/upload": self._warp_upload,
            "/api/warp/mode": self._warp_mode,
            "/api/warp/probe": self._warp_probe,
            # A-WARP-M: obrabotchiki spiska - inache 404
            "/api/warp/select": self._warp_select,
            "/api/warp/remove": self._warp_remove,
            "/api/warp/clear": self._warp_clear,
            "/api/masque/upload": self._masque_upload,
            "/api/masque/select": self._masque_select,
            "/api/masque/remove": self._masque_remove,
            "/api/masque/clear": self._masque_clear,
            "/api/masque/apply": self._masque_apply,
            "/api/masque/probe": self._masque_probe,
            "/api/masque/fetch": self._masque_fetch,
            # A-MASQUE-CREATE: sozdat konfig LOKALNO (bez sayta-generatora).
            "/api/masque/create": self._masque_create,
            "/api/masque/enable": self._masque_enable,
            "/api/keys/add": self._keys_add,
            "/api/keys/refresh": self._keys_refresh,
            "/api/keys/check": self._keys_check,
            "/api/keys/cleanup": self._keys_cleanup,
            "/api/keys/remove": self._keys_remove,
            "/api/keys/active": self._keys_active,
            # A-1040 «Кот-смотритель»: обслуживание канала и данных.
            "/api/diag/run": self._diag_run,
            "/api/speed/run": self._speed_run,
            "/api/autocheck/save": self._autocheck_save,
            "/api/autocheck/run": self._autocheck_run,
            # A-120/A-121/A-123 «Кот-диспетчер»: диспетчер, уведомления, плановый бэкап.
            "/api/failover/save": self._failover_save,
            "/api/failover/run": self._failover_run,
            "/api/notify/save": self._notify_save,
            "/api/notify/test": self._notify_test,
            "/api/autobackup/save": self._autobackup_save,
            "/api/autobackup/run": self._autobackup_run,
            "/api/autobackup/download": self._autobackup_download,
            "/api/backup/export": self._backup_export,
            "/api/recovery/limit": self._rc_limit,
            "/api/recovery/region": self._rc_region,
            "/api/recovery/conn": self._rc_conn,
            "/api/tgws/restart": self._tgws_restart,
            "/api/tgws/enable": self._tgws_enable,
            "/api/vless/enable": self._vless_enable,
            "/api/rusegment/check": self._rusegment_check,
            "/api/rusegment/region": self._rusegment_region,
            "/api/security/rotate": self._security_rotate,
            "/api/security/password": self._security_password,
            "/api/security/twofa": self._security_twofa,
            "/api/whitelist": self._whitelist_set,
            "/api/security/vless/rotate": self._security_vless_rotate,
            "/api/security/sid": self._security_sid,
            "/api/security/access": self._security_access,
            "/api/update/check": self._update_check,
            "/api/update/apply": self._update_apply,
            "/api/settings/save": self._settings_save,
            "/api/setup/complete": self._setup_complete,
            "/api/settings/reset": self._settings_reset,
            "/api/mesh/ping": self._mesh_ping,
        "/api/mesh/signal": self._mesh_signal_post,
            "/api/game/optin": self._game_optin_post,
            "/api/game/scenario": self._game_scenario_post,
            "/api/game/server": self._game_server_post,
            "/api/mesh/invite": self._mesh_invite,
            "/api/mesh/regenerate": self._mesh_regenerate,
            "/api/mesh/node/remove": self._mesh_node_remove,
            "/api/mesh/join": self._mesh_join,
            # Свои правила маршрутизации сохраняются и применяются всегда.
            "/api/routes/custom/save": self._routes_custom_save_raw,
        }.get(path)
        if handler:
            handler(data)
        else:
            self._send(*_json({"error": "unknown endpoint"}, 404))

    # --- POST handlers ---
    def _vpn_mode(self, data):
        on = _as_bool(data.get("on"))
        core.request_mode(on)
        resp = {"ok": True, "vpn_mode": on,
                "msg": "vpn on" if on else "прямой режим"}
        self._send(*_json(resp))

    def _rotate(self, data):
        failover.hold()  # A-120: ручной выбор канала ставит диспетчер на паузу
        if data.get("tag"):
            ok, msg = core.set_active_tag(data.get("tag", ""))
        else:
            tag = core.rotate()
            ok = tag is not None
            msg = "rotated" if ok else "нет живого ключа"
        self._send(*_json({"ok": ok, "msg": msg}))

    def _keys_add(self, data):
        uri = str(data.get("uri", "") or "").strip()
        if not uri:
            self._send(*_json({"ok": False, "error": "empty uri"}, 400))
            return
        key = source._key_from_uri(uri)
        if not key:
            self._send(*_json({"ok": False, "error": "invalid vless uri"}, 400))
            return
        key["source"] = "my"
        r = pool.add_key(key, force=True)
        if r == "added":
            if config.get("vpn_mode", True):
                threading.Thread(target=core.sync, daemon=True).start()
            msg = "ключ добавлен"
        elif r == "exists":
            msg = "ключ уже есть"
        else:
            reason = {"limit": "лимит ключей"}.get(r, "ошибка добавления")
            self._send(*_json({"ok": False, "error": reason}, 400))
            return
        self._send(*_json({"ok": True, "added": r == "added", "msg": msg}))

    def _keys_refresh(self, data):
        # фоново: загрузка списка может занять десятки секунд — не блокируем HTTP-поток
        def _bg():
            n = source.refresh_from_github()
            # после загрузки новых github-ключей — поднять/обновить канал
            if n and config.get("vpn_mode", True):
                threading.Thread(target=core.sync, daemon=True).start()
        threading.Thread(target=_bg, daemon=True).start()
        self._send(*_json({"ok": True, "msg": "refresh started"}))

    def _keys_check(self, data):
        r = source.check_all(bg=True)
        if not r.get("ok"):
            self._send(*_json({"ok": False, "error": r.get("msg", "проверка уже идёт")}, 400))
            return
        self._send(*_json(r))

    # --- A-1040 «Кот-смотритель»: обслуживание ------------------------------
    def _diag_run(self, data):
        self._send(*_json(diag.start()))

    def _speed_run(self, data):
        self._send(*_json(diag.speed_start()))

    def _autocheck_save(self, data):
        values = {}
        enabled = data.get("enabled")
        if type(enabled) is not bool:
            self._send(*_json({"ok": False, "error": "enabled must be boolean"}, 400))
            return
        values["keycheck_enabled"] = enabled
        interval = data.get("interval_min", config.get("keycheck_interval_min", 60))
        # меньше 15 минут не пускаем: частая проверка — это шум и нагрузка
        if type(interval) is not int or interval < 15 or interval > 10080:
            self._send(*_json({"ok": False, "error": "interval is out of range"}, 400))
            return
        values["keycheck_interval_min"] = interval
        if not config.set_many(values):
            self._send(*_json({"ok": False, "error": "settings save failed"}, 500))
            return
        self._send(*_json({"ok": True, "autocheck": autocheck.status()}))

    def _autocheck_run(self, data):
        self._send(*_json(autocheck.run_now()))

    # --- A-120/A-121/A-123 «Кот-диспетчер» ---
    def _failover_save(self, data):
        values = {}
        enabled = data.get("enabled")
        if type(enabled) is not bool:
            self._send(*_json({"ok": False, "error": "enabled must be boolean"}, 400))
            return
        values["failover_enabled"] = enabled
        interval = data.get("interval_s", config.get("failover_interval_s", 60))
        if type(interval) is not int or interval < 30 or interval > 3600:
            self._send(*_json({"ok": False, "error": "interval is out of range"}, 400))
            return
        values["failover_interval_s"] = interval
        if not config.set_many(values):
            self._send(*_json({"ok": False, "error": "settings save failed"}, 500))
            return
        self._send(*_json({"ok": True, "failover": failover.status()}))

    def _failover_run(self, data):
        self._send(*_json(failover.run_now()))

    def _notify_save(self, data):
        values = {}
        enabled = data.get("enabled")
        if type(enabled) is not bool:
            self._send(*_json({"ok": False, "error": "enabled must be boolean"}, 400))
            return
        values["notify_enabled"] = enabled
        for key in ("token", "chat"):
            if key in data:
                value = data[key]
                if not isinstance(value, str) or len(value) > 256:
                    self._send(*_json({"ok": False, "error": "%s is invalid" % key}, 400))
                    return
                values["notify_tg_" + key] = value.strip()
        if not config.set_many(values):
            self._send(*_json({"ok": False, "error": "settings save failed"}, 500))
            return
        # Токен в ответ не возвращаем — только факт настройки.
        self._send(*_json({"ok": True, "notify": notify.status()}))

    def _notify_test(self, data):
        self._send(*_json(notify.test()))

    def _autobackup_save(self, data):
        values = {}
        enabled = data.get("enabled")
        if type(enabled) is not bool:
            self._send(*_json({"ok": False, "error": "enabled must be boolean"}, 400))
            return
        values["backup_schedule_enabled"] = enabled
        interval = data.get("interval_h", config.get("backup_interval_h", 24))
        if type(interval) is not int or interval < 1 or interval > 168:
            self._send(*_json({"ok": False, "error": "interval_h is out of range"}, 400))
            return
        values["backup_interval_h"] = interval
        keep = data.get("keep", config.get("backup_keep", 7))
        if type(keep) is not int or keep < 1 or keep > 60:
            self._send(*_json({"ok": False, "error": "keep is out of range"}, 400))
            return
        values["backup_keep"] = keep
        if "password" in data:
            password = data["password"]
            if not isinstance(password, str) or len(password) > 256:
                self._send(*_json({"ok": False, "error": "password is invalid"}, 400))
                return
            if password and len(password) < backup.MIN_PASSWORD_LEN:
                self._send(*_json({"ok": False, "error": "пароль минимум 8 символов"}, 400))
                return
            values["backup_password"] = password
        if not config.set_many(values):
            self._send(*_json({"ok": False, "error": "settings save failed"}, 500))
            return
        self._send(*_json({"ok": True, "autobackup": autobackup.status()}))

    def _autobackup_run(self, data):
        self._send(*_json(autobackup.run_now()))

    def _autobackup_download(self, data):
        name = str(data.get("name") or "")
        blob = autobackup.read_file(name)
        if blob is None:
            self._send(*_json({"ok": False, "error": "архив не найден"}, 404))
            return
        self._send_binary(200, "application/zip", blob, name)

    def _backup_export(self, data):
        password = data.get("password")
        try:
            blob, name = backup.export(password)
        except (backup.BackupError, crypt.BackupPasswordError, ValueError) as e:
            self._send(*_json({"ok": False, "error": str(e)[:200]}, 400))
            return
        config.log("backup: архив создан (%d байт)" % len(blob))
        self._send_binary(200, "application/zip", blob, name)

    def _backup_import(self, data):
        password = data.get("password")
        encoded = data.get("data")
        if not isinstance(encoded, str) or not encoded:
            self._send(*_json({"ok": False, "error": "нет файла архива"}, 400))
            return
        import base64
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError):
            self._send(*_json({"ok": False, "error": "файл архива не читается"}, 400))
            return
        try:
            report = backup.restore(raw, password)
        except backup.BackupError as e:
            self._send(*_json({"ok": False, "error": str(e)[:200]}, 400))
            return
        self._send(*_json(report))

    # --- A-MASQUE-PUB: rezerv WARP cherez mihomo (MASQUE) ---
    def _masque_upload(self, data):
        raw = data.get("config") or data.get("raw") or ""
        if not isinstance(raw, str) or not raw.strip():
            self._send(*_json({"ok": False, "error": "no config"}, 400))
            return
        if len(raw.encode("utf-8", "ignore")) > masque.MAX_CONFIG_BYTES:
            self._send(*_json({"ok": False, "error": "config too large"}, 400))
            return
        name = data.get("name") if isinstance(data.get("name"), str) else ""
        r = masque.install(raw, name)
        config.log("masque: A-MASQUE konfig zagruzhen ok=%s name=%s"
                   % (bool(r.get("ok")), str(r.get("name", ""))[:40]))
        if not r.get("ok"):
            self._send(*_json(r, 400))
            return
        st = masque.status()
        st["ok"] = True
        self._send(*_json(st))

    def _masque_select(self, data):
        failover.hold()  # A-120: ручной выбор канала ставит диспетчер на паузу
        name = data.get("name") if isinstance(data.get("name"), str) else ""
        res = masque.select(name)
        config.log("masque: vybor name=%s ok=%s" % (name[:40], bool(res.get("ok"))))
        if not res.get("ok"):
            self._send(*_json(res, 400))
            return
        st = masque.status()
        st["ok"] = True
        self._send(*_json(st))

    def _masque_remove(self, data):
        name = data.get("name") if isinstance(data.get("name"), str) else ""
        res = masque.remove(name)
        if not res.get("ok"):
            self._send(*_json(res, 400))
            return
        st = masque.status()
        st["ok"] = True
        self._send(*_json(st))

    def _masque_clear(self, data):
        r = masque.clear()
        st = masque.status()
        st["ok"] = bool(r.get("ok"))
        self._send(*_json(st))

    def _masque_apply(self, data):
        failover.hold()  # A-120: ручное применение конфига — пауза диспетчера
        res = masque.apply()
        st = masque.status()
        st.update(res)
        self._send(*_json(st))

    def _masque_probe(self, data):
        if _MASQUE_PROBE["running"]:
            self._send(*_json({"ok": True, "started": True,
                               "msg": "proba MASQUE uzhe idet"}))
            return
        pname = data.get("name") if isinstance(data.get("name"), str) else ""
        _MASQUE_PROBE["running"] = True

        def _run():
            try:
                r = masque.probe(30, pname)
                config.log("masque: proba: %s" % (r.get("egress") or r.get("error")))
            except Exception as exc:
                config.log("masque: proba ne udalas: %s" % str(exc)[:120])
            finally:
                _MASQUE_PROBE["running"] = False
        threading.Thread(target=_run, daemon=True).start()
        self._send(*_json({"ok": True, "started": True,
                           "msg": "proba MASQUE zapuschena, rezultat cherez ~20 s"}))

    def _masque_fetch(self, data):
        """A-MASQUE-FIX: sam sozdat konfig na sayte i primenit k mihomo."""
        res = masque.fetch_apply()
        config.log("api: A-MASQUE avto-sozdanie ok=%s %s"
                   % (res.get("ok"), res.get("name") or res.get("error")))
        out = masque.status()
        out.update(res)
        self._send(*_json(out))

    def _masque_create(self, data):
        """A-MASQUE-CREATE: sozdat MASQUE-konfig localno i podnyat kanal."""
        name = data.get("name") if isinstance(data.get("name"), str) else ""
        try:
            res = masque.create_apply(name)
        except Exception as exc:
            config.log("api: A-MASQUE-CREATE isklyuchenie: %s" % str(exc)[:120])
            res = {"ok": False, "error": "create failed: %s" % str(exc)[:80]}
        config.log("api: A-MASQUE-CREATE ok=%s %s"
                   % (res.get("ok"), res.get("name") or res.get("error")))
        out = masque.status()
        out.update(res)
        self._send(*_json(out))

    # A-118: vyklyuchatel vneshnego kanala (MASQUE/mihomo) iz paneli.
    def _masque_enable(self, data):
        value = data.get("enabled")
        if type(value) is not bool:
            self._send(*_json({"ok": False, "error": "enabled must be boolean"}, 400))
            return
        try:
            st = masque.set_enabled(value)
        except Exception as exc:
            config.log("masque: enable failed: %s" % type(exc).__name__)
            self._send(*_json({"ok": False, "error": "toggle failed"}, 500))
            return
        config.log("masque: external channel enabled=%s" % value)
        self._send(*_json(st))

    def _keys_cleanup(self, data):
        removed = pool.cleanup()
        if removed:
            threading.Thread(target=_sync_after_pool_change, daemon=True).start()
        self._send(*_json({"ok": True, "removed": removed}))

    def _keys_remove(self, data):
        uri = data.get("uri", "")
        if not uri:
            self._send(*_json({"ok": False, "error": "no uri"}, 400))
            return
        removed = pool.remove_key(uri)
        if removed and pool.dead_reason(uri) is None:
            pool.dead_add(uri, "user_removed")
        if removed:
            threading.Thread(target=_sync_after_pool_change, daemon=True).start()
        self._send(*_json({"ok": removed}))

    def _keys_active(self, data):
        failover.hold()  # A-120: ручной выбор канала ставит диспетчер на паузу
        tag = data.get("tag", "")
        ok, msg = core.set_active_tag(tag)
        # A-949: prichina otkaza dolzhna byt v zhurnale, a ne tolko v toste
        # na 2.5 s - inache "kanal ne pereklyuchen" nevozmozhno diagnostirovat.
        config.log("api: keys/active tag=%s ok=%s msg=%s" % (tag, ok, msg))
        self._send(*_json({"ok": ok, "msg": msg}))

    def _rc_limit(self, data):
        self._send(*_json(recovery.run_limit(data.get("ip", ""))))

    def _rc_region(self, data):
        self._send(*_json(recovery.run_region(data.get("reason", ""))))

    def _rc_conn(self, data):
        self._send(*_json(recovery.run_conn(data.get("host", ""), data.get("port", 0))))

    def _tgws_restart(self, data):
        ok = tgws.restart()
        tgws.refresh_status()
        self._send(*_json({"ok": ok}))

    # A-118: vyklyuchatel TG-WS-proksi iz paneli.
    def _tgws_enable(self, data):
        value = data.get("enabled")
        if type(value) is not bool:
            self._send(*_json({"ok": False, "error": "enabled must be boolean"}, 400))
            return
        try:
            st = tgws.set_enabled(value)
        except Exception as exc:
            config.log("tgws: enable failed: %s" % type(exc).__name__)
            self._send(*_json({"ok": False, "error": "toggle failed"}, 500))
            return
        config.log("tgws: enabled=%s" % value)
        self._send(*_json(st))

    # A-118: vyklyuchatel vneshnego VLESS-Reality inbound :8443.
    def _vless_enable(self, data):
        value = data.get("enabled")
        if type(value) is not bool:
            self._send(*_json({"ok": False, "error": "enabled must be boolean"}, 400))
            return
        if not config.vless_public().get("configured"):
            self._send(*_json({"ok": False, "error": "внешний VLESS не настроен"}, 400))
            return
        if not config.set("vless_enabled", value):
            self._send(*_json({"ok": False, "error": "settings save failed"}, 500))
            return
        config.save_settings()
        config.log("vless: external inbound enabled=%s" % value)
        # xray пересоберётся в фоне: inbound vless-in появится/исчезнет.
        threading.Thread(target=core.sync, daemon=True).start()
        self._send(*_json({"ok": True, "enabled": value,
                           "msg": "внешний VLESS переключается, xray пересобирается"}))

    def _rusegment_check(self, data):
        started = rusegment.check_all()
        self._send(*_json({"ok": True, "started": started}))


        regions = data.get("regions") or []
        if isinstance(regions, list):
            regions = [str(r).strip() for r in regions if str(r).strip() in config.REGIONS]
        else:
            regions = []
        if not regions:
            regions = ["ru"]
        title = str(data.get("title") or "")[:80]
        custom = str(data.get("custom") or "")[:4000]
        config.set("segment_regions", regions)
        config.set("segment_title", title or "")
        config.set("segment_custom", custom or "")
        config.save_settings()
        threading.Thread(target=rusegment.check_all, daemon=True).start()
        self._send(*_json({"ok": True, "title": config.segment_title(),
                           "flag": config.segment_flag()}))

    def _security_rotate(self, data):
        # admin-токен панели (Bearer): чистая ротация, хранение data/admin_secret.json
        token = security.rotate()
        self._send(*_json({"ok": bool(token), "token": token}))

    def _setup_warp_test(self, data):
        """A-MASQUE-PUB: proverit' vybrannyj transport WARP pri ustanovke.

        A-MASQUE-FIX: ran'she proveryalsya TOL'KO aktivnyy konfig odnoy
        probey - esli on mertv, master vsegda pisal "no egress" i ne
        perekllyuchal konfigy. Teper': WireGuard - probe VSEH konfigov
        (pobeditel' stanovitsya aktivnym), MASQUE - probe + pereklyuchenie
        endpontoov na teh zhe klyuchah.
        """
        local = _is_local(self)
        if not local and not _host_in_lan(self.client_address[0]):
            _setup_reject(self, "setup requires localhost", 403)
            return
        if config.get("setup_complete", False):
            _setup_reject(self, "setup already complete", 409)
            return
        tr = str(data.get("transport") or "").strip().lower()
        if tr not in ("wireguard", "masque"):
            self._send(*_json({"ok": False, "error": "bad transport"}, 400))
            return
        if tr == "masque":
            r = masque.fetch_default()
            if not r.get("ok"):
                self._send(*_json({"ok": False, "transport": tr,
                                   "error": r.get("error", "masque fetch failed")}, 200))
                return
            key = str(r.get("name") or "")
            res = masque.probe(30, key)
            # A-MASQUE-EP: konfig s generatora mog popast' na mertvyj
            # endponto - probe vremennyy, mihomo-service ne trogaem.
            if not res.get("ok") and not res.get("busy"):
                m = (masque._read_store()["items"].get(key) or {}).get("masque") or {}
                cur = str(m.get("server") or "")
                for ip, port in masque.MASQUE_ENDPOINTS:
                    if ip == cur:
                        continue
                    if not masque.set_endpoint(key, ip, port):
                        break
                    res = masque.probe(30, key)
                    if res.get("ok"):
                        break
            out = {"ok": bool(res.get("ok")), "transport": tr,
                   "name": key, "egress": res.get("egress", "-")}
            if not res.get("ok"):
                out["error"] = res.get("error", "no egress")
            self._send(*_json(out))
            return
        st = warp.status()
        names = [str(c.get("name") or "") for c in (st.get("configs") or [])]
        names = [n for n in names if n]
        if not names and not warp.load():
            self._send(*_json({"ok": False, "transport": tr,
                               "error": "нет WARP-конфига (загрузите на вкладке WARP)"}, 200))
            return
        if _WARP_PROBE["running"]:
            self._send(*_json({"ok": False, "transport": tr,
                               "error": "проба WARP уже идёт — повторите через минуту"}, 200))
            return
        _WARP_PROBE["running"] = True
        try:
            # aktivnyy - pervym, ostal'nye - po poryadku spiska
            # (ne bolee 5: proverka kazhdogo - do 12 s, browser zhdet)
            active = str(st.get("name") or "")
            order = ([active] if active in names else []) + \
                [n for n in names if n != active]
            order = order[:5]
            if not order:
                order = [""]
            res = {"ok": False, "error": "no egress"}
            picked = ""
            for name in order:
                res = warp.probe(name=name)
                if res.get("ok"):
                    picked = name
                    break
                if str(res.get("error") or "") == "port-busy":
                    break
            # A-MASQUE-FIX: rabochiy konfig delaem aktivnym, chtoby
            # zavershennyy master razvernul imenno ego.
            if picked and active and picked != active and not config.get(
                    "setup_complete", False):
                warp.select(picked)
                config.log("api: setup warp test: vybran rabochiy konfig %s"
                           % picked[:40])
            out = {"ok": bool(res.get("ok")), "transport": tr,
                   "egress": res.get("egress", "-")}
            if picked:
                out["name"] = picked
            if not res.get("ok"):
                out["error"] = res.get("error", "no egress")
            self._send(*_json(out))
        finally:
            _WARP_PROBE["running"] = False

    def _setup_complete(self, data):
        if not isinstance(data, dict):
            data = {}
        local = _is_local(self)
        if not local and not _host_in_lan(self.client_address[0]):
            _setup_reject(self, "setup requires localhost", 403)
            return
        if not local and _instance_claimed() and not config.SETUP_TOKEN:
            config.log("api: setup from LAN on claimed instance (no AURORA_SETUP_TOKEN)")
        if config.get("setup_complete", False):
            _setup_reject(self, "setup already complete", 409)
            return
        if config.SETUP_TOKEN and not _token_matches(data.get("setup_token"), config.SETUP_TOKEN):
            _setup_reject(self, "setup token required", 403)
            return
        name = data.get("server_name")
        password = data.get("password")
        pin = data.get("pin")
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80:
            _setup_reject(self, "invalid server name", 400)
            return
        if not isinstance(password, str):
            _setup_reject(self, "invalid password", 400)
            return
        password = password.strip()
        if not 12 <= len(password) <= 256 or any(
                ch.isspace() or ord(ch) < 32 for ch in password):
            _setup_reject(self, "invalid password", 400)
            return
        if not isinstance(pin, str) or not re.fullmatch(r"[0-9]{6}", pin):
            _setup_reject(self, "invalid pin", 400)
            return
        ports = {}
        for port_key in ("ui_port", "xray_port", "xray_api_port", "tgws_port"):
            port_value = data.get(port_key)
            if port_value is None or port_value == "" or (type(port_value) is int and port_value == 0):
                ports[port_key] = getattr(config, port_key.upper())
            else:
                ports[port_key] = port_value
        if config._validate_ports(ports) is None:
            _setup_reject(self, "invalid ports", 400)
            return
        restart_required = any(ports[key] != getattr(config, key.upper()) for key in ports)
        mesh_joined = False
        transport = data.get("warp_transport")
        if transport not in (None, "", "off", "wireguard", "masque"):
            _setup_reject(self, "invalid warp transport", 400)
            return
        transport = transport or "off"
        values = {
            "server_name": name.strip(),
            "ui_token": password,
            "twofa": True,
            "ui_pin": pin,
            "warp_transport": transport,
        }
        values.update(ports)
        for key in ("lan_only", "block_scanners", "rate_limit"):
            if type(data.get(key)) is not bool:
                _setup_reject(self, "%s must be boolean" % key, 400)
                return
            values[key] = data[key]
        if not config.set_many(values):
            _setup_reject(self, "settings save failed", 500)
            return
        _load_ui_token()
        try:
            if transport == "masque":
                masque.apply()
            elif transport == "wireguard":
                config.set("warp_mode", "on")
        except Exception as exc:
            config.log("api: setup warp deploy failed: %s" % type(exc).__name__)
        self._send(*_json({"ok": True, "mesh_joined": mesh_joined,
                           "restart_required": restart_required,
                           "settings": _settings()["settings"]}))

    def _rusegment_region(self, data):
        regions = data.get("regions") or []
        if isinstance(regions, list):
            regions = [str(r).strip() for r in regions if str(r).strip() in config.REGIONS]
        else:
            regions = []
        if not regions:
            regions = ["ru"]
        title = str(data.get("title") or "").strip()[:80]
        custom = str(data.get("custom") or "").strip()[:4000]
        config.set("segment_regions", regions)
        config.set("segment_title", title)
        config.set("segment_custom", custom)
        config.save_settings()
        threading.Thread(target=rusegment.check_all, daemon=True).start()
        self._send(*_json({"ok": True, "title": config.segment_title(),
                           "flag": config.segment_flag()}))


    def _settings_save(self, data):
        values = {}
        for key in ("server_name", "auto_refresh", "mesh_id"):
            if key not in data:
                continue
            value = data[key]
            if key == "auto_refresh":
                if type(value) is not bool:
                    self._send(*_json({"ok": False, "error": "auto_refresh must be boolean"}, 400))
                    return
                values[key] = value
            else:
                if not isinstance(value, str):
                    self._send(*_json({"ok": False, "error": "%s must be a string" % key}, 400))
                    return
                values[key] = value.strip()
        if not config.set_many(values):
            self._send(*_json({"ok": False, "error": "settings save failed"}, 500))
            return
        self._send(*_json({"ok": True, "settings": _settings()["settings"]}))


    def _security_password(self, data):
        value = data.get("password", "")
        if not isinstance(value, str):
            self._send(*_json({"ok": False, "error": "password must be a string"}, 400))
            return
        pw = value.strip()
        if pw and (not 12 <= len(pw) <= 256
                   or any(ch.isspace() or ord(ch) < 32 for ch in pw)):
            self._send(*_json({"ok": False, "error": "invalid password"}, 400))
            return
        if not config.set_many({"ui_token": pw}):
            self._send(*_json({"ok": False, "error": "settings save failed"}, 500))
            return
        _load_ui_token()
        self._send(*_json({"ok": True, "token_set": bool(pw)}))

    def _security_twofa(self, data):
        value = data.get("pin", "")
        if not isinstance(value, str):
            self._send(*_json({"ok": False, "error": "pin must be a string"}, 400))
            return
        pin = value.strip()
        if pin and (len(pin) != 6 or not pin.isascii() or not pin.isdigit()):
            self._send(*_json({"ok": False, "error": "invalid pin"}, 400))
            return
        if not config.set_many({"twofa": bool(pin), "ui_pin": pin}):
            self._send(*_json({"ok": False, "error": "settings save failed"}, 500))
            return
        msg = "2FA включена" if pin else "2FA выключена"
        self._send(*_json({"ok": True, "msg": msg, "twofa": config.get("twofa")}))

    def _security_vless_rotate(self, data):
        # ротация Reality-ключей (uuid/private/public/short_id) через xray x25519.
        # Публичная сборка держит VLESS в env (AURORA_VLESS_*), механизма хранения
        # data/vless_secret.json здесь нет — честный отказ без падения.
        if not hasattr(config, "_load_vless_secret"):
            self._send(*_json({"ok": False,
                               "error": "механизм хранения Reality-секретов недоступен "
                                        "(VLESS из env AURORA_VLESS_*)"}, 400))
            return
        import re as _re
        import secrets
        import subprocess
        import uuid as _uuid
        bin_path = core._xray_bin()
        priv = pub = None
        if bin_path and os.path.exists(bin_path):
            try:
                out = subprocess.check_output([bin_path, "x25519"], timeout=10).decode("utf-8", "replace")
                m1 = _re.search(r"Private key:\s*([A-Za-z0-9+/=]+)", out)
                m2 = _re.search(r"Public key:\s*([A-Za-z0-9+/=]+)", out)
                if m1 and m2:
                    priv, pub = m1.group(1), m2.group(1)
            except Exception as e:
                config.log("sec: ротация x25519 не удалась: %s" % e)
        if not priv or not pub:
            self._send(*_json({"ok": False, "error": "xray x25519 недоступен"}, 500))
            return
        sec = {
            "uuid": str(_uuid.uuid4()),
            "private_key": priv,
            "public_key": pub,
            "short_id": secrets.token_hex(4),
        }
        path = os.path.join(config.DATA_DIR, "vless_secret.json")
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(sec, f, indent=2)
        except OSError as e:
            self._send(*_json({"ok": False, "error": str(e)}, 500))
            return
        config._load_vless_secret()
        if config.get("vpn_mode", True):
            threading.Thread(target=core.sync, daemon=True).start()
        config.log("sec: ключи VLESS ротированы (uuid/shortId новые)")
        self._send(*_json({"ok": True, "msg": "Reality-ключи ротированы, xray перезапускается"}))

    def _security_sid(self, data):
        sid = str(data.get("sid") or "").strip()
        if not sid:
            self._send(*_json({"ok": False, "error": "no sid"}, 400))
            return
        if not hasattr(config, "_load_vless_secret"):
            self._send(*_json({"ok": False,
                               "error": "механизм хранения Reality-секретов недоступен"}, 400))
            return
        path = os.path.join(config.DATA_DIR, "vless_secret.json")
        try:
            with open(path, "r", encoding="utf-8") as f:
                sec = json.load(f)
        except (OSError, ValueError):
            sec = {}
        sec["short_id"] = sid
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(sec, f, indent=2)
        except OSError as e:
            self._send(*_json({"ok": False, "error": str(e)}, 500))
            return
        config._load_vless_secret()
        if config.get("vpn_mode", True):
            threading.Thread(target=core.sync, daemon=True).start()

    def _whitelist_get(self, data=None):
        self._send(*_json({"ok": True,
                           "white_ip": config.get_white_ip(),
                           "bypass_domains": config.get_bypass_domains()}))

    def _whitelist_set(self, data):
        try:
            config.set_white_ip((data.get("white_ip") or "").strip())
            config.set_bypass_domains([str(x).strip() for x in (data.get("bypass_domains") or []) if str(x).strip()])
            threading.Thread(target=core.sync, daemon=True).start()
            self._send(*_json({"ok": True, "msg": "whitelist saved, xray reloading"}))
        except Exception as e:
            self._send(*_json({"ok": False, "error": str(e)}))

    def _security_access(self, data):
        for key in ("lan_only", "block_scanners", "rate_limit"):
            if key in data:
                config.set(key, _as_bool(data[key]))
        self._send(*_json({"ok": True, "access": _sec()["access"]}))

    def _update_check(self, data):
        r = updater.check()
        self._send(*_json(r))

    def _update_apply(self, data):
        r = updater.apply()
        self._send(*_json(r))
        if r.get("ok") and r.get("restart_required"):
            threading.Timer(0.8, os._exit, args=(0,)).start()


        values = {}
        for key in ("server_name", "auto_refresh", "mesh_id"):
            if key not in data:
                continue
            value = data[key]
            if key == "auto_refresh":
                if type(value) is not bool:
                    self._send(*_json({"ok": False, "error": "auto_refresh must be boolean"}, 400))
                    return
                values[key] = value
            else:
                if not isinstance(value, str):
                    self._send(*_json({"ok": False, "error": "%s must be a string" % key}, 400))
                    return
                values[key] = value.strip()
        if not config.set_many(values):
            self._send(*_json({"ok": False, "error": "settings save failed"}, 500))
            return
        self._send(*_json({"ok": True, "settings": _settings()["settings"]}))

    def _settings_reset(self, data):
        if not config.reset_settings():
            self._send(*_json({"ok": False, "error": "settings save failed"}, 500))
            return
        _load_ui_token()
        self._send(*_json({"ok": True, "msg": "настройки сброшены"}))

    def _mesh_ping(self, data):
        # A-427: ping is what the "ping" button calls, and the panel repaints
        # the white IP from THIS answer. Without the field a ping wiped it.
        self._send(*_json({"ok": True, "white_ip": config.WHITE_IP,
                           "nodes": [_alive_via_tunnel(_node_alive(n))
                                     for n in (mesh.ping_all() or [])],
                           "tunnel": _tunnel_status()}))

    def _mesh_invite(self, data):
        invite = mesh.invite()
        if not invite:
            self._send(*_json({"ok": False, "error": "invite unavailable"}, 503))
            return
        self._send(*_json({"ok": True, "invite": invite}))

    def _mesh_regenerate(self, data):
        invite = mesh.regenerate()
        if not invite:
            self._send(*_json({"ok": False, "error": "invite unavailable"}, 503))
            return
        self._send(*_json({"ok": True, "invite": invite}))

    def _mesh_signal_auth(self):
        # A-557: узловой токен меша, НЕ админский: клиенту
        # входа в меш не нужен доступ к панели.
        token = str(config.get("mesh_token") or "").strip()
        if not token:
            return False
        return _token_matches(self.headers.get("X-Auth"), token)

    def _mesh_signal_post(self, data):
        # A-557: offer/answer/candidate от одного узла к другому.
        if not self._mesh_signal_auth():
            self._send(*_json({"ok": False, "error": "mesh token required"}, 403))
            return
        code, err, info = meshsignal.put(str(config.get("mesh_id") or ""),
                                          data.get("to"), data.get("group"),
                                          data.get("kind"), data.get("payload"))
        self._send(*_json({"ok": err is None, "error": err, "result": info}, code))

    def _mesh_signal_get(self):
        # A-557: забор сигналов адресованным узлу; одноразовое забирание.
        if not self._mesh_signal_auth():
            self._send(*_json({"ok": False, "error": "mesh token required"}, 403))
            return
        qs = urllib.parse.parse_qs(self.path.split("?", 1)[-1]) or {}
        code, err, body = meshsignal.take(str(config.get("mesh_id") or ""),
                                          (qs.get("group") or [""])[0],
                                          (qs.get("peer") or [""])[0],
                                          (qs.get("limit") or ["32"])[0])
        self._send(*_json({"ok": err is None, "error": err, "result": body}, code))

    def _mesh_join(self, data):
        invite = str(data.get("invite") or "").strip()
        if len(invite) > 4096:
            self._send(*_json({"ok": False, "error": "неверный invite"}, 400))
            return
        name = str(data.get("name") or "").strip()
        region = str(data.get("region") or "").strip()
        # A-265: invitation from own subnet (signed with local key).
        # A proof in the body means OUR invite, not the master one.
        if str(data.get("proof") or "").strip():
            node, err = mesh.join(data)
            if not node:
                self._send(*_json({"ok": False, "error": err or "join failed"}, 400))
                return
            self._send(*_json({"ok": True, "node": node}))
            return
        self._send(*_json({"ok": False,
                           "error": "нужен invite своей сети (proof)"}, 400))

    def _routes_custom_save_raw(self, data):
        """Свои правила маршрутизации сохраняются и применяются всегда."""
        rows = data.get("routes")
        if not isinstance(rows, list) or len(rows) > 400:
            self._send(*_json({"ok": False, "error": "routes must be a list (<=400)"}, 400))
            return
        if not effects.set_custom_routes(rows):
            self._send(*_json({"ok": False, "error": "save failed"}, 500))
            return
        try:
            core.sync()
        except Exception as e:
            config.log("routes: saved, xray sync failed: %s" % e)
        self._send(*_json({"ok": True, "routes": effects.routes(),
                           "applied": True}))

    def _mesh_node_remove(self, data):
        nid = str(data.get("id") or "").strip()
        if not nid or not mesh.remove(nid):
            self._send(*_json({"ok": False, "error": "node not found"}, 400))
            return
        self._send(*_json({"ok": True}))

    def _game_optin_post(self, data):
        """A-827 (Ш8): поставить/снять галку узла. Только владелец."""
        nid = str(data.get("id") or "").strip()
        flags = data.get("optins")
        if not isinstance(flags, dict):
            self._send(*_json({"ok": False, "error": "optins must be an object"}, 400))
            return
        ok, err = mesh.set_optin(nid, **flags)
        if not ok:
            self._send(*_json({"ok": False, "error": err}, 400))
            return
        config.log("game: galki uzla %s = %s" % (nid, mesh.optins(nid)))
        self._send(*_json({"ok": True, "id": nid, "optins": mesh.optins(nid)}))


    def _game_scenario_post(self, data):
        """A-827 (Ш4): выбрать сценарий на старте."""
        # A-827-fix: meshtunnel импортируется ЛЕНИВО (см. _tunnel_module).
        # Обращение к имени как к модулю давало NameError -> 500 internal,
        # поймано сквозной проверкой клиента против настоящей панели.
        mt = _tunnel_module()
        if mt is None:
            self._send(*_json({"ok": False, "error": "module_unavailable"}, 503))
            return
        ok, err = mt.game_scenario_set(data.get("scenario"))
        if not ok:
            self._send(*_json({"ok": False, "error": err}, 400))
            return
        self._send(*_json({"ok": True, "scenario": mt.game_scenario_state()}))


    def _warp_upload(self, data):
        """Konfig ot vlaseltsa (generator -> panel)."""
        raw = data.get("config") or data.get("raw") or ""
        if not isinstance(raw, str) or not raw.strip():
            self._send(*_json({"ok": False, "error": "no config"}, 400))
            return
        if len(raw.encode("utf-8", "ignore")) > warp.MAX_CONFIG_BYTES:
            self._send(*_json({"ok": False, "error": "config too large"}, 400))
            return
        # A-WARP-M: vlaselets zadayet IMYA konfiga (spisok, ne odin rezerv)
        name = data.get("name") if isinstance(data.get("name"), str) else ""
        r = warp.install(raw, name)
        if not r.get("ok"):
            self._send(*_json(r, 400))
            return
        config.log("warp: A-WARP-M konfig zagruzhen name=%s endpoint %s"
                   % (str(r.get("name", ""))[:40], r.get("endpoint", "-")))
        st = warp.status()
        st["ok"] = True
        self._send(*_json(st))

    def _warp_mode(self, data):
        m = str(data.get("mode") or "").strip().lower()
        if m not in warp.MODES:
            self._send(*_json({"ok": False, "error": "bad mode"}, 400))
            return
        failover.hold()  # A-120: ручной режим WARP не оспариваем
        if not config.set("warp_mode", m):
            self._send(*_json({"ok": False, "error": "save failed"}, 400))
            return
        config.log("warp: rezhim = %s" % m)
        st = warp.status()
        st["ok"] = True
        self._send(*_json(st))

    def _warp_probe(self, data):
        """Fakticheskiy vyhod WARP cherez vremennyi xray (fon, ~15 s)."""
        if _WARP_PROBE["running"]:
            self._send(*_json({"ok": True, "started": True,
                               "msg": "proba WARP uzhe idet"}))
            return
        # A-WARP-M: proba mozhet byt odnogo iz spiska, ne tolko aktivnogo
        pname = data.get("name") if isinstance(data.get("name"), str) else ""
        if not warp.load(pname):
            self._send(*_json({"ok": False, "error": "no warp config"}, 400))
            return
        _WARP_PROBE["running"] = True

        def _run():
            try:
                r = warp.probe(name=pname)
                config.log("warp: proba: %s" % (r.get("egress") or r.get("error")))
            except Exception as exc:
                config.log("warp: proba ne udalas: %s" % str(exc)[:120])
            finally:
                _WARP_PROBE["running"] = False
        threading.Thread(target=_run, daemon=True).start()
        self._send(*_json({"ok": True, "started": True,
                           "msg": "proba WARP zapuschena, rezultat cherez ~15 s"}))

    def _warp_select(self, data):
        """A-WARP-M: sdelat vybrannyy konfig aktivnym (rezerv ukazyvaet na nego)."""
        failover.hold()  # A-120: ручной выбор канала ставит диспетчер на паузу
        name = data.get("name") if isinstance(data.get("name"), str) else ""
        res = warp.select(name)
        config.log("api: A-WARP-M vybor konfiga name=%s ok=%s"
                   % (name[:40], bool(res.get("ok"))))
        # A-WARP-M: spisok i kanal - odno. Esli kanal UZHE na WARP, prosto
        # smenit active v store nelzya: xray.json ostalsya so STARYM outbound
        # (teg 'warp' tot zhe), i kanal ne pereklyuchalsya. Pereprimenyaem.
        if res.get("ok"):
            try:
                if core.get_vless_now() == warp.WARP_TAG:
                    ok2, msg2 = core.set_active_tag(warp.WARP_TAG)
                    config.log("api: A-WARP-M vybor: kanal na WARP, pereprimenenie"
                               " ok=%s msg=%s" % (ok2, msg2))
            except Exception as exc:
                config.log("api: A-WARP-M vybor: pereprimenenie ne udalos: %s"
                           % type(exc).__name__)
        st = warp.status()
        st["ok"] = bool(res.get("ok"))
        if not res.get("ok"):
            st["error"] = res.get("error", "select failed")
            self._send(*_json(st, 400))
            return
        self._send(*_json(st))

    def _warp_remove(self, data):
        """A-WARP-M: udalit ODIN konfig, spisok ostaetsya zhivym."""
        name = data.get("name") if isinstance(data.get("name"), str) else ""
        res = warp.remove(name)
        config.log("api: A-WARP-M udalen konfiga name=%s ok=%s"
                   % (name[:40], bool(res.get("ok"))))
        st = warp.status()
        st["ok"] = bool(res.get("ok"))
        if not res.get("ok"):
            st["error"] = res.get("error", "remove failed")
            self._send(*_json(st, 400))
            return
        self._send(*_json(st))

    def _warp_clear(self, data):
        r = warp.clear()
        if not r.get("ok"):
            self._send(*_json(r, 400))
            return
        config.log("warp: konfig udalen")
        st = warp.status()
        st["ok"] = True
        self._send(*_json(st))


    def _game_server_post(self, data):
        """A-827 (Ш7): выбрать или снять игровой сервер группы."""
        # A-827-fix: ленивый импорт, см. _game_scenario_post. Обращение к имени
        # как к модулю давало NameError -> 500 internal.
        mt = _tunnel_module()
        if mt is None:
            self._send(*_json({"ok": False, "error": "module_unavailable"}, 503))
            return
        host = str(data.get("host") or "").strip()
        if not host:
            with mt._LOCK:
                mt._STATE["game_server"] = {}
            self._send(*_json({"ok": True, "server": mt.game_server_state()}))
            return
        ok, err = mt.game_server_set(host)
        if not ok:
            self._send(*_json({"ok": False, "error": err}, 400))
            return
        self._send(*_json({"ok": True, "server": mt.game_server_state()}))


# --- данные для новых вкладок UI (тарифы/статистика/маршруты/настройки/безопасность) ---
# --- данные для новых вкладок UI (тарифы/статистика/маршруты/настройки/безопасность) ---
def _versions_list():
    """История версий для панели: без дублей, с описанием (VERSION_NOTES)."""
    notes = getattr(config, "VERSION_NOTES", {}) or {}
    out = []
    seen = set()
    for item in config.VERSION_HISTORY or ():
        try:
            version, name, date = item[0], item[1], item[2]
        except (TypeError, IndexError):
            continue
        version = str(version or "").strip()
        if not version or version in seen:
            continue
        seen.add(version)
        out.append({"v": version, "name": str(name or version),
                    "date": str(date or ""),
                    "desc": str(notes.get(version, "") or "")})
    return out



    """A-101: живость узла для панели.

    Пингуем порт прокси, а если он не отвечает - порт панели узла
    (в узлах часто указан именно порт панели, а не прокси).
    Возвращает копию узла с полями ok/ping_ms/status/ping_port/reason.
    """
    if not isinstance(node, dict):
        return {"id": "", "name": "-", "region": "", "role": "node",
                "ok": False, "ping_ms": 0, "status": "off", "ping_port": 0,
                "reason": "bad-node"}
    host = str(node.get("host") or "").strip()
    ports = []
    for key in ("port", "policy_port"):
        try:
            port = int(node.get(key) or 0)
        except (TypeError, ValueError):
            port = 0
        if 1 <= port <= 65535 and port not in ports:
            ports.append(port)
    ok = False
    ms = 0
    used = 0
    for port in ports:
        try:
            ok, ms = mesh.ping(host, port, timeout)
        except Exception:
            ok, ms = False, 0
        if ok:
            used = port
            break
    out = dict(node)
    out["ok"] = bool(ok)
    out["ping_ms"] = int(ms) if ok else 0
    out["status"] = ("online" if ms <= 500 else "warn") if ok else "off"
    out["ping_port"] = used
    if not ok:
        out["reason"] = "timeout" if ports else "no-port"
    return out



def _node_alive(node, timeout=2.0):
    """A-101: живость узла для панели.

    Пингуем порт прокси, а если он не отвечает - порт панели узла
    (в узлах часто указан именно порт панели, а не прокси).
    Возвращает копию узла с полями ok/ping_ms/status/ping_port/reason.
    """
    if not isinstance(node, dict):
        return {"id": "", "name": "-", "region": "", "role": "node",
                "ok": False, "ping_ms": 0, "status": "off", "ping_port": 0,
                "reason": "bad-node"}
    host = str(node.get("host") or "").strip()
    ports = []
    for key in ("port", "policy_port"):
        try:
            port = int(node.get(key) or 0)
        except (TypeError, ValueError):
            port = 0
        if 1 <= port <= 65535 and port not in ports:
            ports.append(port)
    ok = False
    ms = 0
    used = 0
    for port in ports:
        try:
            ok, ms = mesh.ping(host, port, timeout)
        except Exception:
            ok, ms = False, 0
        if ok:
            used = port
            break
    out = dict(node)
    out["ok"] = bool(ok)
    out["ping_ms"] = int(ms) if ok else 0
    out["status"] = ("online" if ms <= 500 else "warn") if ok else "off"
    out["ping_port"] = used
    if not ok:
        out["reason"] = "timeout" if ports else "no-port"
    return out


def _tunnel_module():
    """A-397: lazy import - v klientskoy sborke meshtunnel mozhet ne byt."""
    try:
        import meshtunnel
    except Exception:
        return None
    return meshtunnel


def _tunnel_status():
    """A-397: status tunnelya BEZ sekretov (uzel, piry, sessii, rtt, potoki)."""
    mod = _tunnel_module()
    if mod is None:
        return {}
    getter = getattr(mod, "status", None)
    if not callable(getter):
        return {}
    try:
        data = getter()
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _game_tun_status():
    """A-817: sostoyanie igrovogo TUN BEZ sekretov.

    Адаптер требует прав (root/CAP_NET_ADMIN на Linux, WinTun на Windows) и может
    честно не подняться. Без этого блока панель не видит разницу между «TUN
    работает» и «TUN выключен молча» — а это ровно тот случай, который нельзя
    диагностировать по логу с чужого ПК.

    Флаг выключен — не трогаем модуль вообще (probe() не вызываем).
    """
    if not config.get("game_tun", False):
        return {}
    try:
        import meshtun
    except Exception:
        return {"error": "module_unavailable"}
    getter = getattr(meshtun, "info", None)
    if not callable(getter):
        return {"error": "old_meshtun"}
    try:
        data = getter()
    except Exception as exc:
        return {"error": "probe_failed: %s" % type(exc).__name__}
    return data if isinstance(data, dict) else {}


def _game_status():
    """A-827: честное состояние игрового контура — сценарий, сервер, права.

    Ничего не обещает: если туннель выключен, здесь так и написано, а не
    «будет работать». Секретов меша в ответе нет."""
    out = {"scenarios": [], "scenario": {}, "server": {}, "candidates": [],
           "optins": []}
    try:
        import meshtunnel
    except Exception:
        return {"error": "module_unavailable"}
    try:
        out["scenarios"] = meshtunnel.game_scenarios()
        out["scenario"] = meshtunnel.game_scenario_state()
        out["server"] = meshtunnel.game_server_state()
        out["candidates"] = meshtunnel.game_server_candidates()
    except Exception as exc:
        return {"error": "probe_failed: %s" % type(exc).__name__}
    # Галки узлов (Ш8) — без секретов, id/name/роль плюс сами галки.
    try:
        for node in mesh.all_nodes():
            nid = node.get("id")
            if not nid:
                continue
            out["optins"].append({
                "id": nid, "name": node.get("name", ""),
                "role": node.get("role", ""),
                "game_address": meshtunnel.game_address(nid),
                "optins": mesh.optins(nid),
            })
    except Exception:
        pass
    return out


def _tunnel_peers():
    """A-397: po odnomu piru - zhiv li soket i svek li 'seen'."""
    mod = _tunnel_module()
    if mod is None:
        return {}
    getter = getattr(mod, "peer_info", None)
    if not callable(getter):
        return {}
    try:
        data = getter()
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _alive_via_tunnel(node):
    """A-397: pryamoy dial ne prohodit, potomu chto u uzla 51821 slushaet
    tolko loopback. Zhiva li sessiya tunnelya - uzel zhiv, i my govorim ob
    etom CHESTNO cherez alive_via="tunnel", ne vydumyvaya ping_ms."""
    if not isinstance(node, dict):
        return node
    row = dict(node)
    row.setdefault("alive_via", "")
    if row.get("ok"):
        return row
    node_id = str(row.get("id") or row.get("node_id") or "")
    if not node_id:
        return row
    info = _tunnel_peers().get(node_id)
    if isinstance(info, dict) and (info.get("sock") or info.get("fresh")):
        row["ok"] = True
        row["alive_via"] = "tunnel"
        row["tunnel_age"] = int(info.get("age", -1) or -1)
        row["tunnel_streams"] = int(info.get("streams", 0) or 0)
    return row

def _ext_packages():
    """A-164: какие сборки расширения реально лежат в этом сервере.

    Архивы раздаёт только головной сервер; в клиентской сборке их нет,
    поэтому список пустой и кнопки «Скачать» не показываются.
    """
    out = []
    names = getattr(config, "EXT_PACKAGES", {}) or {}
    root = getattr(config, "EXT_ASSETS_DIR", "") or ""
    if not root:
        return out
    for target, name in names.items():
        try:
            t = str(target or "").strip().lower()
            n = os.path.basename(str(name or ""))
            if not t or not n:
                continue
            if os.path.isfile(os.path.join(root, n)):
                out.append(t)
        except OSError:
            continue
    return out


def _routes():
    try:
        with open(config.XRAY_CONFIG, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        rules = (cfg.get("routing", {}) or {}).get("rules", []) or []
    except (OSError, ValueError):
        rules = []
    rows = []
    for i, r in enumerate(rules, 1):
        doms = r.get("domain", []) or []
        ips = r.get("ip", []) or []
        inbound = ",".join(r.get("inboundTag", []) or []) or "-"
        if doms:
            what = "; ".join(str(d)[:50] for d in doms[:2])
            if len(doms) > 2:
                what += "…(+%d)" % (len(doms) - 2)
            kind = "domain"
        elif ips:
            what = "; ".join(str(i)[:50] for i in ips[:2])
            if len(ips) > 2:
                what += "…(+%d)" % (len(ips) - 2)
            kind = "ip"
        else:
            what = r.get("type", "field")
            kind = "field"
        rows.append({
            "priority": i,
            "what": what or "-",
            "target": r.get("outboundTag", "-"),
            "inbound": inbound,
            "kind": kind,
            "status": "active",
        })
    final = core.get_vless_now() or "direct"
    rows.append({
        "priority": len(rows) + 1,
        "what": "0.0.0.0/0",
        "target": final,
        "inbound": "http-in, vless-in",
        "kind": "default",
        "status": "final",
    })
    return {"ok": True, "rows": rows, "final": final}


def _settings():
    return {
        "ok": True,
        "settings": {
            "host": config.VM_HOST,
            "port": config.UI_PORT,
            "xray_port": config.XRAY_PORT,
            "ui_port": config.UI_PORT,
            "xray_api_port": config.XRAY_API_PORT,
            "tgws_port": config.TGWS_PORT,
            "version": config.VERSION,
            "version_name": config.VERSION_NAME,
            "uptime": int(time.time() - config._BOOT_TS),
            "server_name": config.get("server_name", "Home"),
            "auto_refresh": config.get("auto_refresh", True),
            "mesh_id": config.get("mesh_id", ""),
            "show_mesh": config.get("show_mesh", False),
            "lan_only": bool(config.get("lan_only", False)),
            "rate_limit": bool(config.get("rate_limit", True)),
            "block_scanners": bool(config.get("block_scanners", False)),
            "setup_complete": bool(config.get("setup_complete", False)),
        },
    }


def _sec(include_secrets=True):
    v = config.vless_public()
    return {
        "ok": True,
        "pbk": v.get("public_key", "") if include_secrets else "",
        "sid": v.get("short_id", "") if include_secrets else "",
        "sni": v.get("sni", ""),
        "enabled": bool(v.get("enabled")),
        "ui_token_set": bool(config.get("ui_token", "")),
        "tls": bool(_TLS_ENABLED),
        "twofa": config.get("twofa", False),
        "access": {
            "lan_only": config.get("lan_only", False),
            "block_scanners": config.get("block_scanners", False),
            "rate_limit": config.get("rate_limit", True),
        },
    }


def _migrate_storage():
    try:
        import crypt
        migrated = crypt.migrate_all()
    except Exception as e:
        config.log("хранилище: миграция не выполнена: %s" % e)
        return []
    if migrated:
        config.log("хранилище: AURORA2 (%s)" % ", ".join(sorted(migrated)))
    return migrated


def serve(port=None):
    config.load_settings()
    security.init()
    _migrate_storage()
    port = port or config.UI_PORT
    _load_ui_token()
    # bind 0.0.0.0 (панель доступна из LAN); защита: Origin-проверка для POST,
    # Bearer (security.check) + опциональный токен (settings.ui_token),
    # секреты — только loopback
    global _AUTO_REFRESH_STARTED
    if not _AUTO_REFRESH_STARTED:
        _AUTO_REFRESH_STARTED = True
        threading.Thread(target=_auto_refresh_loop, daemon=True).start()
    httpd = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    httpd.daemon_threads = True
    httpd.allow_reuse_address = True
    if _enable_tls(httpd):
        config.log("Aurora v%s started (UI :%d, xray :%d, TLS)" % (
            config.VERSION, port, config.XRAY_PORT))
    else:
        config.log("Aurora v%s started (UI :%d, xray :%d%s; TLS выключен — "
                   "учётные данные только из LAN-сегмента)" % (
                       config.VERSION, port, config.XRAY_PORT,
                       "" if _UI_TOKEN else " [без токена]"))
    httpd.serve_forever()


def _auto_refresh_loop():
    """Периодический фоновый refresh ключей (если авто-обновление включено)."""
    while True:
        time.sleep(config.AUTO_REFRESH_INTERVAL)
        if config.get("auto_refresh", True) and config.get("vpn_mode", True):
            try:
                source.refresh_from_github()
            except Exception as e:
                config.log("auto_refresh: ошибка: %s" % e)
