# Aurora v1.6.0 — HTTP API: /api/* + панель. Чистый ThreadingHTTPServer (без фреймворков).
# Порт эталона v1.4.0 (mesh/subs/plans/stats/routes/settings/security) на публичную
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

import config
import core
import mesh
import pool
import recovery
import rusegment
import security
import source
import subs
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


def _configured_hosts():
    values = {"127.0.0.1", "::1", "localhost"}
    for value in (config.VM_HOST, os.environ.get("AURORA_HOST", "")):
        host = str(value or "").strip().lower().rstrip(".")
        if host:
            values.add(host)
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
        server = ipaddress.ip_address(str(config.VM_HOST))
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


def _auth_ok(self):
    """Токен не настроен — пропускаем. Настроен — сверяем X-Auth или ?token=""."""
    return _token_matches(self.headers.get("X-Auth", ""), _UI_TOKEN)


def _token_matches(value, expected):
    return bool(value and expected and hmac.compare_digest(
        str(value).encode("utf-8"), str(expected).encode("utf-8")))


def _admin_ok(self):
    if _token_matches(self.headers.get("X-Auth", ""), _UI_TOKEN):
        return True
    return security.enabled() and security.check(
        self.headers, self.client_address[0])

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
    return security.enabled() and security.check(
        self.headers, self.client_address[0])


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


def _vless_ext():

    """Внешняя vless-ссылка для подключения к домашнему прокси ИЗВНЕ."""
    v = config.vless_public()
    host = config._format_link_host(v.get("host", ""))
    if not v.get("enabled") or not v.get("uuid") or not host:
        return {}
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
    link = "vless://%s@%s:%d?%s#Aurora-Out" % (
        v["uuid"], host, v["port"], q)
    return {
        "link": link,
        "host": v["host"],
        "port": v["port"],
        "uuid": v["uuid"],
        "sni": v["sni"],
        "pbk": v["public_key"],
        "sid": v["short_id"],
        "fp": "chrome",
        "enabled": True,
    }


def _subs_list(include_secrets=False):
    masked = bool(config.SUBS_MASK_UUID) or not include_secrets
    v = config.vless_public()
    params = ({
        "host": v.get("host", ""),
        "port": v.get("port", 8443),
        "public_key": v.get("public_key", ""),
        "short_id": v.get("short_id", ""),
        "sni": v.get("sni", ""),
        "flow": v.get("flow", ""),
        "enabled": bool(v.get("enabled")),
    } if include_secrets else {"enabled": bool(v.get("enabled"))})
    out = []
    for s in subs.all():
        keys = []
        for k in s.get("keys", []):
            kid = k.get("id", "")
            keys.append({
                "id": kid if include_secrets else "",
                "id_masked": str(kid)[:8] + "…" if masked else kid,
                "created": 0 if masked else k.get("created", 0),
                "remark": "" if masked else k.get("remark", ""),
                "note": "" if masked else k.get("note", ""),
            })
        out.append({
            "uid": str(s.get("uid", ""))[:8] + "…" if masked else s.get("uid", ""),
            "name": "" if masked else s.get("name", ""),
            "plan": s.get("plan", ""),
            "remark": "" if masked else s.get("remark", ""),
            "token": s.get("token", "") if include_secrets else "",
            "created": 0 if masked else s.get("created", 0),
            "expires": s.get("expires", 0),
            "plan_next": s.get("plan_next"),
            "expires_next": 0 if masked else s.get("expires_next", 0),
            "used_bytes": s.get("used_bytes", 0),
            "limit_bytes": s.get("limit_bytes", 0),
            "limit_devices": s.get("limit_devices", 0),
            "enabled": bool(s.get("enabled", True)),
            "access_status": subs.access_status(s),
            "access_ok": subs.access_status(s) == "ok",
            "keys": keys,
            "sub_url": subs.public_link(s) if include_secrets else "",
        })
    return {
        "ok": True,
        "subs": out,
        "plans": config.SUBS_PLANS,
        "default": config.SUBS_PLAN_DEFAULT,
        "masked": masked,
        "vless_params": params,
    }


_CSP = ("default-src 'self'; base-uri 'none'; object-src 'none'; "
        "frame-ancestors 'none'; frame-src 'none'; form-action 'self'; "
        "script-src 'self'; script-src-attr 'none'; "
        "style-src 'self'; style-src-attr 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'")


_TLS_ENABLED = False

_TRANSPORT_EXEMPT = ("/sub", "/api/mesh/policy", "/api/mesh/join", "/api/policy",
                     "/api/policy/accept", "/api/rusegment/regions")


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


def _sub_publish(self):
    """GET /sub?token=... — публичная выдача текст-подписки (vless-ссылки).
    Без origin-проверки: клиентские приложения (v2rayNG и т.п.) грузят её напрямую."""
    qs = urllib.parse.parse_qs(self.path.split("?", 1)[-1])
    token = (qs.get("token") or [""])[0].strip()
    if not token:
        self._send(*_json({"error": "token required"}, 400))
        return
    s, status = subs.by_token_status(token)
    if status == "missing":
        self._send(*_json({"error": "subscription not found"}, 404))
        return
    if status == "expired":
        self._send(*_json({"error": "subscription expired"}, 410))
        return
    if status == "quota":
        self._send(*_json({"error": "subscription quota exceeded"}, 410))
        return
    if status != "ok" or not s:
        self._send(*_json({"error": "subscription unavailable"}, 403))
        return
    data = subs.subscription_text(s).encode("utf-8")
    self.send_response(200)
    self.send_header("Content-Type", "text/plain; charset=utf-8")
    self.send_header("Content-Length", str(len(data)))
    self.send_header("Cache-Control", "no-store")
    for _name, _value in _security_headers():
        self.send_header(_name, _value)
    self.send_header("Content-Disposition",
                     'inline; filename="aurora-sub.txt"')
    self.end_headers()
    self.wfile.write(data)


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
    st["auto_recovery"] = config.get("auto_recovery", True)
    st["vless_now"] = core.get_vless_now() or "-"
    st["egress_ip"] = core.egress_ip()
    st["comm"] = st.pop("comm", {"state": "idle", "msg": ""})
    st["vless_ext"] = _vless_ext()
    st["mesh_nodes"] = mesh.node_count()
    st["invite_available"] = False
    st["server_name"] = config.get("server_name", "Home")
    st["show_mesh"] = config.get("show_mesh", False)
    st["show_subs"] = config.get("show_subs", False)
    st["lan_only"] = bool(config.get("lan_only", False))
    st["rate_limit"] = bool(config.get("rate_limit", True))
    st["block_scanners"] = bool(config.get("block_scanners", False))
    st["mesh_master"] = False
    st["setup_complete"] = bool(config.get("setup_complete", False))
    st["setup_token_required"] = bool(config.SETUP_TOKEN)
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
    st["policy_text"] = config.POLICY_TEXT
    st["policy_rev"] = config.POLICY_REV
    st["policy_required"] = config.policy_required()
    st["policy_accepted_rev"] = int(config.get("policy_rev_accepted", 0) or 0)
    st["segment_title"] = config.segment_title()
    st["segment_flag"] = config.segment_flag()
    st["segment_regions"] = config.segment_regions()
    st["regions"] = [
        {"id": k, "flag": v["flag"], "title": v["title"]}
        for k, v in config.REGIONS.items()
    ]
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
        # --- публичная выдача подписки: без авторизации и без LAN-ограничений ---
        if path == "/sub" or path.startswith("/sub?"):
            _sub_publish(self)
            return
        if path == "/favicon.ico":
            self._send(200, "image/svg+xml; charset=utf-8", _FAVICON_SVG.encode("utf-8"))
            return
        # --- публичная политика меша: без авторизации (нужна узлам) ---
        if path == "/api/mesh/policy":
            self._send(*_json(mesh.policy()))
            return
        # --- публичная политика сервиса: всегда доступна (первая страница) ---
        if path == "/api/policy":
            self._send(*_json({"ok": True, "text": config.POLICY_TEXT,
                               "rev": config.POLICY_REV}))
            return
        # --- публичная справка по региональному сегменту ---
        if path == "/api/rusegment/regions":
            self._send(*_json({
                "ok": True,
                "regions": config.segment_regions(),
                "title": config.segment_title(),
                "flag": config.segment_flag(),
                "custom": config.get("segment_custom", ""),
                "all": [
                    {"id": k, "flag": v["flag"], "title": v["title"]}
                    for k, v in config.REGIONS.items()
                ],
            }))
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
        if not trusted and path in ("/api/log", "/api/logs", "/api/recovery/log", "/api/routes"):
            self._send(*_json({"error": "management authentication required"}, 403))
            return
        # гейт видимости: меш-разделы и подписки закрыты, пока головной сервер
        # не поставит show_mesh/show_subs (правятся только через mesh._policy_loop)
        if path in ("/api/mesh", "/api/nodes", "/api/routes") and not config.get("show_mesh", False):
            self._send(*_json({"ok": False, "error": "mesh: закрыто до команды мастера"}, 403))
            return
        if path in ("/api/subs/list", "/api/subs/plans", "/api/plans", "/api/stats") \
                and not config.get("show_subs", False):
            self._send(*_json({"ok": False, "error": "subs: закрыто до команды мастера"}, 403))
            return
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
        if path == "/api/tgws/status":
            status = tgws.status()
            if not trusted:
                status = dict(status)
                status.pop("link", None)
                status["secret_ok"] = False
            self._send(*_json(status))
            return
        if path == "/api/security/status":
            self._send(*_json(_project_security_status(trusted)))
            return
        if path == "/api/update/status":
            self._send(*_json(_project_update_status(trusted)))
            return
        if path == "/api/versions":
            # история версий для вкладки «Версии»
            self._send(*_json({"ok": True, "versions": [
                {"v": v, "name": nm, "date": d}
                for v, nm, d in config.VERSION_HISTORY]}))
            return
        if path == "/api/subs/list":
            self._send(*_json(_subs_list(include_secrets=trusted)))
            return
        if path == "/api/subs/plans":
            self._send(*_json({"ok": True, "plans": config.SUBS_PLANS,
                               "default": config.SUBS_PLAN_DEFAULT}))
            return
        if path == "/api/plans":
            self._send(*_json({"ok": True, "plans": config.SUBS_PLANS,
                               "default": config.SUBS_PLAN_DEFAULT}))
            return
        if path == "/api/stats":
            self._send(*_json(_stats(include_secrets=trusted)))
            return
        if path == "/api/mesh":
            nodes = mesh.all_nodes()
            if not trusted:
                nodes = [dict(n) for n in nodes if isinstance(n, dict)]
                for node in nodes:
                    for key in ("secret", "invite", "host", "port", "ip", "address"):
                        node.pop(key, None)
            self._send(*_json({"ok": True, "invite": mesh.invite() if trusted else "",
                               "nodes": nodes,
                               "count": mesh.node_count()}))
            return
        if path == "/api/nodes":
            nodes = mesh.ping_all()
            if not trusted:
                nodes = [{k: v for k, v in node.items()
                          if k not in ("ip", "host", "port", "address", "secret", "invite")}
                         for node in nodes if isinstance(node, dict)]
            self._send(*_json({"ok": True, "nodes": nodes}))
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
        if path == "/api/security":
            self._send(*_json(_sec(include_secrets=trusted)))
            return
        self._send(*_json({"error": "unknown endpoint"}, 404))

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
        path = self.path.split("?", 1)[0]
        if not _origin_ok(self):
            self._send(*_json({"error": "cross-origin blocked"}, 403))
            return
        # приём политики и регистрация узла у головного — публично (до входа)
        if path == "/api/policy/accept":
            self._policy_accept_raw()
            return
        if path == "/api/mesh/register":
            self._mesh_register_raw()
            return
        if path == "/api/setup/complete":
            setup_data, body_error = _read_json_body(self)
            if body_error:
                self._send(*_json({"error": body_error}, 400))
                return
            self._setup_complete(setup_data or {})
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

        data, body_error = _read_json_body(self)
        if body_error:
            self._send(*_json({"ok": False, "error": body_error}, 400))
            return

        # гейт политики: до принятия политики запрещены все POST, кроме accept
        if config.policy_required() and path != "/api/policy/accept":
            self._send(*_json({"error": "policy required"}, 403))
            return

        # гейт видимости: POST-изменения меша/подписок закрыты, пока мастер
        # не разрешил (show_mesh/show_subs), /api/mesh/policy — public выше
        if path.startswith("/api/mesh/") and not config.get("show_mesh", False):
            self._send(*_json({"ok": False, "error": "mesh: закрыто до команды мастера"}, 403))
            return
        if (path.startswith("/api/subs/") or path in ("/api/plans/save",)) \
                and not config.get("show_subs", False):
            self._send(*_json({"ok": False, "error": "subs: закрыто до команды мастера"}, 403))
            return

        handler = {
            "/api/vpn_mode": self._vpn_mode,
            "/api/rotate": self._rotate,
            "/api/keys/add": self._keys_add,
            "/api/keys/refresh": self._keys_refresh,
            "/api/keys/check": self._keys_check,
            "/api/keys/cleanup": self._keys_cleanup,
            "/api/keys/remove": self._keys_remove,
            "/api/keys/active": self._keys_active,
            "/api/recovery/limit": self._rc_limit,
            "/api/recovery/region": self._rc_region,
            "/api/recovery/conn": self._rc_conn,
            "/api/tgws/restart": self._tgws_restart,
            "/api/rusegment/check": self._rusegment_check,
            "/api/rusegment/region": self._rusegment_region,
            "/api/security/rotate": self._security_rotate,
            "/api/security/password": self._security_password,
            "/api/security/twofa": self._security_twofa,
            "/api/security/vless/rotate": self._security_vless_rotate,
            "/api/security/sid": self._security_sid,
            "/api/security/access": self._security_access,
            "/api/update/check": self._update_check,
            "/api/update/apply": self._update_apply,
            "/api/subs/create": self._subs_create,
            "/api/subs/update": self._subs_update,
            "/api/subs/delete": self._subs_delete,
            "/api/subs/add_key": self._subs_add_key,
            "/api/subs/remove_key": self._subs_remove_key,
            "/api/subs/apply": self._subs_apply,
            "/api/subs/purchase": self._subs_purchase,
            "/api/plans/save": self._plans_save,
            "/api/settings/save": self._settings_save,
            "/api/setup/complete": self._setup_complete,
            "/api/settings/reset": self._settings_reset,
            "/api/mesh/ping": self._mesh_ping,
            "/api/mesh/invite": self._mesh_invite,
            "/api/mesh/regenerate": self._mesh_regenerate,
            "/api/mesh/node/add": self._mesh_node_add,
            "/api/mesh/node/remove": self._mesh_node_remove,
            "/api/mesh/join": self._mesh_join,
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
        tag = data.get("tag", "")
        ok, msg = core.set_active_tag(tag)
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

    def _rusegment_check(self, data):
        started = rusegment.check_all()
        self._send(*_json({"ok": True, "started": started}))

    def _policy_accept_raw(self):
        """Публичный приём политики (без origin/auth). Читает тело вручную."""
        ip = self.client_address[0]
        if not _public_allowed("policy_accept", ip, max_hits=10, window=60):
            self._send(*_json({"ok": False, "error": "too many requests"}, 429))
            return
        data, body_error = _read_json_body(self)
        if body_error:
            self._send(*_json({"ok": False, "error": body_error}, 400))
            return
        rev = data.get("rev")
        if type(rev) is not int or rev != config.POLICY_REV:
            self._send(*_json({"ok": False, "error": "invalid policy revision"}, 400))
            return
        config.set("policy_rev_accepted", rev)
        config.save_settings()
        _public_succeeded("policy_accept", ip)
        self._send(*_json({"ok": True, "rev": rev}))

    def _mesh_register_raw(self):
        """Публичная регистрация узла у головного сервера (v1.8.0).

        Проверка token == config.master_token; успешный узел добавляется в меш
        с ролью node (подчинённый). Без токена / неверный токен — 403."""
        ip = self.client_address[0]
        if not _public_allowed("mesh_register", ip, max_hits=5, window=60, backoff=2):
            self._send(*_json({"ok": False, "error": "too many requests"}, 429))
            return
        expected = str(config.get("master_token") or "").strip()
        if not expected:
            self._send(*_json({"ok": False, "error": "registration closed"}, 403))
            return
        data, body_error = _read_json_body(self)
        if body_error:
            self._send(*_json({"ok": False, "error": body_error}, 400))
            return
        token = str(data.get("token") or "")
        if not _token_matches(token, expected):
            _public_failed("mesh_register", ip)
            self._send(*_json({"ok": False, "error": "bad master token"}, 403))
            return
        host = str(data.get("host") or "").strip()
        port = data.get("port")
        if (not _valid_peer_host(host) or host.lower() in ("localhost", "localhost.localdomain")
                or type(port) is not int or not 1 <= port <= 65535):
            _public_failed("mesh_register", ip)
            self._send(*_json({"ok": False, "error": "invalid host or port"}, 400))
            return
        if len(mesh.all_nodes()) >= 256:
            _public_failed("mesh_register", ip)
            self._send(*_json({"ok": False, "error": "node limit reached"}, 429))
            return
        node, err = mesh.add(data.get("name"), data.get("region") or "RU",
                             host, port, role="node")
        if err:
            _public_failed("mesh_register", ip)
            self._send(*_json({"ok": False, "error": err}, 400))
            return
        _public_succeeded("mesh_register", ip)
        config.log("mesh: узел зарегистрирован через /api/mesh/register (%s)" % node["name"])
        self._send(*_json({"ok": True, "id": node["id"], "node": node}))

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

    def _security_rotate(self, data):
        # admin-токен панели (Bearer): чистая ротация, хранение data/admin_secret.json
        token = security.rotate()
        self._send(*_json({"ok": bool(token), "token": token}))

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
        policy_rev = data.get("policy_rev")
        if type(policy_rev) is not int or policy_rev != config.POLICY_REV:
            _setup_reject(self, "policy revision required", 400)
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
        invite = data.get("mesh_invite")
        if invite is not None and not isinstance(invite, str):
            _setup_reject(self, "invalid mesh invite", 400)
            return
        invite = (invite or "").strip()[:2048]
        mesh_joined = False
        if invite:
            joined, join_err = mesh.join_via_invite(invite, name=name.strip())
            if joined:
                mesh_joined = True
            else:
                config.log("api: setup mesh invite skipped: %s" % (join_err or "unknown"))
        values = {
            "server_name": name.strip(),
            "ui_token": password,
            "twofa": True,
            "ui_pin": pin,
            "policy_rev_accepted": policy_rev,
            "setup_complete": True,
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
        self._send(*_json({"ok": True, "mesh_joined": mesh_joined,
                           "restart_required": restart_required,
                           "settings": _settings()["settings"]}))

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
        self._send(*_json({"ok": True, "msg": "shortId обновлён, xray перезапускается"}))

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
        if r.get("ok") and r.get("restart_required"):
            threading.Timer(0.8, os._exit, args=(0,)).start()
        self._send(*_json(r))

    def _subs_apply_clients_bg(self):
        threading.Thread(target=lambda: core.apply_sub_clients(),
                         daemon=True).start()

    def _subs_create(self, data):
        name = str(data.get("name", "") or "").strip()
        plan = str(data.get("plan", "") or config.SUBS_PLAN_DEFAULT).strip()
        remark = str(data.get("remark", "") or "").strip()
        s = subs.create(name=name or None, plan=plan, remark=remark)
        self._subs_apply_clients_bg()
        self._send(*_json({"ok": True, "sub": s}))

    def _subs_update(self, data):
        uid = str(data.get("uid", "") or "").strip()
        if not uid:
            self._send(*_json({"ok": False, "error": "no uid"}, 400))
            return
        upd = {}
        for f in ("name", "remark", "plan", "enabled", "expires",
                  "limit_bytes", "limit_devices"):
            if f in data:
                upd[f] = data[f]
        if not upd:
            self._send(*_json({"ok": False, "error": "no fields"}, 400))
            return
        s = subs.find(uid)
        if not s:
            self._send(*_json({"ok": False, "error": "subscription not found"}, 400))
            return
        subs.update(uid, **upd)
        self._subs_apply_clients_bg()
        self._send(*_json({"ok": True, "sub": subs.find(uid)}))

    def _subs_delete(self, data):
        uid = str(data.get("uid", "") or "").strip()
        if not uid or not subs.delete(uid):
            self._send(*_json({"ok": False, "error": "subscription not found"}, 400))
            return
        self._subs_apply_clients_bg()
        self._send(*_json({"ok": True}))

    def _subs_add_key(self, data):
        uid = str(data.get("uid", "") or "").strip()
        remark = str(data.get("remark", "") or "").strip()
        device_id = str(data.get("device_id", "") or "").strip()[:64]
        s = subs.find(uid)
        if not s:
            self._send(*_json({"ok": False, "error": "subscription not found"}, 400))
            return
        key, sub = subs.add_key(uid, remark=remark, device_id=device_id)
        if not sub:
            self._send(*_json({"ok": False, "error": "subscription not found"}, 400))
            return
        if not key:
            self._send(*_json({"ok": False, "error": "subscription key/device limit reached"}, 400))
            return
        self._subs_apply_clients_bg()
        self._send(*_json({"ok": True, "key": key, "sub": sub}))

    def _subs_remove_key(self, data):
        uid = str(data.get("uid", "") or "").strip()
        kid = str(data.get("key_id", "") or "").strip()
        if not uid or not subs.remove_key(uid, kid):
            self._send(*_json({"ok": False, "error": "key not found"}, 400))
            return
        self._subs_apply_clients_bg()
        self._send(*_json({"ok": True}))

    def _subs_apply(self, data):
        ok, msg = core.apply_sub_clients()
        self._send(*_json({"ok": ok, "msg": msg}))

    def _subs_purchase(self, data):
        """Внесение оплаты: создание/продление подписки."""
        plan = str(data.get("plan", "") or "").strip()
        if plan and plan not in config.SUBS_PLANS:
            self._send(*_json({"ok": False, "error": "тариф %s не найден" % plan}, 400))
            return
        try:
            sub, status, msg, payment = subs.purchase_with_receipt(
                uid=str(data.get("uid", "") or "").strip() or None,
                name=str(data.get("name", "") or "").strip() or None,
                plan=plan,
                remark=str(data.get("remark", "") or "").strip(),
                amount=data.get("amount") if "amount" in data else None,
                idempotency_key=str(data.get("idempotency_key", "") or "").strip() or None)
        except (TypeError, ValueError) as exc:
            self._send(*_json({"ok": False, "error": str(exc)}, 400))
            return
        if status == "error":
            self._send(*_json({"ok": False, "error": msg}, 400))
            return
        if status == "created":
            self._subs_apply_clients_bg()
        self._send(*_json({"ok": True, "sub": sub, "status": status, "msg": msg, "payment": payment}))

    def _plans_save(self, data):
        plans = data.get("plans")
        if not isinstance(plans, dict) or not plans:
            self._send(*_json({"ok": False, "error": "no plans"}, 400))
            return
        need = ("name", "price", "bytes", "days", "devices", "keys")
        changed = 0
        for k, v in plans.items():
            if not isinstance(v, dict):
                continue
            k = str(k or "").strip()
            # новые тарифы: id = латиница/цифры/_- до 40 симв.
            valid_slug = bool(k) and len(k) <= 40 and k.isascii() and k.islower() and \
                all(c in "abcdefghijklmnopqrstuvwxyz0123456789_-" for c in k)
            if not valid_slug:
                continue
            if k in config.SUBS_PLANS:
                cur = dict(config.SUBS_PLANS[k])
            else:
                # новый план: без названия не создаём
                if not str(v.get("name") or "").strip():
                    continue
                cur = {"name": "", "price": 0, "bytes": 0,
                       "days": 30, "devices": 1, "keys": 1,
                       "features": [], "features_no": []}
            for f in need:
                if f in v:
                    if f == "name":
                        cur[f] = str(v[f]).strip()[:40] or cur[f]
                    else:
                        try:
                            value = int(v[f] or 0)
                            if value < 0 or (f in ("devices", "keys") and value < 1):
                                raise ValueError
                            cur[f] = value
                        except (TypeError, ValueError):
                            return self._send(*_json({"ok": False,
                                                      "error": "поле %s имеет недопустимое значение" % f}, 400))
            # описание тарифа: списки включённых/невключённых возможностей
            for f in ("features", "features_no"):
                if f in v and isinstance(v[f], list):
                    cur[f] = [str(x).strip()[:80] for x in v[f]
                              if isinstance(x, str) and x.strip()]
            config.SUBS_PLANS[k] = cur
            config.log("api: тариф %s обновлён" % k)
            changed += 1
        if not changed:
            self._send(*_json({"ok": False, "error": "пустое обновление"}, 400))
            return
        config.save_plans()
        config.log("api: сохранены тарифы (%d)" % changed)
        self._send(*_json({"ok": True, "plans": config.SUBS_PLANS}))

    def _settings_save(self, data):
        values = {"mesh_master": False}
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
        self._send(*_json({"ok": True, "nodes": mesh.ping_all()}))

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

    def _mesh_join(self, data):
        invite = str(data.get("invite") or "").strip()
        if len(invite) > 4096:
            self._send(*_json({"ok": False, "error": "неверный invite"}, 400))
            return
        name = str(data.get("name") or "").strip()
        region = str(data.get("region") or "").strip()
        ok, err = mesh.join_via_invite(invite, name or None, region or "RU")
        if not ok:
            self._send(*_json({"ok": False, "error": err or "join failed"}, 400))
            return
        self._send(*_json({"ok": True}))

    def _mesh_node_add(self, data):
        host = str(data.get("host") or "").strip()
        try:
            port = int(data.get("port") or 0)
        except (TypeError, ValueError):
            self._send(*_json({"ok": False, "error": "неверный порт"}, 400))
            return
        if not host or port <= 0 or port > 65535:
            self._send(*_json({"ok": False, "error": "неверный host/port"}, 400))
            return
        if not _token_matches(self.headers.get("X-Auth"), config.get("master_token")):
            self._send(*_json({"ok": False, "error": "master token required"}, 403))
            return
        role = str(data.get("role") or "node").strip().lower()
        if role not in ("node", "test"):
            self._send(*_json({"ok": False, "error": "неверная роль узла"}, 400))
            return
        policy_port = data.get("policy_port")
        if policy_port is not None:
            try:
                policy_port = int(policy_port)
            except (TypeError, ValueError):
                policy_port = 0
            if policy_port <= 0 or policy_port > 65535:
                self._send(*_json({"ok": False, "error": "неверный policy_port"}, 400))
                return
        else:
            policy_port = None
        node, err = mesh.add(data.get("name"), data.get("region"),
                             host, port, role,
                             auto_name=_as_bool(data.get("auto_name")),
                             policy_port=policy_port)
        if err:
            self._send(*_json({"ok": False, "error": err}, 400))
            return
        secret = node.pop("secret", None)
        resp = {"ok": True, "node": node}
        if secret:
            resp["secret"] = secret
        self._send(*_json(resp))

    def _mesh_node_remove(self, data):
        nid = str(data.get("id") or "").strip()
        if not nid or not mesh.remove(nid):
            self._send(*_json({"ok": False, "error": "node not found"}, 400))
            return
        self._send(*_json({"ok": True}))


# --- данные для новых вкладок UI (тарифы/статистика/маршруты/настройки/безопасность) ---
def _stats(include_secrets=True):
    now = int(time.time())
    week_ago = now - 7 * 86400
    subs_all = subs.all()
    snapshot = subs.billing_snapshot(now)
    month = str(snapshot.get("month") or subs._billing_month(now))
    by_plan = {}

    def row_for(plan_id):
        plan_id = str(plan_id or config.SUBS_PLAN_DEFAULT)
        row = by_plan.get(plan_id)
        if row is None:
            plan = config.SUBS_PLANS.get(plan_id) or {}
            row = {
                "plan": plan_id,
                "name": plan.get("name", plan_id),
                "price": int(plan.get("price", 0) or 0),
                "count": 0,
                "active_count": 0,
                "income": 0,
            }
            by_plan[plan_id] = row
        return row

    for s in subs_all:
        row = row_for(s.get("plan", config.SUBS_PLAN_DEFAULT))
        row["count"] += 1
        if subs.access_status(s, now) == "ok":
            row["active_count"] += 1

    income_month = 0
    for payment in snapshot.get("month_payments", []) or []:
        if payment.get("kind") != "payment" or payment.get("state") != "paid":
            continue
        try:
            amount = int(payment.get("amount", 0) or 0)
        except (TypeError, ValueError):
            amount = 0
        if amount < 0:
            continue
        income_month += amount
        row = row_for(payment.get("plan", config.SUBS_PLAN_DEFAULT))
        row["income"] += amount

    total = len(subs_all)
    active = sum(1 for s in subs_all if subs.access_status(s, now) == "ok")
    rows = []
    for row in by_plan.values():
        rows.append({
            "plan": row["plan"],
            "name": row["name"],
            "price": row["price"],
            "count": row["count"],
            "active_count": row["active_count"],
            "share": round(row["count"] * 100.0 / total, 1) if total else 0,
            "active_share": round(row["active_count"] * 100.0 / active, 1) if active else 0,
            "income": row["income"],
        })
    rows.sort(key=lambda r: (-r["active_count"], -r["count"], r["plan"]))
    return {
        "ok": True,
        "stats_version": 2,
        "month": month,
        "period": {"month": month, "timezone": "UTC"},
        "total": total,
        "active": active,
        "new_week": sum(1 for s in subs_all if s.get("created", 0) >= week_ago),
        "traffic_month": int(snapshot.get("traffic_month", 0) or 0),
        "income_month": income_month,
        "rows": rows,
        "payments": (snapshot.get("payments", []) or [])
        if include_secrets else [],
    }


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
            "show_subs": config.get("show_subs", False),
            "lan_only": bool(config.get("lan_only", False)),
            "rate_limit": bool(config.get("rate_limit", True)),
            "block_scanners": bool(config.get("block_scanners", False)),
            "mesh_master": False,
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
    mesh.start_policy_loop()
    subs.start_background()
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