# Aurora v1.6.0 — HTTP API: /api/* + панель. Чистый ThreadingHTTPServer (без фреймворков).
# Порт эталона v1.4.0 (mesh/subs/plans/stats/routes/settings/security) на публичную
# сборку: станция отсутствует, сохранены авто-обновление (update), Bearer-токен
# (security.check) и admin-ротация API-токена (/api/security/rotate).

import json
import os
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


def _origin_ok(self):
    origin = self.headers.get("Origin", "")
    if not origin:
        return True
    host = (urllib.parse.urlparse(origin).hostname or "").lower()
    return host in _ALLOWED_ORIGINS


def _is_local(self):
    """Клиент на loopback-интерфейсе (доверенный: UI с самого сервера)."""
    return self.client_address[0] in ("127.0.0.1", "::1")


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

_SCANNER_PATHS = (
    "/admin", "/login", "/wp-", "/.env", "/vendor", "/server-status",
    "/boaform", "/manager", "/cgi-bin", "/config.php", "/phpmyadmin",
    "/.git", "/shell", "/actuator", "/wp-login", "/xmlrpc.php",
)


def _scanner_path(path):
    return any(path == p or path.startswith(p + "/") for p in _SCANNER_PATHS)


def _host_in_lan(ip):
    """Loopback или та же сеть /16, что и VM_HOST (домашняя LAN)."""
    if ip in ("127.0.0.1", "::1"):
        return True
    pfx = ".".join(str(config.VM_HOST).split(".")[:2]) + "."
    return ip.startswith(pfx)


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
    """lan_only + rate-limit. False — запрос надо 403."""
    if not _rate_allowed(self.client_address[0]):
        return False
    if not config.get("lan_only", False):
        return True
    if _is_local(self):
        return True
    if _host_in_lan(self.client_address[0]):
        return True
    if _UI_TOKEN and self.headers.get("X-Auth") == _UI_TOKEN:
        return True
    return False


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


def _auth_ok(self):
    """Токен не настроен — пропускаем. Настроен — сверяем X-Auth или ?token=."""
    if not _UI_TOKEN:
        return True
    given = self.headers.get("X-Auth", "")
    if not given:
        given = (urllib.parse.parse_qs(self.path.split("?", 1)[-1]) or {}).get("token", [""])[0]
    return given == _UI_TOKEN


def _vless_ext():
    """Внешняя vless-ссылка для подключения к домашнему прокси ИЗВНЕ."""
    v = config.VLESS_PUBLIC
    if not v.get("enabled") or not v.get("uuid"):
        return {}
    q = urllib.parse.urlencode({
        "encryption": "none",
        "security": "reality",
        "flow": v.get("flow", "xtls-rprx-vision"),
        "sni": v.get("sni") or v.get("host", "www.microsoft.com"),
        "fp": "chrome",
        "pbk": v.get("public_key", ""),
        "sid": v.get("short_id") or "",
        "type": "tcp",
        "headerType": "none",
    })
    link = "vless://%s@%s:%s?%s#Aurora-Out" % (
        v["uuid"], v.get("host", ""), v.get("port", 8443), q)
    return {
        "link": link,
        "host": v.get("host", ""),
        "port": v.get("port", 8443),
        "uuid": v["uuid"],
        "sni": v.get("sni") or v.get("host", ""),
        "pbk": v.get("public_key", ""),
        "sid": v.get("short_id") or "",
        "fp": "chrome",
        "enabled": True,
    }


def _subs_list():
    """Список подписок для UI: подписки + тарифы + vless-параметры (без секретов)."""
    masked = bool(config.SUBS_MASK_UUID)
    v = config.VLESS_PUBLIC
    params = {
        "host": v.get("host") or config.VM_HOST,
        "port": int(v.get("port", 8443)),
        "public_key": v.get("public_key", ""),
        "short_id": v.get("short_id") or "",
        "sni": v.get("sni") or "www.microsoft.com",
        "flow": v.get("flow", "xtls-rprx-vision"),
        "enabled": bool(v.get("enabled") and v.get("uuid")),
    }
    out = []
    for s in subs.all():
        keys = []
        for k in s.get("keys", []):
            kid = k.get("id", "")
            keys.append({
                "id": kid,
                "id_masked": subs._mask(kid) if masked else kid,
                "created": k.get("created", 0),
                "remark": k.get("remark", ""),
                "note": k.get("note", ""),
            })
        out.append({
            "uid": s.get("uid", ""),
            "name": s.get("name", ""),
            "plan": s.get("plan", ""),
            "remark": s.get("remark", ""),
            "token": s.get("token", ""),
            "created": s.get("created", 0),
            "expires": s.get("expires", 0),
            "plan_next": s.get("plan_next"),
            "expires_next": s.get("expires_next", 0),
            "used_bytes": s.get("used_bytes", 0),
            "limit_bytes": s.get("limit_bytes", 0),
            "limit_devices": s.get("limit_devices", 0),
            "enabled": bool(s.get("enabled", True)),
            "keys": keys,
            "sub_url": subs.public_link(s),
        })
    return {
        "ok": True,
        "subs": out,
        "plans": config.SUBS_PLANS,
        "default": config.SUBS_PLAN_DEFAULT,
        "masked": masked,
        "vless_params": params,
    }


def _sub_publish(self):
    """GET /sub?token=... — публичная выдача текст-подписки (vless-ссылки).
    Без origin-проверки: клиентские приложения (v2rayNG и т.п.) грузят её напрямую."""
    qs = urllib.parse.parse_qs(self.path.split("?", 1)[-1])
    token = (qs.get("token") or [""])[0].strip()
    if not token:
        self._send(*_json({"error": "token required"}, 400))
        return
    s = subs.by_token(token)
    if not s:
        self._send(*_json({"error": "subscription not found"}, 404))
        return
    data = subs.subscription_text(s).encode("utf-8")
    self.send_response(200)
    self.send_header("Content-Type", "text/plain; charset=utf-8")
    self.send_header("Content-Length", str(len(data)))
    self.send_header("Cache-Control", "no-store")
    self.send_header("Content-Disposition",
                     'inline; filename="aurora-sub-%s.txt"' % s.get("uid", "sub"))
    self.end_headers()
    self.wfile.write(data)


def build_state(local=True):
    st = config.get_state()
    st["version"] = config.VERSION
    st["version_name"] = config.VERSION_NAME
    st["app"] = config.APP_NAME
    st["xray_port"] = config.XRAY_PORT
    st["vpn_mode"] = config.get("vpn_mode", True)
    st["auto_recovery"] = config.get("auto_recovery", True)
    st["vless_now"] = core.get_vless_now() or "-"
    st["egress_ip"] = core.egress_ip()
    st["comm"] = st.pop("comm", {"state": "idle", "msg": ""})
    st["vless_ext"] = _vless_ext()
    st["mesh_nodes"] = mesh.node_count()
    st["server_name"] = config.get("server_name", "Home")
    st["show_mesh"] = config.get("show_mesh", True)
    st["show_subs"] = config.get("show_subs", True)
    st["mesh_master"] = False
    if not local and (_UI_TOKEN or config.get("master_only", False)):
        # секреты подключения скрываем при ui_token ИЛИ при замке master_only —
        # подменить доступ наружу может только локальный интерфейс / головной
        v = dict(st["vless_ext"])
        for sec in ("link", "uuid", "pbk", "sid"):
            v.pop(sec, None)
        st["vless_ext"] = v
    # ключи в пуле
    keys = pool.get_keys()
    vless_now = st["vless_now"]
    st["keys_total"] = len(keys)
    st["keys"] = []
    masked = (not local) and (_UI_TOKEN or config.get("master_only", False))
    # скрываем uri ключей пула при ui_token ИЛИ при замке master_only
    for k in keys:
        uri = k.get("uri", "")
        hs = pool.get_status(uri)
        st["keys"].append({
            "uri": "" if masked else uri,
            "tag": k.get("tag", ""),
            "host": k.get("host", ""),
            "port": k.get("port", 443),
            "source": k.get("source", "manual"),
            "status": hs.get("status", "unchecked"),
            "ping_ms": hs.get("ping_ms", 0),
            "exit_ip": hs.get("exit_ip", "-"),
            "sites_ok": hs.get("sites_ok", 0),
            "dead": pool.dead_reason(uri),
            "is_active": k.get("tag") == vless_now,
        })
    # --- политика сервиса и региональный сегмент ---
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
    return st


class Handler(BaseHTTPRequestHandler):
    server_version = "Aurora/1.0"

    def log_message(self, *a):
        pass

    def _send(self, status, ctype, body):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                         "img-src 'self' data:; script-src 'self' 'unsafe-inline'")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        try:
            self._do_get()
        except Exception as e:
            import traceback
            traceback.print_exc()
            self._send(*_json({"error": "internal: %s" % e}, 500))

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
        if not _auth_ok(self):
            self._send(*_json({"error": "unauthorized"}, 401))
            return
        if config.get("block_scanners", False) and _scanner_path(path):
            self._send(*_json({"error": "forbidden"}, 403))
            return
        if not _access_allowed(self):
            self._send(*_json({"error": "outside lan"}, 403))
            return
        trusted = _is_local(self) or bool(_UI_TOKEN and _auth_ok(self) and self.headers.get("X-Auth"))
        if path == "/api/state":
            self._send(*_json(build_state(local=trusted)))
            return
        if path in ("/api/log", "/api/logs"):
            self._send(*_json({"lines": config.log_tail()}))
            return
        if path == "/api/recovery/log":
            self._send(*_json(recovery.status()))
            return
        if path == "/api/tgws/status":
            self._send(*_json(tgws.status()))
            return
        if path == "/api/security/status":
            self._send(*_json(security.status()))
            return
        if path == "/api/update/status":
            self._send(*_json(updater.status()))
            return
        if path == "/api/subs/list":
            self._send(*_json(_subs_list()))
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
            self._send(*_json(_stats()))
            return
        if path == "/api/mesh":
            self._send(*_json({"ok": True, "invite": mesh.invite(),
                               "nodes": mesh.all_nodes(),
                               "count": mesh.node_count()}))
            return
        if path == "/api/nodes":
            self._send(*_json({"ok": True, "nodes": mesh.ping_all()}))
            return
        if path == "/api/routes":
            self._send(*_json(_routes()))
            return
        if path == "/api/settings":
            self._send(*_json(_settings()))
            return
        if path == "/api/security":
            self._send(*_json(_sec()))
            return
        self._send(*_json({"error": "unknown endpoint"}, 404))

    def do_POST(self):
        try:
            self._do_post()
        except Exception as e:
            import traceback
            traceback.print_exc()
            self._send(*_json({"error": "internal: %s" % e}, 500))

    def _do_post(self):
        path = self.path.split("?", 1)[0]
        # приём политики и регистрация узла у головного — публично (до входа)
        if path == "/api/policy/accept":
            self._policy_accept_raw()
            return
        if path == "/api/mesh/register":
            self._mesh_register_raw()
            return
        if not _origin_ok(self):
            self._send(*_json({"error": "cross-origin blocked"}, 403))
            return
        if not security.check(self.headers, self.client_address[0]):
            self._send(*_json({"error": "unauthorized"}, 401))
            return
        if not _auth_ok(self):
            self._send(*_json({"error": "unauthorized"}, 401))
            return
        if not _twofa_ok(self):
            self._send(*_json({"error": "2fa required"}, 401))
            return
        if not _access_allowed(self):
            self._send(*_json({"error": "outside lan"}, 403))
            return
        path = self.path.split("?", 1)[0]

        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length > 65536:
                self._send(*_json({"ok": False, "error": "body too large"}, 400))
                return
            body = self.rfile.read(length) if length else b""
        except ValueError:
            self._send(*_json({"ok": False, "error": "bad content-length"}, 400))
            return
        if body:
            try:
                data = json.loads(body.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                self._send(*_json({"ok": False, "error": "invalid json body"}, 400))
                return
        else:
            data = {}

        # гейт политики: до принятия политики запрещены все POST, кроме accept
        if config.policy_required() and path != "/api/policy/accept":
            self._send(*_json({"error": "policy required"}, 403))
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
            "/api/settings/reset": self._settings_reset,
            "/api/mesh/ping": self._mesh_ping,
            "/api/mesh/invite": self._mesh_invite,
            "/api/mesh/regenerate": self._mesh_regenerate,
            "/api/mesh/node/add": self._mesh_node_add,
            "/api/mesh/node/remove": self._mesh_node_remove,
        }.get(path)
        if handler:
            handler(data)
        else:
            self._send(*_json({"error": "unknown endpoint"}, 404))

    # --- POST handlers ---
    def _vpn_mode(self, data):
        on = _as_bool(data.get("on"))
        config.set("vpn_mode", on)
        if on:
            threading.Thread(target=core.sync, daemon=True).start()
            resp = {"ok": True, "vpn_mode": True, "msg": "vpn on"}
        else:
            threading.Thread(target=core.set_direct, daemon=True).start()
            resp = {"ok": True, "vpn_mode": False, "msg": "прямой режим"}
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
        self._send(*_json({"ok": True, "removed": removed}))

    def _keys_remove(self, data):
        uri = data.get("uri", "")
        if not uri:
            self._send(*_json({"ok": False, "error": "no uri"}, 400))
            return
        removed = pool.remove_key(uri)
        if removed and pool.dead_reason(uri) is None:
            pool.dead_add(uri, "user_removed")
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
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length) if length else b""
            data = json.loads(body.decode("utf-8")) if body else {}
        except (ValueError, UnicodeDecodeError):
            self._send(*_json({"ok": False, "error": "invalid json body"}, 400))
            return
        try:
            rev = int(data.get("rev") or 0)
        except (TypeError, ValueError):
            rev = 0
        config.set("policy_rev_accepted", rev)
        config.save_settings()
        self._send(*_json({"ok": True, "rev": rev}))

    def _mesh_register_raw(self):
        """Публичная регистрация узла у головного сервера (v1.8.0).

        Проверка token == config.master_token; успешный узел добавляется в меш
        с ролью node (подчинённый). Без токена / неверный токен — 403."""
        expected = (config.get("master_token") or "").strip()
        if not expected:
            self._send(*_json({"ok": False, "error": "registration closed"}, 403))
            return
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length > 65536:
                self._send(*_json({"ok": False, "error": "body too large"}, 400))
                return
            body = self.rfile.read(length) if length else b""
            data = json.loads(body.decode("utf-8")) if body else {}
        except (ValueError, UnicodeDecodeError):
            self._send(*_json({"ok": False, "error": "invalid json body"}, 400))
            return
        if str(data.get("token") or "") != expected:
            self._send(*_json({"ok": False, "error": "bad master token"}, 403))
            return
        node, err = mesh.add(data.get("name"), data.get("region") or "RU",
                             data.get("host"), data.get("port"), role="node")
        if err:
            self._send(*_json({"ok": False, "error": err}, 400))
            return
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

    def _security_password(self, data):
        pw = str(data.get("password") or "").strip()
        config.set("ui_token", pw or "")
        _load_ui_token()
        self._send(*_json({"ok": True, "token_set": bool(pw)}))

    def _security_twofa(self, data):
        pin = str(data.get("pin") or "").strip()
        if pin == "":
            config.set("twofa", False)
            config.set("ui_pin", "")
            msg = "2FA выключена"
        else:
            config.set("twofa", True)
            config.set("ui_pin", pin)
            msg = "2FA включена"
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
        ok, msg = updater.apply()
        if ok:
            # применение прошло — рестарт основной процесс; HTTP-ответ уже не дойдёт
            threading.Timer(0.8, os._exit, args=(0,)).start()
        self._send(*_json({"ok": ok, "msg": msg}))

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
        s = subs.find(uid)
        if not s:
            self._send(*_json({"ok": False, "error": "subscription not found"}, 400))
            return
        key, sub = subs.add_key(uid, remark=remark)
        if not sub:
            self._send(*_json({"ok": False, "error": "subscription not found"}, 400))
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
        """Внесение оплаты: создание/продление подписки.
        Одинаковый тариф суммирует время; другой — откладывается (plan_next)."""
        plan = str(data.get("plan", "") or "").strip()
        if plan and plan not in config.SUBS_PLANS:
            self._send(*_json({"ok": False, "error": "тариф %s не найден" % plan}, 400))
            return
        sub, status, msg = subs.purchase(
            uid=str(data.get("uid", "") or "").strip() or None,
            name=str(data.get("name", "") or "").strip() or None,
            plan=plan,
            remark=str(data.get("remark", "") or "").strip())
        if status == "error":
            self._send(*_json({"ok": False, "error": msg}, 400))
            return
        if status == "created":
            self._subs_apply_clients_bg()  # новые ключи нужно добавить в xray
        self._send(*_json({"ok": True, "sub": sub, "status": status, "msg": msg}))

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
                            cur[f] = int(v[f] or 0)
                        except (TypeError, ValueError):
                            return self._send(*_json({"ok": False,
                                                      "error": "поле %s не число" % f}, 400))
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
        for key in ("server_name", "auto_refresh", "mesh_id",
                    "show_mesh", "show_subs"):
            if key in data:
                val = data[key]
                if key in ("auto_refresh", "show_mesh", "show_subs"):
                    val = _as_bool(val)
                else:
                    val = str(val or "").strip()
                config.set(key, val)
        config.set("mesh_master", False)
        self._send(*_json({"ok": True, "settings": _settings()["settings"]}))

    def _settings_reset(self, data):
        config.reset_settings()
        _load_ui_token()
        self._send(*_json({"ok": True, "msg": "настройки сброшены"}))

    def _mesh_ping(self, data):
        self._send(*_json({"ok": True, "nodes": mesh.ping_all()}))

    def _mesh_invite(self, data):
        self._send(*_json({"ok": True, "invite": mesh.invite()}))

    def _mesh_regenerate(self, data):
        self._send(*_json({"ok": True, "invite": mesh.regenerate()}))

    def _mesh_node_add(self, data):
        node, err = mesh.add(data.get("name"), data.get("region"),
                             data.get("host"), data.get("port"),
                             data.get("role"),
                             auto_name=_as_bool(data.get("auto_name")))
        if err:
            self._send(*_json({"ok": False, "error": err}, 400))
            return
        # секрет доверия эксклюзивного узла (role=test) отдаётся ТОЛЬКО при регистрации
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
def _stats():
    st = config.get_state()
    traffic = int((st.get("down") or 0) + (st.get("up") or 0))
    subs_all = subs.all()
    total = len(subs_all)
    now = int(time.time())
    week_ago = now - 7 * 86400
    active = sum(1 for s in subs_all if s.get("enabled", True))
    new_week = sum(1 for s in subs_all if s.get("created", 0) >= week_ago)
    by_plan = {}
    for s in subs_all:
        p = s.get("plan", config.SUBS_PLAN_DEFAULT)
        b = by_plan.setdefault(p, [0, 0])
        b[0] += 1
        b[1] += int((config.SUBS_PLANS.get(p) or {}).get("price", 0))
    rows = []
    for p, (cnt, income) in by_plan.items():
        plan = config.SUBS_PLANS.get(p) or {}
        rows.append({
            "plan": p,
            "name": plan.get("name", p),
            "price": plan.get("price", 0),
            "count": cnt,
            "share": round(cnt * 100.0 / total, 1) if total else 0,
            "income": income,
        })
    rows.sort(key=lambda r: -r["count"])
    return {
        "ok": True,
        "total": total,
        "active": active,
        "new_week": new_week,
        "traffic_month": traffic,
        "income_month": sum(r["income"] for r in rows),
        "rows": rows,
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
            "tgws_port": config.TGWS_PORT,
            "version": config.VERSION,
            "version_name": config.VERSION_NAME,
            "uptime": int(time.time() - config._BOOT_TS),
            "server_name": config.get("server_name", "Home"),
            "auto_refresh": config.get("auto_refresh", True),
            "mesh_id": config.get("mesh_id", ""),
            "show_mesh": config.get("show_mesh", True),
            "show_subs": config.get("show_subs", True),
            "mesh_master": False,
        },
    }


def _sec():
    v = config.VLESS_PUBLIC
    return {
        "ok": True,
        "pbk": v.get("public_key", ""),
        "sid": v.get("short_id") or "",
        "sni": v.get("sni", ""),
        "enabled": bool(v.get("enabled") and v.get("uuid")),
        "ui_token_set": bool(config.get("ui_token", "")),
        "twofa": config.get("twofa", False),
        "access": {
            "lan_only": config.get("lan_only", False),
            "block_scanners": config.get("block_scanners", False),
            "rate_limit": config.get("rate_limit", True),
        },
    }


def serve(port=None):
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
    config.log("Aurora v%s started (UI :%d, xray :%d%s)" % (
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