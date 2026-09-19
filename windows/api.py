# Aurora v1.0 — HTTP API: /api/* + панель. Чистый ThreadingHTTPServer (без фреймворков).

import json
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import config
import core
import pool
import recovery
import rusegment
import source
import telemetry
import tgws
import ui

# origins, которым разрешены POST
_ALLOWED_ORIGINS = {"127.0.0.1", "localhost", config.VM_HOST, "::1"}


def _json(data, status=200):
    body = json.dumps(data, ensure_ascii=False).encode("utf-8")
    return (status, "application/json; charset=utf-8", body)


def _origin_ok(self):
    origin = self.headers.get("Origin", "")
    if not origin:
        return True
    host = re.sub(r"^https?://", "", origin).split(":")[0]
    return host in _ALLOWED_ORIGINS


def _vless_ext():
    """Внешняя vless-ссылка для подключения к домашнему прокси ИЗВНЕ."""
    v = config.VLESS_PUBLIC
    if not v.get("enabled") or not v.get("uuid"):
        return {}
    import urllib.parse
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
    host = config.get_public_ip() or v.get("host", "") if hasattr(config, "get_public_ip") else v.get("host", "")
    link = "vless://%s@%s:%s?%s#Aurora-Out" % (
        v["uuid"], host, v.get("port", 8443), q)
    return {
        "link": link,
        "host": host,
        "port": v.get("port", 8443),
        "uuid": v["uuid"],
        "sni": v.get("sni") or v.get("host", ""),
        "pbk": v.get("public_key", ""),
        "sid": v.get("short_id") or "",
        "fp": "chrome",
        "enabled": True,
    }


def build_state():
    st = config.get_state()
    st["version"] = config.VERSION
    st["version_name"] = config.VERSION_NAME
    st["app"] = config.APP_NAME
    st["vpn_mode"] = config.get("vpn_mode", True)
    st["auto_recovery"] = config.get("auto_recovery", True)
    st["vless_now"] = core.get_vless_now() or "-"
    st["egress_ip"] = core.egress_ip()
    st["comm"] = st.pop("comm", {"state": "idle", "msg": ""})
    st["vless_ext"] = _vless_ext()
    # ключи в пуле
    keys = pool.get_keys()
    vless_now = st["vless_now"]
    st["keys_total"] = len(keys)
    st["keys"] = []
    for k in keys:
        uri = k.get("uri", "")
        hs = pool.get_status(uri)
        st["keys"].append({
            "uri": uri,
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
            self._send(200, "text/html; charset=utf-8", ui.PAGE.encode("utf-8"))
            return
        if path == "/style.css":
            self._send(200, "text/css; charset=utf-8", ui.STYLE.encode("utf-8"))
            return
        if path == "/app.js":
            self._send(200, "application/javascript; charset=utf-8", ui.APP.encode("utf-8"))
            return
        if path == "/api/state":
            self._send(*_json(build_state()))
            return
        if path == "/api/log":
            self._send(*_json({"lines": config.log_tail()}))
            return
        if path == "/api/recovery/log":
            self._send(*_json(recovery.status()))
            return
        if path == "/api/tgws/status":
            self._send(*_json(tgws.status()))
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
        if not _origin_ok(self):
            self._send(*_json({"error": "cross-origin blocked"}, 403))
            return
        path = self.path.split("?", 1)[0]

        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length) if length else b""
            data = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            data = {}

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
            "/api/agent/cmd": self._agent_cmd,
            "/api/tgws/restart": self._tgws_restart,
            "/api/rusegment/check": self._rusegment_check,
        }.get(path)
        if handler:
            handler(data)
        else:
            self._send(*_json({"error": "unknown endpoint"}, 404))

    # --- POST handlers ---
    def _vpn_mode(self, data):
        on = bool(data.get("on"))
        config.set("vpn_mode", on)
        if on:
            threading.Thread(target=core.sync, daemon=True).start()
            resp = {"ok": True, "vpn_mode": True, "msg": "vpn on"}
        else:
            threading.Thread(target=core.set_direct, daemon=True).start()
            resp = {"ok": True, "vpn_mode": False, "msg": "прямой режим"}
        self._send(*_json(resp))

    def _rotate(self, data):
        ok, msg = core.set_active_tag(data.get("tag", "")) if data.get("tag") \
            else (core.rotate() is not None, "rotated")
        self._send(*_json({"ok": ok, "msg": msg}))

    def _keys_add(self, data):
        uri = str(data.get("uri", "") or "").strip()
        if not uri:
            self._send(*_json({"ok": False, "error": "empty uri"}))
            return
        key = source._key_from_uri(uri)
        if not key:
            self._send(*_json({"ok": False, "error": "invalid vless uri"}))
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
            self._send(*_json({"ok": False, "error": "лимит ключей"}))
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
        self._send(*_json(r))

    def _keys_cleanup(self, data):
        removed = pool.cleanup()
        self._send(*_json({"ok": True, "removed": removed}))

    def _keys_remove(self, data):
        uri = data.get("uri", "")
        if not uri:
            self._send(*_json({"ok": False, "error": "no uri"}))
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

    def _agent_cmd(self, data):
        cmd = data.get("command", "")
        r = recovery.send_agent(cmd, data.get("args"))
        self._send(*_json({"ok": bool(r), "result": r}))

    def _tgws_restart(self, data):
        ok = tgws.restart()
        tgws.refresh_status()
        self._send(*_json({"ok": ok}))

    def _rusegment_check(self, data):
        started = rusegment.check_all()
        self._send(*_json({"ok": True, "started": started}))


def serve(port=None):
    port = port or config.UI_PORT
    httpd = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    httpd.daemon_threads = True
    httpd.allow_reuse_address = True
    config.log("Aurora v%s started (UI :%d, xray :%d)" % (config.VERSION, port, config.XRAY_PORT))
    httpd.serve_forever()