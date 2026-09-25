
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import api
import config


class Headers:
    def __init__(self, pairs):
        self._pairs = list(pairs.items()) if isinstance(pairs, dict) else list(pairs)

    def get(self, name, default=None):
        for key, value in self._pairs:
            if key.lower() == name.lower():
                return value
        return default

    def get_all(self, name, default=None):
        values = [value for key, value in self._pairs if key.lower() == name.lower()]
        return values if values else list(default or [])


class Request:
    def __init__(self, headers, client="127.0.0.1"):
        self.headers = Headers(headers)
        self.client_address = (client, 12345)
        self.path = "/api/vpn_mode"


def req(headers, client="127.0.0.1"):
    return Request(headers, client)


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    old_vm = config.VM_HOST
    old_port = config.UI_PORT
    old_token = api._UI_TOKEN
    old_enabled = api.security.enabled
    old_check = api.security.check
    try:
        config.VM_HOST = "127.0.0.1"
        config.UI_PORT = 8890
        api._UI_TOKEN = "panel-token"
        api.security.enabled = lambda: False
        api.security.check = lambda headers, ip: False
        check(api._host_allowed("127.0.0.1"), "configured loopback host rejected")
        check(not api._host_allowed("203.0.113.7"), "foreign literal host accepted")
        check(api._host_ok(req({"Host": "127.0.0.1:8890"})), "valid Host rejected")
        check(not api._host_ok(req([("Host", "127.0.0.1:8890"), ("Host", "localhost:8890")])), "duplicate Host accepted")
        check(not api._origin_ok(req({"Host": "127.0.0.1:8890"})), "originless loopback accepted")
        check(api._origin_ok(req({"Host": "127.0.0.1:8890", "X-Aurora-Request": "1"})), "single marker rejected")
        check(not api._origin_ok(req([("Host", "127.0.0.1:8890"), ("X-Aurora-Request", "1"), ("X-Aurora-Request", "1")])), "duplicate marker accepted")
        check(api._origin_ok(req({"Host": "127.0.0.1:8890", "Origin": "http://127.0.0.1:8890"})), "matching Origin rejected")
        check(not api._origin_ok(req({"Host": "127.0.0.1:8890", "Origin": "http://localhost:8890"})), "mismatched Origin accepted")
        check(not api._origin_ok(req({"Host": "127.0.0.1:8890", "Origin": "https://127.0.0.1:8890"})), "https Origin accepted")
        check(not api._origin_ok(req({"Host": "127.0.0.1:8890", "Origin": "null"})), "null Origin accepted")
        check(not api._origin_ok(req({"Host": "127.0.0.1:8890", "Origin": "http://127.0.0.1:8890/path"})), "Origin path accepted")
        check(not api._admin_ok(req({"Host": "127.0.0.1:8890", "X-Aurora-Request": "1"})), "loopback admin bypass remains")
        check(api._admin_ok(req({"Host": "127.0.0.1:8890", "X-Aurora-Request": "1", "X-Auth": "panel-token"})), "panel token rejected")
        api.security.enabled = lambda: True
        api.security.check = lambda headers, ip: headers.get("Authorization") == "Bearer remote-token"
        check(api._admin_ok(req({"Host": "127.0.0.1:8890", "X-Aurora-Request": "1", "Authorization": "Bearer remote-token"})), "Bearer admin rejected")
        source = (ROOT / "api.py").read_text(encoding="utf-8-sig")
        check(source.index('if path == "/api/setup/complete"') < source.index("if not _admin_ok(self)"), "setup route is behind admin gate")
        ui = (ROOT / "ui" / "app.js").read_text(encoding="utf-8-sig")
        check("sessionStorage.getItem('aurora_token')" in ui, "panel token handoff missing")
        check("sessionStorage.setItem(LS.tfa, d.pin)" in ui, "2FA handoff missing")
    finally:
        config.VM_HOST = old_vm
        config.UI_PORT = old_port
        api._UI_TOKEN = old_token
        api.security.enabled = old_enabled
        api.security.check = old_check


main()
print("A058_CHILD_OK")
