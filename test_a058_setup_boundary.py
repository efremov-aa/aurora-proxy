import os
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TREES = (ROOT / "windows", ROOT)

WORKER = textwrap.dedent(r"""
    import json
    import os
    import sys
    import tempfile

    tree = sys.argv[1]
    os.environ["AURORA_DATA_DIR"] = tempfile.mkdtemp(prefix="a058_data_")
    os.environ["AURORA_HOST"] = "10.1.0.238"
    os.environ["AURORA_SETUP_TOKEN"] = "aurora-setup-token-0123456789"
    sys.path.insert(0, tree)

    import api
    import config

    failed = []

    def check(name, cond):
        if cond:
            return
        failed.append(name)

    class Request(object):
        def __init__(self, client="127.0.0.1"):
            self.client_address = (client, 40000)
            self.headers = {}
            self.path = "/api/setup/complete"
            self.status = None
            self.body = None

        def _send(self, status, ctype, body):
            self.status = status
            self.body = body

    def send(client="127.0.0.1", **over):
        data = {"server_name": "Node", "password": "correct-horse-battery-staple",
                "pin": "123456", "policy_rev": config.POLICY_REV,
                "lan_only": True, "block_scanners": True, "rate_limit": True}
        data.update(over)
        req = Request(client)
        api.Handler._setup_complete(req, data)
        payload = {}
        try:
            payload = json.loads(req.body.decode("utf-8"))
        except Exception:
            pass
        return req.status, payload

    def reset():
        config.set("setup_complete", False)
        config.SETUP_TOKEN = ""
        api.security.status = lambda: {"enabled": False}

    def hard_reset():
        reset()
        config.set("ui_token", "")
        config.set("twofa", False)

    reset()

    check("is_local_loopback", api._is_local(Request("127.0.0.1")) is True)
    check("is_local_lan", api._is_local(Request("10.1.0.146")) is False)
    check("in_lan", api._host_in_lan("10.1.0.146") is True)
    check("in_lan_public", api._host_in_lan("8.8.8.8") is False)

    req = Request()
    api.Handler._setup_complete(req, None)
    check("none_data_400", req.status == 400)
    req = Request()
    api.Handler._setup_complete(req, "not-a-dict")
    check("non_dict_400", req.status == 400)

    status, payload = send(server_name="")
    check("name_400", status == 400 and payload.get("error") == "invalid server name")
    status, payload = send(password="short")
    check("pass_short_400", status == 400 and payload.get("error") == "invalid password")
    status, payload = send(password="has space inside")
    check("pass_space_400", status == 400 and payload.get("error") == "invalid password")
    status, payload = send(pin="12")
    check("pin_400", status == 400 and payload.get("error") == "invalid pin")
    status, payload = send(policy_rev=999)
    check("rev_400", status == 400 and payload.get("error") == "policy revision required")
    status, payload = send(ui_port=99999)
    check("port_high_400", status == 400 and payload.get("error") == "invalid ports")
    logs = []
    real_log = config.log
    config.log = lambda msg: logs.append(str(msg))
    status, payload = send(xray_port=0, xray_api_port=0, tgws_port=0, mesh_invite="zzz")
    config.log = real_log
    check("port_zero_tolerated", status == 200 and payload.get("ok") is True
          and payload.get("mesh_joined") is False)
    check("invite_skip_logged", any("setup mesh invite skipped" in item for item in logs))
    hard_reset()
    status, payload = send(ui_port="", xray_port="", mesh_invite="zzz")
    check("port_blank_tolerated", status == 200 and payload.get("ok") is True)
    hard_reset()

    logs = []
    config.log = lambda msg: logs.append(str(msg))
    send(pin="12")
    config.log = getattr(config, "log", config.log)
    check("reject_logged", any("setup rejected: invalid pin" in item for item in logs))
    status, payload = send(mesh_invite=5)
    check("invite_400", status == 400 and payload.get("error") == "invalid mesh invite")

    status, payload = send("8.8.8.8")
    check("remote_403", status == 403)
    check("remote_error", payload.get("error") == "setup requires localhost")

    check("claimed_false", api._instance_claimed() is False)
    status, payload = send("10.1.0.146", pin="1")
    check("lan_open_400", status == 400)

    api.security.status = lambda: {"enabled": True}
    check("claimed_true", api._instance_claimed() is True)
    status, payload = send("10.1.0.146", pin="1")
    check("lan_claimed_allowed", status == 400)
    config.SETUP_TOKEN = "aurora-setup-token-0123456789"
    status, payload = send("10.1.0.146", pin="1")
    check("lan_claimed_token_required", status == 403)
    check("lan_claimed_token_error", payload.get("error") == "setup token required")
    reset()
    check("claimed_reset", api._instance_claimed() is False)

    config.SETUP_TOKEN = "aurora-setup-token-0123456789"
    status, payload = send(pin="1")
    check("token_missing_403", status == 403)
    check("token_error", payload.get("error") == "setup token required")
    status, payload = send(pin="1", setup_token="wrong-token-value")
    check("token_wrong_403", status == 403)
    status, payload = send(pin="1", setup_token="aurora-setup-token-0123456789")
    check("token_ok_reaches_validation", status == 400
          and payload.get("error") == "invalid pin")
    reset()

    state = api.build_state(local=True)
    check("state_setup_token_required", "setup_token_required" in state)
    check("state_setup_token_false", state["setup_token_required"] is False)
    config.SETUP_TOKEN = "aurora-setup-token-0123456789"
    check("state_setup_token_true",
          api.build_state(local=True)["setup_token_required"] is True)
    reset()

    check("metadata_count", len(config.METADATA_HOSTS) == 4)
    for host in ("169.254.169.254", "100.100.100.200", "168.63.129.16", "fd00:ec2::254"):
        check("metadata_" + host, host in config.METADATA_HOSTS)
        check("peer_" + host, api._valid_peer_host(host) is False)
        check("public_" + host, config._valid_public_host(host) is None)
    check("peer_loopback", api._valid_peer_host("127.0.0.1") is False)
    check("peer_unspecified", api._valid_peer_host("0.0.0.0") is False)
    check("peer_lan_ok", api._valid_peer_host("10.1.0.5") is True)
    check("peer_name_ok", api._valid_peer_host("node.example") is True)
    check("peer_empty", api._valid_peer_host("") is False)
    check("peer_slash", api._valid_peer_host("a/b") is False)

    status, payload = send()
    check("success_200", status == 200)
    check("success_ok", payload.get("ok") is True)
    check("success_state", api.build_state(local=True)["setup_complete"] is True)
    status, payload = send()
    check("done_409", status == 409)
    check("done_error", payload.get("error") == "setup already complete")

    if failed:
        print("A058_CHILD_FAIL", " ".join(failed))
        raise SystemExit(1)
    print("A058_CHILD_OK")
""")


def read(path):
    return path.read_text(encoding="utf-8-sig")


def region(text, start, end):
    i = text.index(start)
    j = text.index(end, i + 1)
    return text[i:j]


def contract(tree):
    api = read(tree / "api.py")
    cfg = read(tree / "config.py")
    app = read(tree / "ui" / "app.js")
    html = read(tree / "ui" / "index.html")
    assert "self._setup_complete(setup_data or {})" in api, tree
    assert "def _instance_claimed():" in api, tree
    assert "config.SETUP_TOKEN and not _token_matches" in api, tree
    assert '"setup token required"' in api, tree
    assert 'st["setup_token_required"] = bool(config.SETUP_TOKEN)' in api, tree
    assert "if str(ip) in config.METADATA_HOSTS:" in api, tree
    assert "if not local and _instance_claimed():" not in api, tree
    assert "setup from LAN on claimed instance" in api, tree
    assert 'if path == "/favicon.ico":' in api, tree
    assert "image/svg+xml; charset=utf-8" in api, tree
    assert "api: %s failed: %s" in api, tree
    assert "METADATA_HOSTS = frozenset((" in cfg, tree
    assert "def _read_setup_token():" in cfg, tree
    assert "AURORA_SETUP_TOKEN" in cfg, tree
    assert "if str(address) in METADATA_HOSTS:" in cfg, tree
    assert "setup_token" in app, tree
    assert "var subsTask = loadSubs();" in app, tree
    assert "typeof subsTask.then === 'function'" in app, tree
    assert "loadSubs().then(" not in app, tree
    assert "var payments = (stats && (Array.isArray(stats.payments)" in app, tree
    assert ")) || [];" in app, tree
    assert 'id="setup-token"' in html, tree
    assert '<link rel="icon" href="/favicon.ico">' in html, tree
    assert api.count("def _setup_reject(req, reason, status=400):") == 1, tree
    assert api.count("_setup_reject(self, ") >= 10, tree
    assert 'config.log("api: setup rejected: %s (%s)"' in api, tree
    assert 'getattr(req, "path", "")' in api, tree
    assert api.count("for port_key in (\"ui_port\", \"xray_port\", \"xray_api_port\", \"tgws_port\"):") == 1, tree
    assert 'port_value == "" or (type(port_value) is int and port_value == 0)' in api, tree
    assert "ports[port_key] = getattr(config, port_key.upper())" in api, tree
    setup_body = region(api, "def _setup_complete(self, data):", "def _mesh")
    assert setup_body.count("_setup_reject(self, ") >= 10, tree
    assert 'self._send(*_json({"ok": False, "error": "invalid server name"}, 400))' not in setup_body, tree
    assert "function setupValidate(all) {" in app, tree
    assert app.count("var err = setupValidate(true);") == 1, tree
    assert app.count("var err = setupValidate();") == 1, tree
    for needle in ("if (all || SETUP.step === 0) {",
                   "if ((all || SETUP.step === 1) && ",
                   "if ((all || SETUP.step === 2) && ",
                   "if ((all || SETUP.step === 3) && ",
                   "if (all || SETUP.step === 5) {"):
        assert app.count(needle) == 1, (needle, tree)
    finish = app[app.index("function setupFinish() {"):][:400]
    assert "setupValidate(true)" in finish, tree
    assert "postJSON('/api/setup/complete'" in finish, tree
    assert "shown: false" in app, tree
    assert app.count("if (SETUP.shown) return;") == 1, tree
    show = region(app, "function setupShow() {", "function setupFinish(")
    assert show.index("if (SETUP.shown) return;") < show.index("SETUP.step = 0;"), tree
    assert "SETUP.step = 0;" in show, tree
    assert "setup mesh invite skipped" in api, tree
    assert '"mesh_joined": mesh_joined,' in api, tree
    assert "mesh invite rejected" not in api, tree
    assert "function setupPort(key, value) {" in app, tree
    assert "SETUP.prefill = {" in show, tree
    assert app.count("setupPort('ui_port', d.ui_port)") == 1, tree
    assert app.count("setupPort('xray_port', d.xray_port)") == 1, tree
    assert app.count("setupPort('xray_api_port', d.xray_api_port)") == 1, tree
    assert app.count("setupPort('tgws_port', d.tgws_port)") == 1, tree
    assert "if (raw === '') continue;" in app, tree
    assert app.count("d.mesh_invite.indexOf('aurora://invite?') !== 0") == 1, tree
    return region(api, "def _instance_claimed():", "def _ui_qr():")


def main():
    for tree in TREES:
        r = subprocess.run([sys.executable, "-c", WORKER, str(tree)], cwd=str(tree),
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace")
        out = (r.stdout or "") + (r.stderr or "")
        assert "A058_CHILD_OK" in out, (tree, out[-1500:])
        contract(tree)
        print("OK", tree.name)
    blocks = [contract(tree) for tree in TREES]
    assert blocks[0] == blocks[1], "parity"
    print("A058_SETUP_OK")


if __name__ == "__main__":
    main()
