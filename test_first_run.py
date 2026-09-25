import os
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlencode

ROOT = os.path.dirname(os.path.abspath(__file__))
data = tempfile.mkdtemp(prefix="aurora-wizard-")
os.environ["AURORA_DATA_DIR"] = data
os.environ["AURORA_MESH_POLICY_KEY"] = "aurora-wizard-policy-key-0123456789"
os.environ["AURORA_MESH_MASTER_ID"] = "home-master"
sys.path.insert(0, ROOT)
import config
import api
import mesh
from crypt import _MAGIC

config.DATA_DIR = data
config._SETTINGS_FILE = str(Path(data) / "settings.json")
config.VM_HOST = "10.1.0.77"
config.UI_PORT = 8890
mesh.MESH_FILE = str(Path(data) / "mesh_nodes.json")


class Request:
    client_address = ("127.0.0.1", 12345)
    headers = {}

    def __init__(self, remote=None):
        self.response = None
        if remote:
            self.client_address = (remote, 12345)

    def _send(self, status, ctype, body):
        self.response = (status, body)


def reset():
    config._settings = dict(config._SETTINGS_DEFAULTS)
    mesh._NODES = []


BASE = {
    "server_name": "Wizard node",
    "password": "correct-horse-battery-staple",
    "pin": "123456",
    "policy_rev": config.POLICY_REV,
    "ui_port": config._SETTINGS_DEFAULTS["ui_port"],
    "xray_port": config._SETTINGS_DEFAULTS["xray_port"],
    "xray_api_port": config._SETTINGS_DEFAULTS["xray_api_port"],
    "tgws_port": config._SETTINGS_DEFAULTS["tgws_port"],
    "lan_only": True,
    "block_scanners": True,
    "rate_limit": True,
}

_seq = [0]


def make_invite(**over):
    _seq[0] += 1
    core = {
        "invite_version": 1,
        "issuer": config.mesh_master_id(),
        "token": "cap-token-1-" + "a" * 24,
        "challenge": "%032x" % _seq[0],
        "host": "10.1.0.238",
        "port": 8890,
        "policy_port": 8890,
        "name": "Home",
        "issued_at": int(time.time()),
        "expires_at": int(time.time()) + mesh.INVITE_TTL_S,
    }
    core.update(over)
    return "aurora://invite?" + urlencode(
        list(core.items()) + [("signature", mesh._invite_signature(core))])

calls = {}


def post_ok(scheme, host, port, path, payload, timeout=5.0, headers=None):
    calls["post"] = (scheme, host, port, path, dict(payload))
    return {"ok": True, "node": {"id": "beef", "name": "Home"}}


def post_bad(scheme, host, port, path, payload, timeout=5.0, headers=None):
    return {"ok": False, "error": "rejected"}


original_post = mesh._fetch_post

assert mesh.invite() is None
assert mesh.regenerate() is None
assert config.get("mesh_token", "") == ""

tampered = make_invite()
tampered = tampered[:-1] + ("0" if tampered[-1] != "0" else "1")
ok, err = mesh.join_via_invite(tampered, name="Wizard")
assert ok is False and err == "неверный invite"
assert mesh._NODES == []
ok, err = mesh.join_via_invite("http://example.invalid/?token=x")
assert ok is False and err == "неверный invite"
ok, err = mesh.join_via_invite("")
assert ok is False and err == "неверный invite"

reset()
mesh._fetch_post = post_bad
ok, err = mesh.join_via_invite(make_invite(), name="Wizard")
assert ok is False and err
assert mesh._NODES == []

mesh._fetch_post = post_ok
INVITE = make_invite()
ok, err = mesh.join_via_invite(INVITE, name="Wizard")
assert ok is True and err is None
scheme, host, port, path, payload = calls["post"]
assert (scheme, host, port, path) == ("http", "10.1.0.238", 8890, "/api/mesh/join")
assert "token" not in payload
assert payload["proof"]
assert payload["invite"] == INVITE
assert payload["host"] == config.VM_HOST
assert payload["port"] == config.XRAY_PORT
assert payload["policy_port"] == config.UI_PORT
assert payload["name"] == "Wizard"
assert len(mesh._NODES) == 1
hub = mesh._NODES[0]
assert hub["role"] == "hub" and hub["host"] == "10.1.0.238" and hub["port"] == 8890
assert hub["policy_port"] == 8890
ok, err = mesh.join_via_invite(INVITE, name="Wizard")
assert ok is False and err == "invite уже использован"
ok, err = mesh.join_via_invite(make_invite(), name="Wizard")
assert ok is True and len(mesh._NODES) == 1

reset()
mesh._fetch_post = post_bad
request = Request()
api.Handler._setup_complete(request, dict(BASE, mesh_invite=INVITE))
status, body = request.response
assert status == 200, (status, body)
assert b'"mesh_joined": false' in body
assert config.get("setup_complete") is True
assert mesh._NODES == []

reset()
mesh._fetch_post = post_ok
request = Request()
api.Handler._setup_complete(request, dict(BASE, mesh_invite="not-an-invite"))
status, body = request.response
assert status == 200, (status, body)
assert b'"mesh_joined": false' in body
assert config.get("setup_complete") is True

reset()
mesh._fetch_post = post_ok
request = Request()
api.Handler._setup_complete(request, dict(BASE, mesh_invite=make_invite()))
status, body = request.response
assert status == 200, (status, body)
assert b'"ok": true' in body.lower()
assert b'"mesh_joined": true' in body.lower()
assert config.get("setup_complete") is True
assert config.get("server_name") == "Wizard node"
assert len(mesh._NODES) == 1 and mesh._NODES[0]["role"] == "hub"
assert Path(config._SETTINGS_FILE).read_bytes().startswith(_MAGIC)

remote = Request(remote="203.0.113.7")
api.Handler._setup_complete(remote, {})
assert remote.response[0] == 403

repeat = Request()
api.Handler._setup_complete(repeat, {})
assert repeat.response[0] == 409

reset()
mesh._fetch_post = post_ok
request = Request()
api.Handler._setup_complete(request, dict(BASE, mesh_invite=123))
assert request.response[0] == 400
assert config.get("setup_complete") is False

reset()
mesh._fetch_post = post_ok
request = Request()
api.Handler._setup_complete(request, dict(BASE, mesh_invite="x" * 2049))
assert request.response[0] == 200
assert b'"mesh_joined": false' in request.response[1]
assert config.get("setup_complete") is True

reset()
request = Request()
api.Handler._setup_complete(request, dict(BASE, policy_rev=config.POLICY_REV + 1))
assert request.response[0] == 400
assert config.get("setup_complete") is False

reset()
request = Request()
api.Handler._setup_complete(request, dict(BASE, xray_port=BASE["ui_port"]))
assert request.response[0] == 400
assert config.get("setup_complete") is False

saved_ports = (config.UI_PORT, config.XRAY_PORT, config.XRAY_API_PORT, config.TGWS_PORT)
try:
    candidate = {
        "ui_port": 9100,
        "xray_port": 9101,
        "xray_api_port": 9102,
        "tgws_port": 9103,
    }
    assert config._apply_port_overrides(candidate) is True
    assert (config.UI_PORT, config.XRAY_PORT, config.XRAY_API_PORT, config.TGWS_PORT) == (
        9100, 9101, 9102, 9103,
    )
    assert config._validate_ports(candidate) == candidate
    assert config._validate_ports({"ui_port": 9200, "xray_port": 9200, "xray_api_port": 9201, "tgws_port": 9202}) is None
finally:
    config.UI_PORT, config.XRAY_PORT, config.XRAY_API_PORT, config.TGWS_PORT = saved_ports

mesh._fetch_post = original_post

for name in ("api.py", "windows/api.py", "mesh.py", "windows/mesh.py"):
    text = (Path(ROOT) / name).read_text(encoding="utf-8")
    assert "def join_via_invite" in text or "join_via_invite(" in text, name
    if name.endswith("api.py"):
        gate = 'if config.policy_required() and path != "/api/policy/accept":'
        accept = 'if path == "/api/policy/accept":'
        assert accept in text and gate in text, name
        assert text.index(accept) < text.index(gate), name
        mesh_gate = 'path.startswith("/api/mesh/") and not config.get("show_mesh", False)'
        assert mesh_gate in text, name
        assert text.index(mesh_gate) < text.index('"/api/setup/complete": self._setup_complete'), name
        serve = text[text.index("def serve("):]
        assert serve.index("config.load_settings()") < serve.index("port = port or config.UI_PORT"), name

assert config._SETTINGS_DEFAULTS["show_mesh"] is False
assert config._SETTINGS_DEFAULTS["show_subs"] is False
assert config._SETTINGS_DEFAULTS["setup_complete"] is False

for name in ("ui/app.js", "windows/ui/app.js"):
    text = (Path(ROOT) / name).read_text(encoding="utf-8")
    assert "mesh_invite: $('setup-mesh')" in text, name
    assert "setupJoinInvite" not in text, name
    assert text.count("/api/mesh/join") == 1, name
    assert text.count("/api/mesh/node/add") == 0, name
    assert "PIN: 6 цифр" in text, name
    assert "setup-policy-ok" in text, name
    assert "setup-ui-port" in text, name
    assert "setup-xray-port" in text, name
    assert "setup-xray-api-port" in text, name
    assert "setup-tgws-port" in text, name
    assert "(step + 1) + '/7'" in text, name
    assert "var last = step === 6;" in text, name
    assert "if (j.setup_complete === false) setupShow();" in text, name
    assert "/api/policy/accept" in text, name

for name in ("ui/index.html", "windows/ui/index.html"):
    text = (Path(ROOT) / name).read_text(encoding="utf-8")
    for marker in ("setup-screen", "setup-policy-ok", "setup-ui-port",
                   "setup-xray-port", "setup-xray-api-port", "setup-tgws-port",
                   "setup-name", "setup-password", "setup-pin", "setup-mesh", "setup-finish"):
        assert marker in text, (name, marker)
    assert "1/7" in text, name

print("FIRST_RUN_API_OK")
