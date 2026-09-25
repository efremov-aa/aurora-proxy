import base64
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PRIVATE_KEY = base64.urlsafe_b64encode(b"a" * 32).rstrip(b"=").decode("ascii")
PUBLIC_KEY = base64.urlsafe_b64encode(b"b" * 32).rstrip(b"=").decode("ascii")
UUID = "22222222-2222-4222-8222-222222222222"
KEY_UUID = "33333333-3333-4333-8333-333333333333"
CASES = ("valid", "host", "port", "subscription", "core", "remote", "storage")
CHILD = r'''
import base64
import json
import os
import sys

tree = sys.argv[1]
data = sys.argv[2]
case = sys.argv[3]
os.environ["AURORA_DATA_DIR"] = data
for name in (
    "AURORA_HOST", "AURORA_VLESS_ENABLED", "AURORA_VLESS_PORT", "AURORA_VLESS_HOST",
    "AURORA_VLESS_UUID", "AURORA_VLESS_PRIVATE_KEY", "AURORA_VLESS_PUBLIC_KEY",
    "AURORA_VLESS_SHORT_ID", "AURORA_VLESS_SNI", "AURORA_VLESS_FLOW",
):
    os.environ.pop(name, None)
private_key = base64.urlsafe_b64encode(b"a" * 32).rstrip(b"=").decode("ascii")
public_key = base64.urlsafe_b64encode(b"b" * 32).rstrip(b"=").decode("ascii")
uuid = "22222222-2222-4222-8222-222222222222"
if case != "storage":
    os.environ.update({
        "AURORA_VLESS_ENABLED": "true",
        "AURORA_VLESS_PORT": "8443",
        "AURORA_VLESS_HOST": "example.com",
        "AURORA_VLESS_UUID": uuid,
        "AURORA_VLESS_PRIVATE_KEY": private_key,
        "AURORA_VLESS_PUBLIC_KEY": public_key,
        "AURORA_VLESS_SHORT_ID": "",
        "AURORA_VLESS_SNI": "example.com",
        "AURORA_VLESS_FLOW": "xtls-rprx-vision",
    })
if case == "host":
    os.environ["AURORA_VLESS_HOST"] = "127.0.0.1"
if case == "port":
    os.environ["AURORA_VLESS_PORT"] = "not-a-port"

sys.path.insert(0, tree)
import config
import core
import api
import subs

if case == "storage" and os.path.basename(tree).lower() == "windows":
    import crypt
    with open(os.path.join(data, "vless_public.json"), "w", encoding="utf-8") as f:
        json.dump({"enabled": True, "port": 8443, "uuid": uuid,
                   "private_key": "bad", "public_key": "bad"}, f)
    try:
        config.ensure_vless()
    except config.StorageDataError:
        assert os.path.exists(os.path.join(data, "vless_public.json.corrupt"))
    else:
        raise AssertionError("invalid persisted VLESS was accepted")
elif case == "storage":
    pass
else:
    value = config.vless_public()
    if case == "valid":
        assert value["enabled"] is True
        assert value["host"] == "example.com"
        assert value["uuid"] == uuid
        assert value["private_key"] == private_key
        assert value["public_key"] == public_key
        assert value["short_id"] == ""
        link = api._vless_ext()
        assert link["host"] == "example.com"
        assert link["port"] == 8443
        assert link["link"].startswith("vless://" + uuid + "@example.com:8443?")
        row = {"uid": "u", "token": "t", "name": "n", "plan": "free",
               "expires": 9999999999, "keys": [{"id": "33333333-3333-4333-8333-333333333333"}]}
        assert subs.vless_link(row["keys"][0]["id"], params=subs._vless_params())
    elif case == "host":
        assert value["enabled"] is True
        assert value["host"] == ""
        assert api._vless_ext() == {}
        row = {"used_bytes": 0, "limit_bytes": 1,
               "keys": [{"id": "33333333-3333-4333-8333-333333333333"}]}
        assert "vless://" not in subs.subscription_text(row)
    elif case == "port":
        assert value["enabled"] is False
        assert value["port"] == 0
    elif case == "subscription":
        bad = {"uid": "u", "token": "t", "name": "n", "plan": "free",
               "keys": [{"id": "a@b"}]}
        try:
            subs._validate_subscriptions([bad])
        except ValueError:
            pass
        else:
            raise AssertionError("invalid subscription UUID was accepted")
        good = dict(bad)
        good["keys"] = [{"id": "33333333333343338333333333333333"}]
        assert subs._validate_subscriptions([good])[0]["keys"][0]["id"] == "33333333-3333-4333-8333-333333333333"
    elif case == "core":
        core.pool.get_keys = lambda: []
        core.config.ru_domains = lambda: []
        core.subs.build_client_list = lambda: []
        cfg = core.build_xray_config("direct")
        assert any(i.get("tag") == "vless-in" for i in cfg["inbounds"])
        config.VLESS_PUBLIC = dict(config.VLESS_PUBLIC, uuid="bad", private_key="bad", public_key="bad")
        cfg = core.build_xray_config("direct")
        assert not any(i.get("tag") == "vless-in" for i in cfg["inbounds"])
    elif case == "remote":
        api.core.get_vless_now = lambda: "direct"
        api.core.egress_ip = lambda: "-"
        api.pool.get_keys = lambda: []
        api.mesh.node_count = lambda: 0
        config.STATE["tgws"] = {"link": "secret-link", "running": False}
        state = api.build_state(local=False)
        assert "link" not in state["tgws"]
print("A041_CHILD_OK")
'''


def run_case(tree, case):
    data = tempfile.mkdtemp(prefix="aurora-a041-")
    try:
        result = subprocess.run(
            [sys.executable, "-c", CHILD, tree, data, case],
            cwd=tree, text=True, capture_output=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "A041_CHILD_OK" in result.stdout, result.stdout
    finally:
        import shutil
        shutil.rmtree(data, ignore_errors=True)


for tree in (os.path.join(ROOT, "windows"), ROOT):
    for case in CASES:
        run_case(tree, case)
print("A041_VLESS_OK")
