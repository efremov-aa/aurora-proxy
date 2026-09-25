import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
CHILD = r'''
import base64
import json
import os
import stat
import sys

tree = sys.argv[1]
data = sys.argv[2]
case = sys.argv[3]
os.environ["AURORA_DATA_DIR"] = data
sys.path.insert(0, tree)

URI = "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=tcp&security=reality&pbk=abc&sid=0123456789abcdef&flow=xtls-rprx-vision#node"
PRIVATE_KEY = base64.urlsafe_b64encode(b"a" * 32).rstrip(b"=").decode("ascii")
PUBLIC_KEY = base64.urlsafe_b64encode(b"b" * 32).rstrip(b"=").decode("ascii")


def write_json(name, value):
    with open(os.path.join(data, name), "w", encoding="utf-8") as f:
        json.dump(value, f)


def write_bytes(name, value):
    with open(os.path.join(data, name), "wb") as f:
        f.write(value)


def read_bytes(name):
    with open(os.path.join(data, name), "rb") as f:
        return f.read()


def encrypted(name):
    raw = read_bytes(name)
    assert raw.startswith((b"AURORA1", b"AURORA2")), name
    return raw


def expect_storage_error(fn):
    try:
        fn()
    except Exception as exc:
        assert exc.__class__.__name__ == "StorageDataError", repr(exc)
        return
    raise AssertionError("StorageDataError was not raised")


if case == "settings_legacy":
    write_json("settings.json", {"ui_token": "settings-secret", "rate_limit": True})
    import config
    config.load_settings()
    assert config.get("ui_token") == "settings-secret"
    raw = encrypted("settings.json")
    assert b"settings-secret" not in raw
    config.set("ui_token", "settings-secret-2")
    assert b"settings-secret-2" not in encrypted("settings.json")
elif case == "vless_legacy":
    if os.path.basename(tree).lower() == "windows":
        write_json("vless_public.json", {
            "enabled": True, "port": 8443, "host": "127.0.0.1",
            "uuid": "22222222-2222-4222-8222-222222222222",
            "private_key": PRIVATE_KEY, "public_key": PUBLIC_KEY,
            "short_id": "0123456789abcdef", "sni": "example.com",
            "flow": "xtls-rprx-vision",
        })
        import config
        value = config.ensure_vless()
        assert value["private_key"] == PRIVATE_KEY
        raw = encrypted("vless_public.json")
        assert PRIVATE_KEY.encode("ascii") not in raw
elif case == "mesh_legacy":
    write_json("mesh_nodes.json", [{
        "id": "n1", "name": "Test", "region": "RU", "host": "example.com",
        "port": 443, "role": "test", "added": 1, "secret": "mesh-secret",
    }])
    import mesh
    assert mesh._NODES[0]["secret"] == "mesh-secret"
    raw = encrypted("mesh_nodes.json")
    assert b"mesh-secret" not in raw
    mesh._save()
    assert b"mesh-secret" not in encrypted("mesh_nodes.json")
elif case == "status_dead":
    import config
    import crypt
    crypt.save_json(os.path.join(data, "keys.json"), [{
        "uri": URI, "host": "example.com", "port": 443,
        "tag": "vless-test", "source": "my",
    }])
    write_json("status.json", {URI: {"status": "ok", "ping_ms": 1, "exit_ip": "1.2.3.4"}})
    write_json("dead.json", {URI: {"reason": "autodead_conn", "ts": 1}})
    import pool
    pool.load()
    assert pool.get_status(URI)["status"] == "ok"
    assert pool.dead_reason(URI) == "autodead_conn"
    assert pool.blocked(URI)
    status_raw = encrypted("status.json")
    dead_raw = encrypted("dead.json")
    assert URI.encode() not in status_raw
    assert URI.encode() not in dead_raw
    assert URI not in crypt.load_json(os.path.join(data, "status.json"))
    assert URI not in crypt.load_json(os.path.join(data, "dead.json"))
    pool.dead_add(URI, "user_removed")
    pool.load()
    assert pool.dead_reason(URI) == "user_removed"
    assert pool.blocked(URI)
elif case == "security_legacy":
    write_json("admin_secret.json", {"admin_token": "admin-secret", "created_at": 1})
    import security
    security.init()
    raw = encrypted("admin_secret.json")
    assert b"admin-secret" not in raw
    result = security.rotate()
    assert isinstance(result, str) and result
    assert b"admin-secret" not in encrypted("admin_secret.json")
elif case == "security_corrupt":
    write_bytes("admin_secret.json", b"not-json")
    import security
    expect_storage_error(security.init)
    assert os.path.exists(os.path.join(data, "admin_secret.json.corrupt"))
elif case == "tgws":
    import tgws
    secret = tgws._get_secret()
    raw = encrypted("tg_secret.txt")
    assert secret.encode() not in raw
    assert tgws._get_secret() == secret
elif case == "keytest":
    import source
    path = os.path.join(data, "keytest_cfg_test.json")
    source._write_keytest_config(path, {"inbounds": []})
    raw = read_bytes("keytest_cfg_test.json")
    assert not raw.startswith(b"AURORA1")
    if os.name != "nt":
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    os.remove(path)
    try:
        source._write_keytest_config(path, {"bad": object()})
    except Exception:
        pass
    else:
        raise AssertionError("invalid keytest config was accepted")
    assert not os.path.exists(path)
else:
    raise AssertionError(case)

print("A031_CHILD_OK")
'''


def run_case(path, case):
    data = tempfile.mkdtemp(prefix="aurora-a031-")
    try:
        result = subprocess.run(
            [sys.executable, "-c", CHILD, path, data, case],
            cwd=path,
            text=True,
            capture_output=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "A031_CHILD_OK" in result.stdout, result.stdout
    finally:
        import shutil
        shutil.rmtree(data, ignore_errors=True)


CASES = (
    "settings_legacy",
    "vless_legacy",
    "mesh_legacy",
    "status_dead",
    "security_legacy",
    "security_corrupt",
    "tgws",
    "keytest",
)

if __name__ == "__main__":
    for tree in (os.path.join(ROOT, "windows"), ROOT):
        for case in CASES:
            run_case(tree, case)
    print("A031_STORAGE_OK")
