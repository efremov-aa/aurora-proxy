import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHILD = r'''
import json
import os
import sys

tree, data, case = sys.argv[1:]
os.environ["AURORA_DATA_DIR"] = data
sys.path.insert(0, tree)


def write_bytes(name, value):
    with open(os.path.join(data, name), "wb") as f:
        f.write(value)


def write_json(name, value):
    write_bytes(name, json.dumps(value, ensure_ascii=False).encode("utf-8"))


def assert_quarantine(name, original):
    path = os.path.join(data, name)
    corrupt = path + ".corrupt"
    assert os.path.isfile(path)
    assert open(path, "rb").read() == original
    assert os.path.isfile(corrupt)
    assert open(corrupt, "rb").read() == original
    assert not os.path.exists(path + ".tmp")


def expect_storage_error(fn):
    try:
        fn()
    except Exception as exc:
        assert exc.__class__.__name__ == "StorageDataError", repr(exc)
        return
    raise AssertionError("StorageDataError was not raised")


if case == "settings_missing":
    import config
    config.load_settings()
    assert config.get("rate_limit") is True
elif case == "settings_valid_empty":
    write_json("settings.json", {})
    import config
    config.load_settings()
    assert config.get("rate_limit") is True
elif case == "settings_invalid":
    original = b'{"rate_limit":"false"}'
    write_bytes("settings.json", original)
    import config
    expect_storage_error(config.load_settings)
    assert_quarantine("settings.json", original)
elif case == "plans_missing":
    import config
    assert isinstance(config.SUBS_PLANS, dict)
elif case == "plans_valid_empty":
    write_json("plans.json", {})
    import config
    assert isinstance(config.SUBS_PLANS, dict)
elif case == "plans_invalid":
    original = b'{"bad":{"name":"Bad","price":true}}'
    write_bytes("plans.json", original)
    expect_storage_error(lambda: __import__("config"))
    assert_quarantine("plans.json", original)
elif case == "pool_missing":
    import config
    import pool
    pool.load()
    assert pool._KEYS == []
    assert pool._STATUS == {}
    assert pool._DEAD == {}
elif case == "pool_valid_empty":
    import config
    import crypt
    crypt.save_json(os.path.join(data, "keys.json"), [])
    write_json("status.json", {})
    write_json("dead.json", {})
    import pool
    pool.load()
    assert pool._KEYS == []
    assert pool._STATUS == {}
    assert pool._DEAD == {}
elif case == "pool_optional_null":
    import config
    import crypt
    crypt.save_json(os.path.join(data, "keys.json"), [{
        "uri": "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=tcp&security=reality&pbk=" + ("A" * 43) + "&flow=xtls-rprx-vision",
        "host": "example.com",
        "port": 443,
        "tag": "vless-example",
        "source": "github",
        "uuid": "11111111-1111-4111-8111-111111111111",
        "pbk": "A" * 43,
        "sid": None,
        "sni": None,
        "fp": "chrome",
        "flow": "xtls-rprx-vision",
    }])
    write_json("status.json", {})
    write_json("dead.json", {})
    import pool
    pool.load()
    assert pool._KEYS[0]["sid"] == ""
    assert pool._KEYS[0]["sni"] == ""
elif case == "pool_invalid_keys":
    original = b"not-json"
    write_bytes("keys.json", original)
    import config
    import crypt
    assert crypt is not None
    import pool
    expect_storage_error(pool.load)
    assert_quarantine("keys.json", original)
elif case == "pool_invalid_status":
    import config
    import crypt
    crypt.save_json(os.path.join(data, "keys.json"), [])
    original = b"[]"
    write_bytes("status.json", original)
    write_json("dead.json", {})
    import pool
    expect_storage_error(pool.load)
    assert_quarantine("status.json", original)
elif case == "pool_invalid_dead":
    import config
    import crypt
    crypt.save_json(os.path.join(data, "keys.json"), [])
    write_json("status.json", {})
    original = b"[]"
    write_bytes("dead.json", original)
    import pool
    expect_storage_error(pool.load)
    assert_quarantine("dead.json", original)
elif case == "mesh_missing":
    import config
    import mesh
    assert mesh._NODES == []
elif case == "mesh_valid_empty":
    write_json("mesh_nodes.json", [])
    import config
    import mesh
    assert mesh._NODES == []
elif case == "mesh_invalid":
    original = b"{}"
    write_bytes("mesh_nodes.json", original)
    import config
    expect_storage_error(lambda: __import__("mesh"))
    assert_quarantine("mesh_nodes.json", original)
elif case == "subs_missing":
    import config
    import subs
    assert subs._SUBS == []
    assert subs.billing_snapshot()["payments"] == []
elif case == "subs_valid_empty":
    import config
    import crypt
    crypt.save_json(os.path.join(data, "subs.json"), [])
    crypt.save_json(os.path.join(data, "billing.json"), {"version": 1, "payments": [], "traffic": {"months": {}}})
    import subs
    assert subs._SUBS == []
    assert subs.billing_snapshot()["payments"] == []
elif case == "subs_invalid":
    original = b"[{}]"
    write_bytes("subs.json", original)
    import config
    expect_storage_error(lambda: __import__("subs"))
    assert_quarantine("subs.json", original)
elif case == "billing_valid_empty":
    import config
    import crypt
    crypt.save_json(os.path.join(data, "billing.json"), {"version": 1, "payments": [], "traffic": {"months": {}}})
    import subs
    assert subs.billing_snapshot()["payments"] == []
elif case == "billing_invalid":
    original = b'{"version":1,"payments":[{}],"traffic":{"months":{}}}'
    write_bytes("billing.json", original)
    import config
    expect_storage_error(lambda: __import__("subs"))
    assert_quarantine("billing.json", original)
else:
    raise AssertionError(case)

print("A029_CHILD_OK")
'''


def run_case(path, case):
    data = tempfile.mkdtemp(prefix="aurora-a029-")
    try:
        result = subprocess.run(
            [sys.executable, "-c", CHILD, path, data, case],
            cwd=path,
            text=True,
            capture_output=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "A029_CHILD_OK" in result.stdout, result.stdout
    finally:
        import shutil
        shutil.rmtree(data, ignore_errors=True)


CASES = (
    "settings_missing",
    "settings_valid_empty",
    "settings_invalid",
    "plans_missing",
    "plans_valid_empty",
    "plans_invalid",
    "pool_missing",
    "pool_valid_empty",
    "pool_optional_null",
    "pool_invalid_keys",
    "pool_invalid_status",
    "pool_invalid_dead",
    "mesh_missing",
    "mesh_valid_empty",
    "mesh_invalid",
    "subs_missing",
    "subs_valid_empty",
    "subs_invalid",
    "billing_valid_empty",
    "billing_invalid",
)

for tree in (os.path.join(ROOT, "windows"), ROOT):
    for name in CASES:
        run_case(tree, name)
print("A029_STORAGE_VALIDATION_OK")
