import pathlib
import subprocess
import sys
import textwrap

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = pathlib.Path(__file__).resolve().parent
TREES = (ROOT / "windows", ROOT)

WORKER = r'''
import os
import sys
import tempfile

with tempfile.TemporaryDirectory(prefix="aurora-a073-") as data:
    os.environ["AURORA_DATA_DIR"] = data
    os.environ.pop("AURORA_ADMIN_TOKEN", None)
    sys.path.insert(0, sys.argv[1])
    import api
    import config
    import security
    import updater

    failed = []

    def ok(label, cond):
        if not cond:
            failed.append(label)

    state = {"comm": {"state": "idle", "msg": "secret internal detail"},
             "xray_api_port": 8897, "xray_port": 8899, "version": config.VERSION,
             "tgws_port": 443}
    same = api._project_state(state, True)
    ok("state_trusted_identity", same is state)
    out = api._project_state(state, False)
    ok("state_comm_msg_cleared", out["comm"]["msg"] == "")
    ok("state_comm_state_kept", out["comm"]["state"] == "idle")
    ok("state_api_port_cleared", out["xray_api_port"] == 0)
    ok("state_xray_port_cleared", out["xray_port"] == 0)
    ok("state_version_kept", out["version"] == config.VERSION)
    ok("state_source_untouched", state["comm"]["msg"] != "")

    security._TOKEN["value"] = "0123456789abcdef0123456789abcdef"
    trusted_sec = api._project_security_status(True)
    ok("sec_trusted_masked", "masked" in trusted_sec)
    public_sec = api._project_security_status(False)
    ok("sec_public_keys", set(public_sec) == {"ok", "enabled"})
    ok("sec_public_no_masked", "masked" not in public_sec)
    ok("sec_public_enabled", public_sec["enabled"] is True)
    security._TOKEN["value"] = ""

    full_upd = api._project_update_status(True)
    ok("upd_trusted_full", "repo" in full_upd or "current" in full_upd)
    public_upd = api._project_update_status(False)
    ok("upd_public_ok", public_upd.get("ok") is True)
    ok("upd_public_allowlist", set(public_upd) <= {"ok", "enabled", "current",
                                                 "latest", "state", "update"})
    ok("upd_public_no_pubkey", "pubkey" not in public_upd)
    ok("upd_public_no_msg", "msg" not in public_upd)

    try:
        built = api.build_state(local=False)
    except Exception as exc:
        built = {}
        failed.append("build_state(%s)" % exc)
    if built:
        vless = dict(built.get("vless_ext") or {})
        for sec in ("link", "uuid", "pbk", "sid", "host", "port", "sni", "fp"):
            ok("state_vless_%s" % sec, sec not in vless)
        ok("state_tgws_link", "link" not in (built.get("tgws") or {}))
        ok("state_server_name", built.get("server_name") == "")
        ok("state_white_ip", built.get("white_ip", "") == "")
        ok("state_egress", built.get("egress_ip", "") == "")
        for row in built.get("keys") or []:
            ok("state_key_uri", row.get("uri") == "")
            ok("state_key_status", row.get("status") == "masked")
        proj = api._project_state(built, False)
        ok("state_proj_ports", proj["xray_api_port"] == 0 and proj["xray_port"] == 0)

    print("A073_CHILD_FAIL " + "|".join(failed) if failed else "A073_CHILD_OK")
'''


def read(path):
    return path.read_text(encoding="utf-8-sig")


def region(text, start, end):
    i = text.find(start)
    j = text.find(end, i + len(start))
    assert i >= 0 and j > i, "region not found: %s" % start
    return text[i:j]


REGIONS = {}
for tree in TREES:
    api = read(tree / "api.py")
    assert "def _project_state(" in api, tree
    assert "def _project_security_status(" in api, tree
    assert "def _project_update_status(" in api, tree
    assert '_project_state(build_state(local=trusted), trusted)' in api, tree
    assert "_project_security_status(trusted)" in api, tree
    assert "_project_update_status(trusted)" in api, tree
    assert "self._send(*_json(security.status()))" not in api, tree
    assert "self._send(*_json(updater.status()))" not in api, tree
    assert "self._send(*_json(build_state(local=trusted)))" not in api, tree
    body = region(api, "def _project_state(", "def build_state(")
    for needle in ('comm["msg"] = ""', "xray_api_port", "xray_port",
                   '{"ok": True, "enabled"', '"enabled", "current", "latest", "state", "update"'):
        assert needle in body, (tree, needle)
    REGIONS[tree.name] = body
    result = subprocess.run([sys.executable, "-c", textwrap.dedent(WORKER), str(tree)],
                            capture_output=True, text=True, encoding="utf-8",
                            errors="replace", cwd=str(tree))
    assert result.returncode == 0, (tree, result.stdout, result.stderr)
    out = result.stdout or ""
    if "A073_CHILD_OK" not in out:
        raise AssertionError((tree, out.strip()))

names = set(REGIONS)
assert len(REGIONS) == 2, names
first = list(REGIONS.values())[0]
for value in REGIONS.values():
    assert value == first, "parity mismatch"

print("A073_READ_SCOPE_OK")
