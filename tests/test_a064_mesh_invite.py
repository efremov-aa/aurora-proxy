import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import time

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = pathlib.Path(__file__).resolve().parent.parent
TREES = (ROOT / "windows", ROOT)

KEY = "aurora-test-policy-key-0123456789abcdef"
MASTER_ID = "home-master"


def read(path):
    return path.read_text(encoding="utf-8-sig")


def region(text, start, end):
    i = text.index(start)
    j = text.index(end, i)
    return text[i:j]


WORKER = textwrap.dedent(r'''
    import os
    import sys
    import time
    import tempfile
    from urllib.parse import urlencode

    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    tree = sys.argv[1]
    sys.path.insert(0, tree)
    data = tempfile.mkdtemp(prefix="aurora_a064_data_")
    os.environ["AURORA_DATA_DIR"] = data
    os.environ["AURORA_MESH_POLICY_KEY"] = sys.argv[2]
    os.environ["AURORA_MESH_MASTER_ID"] = sys.argv[3]

    import config
    import mesh

    failed = []

    def check(name, ok):
        if ok:
            print("PASS", name)
        else:
            failed.append(name)
            print("FAIL", name)

    def raises(name, fn):
        try:
            fn()
        except Exception as exc:
            print("PASS", name, type(exc).__name__)
            return
        failed.append(name)
        print("FAIL", name, "no exception")

    if config.mesh_policy_key() != sys.argv[2]:
        failed.append("policy_key_env")
        print("FAIL policy_key_env")
    if config.mesh_master_id() != sys.argv[3]:
        failed.append("master_id_env")
        print("FAIL master_id_env")

    mesh._local_host = lambda: "10.0.0.5"
    mesh._NODES = []
    mesh._POLICY_NONCES.clear()

    def build_invite(**over):
        now = int(time.time())
        core = {
            "invite_version": 1,
            "issuer": sys.argv[3],
            "token": "T" * 32,
            "challenge": "a" * 32,
            "host": "10.1.0.238",
            "port": 8899,
            "policy_port": 8890,
            "name": "Home",
            "issued_at": now,
            "expires_at": now + mesh.INVITE_TTL_S,
        }
        core.update(over)
        sig = mesh._invite_signature(core)
        return core, "aurora://invite?" + urlencode(list(core.items()) + [("signature", sig)])

    core, url = build_invite()
    parsed = mesh.parse_invite(url)
    check("parse_valid", isinstance(parsed, dict))
    if isinstance(parsed, dict):
        check("parse_ints", isinstance(parsed.get("port"), int)
              and isinstance(parsed.get("issued_at"), int))
        check("parse_fields", set(parsed) == set(mesh._INVITE_FIELDS))

    check("invite_none", mesh.invite() is None)
    check("regenerate_none", mesh.regenerate() is None)

    def bad(label, **over):
        _, u = build_invite(**over)
        check(label, mesh.parse_invite(u) is None)

    bad("bad_issuer", issuer="other-master")
    bad("bad_version", invite_version="2")
    bad("bad_token", token="short")
    bad("bad_challenge", challenge="zz")
    bad("bad_port", port=0)
    bad("big_port", port=70000)
    bad("bad_name", name="")
    bad("bad_host", host="not a host")
    bad("expired", expires_at=int(time.time()) - 5)
    bad("ttl", expires_at=int(time.time()) + mesh.INVITE_TTL_S + 60)

    _, u_short_sig = build_invite()
    tampered = u_short_sig.replace("signature=", "signature=0", 1)
    check("bad_signature", mesh.parse_invite(tampered) is None)
    check("no_signature", mesh.parse_invite("aurora://invite?" + u_short_sig.split("?", 1)[1].rsplit("&signature=", 1)[0]) is None)
    check("extra_field", mesh.parse_invite(url + "&extra=1") is None)
    check("not_url", mesh.parse_invite("http://evil/aurora://invite") is None)
    check("parse_type", mesh.parse_invite(None) is None and mesh.parse_invite(123) is None)

    node = {"name": "Home", "region": "RU", "host": "10.1.0.5",
            "port": 8899, "policy_port": 8890}
    p1 = mesh.invite_proof(url, node)
    p2 = mesh.invite_proof(url, node)
    check("proof_stable", p1 == p2 and len(p1) == 64)
    other = dict(node)
    other["port"] = 5054
    check("proof_bound", mesh.invite_proof(url, other) != p1)
    check("proof_bad", mesh.invite_proof("aurora://invite?x=1", node) is None)

    calls = []

    def fake_post(scheme, host, port, path, data, timeout=5.0, headers=None):
        calls.append((scheme, host, port, path, data))
        return {"ok": True, "node": {"id": "hub"}}

    mesh._fetch_post = fake_post
    ok, err = mesh.join_via_invite(url)
    check("join_ok", ok is True and err is None)
    if calls:
        scheme, host, port, path, data = calls[-1]
        check("join_path", path == "/api/mesh/join")
        check("join_port", port == 8890)
        check("join_keys", set(data) == {"invite", "proof", "name", "region",
                                          "host", "port", "policy_port"})
        check("join_no_token", "token" not in data)
        check("join_self", data.get("host") == "10.0.0.5" and data.get("port") == 8899)
    else:
        check("join_path", False)
    check("join_node_added", any(n.get("host") == "10.1.0.238" for n in mesh.all_nodes()))
    ok2, err2 = mesh.join_via_invite(url)
    check("join_replay", ok2 is False and err2)

    def none_post(*a, **k):
        return None

    mesh._fetch_post = none_post
    _, u3 = build_invite(challenge="b" * 32)
    ok3, err3 = mesh.join_via_invite(u3)
    check("join_refused", ok3 is False and err3)
    ok4, err4 = mesh.join_via_invite("aurora://invite?bad=1")
    check("join_bad_invite", ok4 is False and err4)

    if mesh._remember_challenge("c" * 32, int(time.time()) + 60) is True:
        print("PASS remember_first")
    else:
        failed.append("remember_first")
        print("FAIL remember_first")
    check("remember_replay", mesh._remember_challenge("c" * 32, int(time.time()) + 60) is False)
    check("remember_expired_gone", mesh._remember_challenge("d" * 32, int(time.time()) - 1) is True)

    pcore = {
        "policy_version": 1,
        "master_id": sys.argv[3],
        "master": True,
        "show_mesh": True,
        "show_subs": False,
        "issued_at": int(time.time()),
        "expires_at": int(time.time()) + 120,
        "nonce": "e" * 32,
    }
    psig = mesh._policy_signature(pcore)
    payload = dict(pcore)
    payload["signature"] = psig
    good = mesh._policy_valid(payload)
    check("policy_ok", isinstance(good, dict) and good.get("master") is True)
    check("policy_replay", mesh._policy_valid(dict(payload)) is None)
    p2c = dict(pcore)
    p2c["nonce"] = "f" * 32
    p2v = dict(p2c)
    p2v["signature"] = mesh._policy_signature(p2c)
    check("policy_ok2", isinstance(mesh._policy_valid(p2v), dict))

    def pbad(label, **over):
        item = dict(pcore)
        item.update(over)
        item["nonce"] = "1" * 32
        item["signature"] = mesh._policy_signature(item)
        if over.pop("broken_sig", False):
            item["signature"] = "0" * 64
        check(label, mesh._policy_valid(item) is None)

    pbad("policy_wrong_master", master_id="other")
    pbad("policy_expired", expires_at=int(time.time()) - 5)
    pbad("policy_bool_flag", show_mesh="yes")
    pbad("policy_bad_nonce", nonce="zz", broken_sig=True)
    check("policy_master_false", mesh._policy_valid(
        dict(pcore, master=False, signature=mesh._policy_signature(
            dict(pcore, master=False)))) is None)
    check("policy_type", mesh._policy_valid(None) is None
          and mesh._policy_valid("x") is None)

    if failed:
        print("A064_CHILD_FAIL", ",".join(failed))
        sys.exit(1)
    print("A064_CHILD_OK")
''')


def static_contract(tree):
    api = read(tree / "api.py")
    mesh_text = read(tree / "mesh.py")
    cfg = read(tree / "config.py")
    app = read(tree / "ui" / "app.js")
    for needle in ("verify_invite", "check_invite_token", "invite_token", "invite_valid"):
        assert needle not in api, (tree, needle)
    assert api.count('"/api/mesh/join": self._mesh_join,') == 1, tree
    assert api.count('"/api/mesh/node/add"') == 1, tree
    assert '"invite_available"' in api, tree
    assert api.count("invite unavailable") == 2, tree
    assert "master token required" in api, tree
    assert "policy_port" in api, tree
    assert 'path.startswith("/api/mesh/") and not config.get("show_mesh", False)' in api, tree
    assert "def _mesh_join(self, data):" in api, tree
    assert "mesh.join_via_invite(invite" in api, tree
    for needle in ("def join_via_invite", "def parse_invite", "def invite_proof",
                   "def _policy_valid", "def _remember_challenge", "def _used_challenges",
                   "INVITE_TTL_S", "MAX_INVITE_CHALLENGES", "MAX_POLICY_BYTES",
                   "_POLICY_MAX_NONCES", "INVITE_USED_FILE", "/api/mesh/join",
                   "def _policy_port"):
        assert needle in mesh_text, (tree, needle)
    for needle in ("def verify_invite", "def check_invite_token", "?token=",
                   "def _token("):
        assert needle not in mesh_text, (tree, needle)
    for needle in ("MESH_POLICY_KEY", "MESH_MASTER_ID", "MESH_POLICY_TTL_S",
                   "def mesh_policy_key(", "def mesh_master_id(",
                   "AURORA_MESH_POLICY_KEY", "AURORA_MESH_MASTER_ID"):
        assert needle in cfg, (tree, needle)
    assert app.count("/api/mesh/join") == 1, tree
    assert "aurora://invite?" in app, tree
    assert "q.token" not in app, tree
    return {
        "api": region(api, "    def _mesh_invite(self, data):", "    def _mesh_node_remove(self, data):"),
        "mesh": region(mesh_text, "def join_via_invite(", "def policy():"),
        "app": region(app, "  window.meshJoin = function () {", "  window.meshLeave = function () {"),
    }


def main():
    results = []
    for tree in TREES:
        r = subprocess.run([sys.executable, "-c", WORKER, str(tree), KEY, MASTER_ID],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace")
        print(r.stdout.strip())
        assert r.returncode == 0, (tree, r.stdout, r.stderr)
        assert "A064_CHILD_OK" in r.stdout, tree
        results.append(static_contract(tree))
    assert results[0] == results[1], "linux/windows parity"
    print("A064_MESH_INVITE_OK")


if __name__ == "__main__":
    main()
