import pathlib
import subprocess
import sys
import textwrap

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = pathlib.Path(__file__).resolve().parent
TREES = (ROOT / "windows", ROOT)

WORKER = textwrap.dedent(r'''
    import os
    import sys
    import tempfile

    tree = sys.argv[1]
    data = tempfile.mkdtemp(prefix="a061_")
    os.environ["AURORA_DATA_DIR"] = data
    os.environ["AURORA_HOST"] = "10.1.0.238"
    os.environ.pop("AURORA_TLS_CERT", None)
    os.environ.pop("AURORA_TLS_KEY", None)
    sys.path.insert(0, tree)
    failed = []

    def check(label, ok):
        if not ok:
            failed.append(label)

    import api

    class Req(object):
        def __init__(self, path, headers=None, ip="203.0.113.9"):
            self.path = path
            self.headers = dict(headers or {})
            self.client_address = (ip, 4242)

    api._TLS_ENABLED = False
    api._is_local = lambda req: str(req.client_address[0]).startswith("127.")

    check("no_creds_remote", api._transport_ok(Req("/api/state")))
    check("x_auth_remote", not api._transport_ok(
        Req("/api/state", {"X-Auth": "secret"})))
    check("x_2fa_remote", not api._transport_ok(
        Req("/api/security", {"X-2FA": "123456"})))
    check("bearer_remote", not api._transport_ok(
        Req("/api/settings", {"Authorization": "Bearer abc"})))
    check("query_token_remote", not api._transport_ok(Req("/api/log?token=abc")))
    check("x_auth_lan", api._transport_ok(
        Req("/api/state", {"X-Auth": "secret"}, ip="10.1.0.146")))
    check("x_auth_local", api._transport_ok(
        Req("/api/state", {"X-Auth": "secret"}, ip="127.0.0.1")))
    check("exempt_sub", api._transport_ok(Req("/sub?token=abc")))
    check("exempt_policy", api._transport_ok(Req("/api/mesh/policy?token=abc")))
    check("exempt_join", api._transport_ok(Req("/api/mesh/join", {"X-Auth": "s"})))
    check("exempt_policy_accept", api._transport_ok(
        Req("/api/policy/accept", {"X-Auth": "s"})))
    check("exempt_rusegment", api._transport_ok(Req("/api/rusegment/regions")))
    check("exempt_prefix", api._transport_ok(Req("/api/policy/acceptmore")))
    check("lan_bearer", api._transport_ok(
        Req("/api/settings", {"Authorization": "Bearer abc"}, ip="10.1.0.146")))

    api._TLS_ENABLED = True
    check("tls_remote_auth", api._transport_ok(Req("/api/state", {"X-Auth": "s"})))
    check("tls_remote_query", api._transport_ok(Req("/api/log?token=abc")))
    heads = dict(api._security_headers())
    check("hsts_present", heads.get("Strict-Transport-Security")
          == "max-age=31536000")
    check("csp_present", "script-src 'self'" in heads.get("Content-Security-Policy", ""))
    api._TLS_ENABLED = False
    heads = dict(api._security_headers())
    check("hsts_absent", "Strict-Transport-Security" not in heads)
    check("nosniff_present", heads.get("X-Content-Type-Options") == "nosniff")

    check("tls_env_empty", api._tls_env() == ("", ""))
    os.environ["AURORA_TLS_CERT"] = os.path.join(data, "missing.pem")
    check("tls_env_missing", api._tls_env() == ("", ""))
    cert = os.path.join(data, "cert.pem")
    key = os.path.join(data, "key.pem")
    with open(cert, "w") as fh:
        fh.write("x")
    with open(key, "w") as fh:
        fh.write("x")
    os.environ["AURORA_TLS_CERT"] = cert
    check("tls_env_half", api._tls_env() == ("", ""))
    os.environ["AURORA_TLS_KEY"] = key
    check("tls_env_pair", api._tls_env() == (cert, key))
    os.environ.pop("AURORA_TLS_CERT")
    os.environ.pop("AURORA_TLS_KEY")
    check("tls_enable_false", api._enable_tls(object()) is False)

    if failed:
        print("A061_CHILD_FAIL", " ".join(failed))
    else:
        print("A061_CHILD_OK")
''')


def read(path):
    return path.read_text(encoding="utf-8-sig")


def region(text, start, end):
    i = text.index(start)
    j = text.index(end, i)
    return text[i:j]


def api_contract(path):
    text = read(path)
    for needle in ("_TLS_ENABLED = False", "_TRANSPORT_EXEMPT = (", "/api/mesh/join",
                   "/api/policy/accept", "/api/rusegment/regions",
                   "def _tls_env():", "AURORA_TLS_CERT", "AURORA_TLS_KEY",
                   "def _enable_tls(httpd):", "ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)",
                   "context.minimum_version = ssl.TLSVersion.TLSv1_2",
                   "def _has_credentials(req):", "def _transport_ok(req):",
                   "if not _transport_ok(self):", "https required",
                   "Strict-Transport-Security", "max-age=31536000",
                   '"tls": bool(_TLS_ENABLED),'):
        assert needle in text, "api missing %s" % needle
    assert text.count("if not _transport_ok(self):") == 2, "transport gate count"
    assert text.count("def _security_headers():") == 1, "security headers count"
    block = region(text, "_TLS_ENABLED = False", "def _security_headers():")
    for needle in ("_is_local(req)", "_TLS_ENABLED", "_host_in_lan(req.client_address[0])",
                   "_TRANSPORT_EXEMPT"):
        assert needle in block, "tls block missing %s" % needle
    return block


def main():
    for tree in TREES:
        api_contract(tree / "api.py")
        proc = subprocess.run([sys.executable, "-c", WORKER, str(tree)], cwd=tree,
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace")
        out = (proc.stdout or "").strip()
        assert "A061_CHILD_OK" in out, "%s: %s %s" % (tree.name, out, proc.stderr)
    blocks = [api_contract(tree / "api.py") for tree in TREES]
    assert blocks[0] == blocks[1], "tls block parity"
    print("A061_TRANSPORT_OK")


if __name__ == "__main__":
    main()
