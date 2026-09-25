import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
CHILD = r'''
import os
import sys

tree = sys.argv[1]
data = sys.argv[2]
os.environ["AURORA_DATA_DIR"] = data
sys.path.insert(0, tree)
import config
import rusegment

with config.STATE_LOCK:
    config.STATE["rusegment"] = {"running": False, "results": [], "ts": 0}

class Response:
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def getcode(self):
        return 200

class Opener:
    def open(self, request, timeout=0):
        assert request.full_url == "http://probe.test/"
        return Response()

calls = []
def fake_build_opener(*handlers):
    calls.append(handlers)
    return Opener()

old_build = rusegment.urllib.request.build_opener
old_resolve = rusegment.socket.getaddrinfo
rusegment.urllib.request.build_opener = fake_build_opener
rusegment.socket.getaddrinfo = lambda *args, **kwargs: [(2, 1, 6, "", ("203.0.113.7", 80))]
try:
    result = rusegment._probe("probe.test")
    assert result["code"] == 200, result
    assert calls and calls[0][0].proxies == {}, calls
finally:
    rusegment.urllib.request.build_opener = old_build
    rusegment.socket.getaddrinfo = old_resolve

calls = []
def fake_probe(host):
    return {"host": host, "ip": "203.0.113.%d" % len(calls), "code": 200, "ms": 1}
old_probe = rusegment._probe
old_domains = config.segment_domains
rusegment._probe = fake_probe
config.segment_domains = lambda: ["one.test", "two.test"]
try:
    assert rusegment.check_all() is True
    state = config.get_state()["rusegment"]
    assert state["running"] is False, state
    assert len(state["results"]) == 2, state
    assert [row["host"] for row in state["results"]] == ["one.test", "two.test"]
finally:
    rusegment._probe = old_probe
    config.segment_domains = old_domains

config.segment_domains = lambda: (_ for _ in ()).throw(RuntimeError("domains"))
try:
    rusegment.check_all()
except RuntimeError as exc:
    assert str(exc) == "domains"
else:
    raise AssertionError("domains exception was not propagated")
state = config.get_state()["rusegment"]
assert state["running"] is False, state
assert state["results"] == [], state
assert state["ts"] > 0, state
print("A033_CHILD_OK")
'''


def run_tree(path):
    data = tempfile.mkdtemp(prefix="aurora-a033-")
    try:
        result = subprocess.run(
            [sys.executable, "-c", CHILD, path, data],
            cwd=path,
            text=True,
            capture_output=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "A033_CHILD_OK" in result.stdout, result.stdout
    finally:
        shutil.rmtree(data, ignore_errors=True)


if __name__ == "__main__":
    run_tree(os.path.join(ROOT, "windows"))
    run_tree(ROOT)
    print("A033_DIRECT_OK")
