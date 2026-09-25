import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
CHECK = r'''
import os
import sys
import threading
import time

tree = sys.argv[1]
data = sys.argv[2]
os.environ["AURORA_DATA_DIR"] = data
sys.path.insert(0, tree)
import mesh


def make_nodes(count):
    return [
        {
            "id": "n%d" % i,
            "name": "Node-%d" % i,
            "region": "RU",
            "host": "198.51.100.%d" % (i % 200 + 1),
            "port": 10000 + i,
            "role": "node",
        }
        for i in range(count)
    ]


def set_nodes(nodes):
    with mesh._LOCK:
        mesh._NODES = nodes
    mesh._invalidate_ping_cache()


lock = threading.Lock()
active = 0
max_active = 0
timeouts = []
calls = 0


def fake_tcp(host, port, timeout=2.0):
    global active, max_active, calls
    with lock:
        active += 1
        calls += 1
        max_active = max(max_active, active)
        timeouts.append(timeout)
    time.sleep(0.01)
    with lock:
        active -= 1
    return True


set_nodes(make_nodes(70))
old_tcp = mesh._tcp_ping
mesh._tcp_ping = fake_tcp
result = mesh.ping_all(timeout=99)
assert len(result) == 71, len(result)
assert max_active <= mesh.PING_WORKERS, max_active
assert timeouts and min(timeouts) >= mesh.PING_MIN_TIMEOUT
assert max(timeouts) <= mesh.PING_MAX_TIMEOUT
first_calls = calls
cached = mesh.ping_all(timeout=0)
assert cached == result
assert calls == first_calls, (calls, first_calls)

mesh._invalidate_ping_cache()
calls = 0
release = threading.Event()
started = threading.Event()
second_started = threading.Event()


def blocking_tcp(host, port, timeout=2.0):
    global calls
    with lock:
        calls += 1
    started.set()
    release.wait(2)
    return True


mesh._tcp_ping = blocking_tcp
first_result = []
second_result = []
first = threading.Thread(target=lambda: first_result.append(mesh.ping_all(timeout=2)))
first.start()
assert started.wait(1), "ping scan did not start"


def second_call():
    second_started.set()
    second_result.append(mesh.ping_all(timeout=2))


second = threading.Thread(target=second_call)
second.start()
assert second_started.wait(1), "second call did not start"
time.sleep(0.05)
release.set()
first.join(3)
second.join(3)
assert not first.is_alive()
assert not second.is_alive()
assert len(first_result) == 1 and len(second_result) == 1
assert len(first_result[0]) == 71
assert len(second_result[0]) == 71
assert calls == 71, calls
assert max_active <= mesh.PING_WORKERS, max_active

set_nodes([])
node, error = mesh.add("Alpha", "RU", "203.0.113.10", 12345)
assert node is not None and error is None, error
assert mesh._PING_CACHE == []
assert mesh.remove(node["id"])
assert mesh._PING_CACHE == []

set_nodes(make_nodes(mesh.MAX_NODES - 1))
before = mesh.node_count()
node, error = mesh.add("Overflow", "RU", "203.0.113.20", 12346)
assert node is None and error and "лимит" in error, error
assert mesh.node_count() == before

mesh._tcp_ping = old_tcp
original_create = mesh.socket.create_connection
def bad_create(*args, **kwargs):
    raise ValueError("bad socket data")
mesh.socket.create_connection = bad_create
assert mesh._tcp_ping("bad", 1, 99) is False
mesh.socket.create_connection = original_create
print("A028_TREE_OK")
'''


def run_tree(path):
    data = tempfile.mkdtemp(prefix="aurora-a028-")
    try:
        result = subprocess.run(
            [sys.executable, "-c", CHECK, path, data],
            cwd=path,
            text=True,
            capture_output=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "A028_TREE_OK" in result.stdout, result.stdout
    finally:
        import shutil
        shutil.rmtree(data, ignore_errors=True)


run_tree(os.path.join(ROOT, "windows"))
run_tree(ROOT)
print("A028_PING_LIMIT_OK")
