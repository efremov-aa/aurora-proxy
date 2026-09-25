import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
CHILD = r'''
import os
import sys
import threading
import time

tree = sys.argv[1]
data = sys.argv[2]
os.environ["AURORA_DATA_DIR"] = data
sys.path.insert(0, tree)
import config
import core
import recovery

recovery.RECOVERY_COUNT = 0
recovery.RECOVERY_LOG[:] = []
recovery.RECOVERY_IN_PROGRESS = False
config._settings["auto_recovery"] = False
config._settings["vpn_mode"] = True
calls = []
lock = threading.Lock()

def rotate():
    with lock:
        calls.append("rotate")
    time.sleep(0.05)
    return "vless-test"

recovery.core.rotate = rotate
automatic = recovery.run_limit(automatic=True)
assert automatic == {"ok": False, "msg": "automatic recovery disabled"}, automatic
assert calls == [], calls
manual = recovery.run_limit()
assert manual == {"ok": True, "tag": "vless-test"}, manual
assert calls == ["rotate"], calls
status = recovery.status()
assert status["in_progress"] is False
assert status["count"] == 1, status
assert status["log"] and status["log"][-1]["kind"] == "limit"
config._settings["vpn_mode"] = False
off = recovery.run_region()
assert off["ok"] is False and off["msg"].startswith("vpn off"), off
config._settings["vpn_mode"] = True
recovery.RECOVERY_LOG[:] = []
recovery.RECOVERY_COUNT = 0
calls[:] = []
results = []
def worker():
    results.append(recovery.run_conn("example.com", 443))
threads = [threading.Thread(target=worker) for _ in range(2)]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
assert len(calls) == 1, calls
assert sum(1 for result in results if result.get("ok")) == 1, results
assert all(result.get("ok") is False or result.get("tag") == "vless-test" for result in results), results
print("A032_CHILD_OK")
'''


def run_tree(path):
    data = tempfile.mkdtemp(prefix="aurora-a032-")
    try:
        result = subprocess.run(
            [sys.executable, "-c", CHILD, path, data],
            cwd=path,
            text=True,
            capture_output=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "A032_CHILD_OK" in result.stdout, result.stdout
    finally:
        shutil.rmtree(data, ignore_errors=True)


for tree in (os.path.join(ROOT, "windows"), ROOT):
    run_tree(tree)
print("A032_RECOVERY_OK")
