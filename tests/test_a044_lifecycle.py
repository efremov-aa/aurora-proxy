import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHILD = r'''
import os
import sys
import threading

tree = sys.argv[1]
data = sys.argv[2]
os.environ["AURORA_DATA_DIR"] = data
sys.path.insert(0, tree)
starts = []

def fake_start(thread):
    target = getattr(thread, "_target", None)
    starts.append(getattr(target, "__name__", ""))

threading.Thread.start = fake_start
import run
assert starts == [], starts
import mesh
import subs
assert mesh.start_policy_loop() is True, mesh._POLICY_STARTED
assert mesh.start_policy_loop() is False, mesh._POLICY_STARTED
subs.start_background()
assert subs._BG_STARTED is True
subs.start_background()
assert subs._BG_STARTED is True
assert len(starts) == 2, starts

import api
events = []
run.config.load_settings = lambda: events.append("settings")
run.security.init = lambda: events.append("security")
run.mesh.ensure_unique_name = lambda: events.append("name")
run.pool.load = lambda: events.append("pool")
run.subs.load = lambda: events.append("subs_load")
run.mesh.start_policy_loop = lambda: events.append("policy")
run.subs.start_background = lambda: events.append("subs_bg")
run.pool.cleanup = lambda: events.append("cleanup")
run.config.log = lambda *args, **kwargs: None
run.tgws.refresh_status = lambda: events.append("tgws")
run.core.start_watch = lambda: events.append("watch")
run.rusegment.start = lambda: events.append("segment")
run.updater.auto_update = lambda: events.append("updater")
run._boot()
assert events.index("settings") < events.index("policy")
assert events.index("subs_load") < events.index("subs_bg")
assert events.index("settings") < events.index("subs_bg")

serve_events = []
api.config.load_settings = lambda: serve_events.append("settings")
api.mesh.start_policy_loop = lambda: serve_events.append("policy")
api.subs.start_background = lambda: serve_events.append("subs_bg")
api._load_ui_token = lambda: None
api.config.log = lambda *args, **kwargs: None
api.threading.Thread = type("FakeThread", (), {
    "__init__": lambda self, *args, **kwargs: None,
    "start": lambda self: None,
})
class FakeServer:
    daemon_threads = False
    allow_reuse_address = False
    def __init__(self, *args, **kwargs):
        pass
    def serve_forever(self):
        serve_events.append("serve")
api.ThreadingHTTPServer = FakeServer
api.serve(12345)
assert serve_events[0] == "settings", serve_events
assert serve_events.index("settings") < serve_events.index("policy")
assert serve_events.index("settings") < serve_events.index("subs_bg")
assert serve_events[-1] == "serve"
print("A044_CHILD_OK")
'''


def run_tree(tree):
    data = tempfile.mkdtemp(prefix="aurora-a044-")
    try:
        result = subprocess.run(
            [sys.executable, "-c", CHILD, tree, data],
            cwd=tree, text=True, capture_output=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "A044_CHILD_OK" in result.stdout, result.stdout
    finally:
        import shutil
        shutil.rmtree(data, ignore_errors=True)


run_tree(os.path.join(ROOT, "windows"))
run_tree(ROOT)
print("A044_LIFECYCLE_OK")
