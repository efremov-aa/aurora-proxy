import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
CHILD = r'''
import sys
sys.path.insert(0, sys.argv[1])
import api

class Sink:
    def write(self, body):
        raise BrokenPipeError()

handler = api.Handler.__new__(api.Handler)
handler.send_response = lambda status: None
handler.send_header = lambda name, value: None
handler.end_headers = lambda: None
handler.wfile = Sink()
assert api.Handler._send(handler, 200, "text/plain", b"x") is None
print("API_DISCONNECT_CHILD_OK")
'''

for tree in (os.path.join(ROOT, "windows"), ROOT):
    result = subprocess.run(
        [sys.executable, "-c", CHILD, tree],
        cwd=tree,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "API_DISCONNECT_CHILD_OK" in result.stdout
print("API_DISCONNECT_OK")
