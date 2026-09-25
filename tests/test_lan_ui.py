import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHILD = r'''
import os
import sys
import tempfile

with tempfile.TemporaryDirectory(prefix="aurora-lan-ui-") as data:
    os.environ["AURORA_DATA_DIR"] = data
    os.environ["AURORA_HOST"] = "10.1.136.56"
    os.environ.pop("AURORA_ALLOW_PRIVATE_LINK", None)
    sys.path.insert(0, sys.argv[1])
    import api
    import config

    class Request:
        client_address = ("10.1.136.56", 12345)
        headers = {}
        path = "/api/state"

    config.VM_HOST = "10.1.136.56"
    config._settings["lan_only"] = True
    assert api._read_auth_ok(Request())
    config._settings["lan_only"] = False
    assert not api._read_auth_ok(Request())
    assert config._valid_public_host("10.1.136.56") is None
    os.environ["AURORA_ALLOW_PRIVATE_LINK"] = "1"
    assert config._valid_public_host("10.1.136.56") == "10.1.136.56"
    print("LAN_UI_CHILD_OK")
'''

for tree in (os.path.join(ROOT, "windows"), ROOT):
    result = subprocess.run(
        [sys.executable, "-c", CHILD, tree],
        cwd=tree,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "LAN_UI_CHILD_OK" in result.stdout
print("LAN_UI_CONTRACT_OK")
