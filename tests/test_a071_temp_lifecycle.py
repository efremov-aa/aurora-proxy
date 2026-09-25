
import os
import stat
import sys
import tempfile
import time
from pathlib import Path

root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root))
tmp = Path(tempfile.mkdtemp(prefix="a071-child-"))
data = tmp / "data"
data.mkdir()
os.environ["AURORA_DATA_DIR"] = str(data)

import crypt
import config
import security

crypt.DATA_DIR = str(data)
config.BASE_DIR = str(tmp)
config.DATA_DIR = str(data)
config.XRAY_CONFIG = str(tmp / "xray.json")
config.LOG_FILE = str(tmp / "aurora.log")
config.SUBS_PLANS_FILE = str(data / "plans.json")

first = Path(crypt.secure_temp_path(str(data), "keytest_cfg_", ".json"))
second = Path(crypt.secure_temp_path(str(data), "keytest_cfg_", ".json"))
assert first != second
assert not first.exists() and not second.exists()

stale = [tmp / ".xray-a.tmp", tmp / ".xray-test-b.json", tmp / "keytest_cfg_1.json"]
for path in stale:
    path.write_text("stale", encoding="utf-8")
    os.utime(path, (time.time() - 7200, time.time() - 7200))
fresh = tmp / ".xray-fresh.tmp"
fresh.write_text("fresh", encoding="utf-8")
important = tmp / "important.json"
important.write_text("important", encoding="utf-8")
if os.name != "nt":
    link = tmp / "keytest_cfg_link.json"
    try:
        link.symlink_to(important)
        assert crypt.sweep_stale_temps((tmp,), 3600) == 3
        assert not link.exists() or not link.is_symlink()
    except OSError:
        assert crypt.sweep_stale_temps((tmp,), 3600) == 3
else:
    assert crypt.sweep_stale_temps((tmp,), 3600) == 3
assert all(not path.exists() for path in stale)
assert fresh.exists() and important.exists()

xray = tmp / "xray.json"
log = tmp / "aurora.log"
xray.write_text('{"ok":true}', encoding="utf-8")
log.write_text("log", encoding="utf-8")
if os.name != "nt":
    os.chmod(xray, 0o644)
    os.chmod(log, 0o644)
    security.protect_files()
    assert stat.S_IMODE(xray.stat().st_mode) == 0o600
    assert stat.S_IMODE(log.stat().st_mode) == 0o600
    assert xray.read_text(encoding="utf-8") == '{"ok":true}'
else:
    security.protect_files()

config.SUBS_PLANS = {"basic": {"name": "Basic", "price": 1, "bytes": 1, "days": 1, "devices": 1, "keys": 1}}
config.save_plans()
assert Path(config.SUBS_PLANS_FILE).exists()
assert not (data / "plans.json.tmp").exists()
assert not list(data.glob("*.tmp"))

source_text = (root / "source.py").read_text(encoding="utf-8-sig")
core_text = (root / "core.py").read_text(encoding="utf-8-sig")
config_text = (root / "config.py").read_text(encoding="utf-8-sig")
assert 'keytest_cfg_%d.json' not in source_text
assert "secure_temp_path" in source_text
assert "crypt.unlink_quiet" in source_text
assert "crypt.restrict_file(tmp)" in core_text
assert "crypt.save_json(SUBS_PLANS_FILE" in config_text
print("A071_CHILD_OK")
