import os
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent
PROXY_FILES = (
    "__init__.py", "_aes.py", "balancer.py", "bridge.py", "config.py",
    "fake_tls.py", "pool.py", "raw_websocket.py", "stats.py",
    "tg_ws_proxy.py", "utils.py",
)

for base in (ROOT / "proxy", ROOT / "windows" / "proxy"):
    for name in PROXY_FILES:
        assert (base / name).is_file(), str(base / name)

linux_proxy = (ROOT / "proxy" / "tg_ws_proxy.py").read_text(encoding="utf-8")
windows_proxy = (ROOT / "windows" / "proxy" / "tg_ws_proxy.py").read_text(encoding="utf-8")
for text in (linux_proxy, windows_proxy):
    assert "add_mutually_exclusive_group" in text
    assert "'--secret-file'" in text
    assert "'--secret-fd'" in text
    assert "def _read_secret_fd" in text

runner = (ROOT / "run_tgws.sh").read_text(encoding="utf-8")
assert "--secret " not in runner
assert "--secret-fd 3" in runner
assert "mktemp" in runner
assert "exec 3<" in runner
assert "RUNTIME_SECRET" in runner
assert "umask 077" in runner

service = (ROOT / "tg-ws-proxy.service").read_text(encoding="utf-8")
assert "RuntimeDirectory=aurora-tgws" in service
assert "UMask=0077" in service
assert "NoNewPrivileges=true" in service
assert "MemoryMax=256M" in service

for rel in ("updater.py", "windows/updater.py"):
    text = (ROOT / rel).read_text(encoding="utf-8")
    for name in PROXY_FILES:
        assert '"proxy/%s"' % name in text, (rel, name)
assert '"tg-ws-proxy.service"' in (ROOT / "updater.py").read_text(encoding="utf-8")

for rel in ("api.py", "windows/api.py"):
    text = (ROOT / rel).read_text(encoding="utf-8")
    start = text.index('        if path == "/api/tgws/status":')
    end = text.index('        if path == "/api/security/status":', start)
    block = text[start:end]
    assert "if not trusted:" in block
    assert "lan_client" not in block
    assert ('status.pop("link", None)' in block or 'data["link"] = ""' in block)

win_tgws = (ROOT / "windows" / "tgws.py").read_text(encoding="utf-8")
assert '"--secret-fd", "0"' in win_tgws
assert '"--secret", secret' not in win_tgws
assert "stdin=subprocess.PIPE" in win_tgws
assert "proc.stdin.write" in win_tgws

binary = ROOT / "windows" / "bin" / "tg-ws-proxy.exe"
probe = subprocess.run(
    [str(binary), "--help"], capture_output=True, text=True, timeout=15,
    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
)
help_text = (probe.stdout or "") + (probe.stderr or "")
assert probe.returncode == 0, help_text
assert "--secret-fd" in help_text
assert "--secret-file" in help_text
assert not re.search(r"--secret(?:=|\s)", help_text), help_text

sys.path.insert(0, str(ROOT))
from proxy import tg_ws_proxy

fd, path = tempfile.mkstemp()
try:
    os.write(fd, b"a" * 32 + b"\n")
    os.lseek(fd, 0, os.SEEK_SET)
    assert tg_ws_proxy._read_secret_fd(fd) == "a" * 32
    try:
        os.fstat(fd)
    except OSError:
        pass
    else:
        raise AssertionError("secret fd was not closed")
finally:
    if os.path.exists(path):
        os.unlink(path)

print("A060_TGWS_CREDENTIAL_OK")
