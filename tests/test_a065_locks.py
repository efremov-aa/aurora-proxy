
import base64
import json
import os
import subprocess
import shutil
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def region(text, start, end):
    i = text.index(start)
    j = text.index(end, i)
    return text[i:j]

def core_contract(path):
    text = path.read_text(encoding="utf-8-sig")
    request = region(text, "def request_mode(on):", "\ndef sync():")
    assert "with _MODE_LOCK:" in request
    assert "with _cross_process_lock():" in request
    assert request.index("with _MODE_LOCK:") < request.index("with _cross_process_lock():")
    direct = region(text, "def set_direct():", "\ndef _set_direct_impl():")
    assert "with _MODE_LOCK, _cross_process_lock():" in direct
    apply = region(text, "def apply_sub_clients():", "\ndef set_active_tag(tag):")
    assert "with _cross_process_lock():" in apply
    assert "with XRAY_CONFIG_LOCK:" in apply
    assert apply.index("with _cross_process_lock():") < apply.index("with XRAY_CONFIG_LOCK:")
    assert apply.index("with XRAY_CONFIG_LOCK:") < apply.index("_restart_xray()")
    assert apply.index("_restart_xray()") < apply.rindex("return True")
    rotate = region(text, "def rotate():", "\ndef _rotate_impl():")
    impl = region(text, "def _rotate_impl():", "\n\n# --- watchdog final ---")
    assert "with _MODE_LOCK:" in rotate
    assert "with _cross_process_lock():" in rotate
    assert "_set_active_tag_impl(" in impl
    assert "set_active_tag(" not in rotate
    assert "_XRAY_FILE_LOCK" in text
    if path.parent.name.lower() == "windows":
        assert "LK_NBLCK" in text
        assert "120.0" in text

def windows_config_contract():
    path = ROOT / "windows" / "config.py"
    text = path.read_text(encoding="utf-8-sig")
    assert text.count("from contextlib import contextmanager") == 1
    assert "def _vless_file_lock():" in text
    assert ".vless-public.lock" in text
    assert "LK_NBLCK" in text
    assert "120.0" in text
    ensure = region(text, "def ensure_vless():", "\ndef open_firewall")
    assert "with _vless_file_lock():" in ensure
    assert "crypt.load_json(_VLESS_FILE" in ensure
    assert "crypt.save_json(_VLESS_FILE" in ensure
    assert "if any(name in os.environ for name in env_names):" in ensure
    assert ensure.index("if any(name in os.environ") < ensure.index("with _vless_file_lock():")

def child(tree, data, index):
    os.environ["AURORA_DATA_DIR"] = data
    for name in (
        "AURORA_VLESS_ENABLED", "AURORA_VLESS_PORT", "AURORA_VLESS_HOST",
        "AURORA_VLESS_UUID", "AURORA_VLESS_PRIVATE_KEY", "AURORA_VLESS_PUBLIC_KEY",
        "AURORA_VLESS_SHORT_ID", "AURORA_VLESS_SNI", "AURORA_VLESS_FLOW",
    ):
        os.environ.pop(name, None)
    sys.path.insert(0, tree)
    import config
    config.VLESS_PUBLIC["host"] = "example.com"
    config.VLESS_PUBLIC["sni"] = "example.com"
    value = int(index) + 1
    private = base64.urlsafe_b64encode(bytes([value]) * 32).rstrip(b"=").decode("ascii")
    public = base64.urlsafe_b64encode(bytes([value + 1]) * 32).rstrip(b"=").decode("ascii")
    uuid = "22222222-2222-4222-8222-2222222222" + str(value).zfill(2)
    def generate():
        time.sleep(0.15)
        return uuid, private, public
    config._gen_vless_material = generate
    result = config.ensure_vless()
    print(json.dumps({k: result[k] for k in ("uuid", "private_key", "public_key")}, sort_keys=True))

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--child":
        child(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        for tree in (ROOT / "windows", ROOT):
            core_contract(tree / "core.py")
        windows_config_contract()
        data = tempfile.mkdtemp(prefix="aurora-a065-")
        try:
            procs = []
            for index in range(4):
                procs.append(subprocess.Popen(
                    [sys.executable, str(ROOT / "tests" / "test_a065_locks.py"), "--child", str(ROOT / "windows"), data, str(index)],
                    cwd=str(ROOT), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                ))
            results = []
            for proc in procs:
                out, err = proc.communicate(timeout=30)
                assert proc.returncode == 0, out + err
                results.append(json.loads(out.strip().splitlines()[-1]))
            assert all(item == results[0] for item in results)
            raw = (Path(data) / "vless_public.json").read_bytes()
            assert raw.startswith((b"AURORA1", b"AURORA2"))
            assert results[0]["private_key"].encode("ascii") not in raw
        finally:
            shutil.rmtree(data, ignore_errors=True)
        print("A065_LOCKS_OK")
