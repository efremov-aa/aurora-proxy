import os
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace

ROOT = os.path.dirname(os.path.abspath(__file__))
CHILD = r'''
import os
import sys
from types import SimpleNamespace

tree = sys.argv[1]
data = sys.argv[2]
os.environ["AURORA_DATA_DIR"] = data
sys.path.insert(0, tree)
import config
import telemetry

ports = telemetry._service_ports()
assert config.XRAY_PORT in ports
assert config.TGWS_PORT in ports
assert 1 <= len(ports) <= 3

block = [
    "tcp ESTABLISHED 0 0 10.1.0.1:8899 198.51.100.10:43210",
    "\tbytes_sent:100 bytes_received:200",
]
parsed = telemetry._parse_ss_block(block, ports)
assert parsed == ("198.51.100.10", 100, 200), parsed
assert telemetry._parse_ss_block([
    "tcp ESTABLISHED 0 0 10.1.0.1:9999 198.51.100.10:43210",
    "\tbytes_sent:100 bytes_received:200",
], ports) is None

telemetry._SERVICE_LAST_UP.clear()
telemetry._SERVICE_LAST_DOWN.clear()
telemetry._SERVICE_UP.clear()
telemetry._SERVICE_DOWN.clear()
telemetry._collect_conns = lambda: (1, {"198.51.100.20": 1})
telemetry._collect_sock_stats = lambda: ({"198.51.100.20": 10}, {"198.51.100.20": 20})
telemetry.poll(loop=False)
state = config.get_state()
device = state["devices"]["198.51.100.20"]
assert device["upload"] == 10, state
assert device["download"] == 20, state
telemetry._collect_sock_stats = lambda: ({"198.51.100.20": 15}, {"198.51.100.20": 30})
telemetry.poll(loop=False)
state = config.get_state()
device = state["devices"]["198.51.100.20"]
assert device["upload"] == 15, state
assert device["download"] == 30, state
assert state["up"] == 15 and state["down"] == 30, state

if os.path.basename(tree).lower() == "windows":
    old_run = telemetry.subprocess.run
    telemetry.subprocess.run = lambda *args, **kwargs: SimpleNamespace(
        returncode=0,
        stdout="\n".join((
            f"  TCP    10.1.0.1:{config.XRAY_PORT}    198.51.100.30:43210    ESTABLISHED    10",
            "  TCP    10.1.0.1:9999    198.51.100.31:43210    ESTABLISHED    11",
        )),
    )
    try:
        total, by_ip = telemetry._collect_conns_nt()
    finally:
        telemetry.subprocess.run = old_run
    assert total == 1, (total, by_ip)
    assert by_ip == {"198.51.100.30": 1}, by_ip

print("A034_CHILD_OK")
'''


def run_tree(path):
    data = tempfile.mkdtemp(prefix="aurora-a034-")
    try:
        result = subprocess.run(
            [sys.executable, "-c", CHILD, path, data],
            cwd=path,
            text=True,
            capture_output=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "A034_CHILD_OK" in result.stdout, result.stdout
    finally:
        shutil.rmtree(data, ignore_errors=True)


run_tree(os.path.join(ROOT, "windows"))
run_tree(ROOT)
print("A034_TELEMETRY_OK")
