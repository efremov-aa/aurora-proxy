import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHILD = r'''
import os
import sys

tree = sys.argv[1]
data = sys.argv[2]
os.environ["AURORA_DATA_DIR"] = data
sys.path.insert(0, tree)
import config
import core

config.get = lambda key, default=None: False if key == "master_only" else default
core.pool.get_keys = lambda: []
core.config.ru_domains = lambda: ["ru.example"]
core.subs.build_client_list = lambda: []
cfg = core.build_xray_config("direct")
rules = cfg["routing"]["rules"]
bt = next(i for i, rule in enumerate(rules)
          if rule.get("protocol") == ["bittorrent"] and rule.get("outboundTag") == "direct")
quic = next(i for i, rule in enumerate(rules)
            if rule.get("protocol") == ["quic"] and rule.get("outboundTag") == "block")
udp = next(i for i, rule in enumerate(rules)
           if rule.get("network") == "udp" and rule.get("outboundTag") == "block")
final = next(i for i, rule in enumerate(rules)
             if "http-in" in (rule.get("inboundTag") or []))
ru = next(i for i, rule in enumerate(rules)
          if rule.get("domain") == ["domain:ru.example"])
assert bt < ru < quic < udp < final
for index in (bt, quic, udp):
    assert "inboundTag" not in rules[index]
http = next(i for i in cfg["inbounds"] if i.get("tag") == "http-in")
assert http["sniffing"]["enabled"] is True
assert any(i.get("tag") == "block" for i in cfg["outbounds"])
print("A043_CHILD_OK")
'''


def run_tree(tree):
    data = tempfile.mkdtemp(prefix="aurora-a043-")
    try:
        result = subprocess.run(
            [sys.executable, "-c", CHILD, tree, data],
            cwd=tree, text=True, capture_output=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "A043_CHILD_OK" in result.stdout, result.stdout
    finally:
        import shutil
        shutil.rmtree(data, ignore_errors=True)


run_tree(os.path.join(ROOT, "windows"))
run_tree(ROOT)
print("A043_BT_ROUTE_OK")
