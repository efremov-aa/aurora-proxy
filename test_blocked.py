import os, sys, tempfile, shutil
tmp = tempfile.mkdtemp()
os.environ["AURORA_DATA_DIR"] = tmp
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config
config.DATA_DIR = tmp
try:
    config.init()
except Exception:
    pass
import pool

uri = "vless://11111111-2222-3333-4444-555555555555@vless-77.example.com:443?type=tcp&security=reality&pbk=XXX&sid=YYY&sni=vless-77.example.com#BL"
key = {"uri": uri, "host": "vless-77.example.com", "port": 443, "source": "github"}

# 1) добавляем, потом блокируем как autodead_conn
assert pool.add_key(key) == "added", "add должен быть added"
assert pool.remove_key(uri) is True
pool.dead_add(uri, "autodead_conn")
assert pool.blocked(uri)

# 2) refresh: тот же uri должен НЕ вернуться
k2 = {"uri": uri, "host": "vless-77.example.com", "port": 443, "source": "github"}
r = pool.add_key(k2)
assert r == "blocked", "ожидал blocked, получил %r" % r
assert pool.blocked(uri), "ключ должен остаться в блоке"
assert len(pool.get_keys()) == 0, "пул должен быть пуст"

# 3) force=True (ручное добавление своего) — добавляется
k3 = {"uri": uri, "host": "vless-77.example.com", "port": 443, "source": "my"}
assert pool.add_key(k3, force=True) == "added"
assert len(pool.get_keys()) == 1

# 4) пользователь снял блок через dead_remove — refresh снова работает
pool.dead_remove(uri)
k4 = {"uri": uri, "host": "vless-77.example.com", "port": 443, "source": "github"}
assert pool.add_key(k4) == "exists", "после снятия блока должен быть exists (уже в пуле)"

shutil.rmtree(tmp, ignore_errors=True)
print("BLOCKED_FLOW_OK")