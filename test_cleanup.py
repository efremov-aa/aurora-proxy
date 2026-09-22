import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config
import pool

pool._DEAD = {"vless://dead1@h:443?type=tcp": {"reason": "autodead_conn", "ts": 1}}
pool._STATUS = {
    "vless://bad1@h:443?type=tcp": {"status": "bad", "ping_ms": 9999},
    "vless://slow1@h:443?type=tcp": {"status": "slow", "ping_ms": 600},
    "vless://noip1@h:443?type=tcp": {"status": "noip", "ping_ms": 40},
    "vless://ok1@h:443?type=tcp": {"status": "ok", "ping_ms": 80, "exit_ip": "1.2.3.4"},
}
pool._KEYS = [
    {"uri": "vless://dead1@h:443?type=tcp", "tag": "d1", "source": "github"},
    {"uri": "vless://bad1@h:443?type=tcp", "tag": "b1", "source": "github"},
    {"uri": "vless://slow1@h:443?type=tcp", "tag": "s1", "source": "github"},
    {"uri": "vless://noip1@h:443?type=tcp", "tag": "n1", "source": "github"},
    {"uri": "vless://ok1@h:443?type=tcp", "tag": "o1", "source": "github"},
    {"uri": "vless://my1@h:443?type=tcp", "tag": "m1", "source": "my", "host": "h", "port": 443},
    {"uri": "vless://mn1@h:443?type=tcp", "tag": "mn1", "source": "manual", "host": "h", "port": 443},
]

n = pool.cleanup()
remain = [k["tag"] for k in pool._KEYS]
print("removed:", n)
print("remain:", remain)

assert n == 4, "ожидали удалить 4 мёртвых github, убрано %d" % n
assert remain == ["o1", "m1", "mn1"], "неверный остаток: %s" % remain
assert any(k["source"] == "my" for k in pool._KEYS), "свои ключи не должны удаляться"
print("CLEANUP_FLOW_OK")
