# -*- coding: utf-8 -*-
"""A-160: релей-туннель меш-сети (A-145/A-146) — контракт переноса из эталона.

Проверяем, что клиентская сборка умеет тот же протокол, что и эталон:
константы кадра, round-trip с bytes-ключом, фрагментацию, виртуальные адреса,
безопасный выключенный по умолчанию режим, правила xray (outbound mesh + email)
и то, что автообновление знает про новые модули.
"""
import io
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

FAILED = []


def check(cond, name):
    if cond:
        print("ok", name)
    else:
        FAILED.append(name)
        print("FAIL", name)


def read(path):
    return io.open(path, "r", encoding="utf-8", newline="").read()


def main():
    mt = read(ROOT / "meshtunnel.py")
    mt_win = read(ROOT / "windows" / "meshtunnel.py")
    check(mt == mt_win, "meshtunnel mirror bit-for-bit")

    sys.path.insert(0, str(ROOT))
    import meshtunnel

    # --- константы протокола (менять только синхронно с мастером) ---
    check(meshtunnel.MESH_PORT == 51821, "MESH_PORT=51821")
    check(meshtunnel.MAGIC == b"\xa7\xa1", "MAGIC=a7a1")
    check(meshtunnel.VER == 1, "VER=1")
    check(meshtunnel.REPLAY_WINDOW == 256, "REPLAY_WINDOW=256")
    check(meshtunnel.BUF == 65536, "BUF=65536")
    check(meshtunnel.MAX_PEERS == 64, "MAX_PEERS=64")
    check((meshtunnel.T_HELLO, meshtunnel.T_OK, meshtunnel.T_DATA,
           meshtunnel.T_PING, meshtunnel.T_PONG, meshtunnel.T_BYE,
           meshtunnel.T_FRAG) == (1, 2, 3, 4, 5, 6, 7), "T_* = 1..7")
    check(meshtunnel.MESH_NET == "100.64.0.0/10", "MESH_NET=100.64.0.0/10")

    # --- по умолчанию туннель выключен ---
    check(meshtunnel.enabled() is False, "enabled() False by default")

    # --- round-trip кадра с bytes-ключом ---
    key = b"aurora-test-key-32-bytes-long-0001"
    blob = meshtunnel._pack(meshtunnel.T_DATA, b"example.com:443", key)
    check(isinstance(blob, bytes) and len(blob) > 20, "pack returns bytes")
    got = meshtunnel._unpack(blob, key)
    if isinstance(got, tuple):
        mtype, payload = got[0], got[1]
    elif isinstance(got, dict):
        mtype, payload = got.get("type"), got.get("payload")
    else:
        mtype, payload = None, None
    check(mtype == meshtunnel.T_DATA, "unpack type=T_DATA")
    check(payload == b"example.com:443", "unpack payload round-trip")

    # неверный ключ -> тихий отброс (fail-closed, без исключений наружу)
    try:
        bad = meshtunnel._unpack(blob, b"another-key-entirely-different-9999")
        check(not bad or (isinstance(bad, tuple) and not bad[1]), "bad key rejected")
    except Exception as exc:
        check(True, "bad key rejected (%s)" % type(exc).__name__)

    # пустой payload тоже не должен ломать
    try:
        empty = meshtunnel._pack(meshtunnel.T_PING, b"", key)
        check(isinstance(empty, bytes), "pack empty payload")
    except Exception as exc:
        check(False, "pack empty payload (%s)" % type(exc).__name__)

    # --- фрагментация больших потоков ---
    big = os.urandom(5000)
    try:
        state = {}
        frags = meshtunnel._fragment(big)
        check(isinstance(frags, (list, tuple)) and len(frags) >= 2,
              "fragment splits big payload (%s)" % (len(frags) if isinstance(frags, (list, tuple)) else "?"))
        for part in frags:
            out = meshtunnel._defrag(state, part)
        check(out == big, "defrag restores payload")
    except Exception as exc:
        check(False, "fragment round-trip (%s)" % type(exc).__name__)

    # --- виртуальные адреса и имена туннелей ---
    addr = meshtunnel.node_address("node-1")
    check(isinstance(addr, str) and addr.startswith("100."),
          "node_address in 100.64.0.0/10 (%s)" % addr)
    check(meshtunnel.node_address("node-1") == addr, "node_address deterministic")
    name = meshtunnel.tunnel_name("node-1")
    check(name.startswith("mesh-") and " " not in name and "/" not in name,
          "tunnel_name prefixes mesh- (%s)" % name)
    check(meshtunnel.tunnel_name("bad id!!") == "",
          "tunnel_name rejects invalid id (fail-closed)")

    # --- слушаем только loopback ---
    check('bind(("127.0.0.1"' in mt or "bind(('127.0.0.1'" in mt,
          "_listen binds 127.0.0.1 only")
    check("0.0.0.0" not in mt, "no 0.0.0.0 bind in meshtunnel")

    # --- секрет не пишется в лог/конфиг/панель ---
    for line in mt.splitlines():
        if "config.log" in line:
            check("secret" not in line.lower() or "no secret" in line.lower(),
                  "log line without secret leak")
    check("AURORA_MESH_SECRET" in mt, "reads MESH_SECRET env")

    # --- core.py: A-145 (outbound mesh + правило по email) ---
    for tree in ("", "windows" + os.sep):
        core = read(ROOT / (tree + "core.py"))
        check("def _mesh_outbound(" in core, "core %s _mesh_outbound" % (tree or "linux"))
        check("def _vless_emails(" in core, "core %s _vless_emails" % (tree or "linux"))
        check("def _mesh_rule_position(" in core, "core %s _mesh_rule_position" % (tree or "linux"))
        check('allowed.add("mesh")' in core, "core %s A-146 allowed.add mesh" % (tree or "linux"))
        check('"outboundTag": "mesh"' in core, "core %s mesh rule" % (tree or "linux"))
        check('"inboundTag": ["vless-in"]' in core, "core %s vless-in anchor" % (tree or "linux"))
        check('"address": "127.0.0.1"' in core, "core %s socks loopback" % (tree or "linux"))

    # --- config.py: выключено по умолчанию + env ---
    for tree in ("", "windows" + os.sep):
        cfg = read(ROOT / (tree + "config.py"))
        check('"mesh_tunnel": False' in cfg, "config %s mesh_tunnel False default" % (tree or "linux"))
        check("AURORA_MESH_TUNNEL" in cfg, "config %s reads AURORA_MESH_TUNNEL" % (tree or "linux"))
        check("AURORA_MESH_SECRET" in cfg, "config %s reads AURORA_MESH_SECRET" % (tree or "linux"))
        check("AURORA_MESH_MASTER_ADDR" in cfg, "config %s reads AURORA_MESH_MASTER_ADDR" % (tree or "linux"))
        check("AURORA_MESH_PUBLIC_ADDR" in cfg, "config %s reads AURORA_MESH_PUBLIC_ADDR" % (tree or "linux"))

    # --- updater: новые модули в автообновлении (баг A-111) ---
    for tree in ("", "windows" + os.sep):
        upd = read(ROOT / (tree + "updater.py"))
        check('"meshtunnel.py"' in upd, "updater %s has meshtunnel.py" % (tree or "linux"))
        check('"extgate.py"' in upd, "updater %s has extgate.py" % (tree or "linux"))

    # --- run.py: старт только при включённом флаге ---
    for tree in ("", "windows" + os.sep):
        run = read(ROOT / (tree + "run.py"))
        check("import meshtunnel" in run, "run %s imports meshtunnel" % (tree or "linux"))
        check('config.get("mesh_tunnel"' in run, "run %s guards on mesh_tunnel" % (tree or "linux"))
        check("AURORA_MESH_ROLE" in run, "run %s role from env" % (tree or "linux"))

    # --- релей не поднимается сам (bind не проверяем, только флаг) ---
    check(meshtunnel.status().get("mode") == "relay", "status mode=relay")
    st = meshtunnel.status()
    check("secret" not in st and "_secret" not in st, "status has no secret")
    check(st.get("enabled") is False, "status disabled by default")

    if FAILED:
        print("FAILED", len(FAILED), FAILED)
        print("A160_RELAY_TUNNEL_FAIL")
        sys.exit(1)
    print("A160_RELAY_TUNNEL_OK")


if __name__ == "__main__":
    main()
