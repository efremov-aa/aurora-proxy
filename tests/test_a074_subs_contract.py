# -*- coding: utf-8 -*-
"""A-074: контрактное выравнивание подписки публичной сборки с головным сервером."""
import os
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TREES = (ROOT / "windows", ROOT)

WORKER = r'''
import os, sys, tempfile, time, traceback

tree = sys.argv[1]
data = tempfile.mkdtemp(prefix="aurora_a074_")
os.environ["AURORA_DATA_DIR"] = data
sys.path.insert(0, tree)
import config, crypt, subs, api

failed = []


def check(name, fn):
    try:
        fn()
    except Exception:
        failed.append("%s: %s" % (name, traceback.format_exc().splitlines()[-1]))


def raises(name, exc, fn, *a, **kw):
    try:
        fn(*a, **kw)
    except exc:
        return
    except Exception as e:
        failed.append("%s: wrong exc %s" % (name, type(e).__name__))
        return
    failed.append("%s: no exc" % name)


subs._reconcile_clients = lambda: None
DAY = 86400
now = int(time.time())


def fresh(plan="basic", name="Alpha"):
    s = subs.create(name, plan)
    subs._SUBS[:] = [s]
    subs._BILLING["payments"] = []
    subs._BILLING["traffic"] = {"months": {}}
    return s


def t_create_fields():
    s = fresh()
    assert s["limit_keys"] == 2, s.get("limit_keys")
    assert s["plan_next_starts"] == 0
    assert s["period_started"] > 0
    assert s["period_ends"] == s["expires"]
    assert s["usage_tracking"] is True
    assert s["used_bytes"] == 0
    assert len(s["keys"]) == 2


def t_require_plan():
    raises("require_plan", ValueError, subs.require_plan, "nope")


def t_access_ok():
    s = fresh()
    st = subs.access_state(s)
    assert st["ok"] and st["status"] == 200 and st["reason"] == "active", st
    assert subs.access_reason(s) == "active"
    assert subs.access_status(s) == "ok"
    assert len(st["keys"]) == 2


def t_access_expired():
    s = fresh()
    s["expires"] = now - 10
    st = subs.access_state(s)
    assert st["status"] == 410 and st["reason"] == "expired", st
    assert subs.access_status(s) == "expired"


def t_access_quota():
    s = fresh()
    s["used_bytes"] = s["limit_bytes"]
    st = subs.access_state(s)
    assert st["status"] == 429 and st["reason"] == "traffic_exhausted", st
    assert subs.access_status(s) == "quota"


def t_access_disabled():
    s = fresh()
    s["enabled"] = False
    st = subs.access_state(s)
    assert st["status"] == 403 and st["reason"] == "disabled", st
    assert subs.access_status(s) == "disabled"


def t_access_suspended():
    s = fresh()
    s["blocked_until"] = now + 600
    s["block_reason"] = "bt"
    st = subs.access_state(s)
    assert st["status"] == 403 and st["reason"] == "suspended", st
    assert st["detail"] == "bt", st
    assert subs.access_status(s) == "disabled"


def t_access_invalid_plan():
    s = fresh()
    s["plan"] = "nope"
    st = subs.access_state(s)
    assert st["status"] == 403 and st["reason"] == "invalid", st
    assert subs.access_status(s) == "invalid"
    assert subs.access_state(None)["status"] == 403


def t_limit_keys_cap():
    s = fresh()
    s["limit_keys"] = 1
    assert len(subs.access_state(s)["keys"]) == 1


def t_revoked_filter():
    s = fresh()
    s["revoked_key_ids"] = [s["keys"][0]["id"]]
    keys = subs.access_state(s)["keys"]
    assert len(keys) == 1 and s["keys"][0]["id"] not in keys


def t_unassigned_filter():
    s = fresh()
    s["unassigned_key_ids"] = [s["keys"][1]["id"]]
    assert len(subs.access_state(s)["keys"]) == 1


def t_purchase_sum():
    s = fresh()
    s["expires"] = now + 10 * DAY
    before = s["expires"]
    sub, status, msg = subs.purchase(s["uid"], None, "basic")
    assert status == "renewed", status
    assert sub["expires"] == before + 30 * DAY, (sub["expires"], before)
    assert "суммировано" in msg, msg


def t_purchase_lifetime_kept():
    s = fresh()
    s["expires"] = 0
    sub, status, _ = subs.purchase(s["uid"], None, "basic")
    assert status == "renewed" and sub["expires"] == 0, (status, sub["expires"])


def t_purchase_expired_resets_usage():
    s = fresh()
    s["expires"] = now - 5
    s["used_bytes"] = 777
    s["usage_snapshot"] = {s["keys"][0]["id"]: 777}
    sub, status, _ = subs.purchase(s["uid"], None, "basic")
    assert status == "renewed", status
    assert sub["used_bytes"] == 0, sub["used_bytes"]
    assert sub["usage_snapshot"] == {}, sub["usage_snapshot"]
    assert sub["usage_tracking"] is False
    assert sub["period_ends"] == sub["expires"]
    assert sub["period_started"] >= now - 60


def t_purchase_queued():
    s = fresh()
    s["expires"] = now + 5 * DAY
    sub, status, msg = subs.purchase(s["uid"], None, "prem")
    assert status == "queued", status
    assert sub["plan"] == "basic" and sub["plan_next"] == "prem"
    assert sub["plan_next_starts"] == now + 5 * DAY, sub["plan_next_starts"]
    assert sub["expires_next"] == now + 5 * DAY + 30 * DAY
    assert "вступит после окончания" in msg, msg


def t_purchase_conflict():
    config.SUBS_PLANS["gold"] = {"name": "Золотой", "price": 1999, "bytes": 0,
                                 "days": 30, "devices": 20, "keys": 9,
                                 "features": [], "features_no": []}
    try:
        s = fresh()
        s["expires"] = now + 5 * DAY
        sub, status, _ = subs.purchase(s["uid"], None, "prem")
        assert status == "queued", status
        sub2, status2, msg2 = subs.purchase(s["uid"], None, "gold")
        assert status2 == "conflict", (status2, msg2)
        assert sub2 is None
        assert "очередь уже содержит" in msg2, msg2
        cur = subs.find(s["uid"])
        assert cur["plan_next"] == "prem", cur["plan_next"]
    finally:
        config.SUBS_PLANS.pop("gold", None)


def t_purchase_queued_renewal():
    s = fresh()
    s["expires"] = now + 5 * DAY
    subs.purchase(s["uid"], None, "prem")
    cur = subs.find(s["uid"])
    first = cur["expires_next"]
    start = cur["plan_next_starts"]
    sub, status, msg = subs.purchase(s["uid"], None, "prem")
    assert status == "renewed", status
    assert "отложенный" in msg, msg
    assert sub["plan_next_starts"] == start, (sub["plan_next_starts"], start)
    assert sub["expires_next"] == first, (sub["expires_next"], first)
    assert sub["expires_next"] == start + 30 * DAY, sub["expires_next"]


def t_purchase_lifetime_queue_forbidden():
    s = fresh()
    s["expires"] = 0
    sub, status, msg = subs.purchase(s["uid"], None, "prem")
    assert status == "error" and sub is None, (status, msg)
    assert "бессрочную" in msg, msg


def t_purchase_lifetime_queued_renew_forbidden():
    s = fresh()
    s["expires"] = 0
    s["plan_next"] = "prem"
    s["plan_next_starts"] = 0
    sub, status, msg = subs.purchase(s["uid"], None, "prem")
    assert status == "error" and sub is None, (status, msg)
    assert "бессрочной" in msg, msg


def t_purchase_idempotent():
    s = fresh()
    subs.purchase(s["uid"], None, "basic", idempotency_key="k1")
    sub, status, msg = subs.purchase(s["uid"], None, "basic", idempotency_key="k1")
    assert status == "duplicate", status
    assert "проигнорирована" in msg, msg


def t_update_plan_forbidden():
    s = fresh()
    raises("update_plan", ValueError, subs.update, s["uid"], None, "prem")
    assert subs.find(s["uid"])["plan"] == "basic"


def t_update_limit_keys():
    s = fresh()
    out = subs.update(s["uid"], limit_keys=5)
    assert out["limit_keys"] == 5, out["limit_keys"]


def t_update_enabled_bool():
    s = fresh()
    raises("update_enabled", ValueError, subs.update, s["uid"], None, None, "yes")
    assert subs.update(s["uid"], enabled=False)["enabled"] is False
    assert subs.find(s["uid"])["enabled"] is False


def t_add_key_limits():
    s = fresh()
    key, out = subs.add_key(s["uid"])
    assert key is None and out is None, (key, out)
    s["limit_keys"] = 3
    key, out = subs.add_key(s["uid"])
    assert key and len(out["keys"]) == 3, out
    s["enabled"] = False
    raises("add_key_disabled", PermissionError, subs.add_key, s["uid"])


def t_token_digest():
    s = fresh()
    row, status = subs.by_token_status(s["token"])
    assert row and status == "ok", status
    assert subs.by_token_status("wrong")[0] is None
    assert subs.by_token_status("")[0] is None
    assert subs.by_token_status("a" * 300)[0] is None
    assert subs.by_token_status(s["token"] + "ы")[0] is None
    assert subs.by_token(s["token"])["uid"] == s["uid"]


def t_tick_activates():
    s = fresh()
    s["plan_next"] = "prem"
    s["plan_next_starts"] = now - 10
    s["expires"] = now - 100
    s["expires_next"] = now + 30 * DAY
    s["used_bytes"] = 999
    assert subs._tick() is True
    cur = subs.find(s["uid"])
    assert cur["plan"] == "prem", cur["plan"]
    assert cur["plan_next"] is None
    assert cur["expires"] == now + 30 * DAY
    assert cur["used_bytes"] == 0
    assert cur["usage_tracking"] is False
    assert cur["limit_keys"] == 5, cur["limit_keys"]
    assert cur["period_ends"] == now + 30 * DAY


def t_tick_keeps_lifetime():
    s = fresh()
    s["expires"] = 0
    s["plan_next"] = "prem"
    s["plan_next_starts"] = now - 10
    subs._tick()
    cur = subs.find(s["uid"])
    assert cur["plan"] == "basic", cur["plan"]
    assert cur["plan_next"] == "prem"


def t_normalize_compat():
    legacy = {"uid": "sub_legacy", "name": "L", "plan": "basic", "token": "t" * 20,
              "created": now - 500, "expires": now + 500, "plan_next": "prem",
              "expires_next": now + 900, "next_duration": 400,
              "limit_bytes": 1024, "limit_devices": 3, "enabled": True,
              "used_bytes": 0, "usage_snapshot": {}, "keys": []}
    subs._SUBS[:] = [legacy]
    subs._normalize_compat(subs._SUBS)
    row = subs._SUBS[0]
    assert row["plan_next_starts"] == now + 500, row["plan_next_starts"]
    assert row["limit_keys"] == 2, row["limit_keys"]
    assert row["period_ends"] == now + 500
    assert row["usage_tracking"] is False


def t_plans_normalize():
    ok = config.normalize_plan("gold", {"name": "Золотой", "price": 1999, "bytes": 0,
                                        "days": 30, "devices": 20, "keys": 9})
    assert ok["name"] == "Золотой" and ok["keys"] == 9
    raises("plan_id_upper", ValueError, config.normalize_plan, "Gold", ok)
    raises("plan_id_space", ValueError, config.normalize_plan, "gol d", ok)
    raises("plan_missing", ValueError, config.normalize_plan, "gold", {"name": "x"})
    raises("plan_price", ValueError, config.normalize_plan, "gold", dict(ok, price=-1))
    raises("plan_devices", ValueError, config.normalize_plan, "gold", dict(ok, devices=0))
    raises("plan_features", ValueError, config.normalize_plan, "gold",
           dict(ok, features=["x" * 200]))
    raises("plan_features_many", ValueError, config.normalize_plan, "gold",
           dict(ok, features=["x"] * 101))
    base = config.normalize_plan("gold", {}, base=ok)
    assert base["keys"] == 9
    assert base["name"] == "Золотой"


def t_plans_persist():
    assert config.save_plans() is True
    with open(config.SUBS_PLANS_FILE, "rb") as f:
        raw = f.read()
    assert raw.startswith(b"AURORA2"), raw[:16]
    data = crypt.load_json(config.SUBS_PLANS_FILE, {})
    assert data.get("basic", {}).get("keys") == 2, list(data)
    raises("save_empty", ValueError, config.save_plans, {})
    probe = dict(config.SUBS_PLANS)
    probe["BAD"] = dict(config.SUBS_PLANS["basic"])
    raises("save_bad", ValueError, config.save_plans, probe)


for _name, _fn in sorted(list(globals().items())):
    if _name.startswith("t_") and callable(_fn):
        check(_name, _fn)

if failed:
    print("A074_CHILD_FAIL")
    for _f in failed:
        print(_f)
    raise SystemExit(1)
print("A074_CHILD_OK")
'''


def read(tree, rel):
    return (tree / rel).read_text(encoding="utf-8-sig")


def region(text, start, end):
    i = text.find(start)
    j = text.find(end)
    assert i >= 0, start
    assert j > i, end
    return text[i:j]


def run_child(tree):
    proc = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(WORKER), str(tree)],
        capture_output=True, text=True, encoding="utf-8", errors="replace")
    out = (proc.stdout or "") + (proc.stderr or "")
    assert "A074_CHILD_OK" in out, out[-4000:]
    return True


def static_contract(tree):
    api = read(tree, "api.py")
    subs_py = read(tree, "subs.py")
    conf = read(tree, "config.py")
    core = read(tree, "core.py")

    pub = region(api, "def _sub_publish(self):", "def _setup_reject(")
    for needle in ('"invalid subscription request"', '"subscription not found"',
                   '"subscription access denied"', '"subscription state unavailable"',
                   '"subscription response too large"', 'aurora-sub-%s.txt',
                   "_opaque_uid(s.get(\"uid\"))", "subs.access_state(s)",
                   'int(state.get("status") or 403)', "len(data) > 1024 * 1024",
                   "_security_headers()"):
        assert needle in pub, (tree, needle)

    safe = region(api, "def _opaque_uid(uid):", "def _sub_publish(")
    for needle in ("def _opaque_uid(uid):", 'crypt.opaque_id(str(uid or ""), "subuid")',
                   '"key_handle"', '"plan_next_starts"', '"limit_keys"',
                   '"access_reason"', '"access_detail"', '"access_status"',
                   '"access_state"', '"credential_required": False',
                   '"sub_url": ""'):
        assert needle in safe, (tree, needle)

    for needle in ("def access_state(sub, now=None):", "def access_reason(sub, now=None):",
                   "def require_plan(plan):", "def _start_new_period(sub, now, expires):",
                   "def _normalize_compat(rows):", "_USAGE_LOCK",
                   'return None, "conflict", "очередь уже содержит тариф %s" % nxt_plan',
                   'raise ValueError("смена тарифа только через purchase")',
                   "hmac.compare_digest(stored, clean)", "plan_next_starts",
                   "limit_keys", "period_started", "period_ends"):
        assert needle in subs_py, (tree, needle)
    assert "def _valid_plan_id(" not in conf, tree
    assert "def _atomic_write(" in subs_py, tree

    for needle in ("_PLAN_FIELDS = ", "_PLAN_LIST_FIELDS = ",
                   "def normalize_plan(plan_id, value, base=None):", "def _plan_id(value):",
                   "def save_plans(plans=None):", '_PLANS_GOOD = None',
                   'raise ValueError("default plan is missing")',
                   "crypt.save_json(SUBS_PLANS_FILE, payload)",
                   "crypt.load_bytes(SUBS_PLANS_FILE)", "def _plans_snapshot():"):
        assert needle in conf, (tree, needle)

    core_sub = region(core, "def apply_sub_clients():", "def set_active_tag(")
    for needle in ("_authoritative_config(previous, get_vless_now())",
                   "_xray_config_valid(cfg)", "_restore_config_cas(expected, previous)",
                   "_config_fingerprint(cfg)", 'level["statsUserUplink"] = True',
                   'level["statsUserDownlink"] = True', '"clients unavailable"',
                   '"config preflight failed"',
                   'target.setdefault("settings", {}).get("clients") == clients'):
        assert needle in core_sub, (tree, needle)
    return True


def parity():
    linux, windows = ROOT, ROOT / "windows"
    for rel, start, end in (
            ("api.py", "def _opaque_uid(uid):", "def _sub_publish("),
            ("api.py", "def _sub_publish(self):", "def _setup_reject("),
            ("config.py", "# --- тарифы:", "# --- меш:"),
            ("core.py", "def apply_sub_clients():", "def set_active_tag("),
            ("subs.py", "def access_state(", "def _vless_params("),
            ("subs.py", "def _purchase_impl(", "def _tick(")):
        assert region(read(linux, rel), start, end) == \
            region(read(windows, rel), start, end), (rel, start)
    return True


def main():
    for tree in TREES:
        run_child(tree)
        static_contract(tree)
    parity()
    print("A074_SUBS_OK")


if __name__ == "__main__":
    main()
