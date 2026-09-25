import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
CHECK = r'''
import os
import shutil
import sys
import time
from types import SimpleNamespace

tree = sys.argv[1]
data = sys.argv[2]
os.environ["AURORA_DATA_DIR"] = data
sys.path.insert(0, tree)
import config
import subs

config.SUBS_FILE = os.path.join(data, "subs.json")
config.SUBS_PLANS = {
    "free": {"name": "Free", "price": 0, "bytes": 10, "days": 7, "devices": 1, "keys": 1},
    "basic": {"name": "Basic", "price": 399, "bytes": 100, "days": 30, "devices": 3, "keys": 2},
    "prem": {"name": "Premium", "price": 799, "bytes": 0, "days": 30, "devices": 10, "keys": 5},
}
config.SUBS_PLAN_DEFAULT = "basic"
subs.SUBS_FILE = config.SUBS_FILE
subs.BILLING_FILE = os.path.join(data, "billing.json")
subs._SUBS = []
subs._BILLING = subs._empty_billing()
subs._reconcile_clients = lambda: None
subs._save()
subs._save_billing_locked()

sub, status, msg, payment = subs.purchase_with_receipt(name="Alpha", plan="basic", amount=399, idempotency_key="order-1")
assert status == "created", status
assert payment["amount"] == 399
assert payment["plan_snapshot"]["price"] == 399
first_uid = sub["uid"]
first_expires = sub["expires"]
same, duplicate_status, _, duplicate_payment = subs.purchase_with_receipt(uid=first_uid, plan="basic", idempotency_key="order-1")
assert duplicate_status == "duplicate", duplicate_status
assert same["expires"] == first_expires
assert len(subs.billing_snapshot()["payments"]) == 1
config.SUBS_PLANS["basic"]["price"] = 999
assert subs.billing_snapshot()["payments"][0]["amount"] == 399

queued, queued_status, _, queued_payment = subs.purchase_with_receipt(uid=first_uid, plan="prem", amount=799, idempotency_key="order-2")
assert queued_status == "queued", queued_status
assert queued_payment["operation"] == "queued"
free = subs.create("Free", "free")
assert len(subs.billing_snapshot()["payments"]) == 2

import api
stats = api._stats()
assert stats["income_month"] == 1198, stats
assert stats["stats_version"] == 2
assert len(stats["payments"]) == 2
listed = api._subs_list()
assert all("access_status" in row and "access_ok" in row for row in listed["subs"])
subs.delete(first_uid)
assert len(subs.billing_snapshot()["payments"]) == 2

matrix = subs.create("Matrix", "basic")
now = int(time.time())
with subs._LOCK:
    row = next(s for s in subs._SUBS if s.get("uid") == matrix["uid"])
    row["expires"] = now - 1
    assert subs.access_status(row, now) == "expired"
    row["expires"] = now
    assert subs.access_status(row, now) == "expired"
    row["enabled"] = False
    assert subs.access_status(row, now) == "disabled"
    row["enabled"] = True
    row["expires"] = now + 60
    row["used_bytes"] = row["limit_bytes"]
    assert subs.access_status(row, now) == "quota", (subs.access_status(row, now), row)
    row["used_bytes"] = 0
    row["expires"] = 0
    assert subs.access_status(row, now) == "ok"

with subs._LOCK:
    subs._SUBS = []
    subs._BILLING = subs._empty_billing()
    subs._save()
    subs._save_billing_locked()
traffic = subs.create("Traffic", "basic")
with subs._LOCK:
    subs._SUBS[0]["keys"][0]["id"] = "k1"
    subs._SUBS[0]["usage_snapshot"] = {}
    subs._SUBS[0]["usage_tracking"] = False
    subs._save()

outputs = [b"name: user>>>k1\nvalue: 100\n", b"name: user>>>k1\nvalue: 150\n", b"name: user>>>k1\nvalue: 20\n", b"", b""]

def fake_run(*args, **kwargs):
    value = outputs.pop(0)
    return SimpleNamespace(returncode=1 if not value else 0, stdout=value)

subs._XRAY_BIN = "xray"
old_run = subs.subprocess.run
subs.subprocess.run = fake_run
try:
    subs.refresh_usage()
    assert subs._SUBS[0]["used_bytes"] == 0
    subs.refresh_usage()
    assert subs._SUBS[0]["used_bytes"] == 50
    subs.refresh_usage()
    assert subs._SUBS[0]["used_bytes"] == 70
    subs.refresh_usage()
    assert subs._SUBS[0]["used_bytes"] == 70
    subs.refresh_usage()
    assert subs._SUBS[0]["used_bytes"] == 70
finally:
    subs.subprocess.run = old_run

assert sum(subs._BILLING["traffic"]["months"].values()) == 70
assert subs._billing_month(0) == "1970-01"
print("BILLING_TREE_OK")
shutil.rmtree(data, ignore_errors=True)
'''


def run_tree(path):
    data = tempfile.mkdtemp(prefix="aurora-billing-")
    try:
        result = subprocess.run(
            [sys.executable, "-c", CHECK, path, data],
            cwd=path,
            text=True,
            capture_output=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "BILLING_TREE_OK" in result.stdout, result.stdout
    finally:
        import shutil
        shutil.rmtree(data, ignore_errors=True)


run_tree(os.path.join(ROOT, "windows"))
run_tree(ROOT)
print("BILLING_REGRESSION_OK")
