# Aurora v1.4.0 — подписки: клиентские аккаунты, тарифы, привязка ключей к серверу.
# Хранение: data/subs.json. Подписка = аккаунт клиента с N ключами (uuid).
# Привязка: uuid клиента попадает в clients inbound vless-in в xray.json
# (REST реально перезапускает inbound), и клиент может подключаться извне.

import copy
import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid as _uuid

import config
import crypt

SUBS_FILE = config.SUBS_FILE
BILLING_FILE = os.path.join(os.path.dirname(SUBS_FILE), "billing.json")

_LOCK = threading.RLock()
_SUBS = []
_BILLING = {"version": 1, "payments": [], "traffic": {"months": {}}}

# бинарь xray для statsquery (счётчики трафика по ключам):
# сначала PATH, потом типовые места установки (дом/сервер/Docker/Windows)
_XRAY_BIN = ""
for _c in (shutil.which("xray"),
           os.path.join(os.path.expanduser("~"), "xray"),
           os.path.join(config.BASE_DIR, "xray"),
           "/usr/local/bin/xray",
           "/home/ai/xray"):
    if _c and os.path.exists(_c):
        _XRAY_BIN = _c
        break

_BG_STARTED = False  # демон-поток (активация plan_next + сбор трафика) стартует один раз


def _now():
    return int(time.time())


def _clean_id(text):
    """Из произвольного имени/токена — безопасный фрагмент для id."""
    s = re.sub(r"[^a-zA-Z0-9_-]", "", str(text).strip())
    return s[:40]


def _uid():
    return "sub_%s" % _uuid.uuid4().hex[:8]


_MISSING = object()


def _storage_failure(path, reason):
    config.quarantine_file(path)
    raise config.StorageDataError("%s: %s" % (os.path.basename(path), reason))


def _read_crypt(path, default):
    try:
        return crypt.load_json(path, default=default)
    except Exception as e:
        _storage_failure(path, str(e))


def _is_nonnegative_int(value):
    return type(value) is int and value >= 0


def _validate_subscriptions(raw):
    if not isinstance(raw, list):
        raise ValueError("subscriptions root is not a list")
    out = []
    uids = set()
    tokens = set()
    key_ids = set()
    int_fields = ("created", "expires", "limit_bytes", "limit_devices",
                  "expires_next", "next_duration", "used_bytes")
    string_fields = ("name", "remark", "token")
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("subscription record is not an object")
        rec = dict(item)
        uid = rec.get("uid")
        if not isinstance(uid, str) or not uid.strip():
            raise ValueError("subscription uid is invalid")
        uid = uid.strip()
        if uid in uids:
            raise ValueError("duplicate subscription uid")
        token = rec.get("token")
        if not isinstance(token, str) or not token.strip():
            raise ValueError("subscription token is invalid")
        token = token.strip()
        if token in tokens:
            raise ValueError("duplicate subscription token")
        name = rec.get("name")
        if not isinstance(name, str):
            raise ValueError("subscription name is invalid")
        plan = rec.get("plan")
        if not isinstance(plan, str) or plan not in config.SUBS_PLANS:
            raise ValueError("subscription plan is invalid")
        for field in string_fields:
            if field in rec and not isinstance(rec[field], str):
                raise ValueError("subscription field %s is invalid" % field)
        for field in int_fields:
            if field in rec and not _is_nonnegative_int(rec[field]):
                raise ValueError("subscription field %s is invalid" % field)
        if "enabled" in rec and type(rec["enabled"]) is not bool:
            raise ValueError("subscription enabled is invalid")
        if "usage_tracking" in rec and type(rec["usage_tracking"]) is not bool:
            raise ValueError("subscription usage_tracking is invalid")
        plan_next = rec.get("plan_next")
        if plan_next is not None and (not isinstance(plan_next, str)
                                      or plan_next not in config.SUBS_PLANS):
            raise ValueError("subscription next plan is invalid")
        usage = rec.get("usage_snapshot", {})
        if not isinstance(usage, dict):
            raise ValueError("subscription usage snapshot is invalid")
        usage = dict(usage)
        for key, value in usage.items():
            if not isinstance(key, str) or not _is_nonnegative_int(value):
                raise ValueError("subscription usage value is invalid")
        keys = rec.get("keys", [])
        if keys is None:
            keys = []
        if not isinstance(keys, list):
            raise ValueError("subscription keys are invalid")
        normalized_keys = []
        for key in keys:
            if not isinstance(key, dict):
                raise ValueError("subscription key record is invalid")
            item_key = dict(key)
            key_id = config.canonical_uuid(item_key.get("id"))
            if not key_id:
                raise ValueError("subscription key id is invalid")
            if key_id in key_ids:
                raise ValueError("duplicate subscription key id")
            key_ids.add(key_id)
            for field in ("device_id", "remark", "note"):
                if field in item_key and not isinstance(item_key[field], str):
                    raise ValueError("subscription key field %s is invalid" % field)
            if "created" in item_key and not _is_nonnegative_int(item_key["created"]):
                raise ValueError("subscription key created is invalid")
            item_key["id"] = key_id
            normalized_keys.append(item_key)
        rec["uid"] = uid
        rec["token"] = token
        rec["name"] = name
        rec["remark"] = rec.get("remark", "")
        rec["created"] = rec.get("created", 0)
        rec["expires"] = rec.get("expires", 0)
        rec["limit_bytes"] = rec.get("limit_bytes", 0)
        rec["limit_devices"] = rec.get("limit_devices", 0)
        rec["enabled"] = rec.get("enabled", True)
        rec["plan_next"] = plan_next
        rec["expires_next"] = rec.get("expires_next", 0)
        rec["next_duration"] = rec.get("next_duration", 0)
        rec["used_bytes"] = rec.get("used_bytes", 0)
        rec["usage_snapshot"] = usage
        rec["usage_tracking"] = rec.get("usage_tracking", False)
        rec["keys"] = normalized_keys
        uids.add(uid)
        tokens.add(token)
        out.append(rec)
    return out


def load():
    """Загрузка data/subs.json без потери исходных данных."""
    global _SUBS
    raw = _read_crypt(SUBS_FILE, _MISSING)
    present = raw is not _MISSING
    if not present:
        raw = []
    try:
        local = _validate_subscriptions(raw)
    except (TypeError, ValueError) as e:
        _storage_failure(SUBS_FILE, str(e))
    if present:
        crypt.save_json(SUBS_FILE, local)
    with _LOCK:
        _SUBS = local


def _atomic_write(path, obj):
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=1, ensure_ascii=False)
        os.replace(tmp, path)
        return True
    except OSError as e:
        config.log("subs: запись %s не удалась: %s" % (os.path.basename(path), e))
        return False


def _save():
    with _LOCK:
        crypt.save_json(SUBS_FILE, _SUBS)


def _empty_billing():
    return {"version": 1, "payments": [], "traffic": {"months": {}}}


def _billing_month(now=None):
    ts = _now() if now is None else _int(now, _now())
    dt = time.gmtime(ts)
    return "%04d-%02d" % (dt.tm_year, dt.tm_mon)


def _validate_billing(raw):
    if not isinstance(raw, dict):
        raise ValueError("billing root is not an object")
    version = raw.get("version", 1)
    if type(version) is not int or version != 1:
        raise ValueError("billing version is invalid")
    payments = raw.get("payments", [])
    if not isinstance(payments, list):
        raise ValueError("billing payments are invalid")
    out_payments = []
    payment_ids = set()
    int_fields = ("paid_at", "amount", "coverage_start", "coverage_end")
    string_fields = ("kind", "state", "uid", "name", "plan", "plan_name",
                     "currency", "operation", "source", "idempotency_key")
    for item in payments:
        if not isinstance(item, dict):
            raise ValueError("billing payment is not an object")
        payment_id = item.get("id")
        if not isinstance(payment_id, str) or not payment_id.strip():
            raise ValueError("billing payment id is invalid")
        payment_id = payment_id.strip()
        if payment_id in payment_ids:
            raise ValueError("duplicate billing payment id")
        if "paid_at" not in item or type(item["paid_at"]) is not int or item["paid_at"] <= 0:
            raise ValueError("billing payment time is invalid")
        for field in int_fields:
            if field in item and not _is_nonnegative_int(item[field]):
                raise ValueError("billing payment field %s is invalid" % field)
        for field in string_fields:
            if field in item and not isinstance(item[field], str):
                raise ValueError("billing payment field %s is invalid" % field)
        snapshot = item.get("plan_snapshot", {})
        if not isinstance(snapshot, dict):
            raise ValueError("billing payment snapshot is invalid")
        rec = copy.deepcopy(item)
        rec["id"] = payment_id
        rec["plan_snapshot"] = copy.deepcopy(snapshot)
        out_payments.append(rec)
        payment_ids.add(payment_id)
    traffic = raw.get("traffic", {})
    if not isinstance(traffic, dict):
        raise ValueError("billing traffic is invalid")
    months = traffic.get("months", {})
    if not isinstance(months, dict):
        raise ValueError("billing traffic months are invalid")
    out_months = {}
    for month, value in months.items():
        if (not isinstance(month, str)
                or not re.fullmatch(r"\d{4}-\d{2}", month)
                or not _is_nonnegative_int(value)):
            raise ValueError("billing traffic value is invalid")
        out_months[month] = value
    return {"version": 1, "payments": out_payments,
            "traffic": {"months": out_months}}


def _normalize_billing(raw):
    return _validate_billing(raw)


def _load_billing():
    global _BILLING
    raw = _read_crypt(BILLING_FILE, _MISSING)
    present = raw is not _MISSING
    if not present:
        local = _empty_billing()
    else:
        try:
            local = _validate_billing(raw)
        except (TypeError, ValueError) as e:
            _storage_failure(BILLING_FILE, str(e))
    if present:
        crypt.save_json(BILLING_FILE, local)
    with _LOCK:
        _BILLING = local


def _save_billing_locked(value=None):
    data = _BILLING if value is None else value
    crypt.save_json(BILLING_FILE, data)
    return True


def _public_payment(payment):
    if not isinstance(payment, dict):
        return {}
    return {
        "id": str(payment.get("id", "") or ""),
        "kind": str(payment.get("kind", "payment") or "payment"),
        "state": str(payment.get("state", "paid") or "paid"),
        "paid_at": _int(payment.get("paid_at"), 0),
        "uid": str(payment.get("uid", "") or ""),
        "name": str(payment.get("name", "") or "")[:120],
        "plan": str(payment.get("plan", "") or ""),
        "plan_snapshot": copy.deepcopy(payment.get("plan_snapshot") or {}),
        "plan_name": str(payment.get("plan_name", "") or "")[:120],
        "amount": max(0, _int(payment.get("amount"), 0)),
        "currency": str(payment.get("currency", "RUB") or "RUB")[:8],
        "operation": str(payment.get("operation", "payment") or "payment")[:24],
        "coverage_start": _int(payment.get("coverage_start"), 0),
        "coverage_end": _int(payment.get("coverage_end"), 0),
        "source": str(payment.get("source", "manual") or "manual")[:24],
        "idempotency_key": str(payment.get("idempotency_key", "") or "")[:128],
    }


def billing_snapshot(now=None):
    month = _billing_month(now)
    with _LOCK:
        payments = [_public_payment(p) for p in _BILLING.get("payments", [])]
        payments.sort(key=lambda p: (p.get("paid_at", 0), p.get("id", "")), reverse=True)
        month_payments = [p for p in payments
                          if p.get("kind") == "payment"
                          and p.get("state") == "paid"
                          and _billing_month(p.get("paid_at")) == month]
        traffic = max(0, _int(_BILLING.get("traffic", {}).get("months", {}).get(month), 0))
        return {
            "month": month,
            "payments": payments[:100],
            "month_payments": month_payments,
            "traffic_month": traffic,
        }


def _payment_amount(value, default):
    if value is None or value == "":
        return max(0, _int(default, 0))
    if isinstance(value, bool) or isinstance(value, float) and not value.is_integer():
        raise ValueError("invalid payment amount")
    try:
        amount = int(value)
    except (TypeError, ValueError):
        raise ValueError("invalid payment amount")
    if amount < 0 or amount > 1000000000000:
        raise ValueError("invalid payment amount")
    return amount


def _payment_by_key(key):
    if not key:
        return None
    for payment in reversed(_BILLING.get("payments", [])):
        if payment.get("idempotency_key") == key:
            return payment
    return None


def _append_payment_locked(sub, plan, plan_snapshot, amount, operation,
                           coverage_start, coverage_end, idempotency_key):
    payment = {
        "id": "pay_" + _uuid.uuid4().hex,
        "kind": "payment",
        "state": "paid",
        "paid_at": _now(),
        "uid": sub.get("uid", ""),
        "name": str(sub.get("name", "") or "")[:120],
        "plan": plan,
        "plan_snapshot": copy.deepcopy(plan_snapshot),
        "plan_name": str(plan_snapshot.get("name", plan) or plan)[:120],
        "amount": max(0, _int(amount, 0)),
        "currency": "RUB",
        "operation": operation,
        "coverage_start": max(0, _int(coverage_start, 0)),
        "coverage_end": max(0, _int(coverage_end, 0)),
        "source": "manual",
        "idempotency_key": str(idempotency_key or "")[:128],
    }
    billing = copy.deepcopy(_BILLING)
    billing.setdefault("payments", []).append(payment)
    _save_billing_locked(billing)
    _BILLING.clear()
    _BILLING.update(billing)
    return _public_payment(payment)


def all():
    """Все подписки (копии)."""
    with _LOCK:
        return [copy.deepcopy(s) for s in _SUBS]


def count():
    with _LOCK:
        return len(_SUBS)


def find(uid):
    """Подписка по uid или None."""
    with _LOCK:
        for s in _SUBS:
            if s.get("uid") == uid:
                return copy.deepcopy(s)
    return None


def _gen_token():
    import secrets
    return secrets.token_urlsafe(12)


def _gen_uuid():
    return str(_uuid.uuid4())


def plan_info(plan):
    p = config.SUBS_PLANS.get(plan or "")
    return dict(p) if isinstance(p, dict) else {}


def _int(value, default=0):
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return default


def _active_key_limit(sub):
    p = plan_info(sub.get("plan"))
    plan_keys = max(1, _int(p.get("keys"), 1))
    devices = _int(sub.get("limit_devices"), plan_keys)
    if devices <= 0:
        devices = plan_keys
    return min(plan_keys, devices)


def _quota_exceeded(sub):
    limit = _int(sub.get("limit_bytes"), 0)
    used = _int(sub.get("used_bytes"), 0)
    return limit > 0 and used >= limit


def _expired(sub, now=None):
    exp = _int(sub.get("expires", 0), 0)
    return bool(exp and exp <= (_now() if now is None else now))


def _reconcile_clients():
    try:
        import core
        core.apply_sub_clients()
    except Exception as e:
        config.log("subs: client reconcile failed: %s" % e)


def make_key(device_id=""):
    """Новый ключ для подписки: uuid + метаданные."""
    return {
        "id": _gen_uuid(),
        "device_id": str(device_id or "").strip()[:64],
        "created": _now(),
        "remark": "",
        "note": "",
    }


def create(name, plan=None, remark=""):
    """Создаёт подписку с указанным тарифом и ключами. Возвращает подписку."""
    plan = plan or config.SUBS_PLAN_DEFAULT
    p = plan_info(plan)
    if not p:
        raise ValueError("unknown subscription plan")
    days = p.get("days", 0)
    expires = _now() + days * 86400 if days else 0
    sub = {
        "uid": _uid(),
        "name": str(name or "").strip() or "Клиент %d" % (int(time.time()) % 10000),
        "plan": plan,
        "remark": str(remark or "").strip(),
        "token": _gen_token(),
        "created": _now(),
        "expires": expires,          # unix ts, 0 = бессрочно
        "limit_bytes": p.get("bytes", 0),
        "limit_devices": p.get("devices", 0),
        "enabled": True,
        "plan_next": None,       # отложенная смена тарифа (после окончания текущего)
        "expires_next": 0,       # срок отложенного тарифа, unix ts
        "next_duration": 0,       # длительность отложенного тарифа, секунды
        "used_bytes": 0,         # кэш фактического трафика клиента (из xray API)
        "usage_snapshot": {},
        "usage_tracking": False,
        "keys": [make_key() for _ in range(max(1, p.get("keys", 1)))],
    }
    with _LOCK:
        _SUBS.append(sub)
        _save()
    config.log("subs: создана подписка %s (%s, ключей %d)" % (
        sub["name"], plan, len(sub["keys"])))
    return copy.deepcopy(sub)


def _purchase_impl(uid=None, name=None, plan=None, remark="", amount=None,
                   idempotency_key=None):
    plan = plan or config.SUBS_PLAN_DEFAULT
    p = plan_info(plan)
    if not p:
        raise ValueError("unknown subscription plan")
    days = p.get("days", 0)
    add = days * 86400
    now = _now()
    key = str(idempotency_key or "").strip()[:128]
    plan_snapshot = copy.deepcopy(p)
    payment_amount = _payment_amount(amount, p.get("price", 0))
    with _LOCK:
        prior = _payment_by_key(key) if key else None
        if prior:
            if prior.get("plan") != plan or uid and prior.get("uid") != uid:
                raise ValueError("idempotency key already used")
            target = next((s for s in _SUBS
                           if s.get("uid") == prior.get("uid")), None)
            if target is None:
                return None, "error", "подписка не найдена", _public_payment(prior)
            return copy.deepcopy(target), "duplicate", "повторная оплата проигнорирована", _public_payment(prior)

        sub = None
        if uid:
            for s in _SUBS:
                if s.get("uid") == uid:
                    sub = s
                    break
            if sub is None:
                return None, "error", "подписка не найдена", {}
        else:
            nm = str(name or "").strip()
            for s in _SUBS:
                if nm and s.get("name", "").strip().lower() == nm.lower():
                    sub = s
                    break

        if sub is None:
            sub = create(nm or None, plan=plan, remark=remark)
            coverage_start = now
            coverage_end = int(sub.get("expires", 0) or 0)
            operation = "created"
            status, msg = "created", "подписка создана по тарифу %s" % plan
        else:
            cur_plan = sub.get("plan")
            cur_exp = int(sub.get("expires", 0) or 0)
            nxt_plan = sub.get("plan_next")
            nxt_exp = int(sub.get("expires_next", 0) or 0)
            nxt_duration = _int(sub.get("next_duration"), 0)

            if plan == nxt_plan:
                queue_base = nxt_exp or (max(cur_exp, now) if cur_exp else now)
                if nxt_duration <= 0 and nxt_exp:
                    nxt_duration = max(0, nxt_exp - queue_base)
                nxt_duration += add
                sub["next_duration"] = nxt_duration
                sub["expires_next"] = queue_base + nxt_duration
                coverage_start = queue_base
                coverage_end = sub["expires_next"]
                operation = "queued_renewal"
                status, msg = "renewed", "отложенный %s продлен до %s" % (plan, sub["expires_next"])
            elif cur_plan == plan and (cur_exp == 0 or cur_exp >= now):
                coverage_start = cur_exp or now
                if cur_exp:
                    sub["expires"] = cur_exp + add
                    if nxt_plan and nxt_duration > 0:
                        sub["expires_next"] = sub["expires"] + nxt_duration
                    elif nxt_plan and nxt_exp:
                        sub["expires_next"] = nxt_exp + add
                        sub["next_duration"] = max(0, nxt_exp - cur_exp)
                coverage_end = int(sub.get("expires_next", 0) or sub.get("expires", 0) or 0)
                operation = "renewed"
                status, msg = "renewed", "время %s суммировано" % plan
            elif cur_plan == plan:
                sub["expires"] = now + add
                if nxt_plan and nxt_duration <= 0 and nxt_exp:
                    nxt_duration = max(0, nxt_exp - cur_exp)
                if nxt_plan and nxt_duration > 0:
                    sub["expires_next"] = sub["expires"] + nxt_duration
                    sub["next_duration"] = nxt_duration
                coverage_start = now
                coverage_end = int(sub.get("expires", 0) or 0)
                operation = "renewed"
                status, msg = "renewed", "%s продлен с текущего момента" % plan
            else:
                base_start = max(nxt_exp, cur_exp, now) if (nxt_exp or cur_exp) else now
                sub["plan_next"] = plan
                sub["next_duration"] = add
                sub["expires_next"] = base_start + add
                coverage_start = base_start
                coverage_end = sub["expires_next"]
                operation = "queued"
                status, msg = "queued", "%s вступит после окончания %s" % (plan, cur_plan or "текущего")
            _save()
        receipt = _append_payment_locked(
            sub, plan, plan_snapshot, payment_amount, operation,
            coverage_start, coverage_end, key)
        config.log("subs: оплата %s -> %s (%s)" % (sub.get("name"), status, msg))
        return copy.deepcopy(sub), status, msg, receipt


def purchase(uid=None, name=None, plan=None, remark="", amount=None,
             idempotency_key=None):
    sub, status, msg, _ = _purchase_impl(
        uid, name, plan, remark, amount, idempotency_key)
    return sub, status, msg


def purchase_with_receipt(uid=None, name=None, plan=None, remark="", amount=None,
                          idempotency_key=None):
    return _purchase_impl(uid, name, plan, remark, amount, idempotency_key)


def _tick():
    """Активация отложенных тарифов: когда срок текущего истёк (expires <= now),
    plan_next переводится в активный план (expires/limit пересчитываются)."""
    now = _now()
    changed = False
    access_changed = False
    with _LOCK:
        for s in _SUBS:
            before = access_status(s, now)
            pn = s.get("plan_next")
            if pn:
                exp = int(s.get("expires", 0) or 0)
                if exp and exp > now:
                    continue
                p = plan_info(pn)
                days = p.get("days", 0)
                nxt = int(s.get("expires_next", 0) or 0)
                s["plan"] = pn
                s["plan_next"] = None
                s["expires"] = nxt or (now + days * 86400 if days else 0)
                s["expires_next"] = 0
                s["next_duration"] = 0
                s["limit_bytes"] = p.get("bytes", 0)
                s["limit_devices"] = p.get("devices", 0)
                config.log("subs: %s переведена на тариф %s" % (s.get("name"), pn))
                changed = True
            if before != access_status(s, now):
                access_changed = True
    if changed or access_changed:
        _save()
        _reconcile_clients()
    return changed or access_changed


def refresh_usage():
    """Собирает фактический трафик клиентов из xray API (statsquery) и
    обновляет накопительный used_bytes и месячный billing traffic."""
    if not _XRAY_BIN:
        return
    cmd = [_XRAY_BIN, "api", "statsquery",
           "--server=127.0.0.1:%d" % config.XRAY_API_PORT,
           "--pattern=user>>>", "--reset=false"]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=15)
        if getattr(r, "returncode", 0) != 0:
            return
        raw = (r.stdout or b"").decode("utf-8", errors="replace")
    except Exception:
        return
    used = {}
    cur = None
    for line in raw.splitlines():
        ls = line.strip()
        if ls.startswith("name:"):
            nm = ls.split(":", 1)[1].strip()
            if "user>>>" in nm:
                parts = nm.split(">>>")
                cur = parts[1] if len(parts) >= 2 else None
            else:
                cur = None
        elif cur and ls.startswith("value:"):
            try:
                value = int(ls.split(":", 1)[1].strip())
                if value >= 0:
                    used[cur] = used.get(cur, 0) + value
            except ValueError:
                pass
    if not used:
        return
    changed = False
    traffic_delta = 0
    month = _billing_month()
    with _LOCK:
        for s in _SUBS:
            snapshot = s.get("usage_snapshot")
            if not isinstance(snapshot, dict):
                snapshot = {}
            tracking = bool(s.get("usage_tracking", False))
            delta_total = 0
            for k in s.get("keys", []):
                kid = str(k.get("id", "") or "")
                if kid not in used:
                    continue
                current = used[kid]
                previous = snapshot.get(kid)
                if not tracking:
                    delta = 0
                elif previous is None:
                    delta = current
                else:
                    previous = max(0, _int(previous, 0))
                    delta = current - previous if current >= previous else current
                snapshot[kid] = current
                delta_total += max(0, delta)
            if s.get("usage_snapshot") != snapshot:
                s["usage_snapshot"] = snapshot
                changed = True
            if not tracking:
                s["usage_tracking"] = True
                changed = True
            if delta_total:
                s["used_bytes"] = max(0, _int(s.get("used_bytes"), 0)) + delta_total
                traffic_delta += delta_total
                changed = True
        if traffic_delta:
            months = _BILLING.setdefault("traffic", {}).setdefault("months", {})
            months[month] = max(0, _int(months.get(month), 0)) + traffic_delta
            _save_billing_locked()
        if changed:
            _save()
    if changed:
        _reconcile_clients()


def start_background():
    """Демон-поток: раз в 60с активирует отложенные тарифы (plan_next)
    и пересчитывает трафик клиентов. Запускается один раз после bootstrap."""
    global _BG_STARTED
    with _LOCK:
        if _BG_STARTED:
            return
        _BG_STARTED = True
    threading.Thread(target=_bg_loop, daemon=True).start()


def _bg_loop():
    while True:
        time.sleep(60)
        try:
            _tick()
        except Exception:
            pass
        try:
            refresh_usage()
        except Exception:
            pass


def update(uid, name=None, plan=None, enabled=None, limit_bytes=None,
           limit_devices=None, expires=None, remark=None):
    """Обновление полей подписки. Возвращает подписку или None."""
    with _LOCK:
        for s in _SUBS:
            if s.get("uid") != uid:
                continue
            if name is not None:
                s["name"] = str(name).strip() or s["name"]
            if plan is not None:
                p = plan_info(plan)
                if not p:
                    return None
                s["plan"] = plan
                s["limit_bytes"] = p.get("bytes", 0)
                s["limit_devices"] = p.get("devices", 0)
            if enabled is not None:
                s["enabled"] = bool(enabled)
            if limit_bytes is not None:
                s["limit_bytes"] = int(limit_bytes or 0)
            if limit_devices is not None:
                s["limit_devices"] = int(limit_devices or 0)
            if expires is not None:
                s["expires"] = int(expires or 0)
            if remark is not None:
                s["remark"] = str(remark or "").strip()
            _save()
            return dict(s)
    return None


def add_key(uid, remark="", device_id=""):
    """Добавляет ключ в подписку. Возвращает (new_key, sub) или (None, None)."""
    with _LOCK:
        for s in _SUBS:
            if s.get("uid") != uid:
                continue
            keys = s.get("keys", [])
            if not isinstance(keys, list):
                raise ValueError("subscription has invalid keys")
            if _quota_exceeded(s):
                return None, dict(s)
            devices = set()
            for key in keys:
                if not isinstance(key, dict):
                    raise ValueError("subscription has invalid key record")
                devices.add(str(key.get("device_id") or key.get("id") or ""))
            device = str(device_id or "").strip()[:64]
            if device and device in devices:
                return None, dict(s)
            cap = _active_key_limit(s)
            if len(keys) >= cap or len(devices) >= cap:
                return None, dict(s)
            k = make_key(device_id=device)
            k["remark"] = str(remark or "").strip()
            keys.append(k)
            s["keys"] = keys
            _save()
            return dict(k), dict(s)
    return None, None


def remove_key(uid, key_id):
    """Удаляет ключ по id из подписки. Возвращает True при удалении."""
    with _LOCK:
        for s in _SUBS:
            if s.get("uid") != uid:
                continue
            before = len(s["keys"])
            s["keys"] = [k for k in s["keys"] if k.get("id") != key_id]
            if len(s["keys"]) != before:
                _save()
                return True
    return False


def delete(uid):
    """Удаляет подписку. Возвращает True при удалении."""
    global _SUBS
    with _LOCK:
        before = len(_SUBS)
        _SUBS = [s for s in _SUBS if s.get("uid") != uid]
        if len(_SUBS) != before:
            _save()
            config.log("subs: удалена подписка %s" % uid)
            return True
    return False


def access_status(sub, now=None):
    if not isinstance(sub, dict):
        return "invalid"
    if not sub.get("enabled", True):
        return "disabled"
    if _expired(sub, now):
        return "expired"
    if _quota_exceeded(sub):
        return "quota"
    return "ok"


def by_token_status(token):
    clean = _clean_id(token or "")
    with _LOCK:
        for s in _SUBS:
            if s.get("token") and _clean_id(s["token"]) == clean:
                return dict(s), access_status(s)
    return None, "missing"


def by_token(token):
    sub, status = by_token_status(token)
    return sub if status == "ok" else None


def _vless_params():
    """Параметры внешнего Reality-входа для сборки клиентской ссылки."""
    v = config.vless_public()
    if not v.get("enabled") or not v.get("host"):
        return {}
    return {
        "host": v["host"],
        "port": v["port"],
        "pbk": v["public_key"],
        "sid": v["short_id"],
        "sni": v["sni"],
        "flow": v["flow"],
    }


def vless_link(key_id, remark=None, params=None):
    """Строит клиентскую vless:// ссылку по uuid ключа (Reality, через :8443)."""
    import urllib.parse
    key_id = config.canonical_uuid(key_id)
    p = params or _vless_params()
    host = config._format_link_host(p.get("host", ""))
    if not key_id or not p or not host:
        return ""
    q = urllib.parse.urlencode({
        "encryption": "none",
        "security": "reality",
        "flow": p["flow"],
        "sni": p["sni"],
        "fp": "chrome",
        "pbk": p["pbk"],
        "sid": p["sid"],
        "type": "tcp",
        "headerType": "none",
    })
    frag = remark or "Aurora-Sub"
    frag = re.sub(r"[^\w\- ]", "", frag) or "Aurora-Sub"
    return "vless://%s@%s:%d?%s#%s" % (key_id, host, p["port"], q, frag)


def public_link(sub):
    """Ссылка на подписку (её содержимое отдаётся по /sub?token=...)."""
    host = config._format_link_host(config.external_link_host())
    if not host:
        return ""
    import urllib.parse
    return "http://%s:%d/sub?%s" % (
        host, config.UI_PORT, urllib.parse.urlencode({"token": sub.get("token", "")}))


def subscription_text(sub):
    """Текст подписки для клиента: vless-ссылки всех ключей.
    Первой строкой — служебный комментарий с расходом трафика."""
    p = _vless_params()
    used = int(sub.get("used_bytes", 0) or 0)
    limit = int(sub.get("limit_bytes", 0) or 0)
    rows = ["# Aurora Sub — использовано: %d / %d байт" % (used, limit)]
    for k in sub.get("keys", []):
        rid = config.canonical_uuid(k.get("id"))
        if not rid:
            continue
        link = vless_link(rid, remark=k.get("remark") or sub.get("name"), params=p)
        if link:
            rows.append(link)
    return "\n".join(rows)


def build_client_list():
    """Все uuid подписок (для clients inbound vless-in в xray.json).
    Истёкшие подписки без отложенного тарифа (plan_next) отключаются."""
    now = _now()
    out = []
    seen = set()
    for idx, s in enumerate(_SUBS):
        if not isinstance(s, dict):
            raise ValueError("subscription record %d is not an object" % idx)
        if not s.get("enabled", True):
            continue
        try:
            exp = int(s.get("expires", 0) or 0)
        except (TypeError, ValueError) as e:
            raise ValueError("subscription record %d has invalid expiry" % idx) from e
        if access_status(s, now) != "ok":
            continue
        keys = s.get("keys", [])
        if keys is None:
            keys = []
        if not isinstance(keys, list):
            raise ValueError("subscription record %d has invalid keys" % idx)
        cap = _active_key_limit(s)
        device_ids = set()
        for k in keys:
            if not isinstance(k, dict):
                raise ValueError("subscription record %d has invalid key record" % idx)
            kid = config.canonical_uuid(k.get("id"))
            if not kid:
                raise ValueError("subscription record %d has invalid key id" % idx)
            device = str(k.get("device_id") or kid).strip()
            if device in device_ids or len(device_ids) >= cap:
                continue
            device_ids.add(device)
            if kid not in seen:
                seen.add(kid)
                out.append(kid)
    return out


def _mask(u):
    """Маскирует uuid для отображения (сохранив визуальный контроль)."""
    if not u:
        return "-"
    return u[:8] + "…" if config.SUBS_MASK_UUID else u


# самодостаточный модуль: подписки загружаются при импорте (без правки run.py
# на старых серверах они подхватятся сразу подключением import subs в api.py)
_load_billing()
load()