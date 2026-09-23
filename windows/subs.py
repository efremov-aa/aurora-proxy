# Aurora v1.4.0 — подписки: клиентские аккаунты, тарифы, привязка ключей к серверу.
# Хранение: data/subs.json. Подписка = аккаунт клиента с N ключами (uuid).
# Привязка: uuid клиента попадает в clients inbound vless-in в xray.json
# (REST реально перезапускает inbound), и клиент может подключаться извне.

import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid as _uuid

import config

SUBS_FILE = config.SUBS_FILE

_LOCK = threading.RLock()
_SUBS = []

# бинарь xray для statsquery (счётчики трафика по ключам):
# сначала PATH, потом типовые места установки (дом/сервер/Docker/Windows)
_XRAY_BIN = ""
for _c in (os.path.join(config.BASE_DIR, "bin", "xray.exe"),
           shutil.which("xray"),
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


def load():
    """Загрузка data/subs.json. Молчаливый фолбэк на пустой список."""
    global _SUBS
    with _LOCK:
        try:
            with open(SUBS_FILE, "r", encoding="utf-8") as f:
                _SUBS = json.load(f)
            if not isinstance(_SUBS, list):
                _SUBS = []
        except (OSError, ValueError):
            _SUBS = []


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
        _atomic_write(SUBS_FILE, _SUBS)


def all():
    """Все подписки (копии)."""
    with _LOCK:
        return [dict(s) for s in _SUBS]


def count():
    with _LOCK:
        return len(_SUBS)


def find(uid):
    """Подписка по uid или None."""
    with _LOCK:
        for s in _SUBS:
            if s.get("uid") == uid:
                return dict(s)
    return None


def _gen_token():
    import secrets
    return secrets.token_urlsafe(12)


def _gen_uuid():
    return str(_uuid.uuid4())


def plan_info(plan):
    p = config.SUBS_PLANS.get(plan or "")
    if not p:
        p = config.SUBS_PLANS.get(config.SUBS_PLAN_DEFAULT, {})
    return dict(p)


def make_key():
    """Новый ключ для подписки: uuid + метаданные."""
    return {
        "id": _gen_uuid(),
        "created": _now(),
        "remark": "",
        "note": "",
    }


def create(name, plan=None, remark=""):
    """Создаёт подписку с указанным тарифом и ключами. Возвращает подписку."""
    plan = plan or config.SUBS_PLAN_DEFAULT
    p = plan_info(plan)
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
        "used_bytes": 0,         # кэш фактического трафика клиента (из xray API)
        "keys": [make_key() for _ in range(max(1, p.get("keys", 1)))],
    }
    with _LOCK:
        _SUBS.append(sub)
        _save()
    config.log("subs: создана подписка %s (%s, ключей %d)" % (
        sub["name"], plan, len(sub["keys"])))
    return dict(sub)


def purchase(uid=None, name=None, plan=None, remark=""):
    """Внесение оплаты: создание подписки или продление по правилу юзера —
    одинаковый тариф суммирует время (expires += days), другой тариф
    откладывается в plan_next и вступает после окончания текущего.
    Возвращает (sub_dict, status, msg). status: created|renewed|queued|error."""
    plan = plan or config.SUBS_PLAN_DEFAULT
    p = plan_info(plan)
    days = p.get("days", 0)
    add = days * 86400
    now = _now()
    with _LOCK:
        # выбор подписки: по uid -> по имени -> новая
        sub = None
        if uid:
            for s in _SUBS:
                if s.get("uid") == uid:
                    sub = s
                    break
            if sub is None:
                return None, "error", "подписка не найдена"
        else:
            nm = str(name or "").strip()
            for s in _SUBS:
                if nm and s.get("name", "").strip().lower() == nm.lower():
                    sub = s
                    break
        if sub is None:
            return create(nm or None, plan=plan, remark=remark), "created", \
                "подписка создана по тарифу %s" % plan

        cur_plan = sub.get("plan")
        cur_exp = int(sub.get("expires", 0) or 0)
        nxt_plan = sub.get("plan_next")
        nxt_exp = int(sub.get("expires_next", 0) or 0)

        if plan == nxt_plan:
            # в очереди уже этот же тариф — суммируем его будущий срок
            base = (nxt_exp or (max(cur_exp, now) if cur_exp else now)) + add
            sub["expires_next"] = base
            status, msg = "renewed", "отложенный %s продлен до %s" % (plan, base)
        elif cur_plan == plan and (cur_exp == 0 or cur_exp >= now):
            # тот же тариф при действующей подписке — время суммируется;
            # cur_exp == 0 (бессрочно) не превращается в срочный/просроченный
            if cur_exp:
                sub["expires"] = cur_exp + add
                # очередь (другой тариф) не должна вступить раньше продлённого срока
                if nxt_exp and nxt_exp < sub["expires"]:
                    sub["expires_next"] = sub["expires"]
            status, msg = "renewed", "время %s суммировано" % plan
        elif cur_plan == plan:
            # просроченный тот же тариф — считаем с текущего момента
            sub["expires"] = now + add
            status, msg = "renewed", "%s продлен с текущего момента" % plan
        else:
            # другой тариф — ждёт окончания текущего (plan_next);
            # уже стоящая очередь (nxt_exp) не затирается, её срок учитывается
            base_start = max(nxt_exp, cur_exp, now) if (nxt_exp or cur_exp) else now
            sub["plan_next"] = plan
            sub["expires_next"] = base_start + add
            status, msg = "queued", "%s вступит после окончания %s" % (plan, cur_plan or "текущего")
        _save()
        config.log("subs: оплата %s -> %s (%s)" % (sub.get("name"), status, msg))
        return dict(sub), status, msg


def _tick():
    """Активация отложенных тарифов: когда срок текущего истёк (expires <= now),
    plan_next переводится в активный план (expires/limit пересчитываются)."""
    now = _now()
    changed = False
    with _LOCK:
        for s in _SUBS:
            pn = s.get("plan_next")
            if not pn:
                continue
            exp = int(s.get("expires", 0) or 0)
            if exp and exp > now:
                continue  # текущий тариф ещё действует
            p = plan_info(pn)
            days = p.get("days", 0)
            nxt = int(s.get("expires_next", 0) or 0)
            s["plan"] = pn
            s["plan_next"] = None
            s["expires"] = nxt or (now + days * 86400 if days else 0)
            s["expires_next"] = 0
            s["limit_bytes"] = p.get("bytes", 0)
            s["limit_devices"] = p.get("devices", 0)
            config.log("subs: %s переведена на тариф %s" % (s.get("name"), pn))
            changed = True
    if changed:
        _save()
    return changed


def refresh_usage():
    """Собирает фактический трафик клиентов из xray API (statsquery) и
    обновляет used_bytes у подписок (кэш). Ошибки игнорируются молча."""
    if not _XRAY_BIN:
        return
    cmd = [_XRAY_BIN, "api", "statsquery",
           "--server=127.0.0.1:%d" % config.XRAY_API_PORT,
           "--pattern=user>>>", "--reset=false"]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=15,
                           creationflags=config.HIDE_FLAG)
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
                used[cur] = used.get(cur, 0) + int(ls.split(":", 1)[1].strip())
            except ValueError:
                pass
    if not used:
        return
    changed = False
    with _LOCK:
        for s in _SUBS:
            tot = 0
            for k in s.get("keys", []):
                tot += used.get(k.get("id", ""), 0)
            if int(s.get("used_bytes", 0) or 0) != tot:
                s["used_bytes"] = tot
                changed = True
    if changed:
        _save()


def start_background():
    """Демон-поток: раз в 60с активирует отложенные тарифы (plan_next)
    и пересчитывает трафик клиентов. Запускается один раз при импорте."""
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
                s["plan"] = plan
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


def add_key(uid, remark=""):
    """Добавляет ключ в подписку. Возвращает (new_key, sub) или (None, None)."""
    with _LOCK:
        for s in _SUBS:
            if s.get("uid") != uid:
                continue
            k = make_key()
            k["remark"] = str(remark or "").strip()
            s["keys"].append(k)
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


def by_token(token):
    """Подписка по token (для публичной выдачи /sub). None если нет/выключена."""
    with _LOCK:
        for s in _SUBS:
            if s.get("token") and _clean_id(s["token"]) == _clean_id(token or ""):
                return dict(s) if s.get("enabled", True) else None
    return None


def _vless_params():
    """Параметры внешнего Reality-входа для сборки клиентской ссылки."""
    v = config.VLESS_PUBLIC
    return {
        "host": v.get("host") or config.VM_HOST or "127.0.0.1",
        "port": v.get("port", 8443),
        "pbk": v.get("public_key", ""),
        "sid": v.get("short_id") or "",
        "sni": v.get("sni") or v.get("host") or "www.microsoft.com",
        "flow": v.get("flow", "xtls-rprx-vision"),
    }


def vless_link(key_id, remark=None, params=None):
    """Строит клиентскую vless:// ссылку по uuid ключа (Reality, через :8443)."""
    import urllib.parse
    p = params or _vless_params()
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
    return "vless://%s@%s:%s?%s#%s" % (key_id, p["host"], p["port"], q, frag)


def public_link(sub):
    """Ссылка на подписку (её содержимое отдаётся по /sub?token=...)."""
    v = config.VLESS_PUBLIC
    host = v.get("host") or config.VM_HOST or "127.0.0.1"
    return "http://%s:%d/sub?token=%s" % (host, config.UI_PORT, sub["token"])


def subscription_text(sub):
    """Текст подписки для клиента: vless-ссылки всех ключей.
    Первой строкой — служебный комментарий с расходом трафика."""
    p = _vless_params()
    used = int(sub.get("used_bytes", 0) or 0)
    limit = int(sub.get("limit_bytes", 0) or 0)
    rows = ["# Aurora Sub — использовано: %d / %d байт" % (used, limit)]
    for k in sub.get("keys", []):
        rid = k.get("id", "")
        if not rid:
            continue
        rows.append(vless_link(rid, remark=k.get("remark") or sub.get("name"), params=p))
    return "\n".join(rows)


def build_client_list():
    """Все uuid подписок (для clients inbound vless-in в xray.json).
    Истёкшие подписки без отложенного тарифа (plan_next) отключаются."""
    now = _now()
    out = []
    seen = set()
    for s in _SUBS:
        if not s.get("enabled", True):
            continue
        exp = int(s.get("expires", 0) or 0)
        if exp and exp <= now and not s.get("plan_next"):
            continue  # просрочена и нечего активировать — доступ снят
        for k in s.get("keys", []):
            kid = k.get("id", "")
            if kid and kid not in seen:
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
load()
start_background()  # демон активации отложенных тарифов и сбора трафика