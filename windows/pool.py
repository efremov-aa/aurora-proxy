# Aurora v1.0 — пул ключей: хранение, статусы, блеклист мёртвых.
# Ключи живут в data/keys.json (список) и data/status.json (результаты проверок).

import json
import os
import re
import threading

import config

KEYS_FILE = os.path.join(config.DATA_DIR, "keys.json")
STATUS_FILE = os.path.join(config.DATA_DIR, "status.json")
DEAD_FILE = os.path.join(config.DATA_DIR, "dead.json")

_LOCK = threading.RLock()

# ключ: {uri, tag, host, port, params{...}, source(github|manual)}
_KEYS = []
# статус: {uri: {status: ok|slow|noip|bad|unchecked, ping_ms, exit_ip, sites_ok, ts}}
_STATUS = {}
# блеклист: {uri: {reason, ts}}
_DEAD = {}


def _norm_uri(uri):
    """Нормализация vless-uri для ключа в статусе/блеклисте (без #remark)."""
    u = str(uri)
    if "#" in u:
        u = u.split("#", 1)[0]
    return u


def _endpoint(host, port):
    h = str(host).lower().rstrip(".")
    return "%s:%s" % (h, port)


def _tag_from_uri(uri, host):
    """Делает короткий тег из host (vless-<первая метка>), уникализирует."""
    lbl = str(host).split(".")[0]
    lbl = re.sub(r"[^a-zA-Z0-9_-]", "-", lbl) or "k"
    base = "vless-%s" % lbl
    tag = base
    i = 2
    while tag in [k.get("tag") for k in _KEYS]:
        tag = "%s-%d" % (base, i)
        i += 1
    return tag


def _uri_host(uri):
    """Извлекает host из vless-uri (без парсинга параметров)."""
    import urllib.parse
    try:
        return urllib.parse.urlparse(_norm_uri(uri)).hostname
    except Exception:
        return None


def _ensure_tag(k):
    """Проставляет тег, host и port если пустые (могут прийти без них из uri)."""
    import urllib.parse
    if not k.get("host") or not k.get("port"):
        try:
            p = urllib.parse.urlparse(_norm_uri(k.get("uri", "")))
            if not k.get("host"):
                k["host"] = p.hostname
            if not k.get("port"):
                k["port"] = p.port or 443
        except Exception:
            pass
    if not k.get("tag"):
        host = k.get("host") or _uri_host(k.get("uri", ""))
        if host:
            k["tag"] = _tag_from_uri(k.get("uri", ""), host)
    return k


def load():
    """Загрузка keys.json / status.json / dead.json при старте. Безопасная."""
    global _KEYS, _STATUS, _DEAD
    with _LOCK:
        try:
            with open(KEYS_FILE, "r", encoding="utf-8") as f:
                _KEYS = [_ensure_tag(dict(k)) for k in json.load(f)]
        except (OSError, ValueError):
            _KEYS = []
        try:
            with open(STATUS_FILE, "r", encoding="utf-8") as f:
                _STATUS = json.load(f)
        except (OSError, ValueError):
            _STATUS = {}
        try:
            with open(DEAD_FILE, "r", encoding="utf-8") as f:
                _DEAD = json.load(f)
        except (OSError, ValueError):
            _DEAD = {}
    prune_status()


def _atomic_write(path, obj):
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=1, ensure_ascii=False)
        os.replace(tmp, path)
        return True
    except OSError as e:
        config.log("pool: запись %s не удалась: %s" % (os.path.basename(path), e))
        return False


def _save_keys():
    with _LOCK:
        _atomic_write(KEYS_FILE, _KEYS)


def _save_status():
    with _LOCK:
        _atomic_write(STATUS_FILE, _STATUS)


def _save_dead():
    with _LOCK:
        _atomic_write(DEAD_FILE, _DEAD)


# --- public API ---
def get_keys():
    with _LOCK:
        return [dict(k) for k in _KEYS]


def set_keys(keys):
    """Полная замена пула (например после github-перезагрузки)."""
    global _KEYS
    with _LOCK:
        _KEYS = [_ensure_tag(dict(k)) for k in keys]
        _save_keys()


def add_key(key, force=False):
    """Добавляет ключ в пул. Возвращает 'added' / 'exists' / 'limit' / 'blocked'.

    Ключи из блеклиста (dead.json) НЕ добавляются автоматически — правило юзера:
    мёртвые не возвращаются. force=True (ручное добавление своих) разрешает отмену."""
    uri = _norm_uri(key.get("uri", ""))
    with _LOCK:
        if uri in _DEAD and not force:
            return "blocked"
        for k in _KEYS:
            if _norm_uri(k.get("uri", "")) == uri:
                return "exists"
        if len(_KEYS) >= config.MAX_USER_KEYS:
            return "limit"
        _KEYS.append(_ensure_tag(dict(key)))
        _save_keys()
    return "added"


def remove_key(uri):
    """Удаляет ключ по uri. Возвращает True при реальном удалении."""
    global _KEYS
    n = _norm_uri(uri)
    with _LOCK:
        before = len(_KEYS)
        _KEYS = [k for k in _KEYS if _norm_uri(k.get("uri", "")) != n]
        after = len(_KEYS)
        if before != after:
            _save_keys()
            _STATUS.pop(n, None)
            _save_status()
    return before != after


def get_status(uri):
    return dict(_STATUS.get(_norm_uri(uri), {}))


def set_status(uri, **fields):
    n = _norm_uri(uri)
    with _LOCK:
        st = dict(_STATUS.get(n, {}))
        st.update(fields)
        _STATUS[n] = st
        _save_status()


def status_mark(uri, status, ping_ms=0, exit_ip="-", sites_ok=0, reason=""):
    import time
    fields = dict(status=status, ping_ms=ping_ms, exit_ip=exit_ip,
                  sites_ok=sites_ok, ts=int(time.time()))
    if reason:
        fields["reason"] = reason
    set_status(uri, **fields)


def prune_status():
    """Убирает статусы ключей, которых уже нет в пуле (анти-мусор)."""
    known = set(_norm_uri(k.get("uri", "")) for k in _KEYS)
    stale = [u for u in _STATUS if u not in known]
    if stale:
        with _LOCK:
            for u in stale:
                _STATUS.pop(u, None)
            _save_status()


# --- блеклист мёртвых ---
def dead_add(uri, reason="user_removed"):
    import time
    n = _norm_uri(uri)
    with _LOCK:
        _DEAD[n] = {"reason": reason, "ts": int(time.time())}
        _save_dead()


def dead_remove(uri):
    n = _norm_uri(uri)
    with _LOCK:
        if n in _DEAD:
            _DEAD.pop(n, None)
            _save_dead()
            return True
    return False


def dead_reason(uri):
    return _DEAD.get(_norm_uri(uri), {}).get("reason")


def blocked(uri):
    return _norm_uri(uri) in _DEAD


def alive(uri):
    """Ключ не в блеклисте и не bad — может жить в пуле."""
    if blocked(uri):
        return False
    st = _STATUS.get(_norm_uri(uri), {})
    return st.get("status") != "bad"


# --- выбор активного: pick_final по рангам (0 лучший) ---
def _good_ip(ip):
    return ip not in ("", "-", config.WHITE_IP)


def _rank(st):
    s = st.get("status")
    if s == "ok" and (st.get("sites_ok") or 0) > 0:
        return 0
    if s == "ok":
        return 1
    if s == "unchecked" or not s:
        return 2
    if s == "slow":
        return 3
    return 5  # bad / noip / провал


def pick_final():
    """Возвращает ключ с лучшим рангом и реальным egress, либо None."""
    cands = []
    for k in _KEYS:
        if blocked(k.get("uri", "")):
            continue
        st = _STATUS.get(_norm_uri(k.get("uri", "")), {})
        cands.append((_rank(st), st.get("exit_ip", "-"), k))
    cands.sort(key=lambda t: (t[0], t[1]))
    for rank, ip, k in cands:
        # tier1: ранг 0 (ok с сайтами) и живой egress
        if rank == 0 and _good_ip(ip):
            return dict(k)
    for rank, ip, k in cands:
        # tier2: ранг 0..2 и живой egress
        if rank in (0, 1, 2) and _good_ip(ip):
            return dict(k)
    return None


def build_outbound(key):
    """Строит VLESS-outbound для xray.json. None при невалидности."""
    import urllib.parse

    k = dict(key)
    uri = _norm_uri(k.get("uri", ""))
    parsed = urllib.parse.urlparse(uri)
    host = parsed.hostname or k.get("host")
    port = parsed.port or k.get("port") or 443
    if not host:
        return None
    q = urllib.parse.parse_qs(parsed.query)
    pbk = q.get("pbk") or [k.get("pbk")] if (q.get("pbk") or k.get("pbk")) else None
    sid = q.get("sid") or [k.get("sid")] if (q.get("sid") or k.get("sid")) else None
    fp = q.get("fp") or [k.get("fp")] if (q.get("fp") or k.get("fp")) else None
    sni = q.get("sni") or [k.get("sni")] if (q.get("sni") or k.get("sni")) else None

    def scalar(v, default=None):
        if isinstance(v, list):
            v = v[0] if v else None
        return v or default

    pbk = scalar(pbk)
    sid = scalar(sid)
    fp = scalar(fp)
    sni = scalar(sni)

    if not pbk:  # Reality обязателен, туннель без pbk не собрать
        return None

    # xray v26.9.9: serverName/fingerprint/shortId — строки, НЕ массивы
    stream = {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
            "serverName": sni or host,
            "fingerprint": fp or "chrome",
            "publicKey": pbk,
            "show": False,
        },
    }
    if sid:
        stream["realitySettings"]["shortId"] = sid

    tag = k.get("tag") or _tag_from_uri(uri, host)
    return {
        "tag": tag,
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": host,
                "port": int(port),
                "users": [{
                    "id": parsed.username or k.get("uuid", ""),
                    "encryption": "none",
                    "flow": "xtls-rprx-vision",
                }],
            }],
        },
        "streamSettings": stream,
    }


def dedupe():
    """Дедуп: держим первый по (host,port), остальные дубли убираем."""
    global _KEYS
    seen = set()
    out = []
    for k in _KEYS:
        ep = _endpoint(k.get("host", ""), k.get("port")) if k.get("host") else _norm_uri(k.get("uri", ""))
        if ep in seen:
            continue
        seen.add(ep)
        out.append(dict(k))
    if len(out) != len(_KEYS):
        with _LOCK:
            _KEYS = out
            _save_keys()


def cleanup():
    """Удаление мёртвых ключей из пула.

    Правило юзера (18.09): мёртвый github-ключ = bad / slow (>500мс) / noip (без
    выходного IP) / в блеклисте. Такие вычищаем. 'my' и 'manual' (свои/вручную
    добавленные) не трогаем — нужны всегда.
    Возвращает число удалённых."""
    global _KEYS
    removed = 0
    with _LOCK:
        keep = []
        for k in _KEYS:
            uri = _norm_uri(k.get("uri", ""))
            src = k.get("source", "github")
            st = _STATUS.get(uri, {})
            deadish = uri in _DEAD or st.get("status") in ("bad", "slow", "noip")
            if src == "github" and deadish:
                removed += 1
                continue
            keep.append(dict(k))
        if removed:
            _KEYS = keep
            _save_keys()
            prune_status()
    if removed:
        config.log("pool: cleanup удалил %d мёртвых ключей" % removed)
    return removed