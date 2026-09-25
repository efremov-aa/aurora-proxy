# Aurora v1.0 — пул ключей: хранение, статусы, блеклист мёртвых.
# Ключи живут в data/keys.json (список) и data/status.json (результаты проверок).

import ipaddress
import json
import os
import re
import socket
import threading
import urllib.parse
import uuid

import config
import crypt

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


def _canonical_host(value):
    host = str(value or "").strip().rstrip(".").lower()
    if not host or len(host) > 253 or any(ch.isspace() for ch in host):
        return ""
    if any(ch in host for ch in "/\\@?#%[]"):
        return ""
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return ""
    labels = host.split(".")
    if len(labels) < 2 or any(not label for label in labels):
        return ""
    if host in ("localhost", "localhost.localdomain"):
        return ""
    if host.endswith((".localhost", ".local", ".internal", ".home.arpa")):
        return ""
    return host


def _public_ip(value):
    try:
        ip = ipaddress.ip_address(str(value).split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if str(ip) == "168.63.129.16":
        return False
    return bool(
        ip.is_global
        and not ip.is_private
        and not ip.is_loopback
        and not ip.is_link_local
        and not ip.is_reserved
        and not ip.is_unspecified
        and not ip.is_multicast
        and not getattr(ip, "is_site_local", False)
    )


def _host_name_allowed(value):
    host = _canonical_host(value)
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return True
    return _public_ip(host)


def resolve_public_host(value, port=443):
    host = _canonical_host(value)
    if not _host_name_allowed(host):
        return None
    try:
        port = int(port)
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (OSError, TypeError, ValueError):
        return None
    resolved = []
    for item in addresses:
        try:
            raw = str(item[4][0])
            if "%" in raw or not _public_ip(raw):
                return None
            resolved.append(str(ipaddress.ip_address(raw)))
        except (IndexError, TypeError, ValueError):
            return None
    return resolved[0] if resolved else None


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


_MISSING = object()


def _storage_failure(path, reason):
    config.quarantine_file(path)
    raise config.StorageDataError("%s: %s" % (os.path.basename(path), reason))


def _read_plain(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default
    except (OSError, ValueError, TypeError, UnicodeError) as e:
        _storage_failure(path, str(e))


def _read_crypt(path, default):
    try:
        return crypt.load_json(path, default=default)
    except Exception as e:
        _storage_failure(path, str(e))


def _is_nonnegative_int(value):
    return type(value) is int and value >= 0


def _prepare_keys(raw):
    if not isinstance(raw, list):
        raise ValueError("keys root is not a list")
    out = []
    uris = set()
    tags = set()
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("key record is not an object")
        rec = dict(item)
        uri = rec.get("uri")
        if not isinstance(uri, str) or not uri.strip():
            raise ValueError("key uri is invalid")
        norm = _norm_uri(uri)
        if norm in uris:
            raise ValueError("duplicate key uri")
        uris.add(norm)
        try:
            parsed = urllib.parse.urlparse(norm)
            uri_host = _canonical_host(parsed.hostname)
            stored_host = rec.get("host")
            host = _canonical_host(stored_host) if stored_host not in (None, "") else uri_host
            port = rec.get("port")
            if port is None:
                port = parsed.port or 443
        except (TypeError, ValueError, UnicodeError) as e:
            raise ValueError("key endpoint is invalid") from e
        if not uri_host or not _host_name_allowed(uri_host) or not host or host != uri_host:
            raise ValueError("key host is invalid")
        if not _is_nonnegative_int(port) or not 1 <= port <= 65535:
            raise ValueError("key port is invalid")
        tag = rec.get("tag")
        if tag is None:
            label = re.sub(r"[^a-zA-Z0-9_-]", "-", host.split(".")[0]) or "k"
            base = "vless-%s" % label
            tag = base
            index = 2
            while tag in tags:
                tag = "%s-%d" % (base, index)
                index += 1
        if not isinstance(tag, str) or not tag.strip() or tag in tags:
            raise ValueError("key tag is invalid")
        for name in ("pbk", "sid", "sni"):
            if name in rec and rec[name] is None:
                rec[name] = ""
        for name in ("source", "uuid", "pbk", "sid", "sni", "fp", "flow"):
            if name in rec and not isinstance(rec[name], str):
                raise ValueError("key field %s is invalid" % name)
        rec["uri"] = uri
        rec["host"] = host
        rec["port"] = port
        rec["tag"] = tag
        tags.add(tag)
        out.append(rec)
    return out


def _validate_status(raw):
    if not isinstance(raw, dict):
        raise ValueError("status root is not an object")
    out = {}
    allowed = {"ok", "slow", "noip", "bad", "unchecked"}
    for uri, value in raw.items():
        if not isinstance(uri, str) or not isinstance(value, dict):
            raise ValueError("status record is invalid")
        rec = dict(value)
        if "status" in rec and rec["status"] not in allowed:
            raise ValueError("status value is invalid")
        for name in ("ping_ms", "sites_ok", "ts"):
            if name in rec and not _is_nonnegative_int(rec[name]):
                raise ValueError("status field %s is invalid" % name)
        for name in ("exit_ip", "reason"):
            if name in rec and not isinstance(rec[name], str):
                raise ValueError("status field %s is invalid" % name)
        out[uri] = rec
    return out


def _validate_dead(raw):
    if not isinstance(raw, dict):
        raise ValueError("dead root is not an object")
    out = {}
    for uri, value in raw.items():
        if not isinstance(uri, str) or not isinstance(value, dict):
            raise ValueError("dead record is invalid")
        rec = dict(value)
        if "reason" in rec and not isinstance(rec["reason"], str):
            raise ValueError("dead reason is invalid")
        if "ts" in rec and not _is_nonnegative_int(rec["ts"]):
            raise ValueError("dead timestamp is invalid")
        out[uri] = rec
    return out

def _opaque_map(raw, domain):
    out = {}
    for key, value in raw.items():
        ident = key if crypt.is_opaque_id(key) else crypt.opaque_id(_norm_uri(key), domain)
        if ident in out:
            raise ValueError("duplicate opaque record")
        out[ident] = dict(value)
    return out


def _record_key(mapping, uri, domain):
    normalized = _norm_uri(uri)
    opaque = crypt.opaque_id(normalized, domain)
    if opaque in mapping:
        return opaque
    if normalized in mapping:
        return normalized
    return opaque


def load():
    """Загрузка keys.json / status.json / dead.json при старте. Безопасная."""
    global _KEYS, _STATUS, _DEAD
    keys_raw = _read_crypt(KEYS_FILE, _MISSING)
    keys_present = keys_raw is not _MISSING
    if not keys_present:
        keys_raw = []
    try:
        keys_local = _prepare_keys(keys_raw)
    except (TypeError, ValueError) as e:
        _storage_failure(KEYS_FILE, str(e))
    status_raw = _read_crypt(STATUS_FILE, _MISSING)
    status_present = status_raw is not _MISSING
    if not status_present:
        status_raw = {}
    try:
        status_local = _opaque_map(_validate_status(status_raw), "status")
    except (TypeError, ValueError) as e:
        _storage_failure(STATUS_FILE, str(e))
    dead_raw = _read_crypt(DEAD_FILE, _MISSING)
    dead_present = dead_raw is not _MISSING
    if not dead_present:
        dead_raw = {}
    try:
        dead_local = _opaque_map(_validate_dead(dead_raw), "dead")
    except (TypeError, ValueError) as e:
        _storage_failure(DEAD_FILE, str(e))
    try:
        if keys_present:
            crypt.save_json(KEYS_FILE, keys_local)
        if status_present:
            crypt.save_json(STATUS_FILE, status_local)
        if dead_present:
            crypt.save_json(DEAD_FILE, dead_local)
    except (OSError, crypt.StorageError) as e:
        path = KEYS_FILE if keys_present else STATUS_FILE if status_present else DEAD_FILE
        _storage_failure(path, str(e))
    with _LOCK:
        _KEYS = keys_local
        _STATUS = status_local
        _DEAD = dead_local
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


def _save_keys(value=None):
    with _LOCK:
        crypt.save_json(KEYS_FILE, _KEYS if value is None else value)


def _save_status(value=None):
    with _LOCK:
        data = _STATUS if value is None else value
        crypt.save_json(STATUS_FILE, _opaque_map(data, "status"))
    return True


def _save_dead():
    with _LOCK:
        try:
            crypt.save_json(DEAD_FILE, _opaque_map(_DEAD, "dead"))
            return True
        except (OSError, crypt.StorageError) as e:
            config.log("pool: запись dead.json не удалась: %s" % e)
            return False


# --- public API ---
def get_keys():
    with _LOCK:
        return [dict(k) for k in _KEYS]


def set_keys(keys):
    """Полная замена пула (например после github-перезагрузки)."""
    global _KEYS
    local = [_ensure_tag(dict(k)) for k in keys]
    _save_keys(local)
    with _LOCK:
        _KEYS = local


def add_key(key, force=False):
    """Добавляет ключ в пул. Возвращает 'added' / 'exists' / 'limit' / 'blocked'.

    Ключи из блеклиста (dead.json) НЕ добавляются автоматически :
    мёртвые не возвращаются. force=True (ручное добавление своих) разрешает отмену."""
    global _KEYS, _STATUS, _DEAD
    uri = _norm_uri(key.get("uri", ""))
    with _LOCK:
        dead_key = _record_key(_DEAD, uri, "dead")
        status_key = _record_key(_STATUS, uri, "status")
        if dead_key in _DEAD and not force:
            return "blocked"
        for k in _KEYS:
            if _norm_uri(k.get("uri", "")) == uri:
                return "exists"
        if len(_KEYS) >= config.MAX_USER_KEYS:
            return "limit"
        keys_local = list(_KEYS)
        status_local = dict(_STATUS)
        dead_local = dict(_DEAD)
        if force:
            dead_local.pop(dead_key, None)
            status_local.pop(status_key, None)
        keys_local.append(_ensure_tag(dict(key)))
    old_keys = list(_KEYS)
    old_status = dict(_STATUS)
    old_dead = dict(_DEAD)
    rollback = [(KEYS_FILE, old_keys)]
    if force:
        rollback.extend((
            (DEAD_FILE, _opaque_map(old_dead, "dead")),
            (STATUS_FILE, _opaque_map(old_status, "status")),
        ))
    try:
        if force:
            crypt.save_json(DEAD_FILE, _opaque_map(dead_local, "dead"))
            crypt.save_json(STATUS_FILE, _opaque_map(status_local, "status"))
        crypt.save_json(KEYS_FILE, keys_local)
    except Exception:
        for path, value in rollback:
            try:
                crypt.save_json(path, value)
            except Exception:
                pass
        raise
    _KEYS = keys_local
    _STATUS = status_local
    _DEAD = dead_local
    return "added"


def remove_key(uri):
    """Удаляет ключ по uri. Возвращает True при реальном удалении."""
    global _KEYS
    n = _norm_uri(uri)
    with _LOCK:
        before = len(_KEYS)
        filtered = [k for k in _KEYS if _norm_uri(k.get("uri", "")) != n]
        after = len(filtered)
        if before == after:
            return False
        status = dict(_STATUS)
        status.pop(_record_key(status, n, "status"), None)
        try:
            _save_keys(filtered)
            _save_status(status)
        except Exception:
            try:
                _save_keys(_KEYS)
            except Exception:
                pass
            raise
        _KEYS[:] = filtered
        _STATUS.clear()
        _STATUS.update(status)
        return True


def get_status(uri):
    with _LOCK:
        return dict(_STATUS.get(_record_key(_STATUS, uri, "status"), {}))


def set_status(uri, **fields):
    with _LOCK:
        n = _record_key(_STATUS, uri, "status")
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
    with _LOCK:
        known_ids = set(crypt.opaque_id(_norm_uri(k.get("uri", "")), "status")
                        for k in _KEYS)
        known_raw = set(_norm_uri(k.get("uri", "")) for k in _KEYS)
        stale = []
        for key in _STATUS:
            if crypt.is_opaque_id(key):
                if key not in known_ids:
                    stale.append(key)
            elif key not in known_raw:
                stale.append(key)
        for key in stale:
            _STATUS.pop(key, None)
        if stale:
            _save_status()


# --- блеклист мёртвых ---
def dead_add(uri, reason="user_removed"):
    import time
    with _LOCK:
        n = _record_key(_DEAD, uri, "dead")
        _DEAD[n] = {"reason": reason, "ts": int(time.time())}
        _save_dead()


def dead_remove(uri):
    with _LOCK:
        n = _record_key(_DEAD, uri, "dead")
        if n in _DEAD:
            _DEAD.pop(n, None)
            _save_dead()
            return True
    return False


def dead_reason(uri):
    with _LOCK:
        n = _record_key(_DEAD, uri, "dead")
        return _DEAD.get(n, {}).get("reason")


def blocked(uri):
    with _LOCK:
        return _record_key(_DEAD, uri, "dead") in _DEAD


def alive(uri):
    """Ключ не в блеклисте и не bad — может жить в пуле."""
    if blocked(uri):
        return False
    st = get_status(uri)
    return st.get("status") != "bad"


# --- выбор активного: pick_final по рангам (0 лучший) ---
def _good_ip(ip):
    direct_ip = config.get_direct_ip()
    return bool(direct_ip) and ip not in ("", "-", direct_ip)


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
        st = get_status(k.get("uri", ""))
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


def validate_vless_key(key, require_pbk=True):
    uri = _norm_uri(str(key.get("uri", "")))
    try:
        parsed = urllib.parse.urlparse(uri)
    except (TypeError, ValueError):
        return "invalid vless uri"
    if parsed.scheme != "vless" or not parsed.hostname:
        return "invalid vless uri"
    host = _canonical_host(parsed.hostname)
    if not _host_name_allowed(host):
        return "invalid host"
    try:
        port = parsed.port
        if port is None:
            port = key.get("port", 443)
        port = int(port)
    except (TypeError, ValueError):
        return "invalid port"
    if not 1 <= port <= 65535:
        return "invalid port"
    value_uuid = parsed.username or key.get("uuid", "")
    try:
        uuid.UUID(str(value_uuid))
    except (ValueError, TypeError, AttributeError):
        return "invalid uuid"
    q = urllib.parse.parse_qs(parsed.query)

    def one(name, default=None):
        value = q.get(name)
        if isinstance(value, list):
            value = value[0] if value else None
        return value or default

    pbk = one("pbk") or key.get("pbk")
    if require_pbk and not pbk:
        return "pbk required"
    if pbk and not re.fullmatch(r"[A-Za-z0-9_-]{43}", str(pbk)):
        return "invalid pbk"
    sid = one("sid") or key.get("sid")
    if sid and not re.fullmatch(r"(?:[0-9a-fA-F]{2}){1,8}", str(sid)):
        return "invalid sid"
    if one("type", "tcp") != "tcp":
        return "unsupported transport"
    if one("security", "reality") != "reality":
        return "unsupported security"
    if one("flow", "xtls-rprx-vision") != "xtls-rprx-vision":
        return "unsupported flow"
    if one("encryption", "none") != "none":
        return "unsupported encryption"
    return None


def build_outbound(key):
    """Строит VLESS-outbound для xray.json. None при невалидности."""
    if validate_vless_key(key):
        return None
    import urllib.parse

    k = dict(key)
    uri = _norm_uri(k.get("uri", ""))
    parsed = urllib.parse.urlparse(uri)
    host = _canonical_host(parsed.hostname or k.get("host"))
    try:
        port = parsed.port
        if port is None:
            port = k.get("port", 443)
        port = int(port)
    except (TypeError, ValueError):
        return None
    if not _host_name_allowed(host) or not 1 <= port <= 65535:
        return None
    address = resolve_public_host(host, port)
    if not address:
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
                "address": address,
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
    with _LOCK:
        seen = set()
        out = []
        for k in _KEYS:
            ep = _endpoint(k.get("host", ""), k.get("port")) if k.get("host") else _norm_uri(k.get("uri", ""))
            if ep in seen:
                continue
            seen.add(ep)
            out.append(dict(k))
        if len(out) != len(_KEYS):
            _KEYS = out
            _save_keys()


def cleanup():
    """Удаление мёртвых ключей из пула.

    мёртвый github-ключ = bad / slow (>500мс) / noip (без
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
            st = get_status(uri)
            deadish = blocked(uri) or st.get("status") in ("bad", "slow", "noip")
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
