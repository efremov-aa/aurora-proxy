# Aurora v1.4.0 — меш: ноды сети, invite-ссылка, пинги доступности.
# Хранение: data/mesh_nodes.json. Хаб = текущий сервер; внешние ноды добавляются
# из invite-ссылок других серверов Aurora (или вручную через UI).

import concurrent.futures
import base64
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import socket
import threading
import time
import uuid as _uuid

import config

MESH_FILE = os.path.join(config.DATA_DIR, "mesh_nodes.json")

_LOCK = threading.RLock()
_NODES = []

MAX_NODES = 256
# A-827 (Ш8): галки прав узла. ВСЕ три по умолчанию ВЫКЛ — владелец сам
# решает, можно ли через узел гнать чужой трафик и пускать ли к нему.
#   allow_relay — «разрешить гнать мой трафик» (узел работает релем для других)
#   allow_lan   — «разрешить доступ к моей Aurora» (трафик к своей локалке)
#   no_relay   — узел вообще никогда не рель (hub/test помечены заранее)
OPTIN_FLAGS = ("allow_relay", "allow_lan", "no_relay")
OPTIN_DEFAULTS = {"allow_relay": False, "allow_lan": False, "no_relay": False}
PING_WORKERS = 32
PING_MIN_TIMEOUT = 0.25
PING_MAX_TIMEOUT = 1.0
PING_COOLDOWN_S = 15.0
_PING_WAIT_S = 10.0
_PING_LOCK = threading.Lock()
_PING_RUNNING = False
_PING_EVENT = None
_PING_CACHE = []
_PING_CACHE_AT = 0.0
_PING_GENERATION = 0


INVITE_TTL_S = 300
MAX_INVITE_CHALLENGES = 1024
_INVITE_FIELDS = ("invite_version", "issuer", "token", "challenge", "host",
                  "port", "policy_port", "name", "issued_at", "expires_at")

def policy_entitlements():
    """Совместимость с панелью: отдельных прав больше нет, всё локальное."""
    return []


def has_mesh(uid):
    """Все локальные пиры имеют право на меш."""
    return bool(str(uid or "").strip())

INVITE_USED_FILE = os.path.join(config.DATA_DIR, "mesh_invite_used.json")


# --- корень своей локальной подсети -----------------------------------------
# Приглашение подписывается локальным ключом подсети. Ключ и идентификатор
# лежат в data/mesh_local.json (0600). Внешних серверов и ролей здесь нет.
MESH_LOCAL_FILE = os.path.join(config.DATA_DIR, "mesh_local.json")
_LOCAL_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{2,63}")


def _local_state():
    """Читает локальный issuer/ключ/токен подсети. Только из зашифрованного хранилища."""
    import crypt
    try:
        data = crypt.load_json(MESH_LOCAL_FILE, default={})
    except Exception:
        return {}
    return dict(data) if isinstance(data, dict) else {}


def _local_save(data):
    import crypt
    crypt.save_json(MESH_LOCAL_FILE, data)


def _local_issuer():
    """Возвращает (issuer, key) своей подсети или ("", "") - fail-closed."""
    data = _local_state()
    issuer = str(data.get("id") or "").strip().lower()
    key = str(data.get("key") or "")
    if not _LOCAL_ID_RE.fullmatch(issuer):
        return "", ""
    if len(key.encode("utf-8")) < 32:
        return "", ""
    return issuer, key


def _local_issuer_ensure():
    """Лениво создаёт локальный issuer/ключ (секреты в лог не пишутся)."""
    issuer, key = _local_issuer()
    if issuer and key:
        return issuer, key
    issuer = "local-" + secrets.token_hex(6)
    key = secrets.token_urlsafe(32)
    data = _local_state()
    data["id"] = issuer
    data["key"] = key
    data["token"] = secrets.token_urlsafe(32)
    try:
        _local_save(data)
    except (OSError, RuntimeError, TypeError, ValueError):
        return "", ""
    return issuer, key


def _local_token():
    data = _local_state()
    token = str(data.get("token") or "")
    if re.fullmatch(r"[A-Za-z0-9_-]{24,256}", token):
        return token
    return ""


def _invite_expected_key(issuer):
    """Принимаем только приглашения своей локальной подсети."""
    issuer = str(issuer or "").strip().lower()
    local_id, local_key = _local_issuer()
    if local_id and issuer == local_id:
        return local_key
    return ""


def _canonical_bytes(core):
    return json.dumps(core, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _signed_bytes(core, fields):
    return _canonical_bytes({field: core.get(field) for field in fields})


def _hmac_hex(key, payload):
    return hmac.new(str(key).encode("utf-8"), payload, hashlib.sha256).hexdigest()


def _invite_bytes(core):
    return _signed_bytes(core, _INVITE_FIELDS)


def _invite_signature(core, key):
    """Подпись локального invite: только локальный ключ подсети."""
    return _hmac_hex(key, _invite_bytes(core)) if key else ""


def _valid_port(value):
    if isinstance(value, bool) or not isinstance(value, int):
        return False
    return 1 <= value <= 65535


def _ascii_int(value, max_len=12):
    if not isinstance(value, str) or not value or len(value) > max_len:
        return None
    for ch in value:
        if ch < "0" or ch > "9":
            return None
    return int(value)


def _is_hex(value, length):
    if not isinstance(value, str) or len(value) != length:
        return False
    for ch in value:
        if ch not in "0123456789abcdef":
            return False
    return True


def _invite_node(value):
    """Строгая нормализация endpoint-а узла для подписанного invite."""
    if not isinstance(value, dict):
        return None
    if set(value) != {"name", "region", "host", "port", "policy_port"}:
        return None
    name = value.get("name")
    region = value.get("region")
    if not isinstance(name, str) or not name or len(name) > 64:
        return None
    if not isinstance(region, str) or not region or len(region) > 64:
        return None
    if not _valid_peer_host(value.get("host")):
        return None
    port = value.get("port")
    policy_port = value.get("policy_port")
    if not _valid_port(port) or not _valid_port(policy_port):
        return None
    return {"name": name, "region": region, "host": value.get("host"),
            "port": port, "policy_port": policy_port}


def _invite_used_schema(value):
    if not isinstance(value, dict) or len(value) > MAX_INVITE_CHALLENGES:
        return False
    for key, expires in value.items():
        if not _is_hex(key, 32):
            return False
        if isinstance(expires, bool) or not isinstance(expires, int):
            return False
        if expires <= 0:
            return False
    return True


def _used_challenges():
    try:
        import crypt
        value = crypt.load_json(INVITE_USED_FILE, {})
    except Exception:
        return {}
    return value if _invite_used_schema(value) else {}


def _remember_challenge(challenge, expires_at):
    """Атомарно помечает challenge как использованный (одноразовость)."""
    with _LOCK:
        used = _used_challenges()
        now = int(time.time())
        for known in [k for k, v in used.items() if v <= now]:
            used.pop(known, None)
        if challenge in used:
            return False
        if len(used) >= MAX_INVITE_CHALLENGES:
            return False
        candidate = dict(used)
        candidate[challenge] = int(expires_at)
        try:
            import crypt
            crypt.save_json(INVITE_USED_FILE, candidate)
        except Exception:
            return False
    return True


def _local_host():
    """Собственный адрес узла для локального приглашения."""
    for name in ("VM_HOST", "HOST"):
        value = getattr(config, name, "")
        if isinstance(value, str) and _valid_peer_host(value):
            return value
    try:
        value = socket.gethostbyname(socket.gethostname())
    except Exception:
        return None
    return value if _valid_peer_host(value) else None


def _invalidate_ping_cache():
    global _PING_CACHE, _PING_CACHE_AT, _PING_GENERATION
    with _PING_LOCK:
        _PING_CACHE = []
        _PING_CACHE_AT = 0.0
        _PING_GENERATION += 1


def _ping_cache_copy():
    return [dict(item) for item in _PING_CACHE]


def _safe_ping_timeout(value):
    try:
        value = float(value)
    except (TypeError, ValueError, OverflowError):
        return PING_MAX_TIMEOUT
    if not math.isfinite(value):
        return PING_MAX_TIMEOUT
    return max(PING_MIN_TIMEOUT, min(PING_MAX_TIMEOUT, value))


def hub():
    """Нода хаба — сам сервер."""
    return {
        "id": "hub",
        "name": config.get("server_name") or "Home",
        "region": "RU",
        "host": config.VM_HOST,
        "port": config.XRAY_PORT,
        "role": "hub",
    }


def _mesh_storage_failure(reason):
    config.quarantine_file(MESH_FILE)
    raise config.StorageDataError("mesh_nodes.json: %s" % reason)


def _validate_nodes(raw):
    if not isinstance(raw, list):
        raise ValueError("mesh root is not a list")
    if len(raw) > MAX_NODES - 1:
        raise ValueError("mesh node limit exceeded")
    out = []
    ids = set()
    endpoints = set()
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("mesh record is not an object")
        rec = dict(item)
        node_id = rec.get("id")
        if (not isinstance(node_id, str) or not node_id.strip()
                or node_id == "hub" or len(node_id) > 64):
            raise ValueError("mesh id is invalid")
        node_id = node_id.strip()
        name = _valid_node_name(rec.get("name"))
        if name is None:
            raise ValueError("mesh name is invalid")
        region = rec.get("region")
        if not isinstance(region, str):
            raise ValueError("mesh region is invalid")
        role = rec.get("role")
        if role not in ("hub", "node", "test"):
            raise ValueError("mesh role is invalid")
        host = rec.get("host")
        if not isinstance(host, str):
            raise ValueError("mesh host is invalid")
        host = host.strip().lower()
        if not _valid_peer_host(host, allow_loopback=(role == "hub")):
            raise ValueError("mesh host is invalid")
        port = rec.get("port")
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("mesh port is invalid")
        if "added" in rec and (type(rec["added"]) is not int or rec["added"] < 0):
            raise ValueError("mesh added is invalid")
        if "secret" in rec and not isinstance(rec["secret"], str):
            raise ValueError("mesh secret is invalid")
        # A-827 (Ш8): оптины узла. Строгий bool — «1»/«да»/1 НЕ молча истина,
        # потому что молчаливая истина в правах означает «трафик пошёл», а это
        # ровно то, что владелец не давал.
        for flag in OPTIN_FLAGS:
            if flag in rec and type(rec[flag]) is not bool:
                raise ValueError("mesh %s is invalid" % flag)
        if node_id in ids or (host, port) in endpoints:
            raise ValueError("duplicate mesh node")
        ids.add(node_id)
        endpoints.add((host, port))
        rec["id"] = node_id
        rec["name"] = name
        rec["host"] = host
        rec["region"] = region
        # A-827 (ШИ): отсутствующую галку ДОПИСЫВАЕМ как выключенную, чтобы
        # дальше по коду «нет галки» и «выключено» не расходились.
        for flag in OPTIN_FLAGS:
            rec.setdefault(flag, OPTIN_DEFAULTS[flag])
        # Служебные узлы релью быть не могут НИКОГДА (ДОРОЖНАЯ КАРТА §5).
        # Ставим принудительно, даже если в файле было написано иначе:
        # поднять флаг на служебном узле нельзя, это ограничение роли.
        if role in ("hub", "test"):
            rec["no_relay"] = True
            rec["allow_relay"] = False
        out.append(rec)
    return out


def load():
    """Загрузка data/mesh_nodes.json без потери исходных данных."""
    global _NODES
    import crypt
    missing = object()
    try:
        raw = crypt.load_json(MESH_FILE, default=missing)
    except crypt.StorageError as e:
        _mesh_storage_failure(str(e))
    exists = raw is not missing
    if not exists:
        nodes = []
    else:
        try:
            nodes = _validate_nodes(raw)
        except (TypeError, ValueError) as e:
            _mesh_storage_failure(str(e))
        try:
            crypt.save_json(MESH_FILE, nodes)
        except (crypt.StorageError, OSError) as e:
            _mesh_storage_failure(str(e))
    with _LOCK:
        _NODES = nodes
    _invalidate_ping_cache()


def _atomic_write(path, obj):
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=1, ensure_ascii=False)
        os.replace(tmp, path)
        return True
    except OSError:
        return False


def _save():
    with _LOCK:
        import crypt
        crypt.save_json(MESH_FILE, _NODES)


# --- авто-имена узлов (рандомные, неповторяющиеся) ---
# Генерация на головном сервере: при пустом/занятом имени выдаём уникальное.
_NAME_ADJ = (
    "Белый", "Рыжий", "Чёрный", "Серый", "Пушистый", "Мурлычный",
    "Смелый", "Ловкий", "Быстрый", "Тёплый", "Ночной", "Солнечный",
    "Хитрый", "Весёлый", "Добрый", "Мягкий",
)
_NAME_NOUN = (
    "Кот", "Лис", "Пёс", "Ёж", "Барс", "Рысь", "Волк", "Барсук",
    "Заяц", "Сова", "Сокол", "Тигр", "Лев", "Бобр", "Кролик",
)


def _used_names():
    """Множество занятых имён (хаб + все внешние ноды)."""
    names = {str(hub().get("name", "") or "").strip()}
    with _LOCK:
        names.update(str(n.get("name", "") or "").strip() for n in _NODES)
    names.discard("")
    return names


def generate_name():
    """Рандомное уникальное имя узла (гарантированно не пересекается с другими)."""
    import random
    used = _used_names()
    for _ in range(64):
        name = "%s-%s" % (random.choice(_NAME_ADJ), random.choice(_NAME_NOUN))
        if name not in used:
            return name
    for _ in range(32):
        name = "Узел-%d" % random.randint(1000, 9999)
        if name not in used:
            return name
    return "Узел-%d" % int(time.time())


def _mask(node):
    """Публичная копия ноды БЕЗ секретов (secret доступен только владельцу)."""
    n = dict(node)
    n.pop("secret", None)
    return n


def all_nodes():
    """Хаб + внешние ноды (копии, секреты скрыты)."""
    with _LOCK:
        return [hub()] + [_mask(n) for n in _NODES]


def node_count():
    """Всего нод (хаб + внешние)."""
    with _LOCK:
        return len(_NODES) + 1


def test_node_count():
    """Число эксклюзивных узлов (role=test), которыми пользуется только головной."""
    with _LOCK:
        return sum(1 for n in _NODES if n.get("role") == "test")


def _optins_locked(node):
    """Галки узла из записи. Отсутствующая = выключена (никогда не истина)."""
    out = {}
    for flag in OPTIN_FLAGS:
        out[flag] = node.get(flag) is True
    return out


def optins(node_id):
    """Публичные галки узла (или хаба). Секретов здесь нет."""
    with _LOCK:
        if node_id == "hub":
            return {"allow_relay": False, "allow_lan": False, "no_relay": True}
        for n in _NODES:
            if n.get("id") == node_id:
                return _optins_locked(n)
    return dict(OPTIN_DEFAULTS)


def relay_eligible(node_id):
    """A-827 (Ш8): можно ли назначить узел рельём чужого игрового трафика.

    Fail-closed: узла нет, галки нет, узел служебный — всё равно НЕЛЬЗЯ.
    Право выдаётся только явной галкой владельца."""
    return bool(optins(node_id).get("allow_relay"))


def lan_eligible(node_id):
    """A-827 (Ш8): можно ли пускать трафик к локалке узла (его Aurora)."""
    return bool(optins(node_id).get("allow_lan"))


def set_optin(node_id, **flags):
    """A-827 (Ш8): поставить галку. Возвращает (ok, error).

    Ключи вне OPTIN_FLAGS и не-bool отвергаются: молча выкинутое значение
    галки прав — это «я думал включено, а оно выключено»."""
    clean = {}
    for key, value in flags.items():
        if key not in OPTIN_FLAGS:
            return False, "неизвестная галка: %s" % key
        if type(value) is not bool:
            return False, "галка %s должна быть true/false" % key
        clean[key] = value
    if not clean:
        return False, "нечего менять"
    node_id = str(node_id or "").strip()
    with _LOCK:
        for n in _NODES:
            if n.get("id") != node_id:
                continue
            role = n.get("role")
            if role in ("hub", "test"):
                # A-827: служебный узел релью не становится ни при каком вводе.
                if clean.get("allow_relay") is True or clean.get("no_relay") is False:
                    return False, "служебный узел не может быть релью"
            for flag, value in clean.items():
                if role in ("hub", "test") and flag == "allow_relay" and value is False:
                    continue
                n[flag] = value
            _save()
            return True, None
    return False, "узел не найден"


def _valid_peer_host(value, allow_loopback=False):
    host = str(value or "").strip().lower()
    if not host or len(host) > 253:
        return False
    if any(ch.isspace() for ch in host) or any(ch in host for ch in "/\\@?#"):
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return allow_loopback
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_unspecified or ip.is_multicast or ip.is_link_local:
            return False
        return allow_loopback or not ip.is_loopback
    except ValueError:
        return all(ch.isalnum() or ch in ".-" for ch in host)


def _valid_node_name(value):
    name = str(value or "").strip()
    if not name or len(name) > 40:
        return None
    if any(ord(ch) < 32 or ch in "<>\"'" for ch in name):
        return None
    return name


def add(name, region, host, port, role=None, auto_name=False, policy_port=None):
    """Добавляет внешнюю ноду. Возвращает (node, error).

    auto_name=True или пустое имя — головной генерирует рандомное уникальное имя.
    Занятое имя (хаб/другие ноды) тоже уходит в авто-генерацию без ошибки.
    role=test — эксклюзивный узел: используется ТОЛЬКО головным сервером,
    при добавлении генерируется secret доверия, который отдаётся один раз.
    """
    raw_name = str(name or "").strip()
    if auto_name or not raw_name:
        raw_name = generate_name()
    raw_name = _valid_node_name(raw_name)
    if raw_name is None:
        return None, "неверное имя узла"
    region = str(region or "").strip() or "—"
    host = str(host or "").strip()
    role = str(role or "node").strip().lower()
    if role not in ("hub", "node", "test"):
        return None, "неверная роль узла"
    try:
        port = int(port or 0)
    except (TypeError, ValueError):
        return None, "неверный порт"
    try:
        policy_port = int(config.UI_PORT if policy_port is None else policy_port)
    except (TypeError, ValueError):
        return None, "неверный policy_port"
    if not _valid_port(policy_port):
        return None, "неверный policy_port"
    if (not _valid_peer_host(host, allow_loopback=(role == "hub"))
            or port <= 0 or port > 65535):
        return None, "неверный host/port"
    with _LOCK:
        if len(_NODES) + 1 >= MAX_NODES:
            return None, "достигнут лимит mesh-узлов"
        if any(n.get("host") == host and n.get("port") == port for n in _NODES):
            return None, "узел уже есть"
        if raw_name in _used_names():
            raw_name = generate_name()
            config.log("mesh: имя занято, выдано авто-имя %s" % raw_name)
        node = {
            "id": _uuid.uuid4().hex[:4],
            "name": raw_name[:40],
            "region": region[:20],
            "host": host,
            "port": port,
            "role": role,
            "policy_port": policy_port,
            "added": int(time.time()),
        }
        # A-827 (Ш8): галки сразу заполнены, служебные узлы — сразу no_relay.
        # Иначе до перезагрузки узел числился бы «можно рель», хотя роль запрещает.
        for flag in OPTIN_FLAGS:
            node[flag] = OPTIN_DEFAULTS[flag]
        if role in ("hub", "test"):
            node["no_relay"] = True
        if role == "test":
            import secrets
            node["secret"] = secrets.token_hex(16)
        _NODES.append(node)
        _save()
    _invalidate_ping_cache()
    config.log("mesh: добавлен узел %s (%s:%d, role=%s)" % (
        node["name"], host, port, role))
    return dict(node), None


def get_secret(node_id):
    """Секрет доверия эксклюзивного узла (только для головного сервера)."""
    with _LOCK:
        for n in _NODES:
            if n.get("id") == node_id:
                return n.get("secret")
    return None


def _valid_node_id(value):
    """Идентификатор узла: 8/32 hex, ULID или канонический UUID."""
    if not isinstance(value, str):
        return False
    v = value.strip()
    if not v or len(v) > 64:
        return False
    if re.fullmatch(r"[0-9a-f]{8}", v) or re.fullmatch(r"[0-9a-f]{32}", v):
        return True
    if re.fullmatch(r"[0-7][0-9A-HJKMNP-TV-Z]{25}", v):
        return True
    if len(v) == 36:
        try:
            return str(_uuid.UUID(v)) == v.lower()
        except (AttributeError, TypeError, ValueError):
            return False
    return False


def _vless_client_valid(value):
    """Профиль внешнего VLESS узла: ровно шесть полей, каждое проверяется."""
    if not isinstance(value, dict):
        return False
    if set(value.keys()) != {"uuid", "pbk", "short_id", "sni", "host", "port"}:
        return False
    uid = value.get("uuid")
    if not isinstance(uid, str) or len(uid) != 36:
        return False
    try:
        if str(_uuid.UUID(uid)) != uid.lower():
            return False
    except (AttributeError, TypeError, ValueError):
        return False
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", str(value.get("pbk") or "")):
        return False
    sid = value.get("short_id")
    if not isinstance(sid, str) or not sid or len(sid) > 16 or len(sid) % 2:
        return False
    try:
        int(sid, 16)
    except ValueError:
        return False
    sni = value.get("sni")
    if not isinstance(sni, str) or not sni or len(sni) > 253:
        return False
    if any(ch.isspace() for ch in sni):
        return False
    if not _valid_peer_host(value.get("host"), allow_loopback=False):
        return False
    return _valid_port(value.get("port"))


def set_vless_client(node_id, value):
    """Записать или снять профиль внешнего VLESS узла (пир шлёт, узел читает)."""
    global _NODES
    if not _valid_node_id(node_id):
        return False
    if value is not None and not _vless_client_valid(value):
        return False
    with _LOCK:
        rows = [dict(n) for n in _NODES]
        found = False
        for rec in rows:
            if rec.get("id") != node_id:
                continue
            found = True
            if value is None:
                rec.pop("vless_client", None)
            else:
                rec["vless_client"] = dict(value)
            break
        if not found:
            return value is None
        try:
            rows = _validate_nodes(rows)
        except (TypeError, ValueError):
            return False
        previous = _NODES
        _NODES = rows
        try:
            _save()
        except Exception:
            _NODES = previous
            return False
    _invalidate_ping_cache()
    return True


def ensure_peer_profile(node_id, name=None, value=None):
    """A-943/A-944: sozdaet ili obnovlyaet zapis uzla s ZADANNYM id + profilem.

    Nuzhno A-940: profil pira prihodit s id iz kadra pira, a `add()`
    generiruet SVOY id - posle `add()` zapis pira pisalsya pod chuzhim id i
    `set_vless_client` TIHO vozvrashchal False. Zdes id beretsya iz kadra.

    Fail-closed: id cherez `_valid_node_id`, profil cherez
    `_vless_client_valid`, imya cherez `_valid_node_name`/`_used_names`,
    limit - MAX_NODES, zapis prohodyat `_validate_nodes` i `_save`.
    Zapis `role="test"` ne trogaetsya."""
    if not _valid_node_id(node_id) or not _vless_client_valid(value):
        return False
    target = str(node_id)
    raw_name = _valid_node_name(str(name or "").strip()) or ""
    if not raw_name:
        raw_name = generate_name()
    with _LOCK:
        rows = [dict(item) for item in _NODES]
        index = -1
        for position, item in enumerate(rows):
            if isinstance(item, dict) and item.get("id") == target:
                index = position
                break
        if index >= 0:
            item = rows[index]
            if item.get("role") == "test":
                return False
            updated = dict(item)
            updated["name"] = raw_name[:40]
            updated["vless_client"] = dict(value)
        else:
            if len(_NODES) >= MAX_NODES:
                return False
            if raw_name in _used_names():
                raw_name = generate_name()
            updated = {"id": target,
                       "name": raw_name[:40],
                       "region": "\u2014",
                       "host": str(value.get("host")),
                       "port": int(value.get("port")),
                       "role": "node",
                       "added": int(time.time()),
                       "vless_client": dict(value)}
            try:
                policy_port = int(getattr(config, "UI_PORT", 0) or 0)
            except (TypeError, ValueError):
                policy_port = 0
            if _valid_port(policy_port):
                updated["policy_port"] = policy_port
            for flag in OPTIN_FLAGS:
                updated[flag] = OPTIN_DEFAULTS[flag]
        if index >= 0:
            rows[index] = updated
        else:
            rows.append(updated)
        try:
            rows = _validate_nodes(rows)
        except (TypeError, ValueError):
            return False
        previous = _NODES
        globals()["_NODES"] = rows
        try:
            _save()
        except Exception:
            globals()["_NODES"] = previous
            return False
    _invalidate_ping_cache()
    return True


def vless_client(node_id):
    """Копия профиля внешнего VLESS узла (пусто, если профиля нет или он битый)."""
    if not _valid_node_id(node_id):
        return {}
    with _LOCK:
        for n in _NODES:
            if n.get("id") != node_id:
                continue
            value = n.get("vless_client")
            if _vless_client_valid(value):
                return dict(value)
            return {}
    return {}


def remove(node_id):
    """Удаляет внешнюю ноду по id. Возвращает True при удалении."""
    global _NODES
    with _LOCK:
        before = len(_NODES)
        _NODES = [n for n in _NODES if n.get("id") != node_id]
        removed = len(_NODES) != before
        if removed:
            _save()
    if removed:
        _invalidate_ping_cache()
        config.log("mesh: удалён узел %s" % node_id)
        return True
    return False


def _tcp_ping(host, port, timeout=2.0):
    """Проверка TCP-доступности host:port. Возвращает bool."""
    s = None
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        return True
    except (OSError, TypeError, ValueError, OverflowError):
        return False
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass


def ping(host, port, timeout=2.0):
    """Замер доступности. Возвращает (ok, latency_ms)."""
    t0 = time.time()
    ok = _tcp_ping(host, port, _safe_ping_timeout(timeout))
    ms = int((time.time() - t0) * 1000)
    return ok, ms


def _ping_node(node, timeout):
    try:
        ok, ms = ping(node.get("host"), node.get("port"), timeout)
    except (OSError, TypeError, ValueError, OverflowError):
        ok, ms = False, 0
    return {
        "id": node.get("id"),
        "name": node.get("name"),
        "region": node.get("region"),
        "host": node.get("host"),
        "port": node.get("port"),
        "role": node.get("role"),
        "ok": ok,
        "ping_ms": ms,
    }


def _scan_nodes(nodes, timeout):
    if not nodes:
        return []
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(PING_WORKERS, len(nodes))) as pool:
        futures = [pool.submit(_ping_node, node, timeout) for node in nodes]
        return [future.result() for future in futures]


def ping_all(timeout=2.0):
    """Пинги всех нод (хаб + внешние). Возвращает список со статусом."""
    global _PING_RUNNING, _PING_EVENT, _PING_CACHE, _PING_CACHE_AT
    timeout = _safe_ping_timeout(timeout)
    with _PING_LOCK:
        now = time.monotonic()
        if _PING_RUNNING:
            if _PING_CACHE and now - _PING_CACHE_AT < PING_COOLDOWN_S:
                return _ping_cache_copy()
            event = _PING_EVENT
        elif _PING_CACHE and now - _PING_CACHE_AT < PING_COOLDOWN_S:
            return _ping_cache_copy()
        else:
            _PING_RUNNING = True
            _PING_EVENT = threading.Event()
            event = None
            generation = _PING_GENERATION
    if event is not None:
        event.wait(_PING_WAIT_S)
        with _PING_LOCK:
            return _ping_cache_copy()
    try:
        result = _scan_nodes(all_nodes()[:MAX_NODES], timeout)
    except Exception:
        result = []
    with _PING_LOCK:
        if generation == _PING_GENERATION:
            _PING_CACHE = [dict(item) for item in result]
            _PING_CACHE_AT = time.monotonic()
        _PING_RUNNING = False
        if _PING_EVENT is not None:
            _PING_EVENT.set()
    return [dict(item) for item in result]


def invite():
    """Приглашение для своей локальной подсети, подписанное локальным ключом."""
    issuer, key = _local_issuer_ensure()
    if not issuer or not key:
        return None
    if not _valid_port(config.XRAY_PORT) or not _valid_port(config.UI_PORT):
        return None
    host = _local_host() or str(config.VM_HOST or "").strip()
    if not host or not _valid_peer_host(host, allow_loopback=True):
        return None
    token = _local_token()
    if not token:
        return None
    issued_at = int(time.time())
    name = str(config.get("server_name") or "").strip()[:64] or "Node"
    core = {
        "invite_version": 1,
        "issuer": issuer,
        "token": token,
        "challenge": secrets.token_hex(16),
        "host": host,
        "port": int(config.XRAY_PORT),
        "policy_port": int(config.UI_PORT),
        "name": name,
        "issued_at": issued_at,
        "expires_at": issued_at + INVITE_TTL_S,
    }
    signature = _invite_signature(core, key)
    if not signature:
        return None
    from urllib.parse import urlencode
    return "aurora://invite?" + urlencode(list(core.items()) + [("signature", signature)])


def regenerate():
    """Перевыпускает приглашение своей подсети: старый токен и локальный ключ сгорают."""
    issuer, _key = _local_issuer()
    if not issuer:
        return None
    data = _local_state()
    data["token"] = secrets.token_urlsafe(32)
    data["key"] = secrets.token_urlsafe(32)
    try:
        _local_save(data)
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    return invite()


def parse_invite(url):
    """Проверяет подпись, issuer и срок приглашения. Возвращает core или None."""
    if not isinstance(url, str) or not url or len(url) > 4096:
        return None
    for ch in url:
        if ord(ch) < 32 or ord(ch) == 127:
            return None
    from urllib.parse import parse_qs, urlparse
    try:
        parsed = urlparse(url)
        query = parse_qs(parsed.query, strict_parsing=True,
                         max_num_fields=len(_INVITE_FIELDS) + 1)
    except (TypeError, ValueError):
        return None
    if parsed.scheme != "aurora" or parsed.netloc != "invite" or parsed.fragment:
        return None
    if set(query) != set(_INVITE_FIELDS) | {"signature"}:
        return None
    if any(len(values) != 1 for values in query.values()):
        return None
    raw = {field: values[0] for field, values in query.items()}
    if raw.get("invite_version") != "1":
        return None
    issuer = str(raw.get("issuer") or "").strip().lower()
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", issuer):
        return None
    if not _invite_expected_key(issuer):
        return None
    token = raw.get("token")
    if not isinstance(token, str) or not 24 <= len(token) <= 256:
        return None
    for ch in token:
        if ord(ch) > 127 or not (ch.isalnum() or ch in "-_"):
            return None
    if not _is_hex(raw.get("challenge"), 32) or not _is_hex(raw.get("signature"), 64):
        return None
    name = raw.get("name")
    if not isinstance(name, str) or not name or len(name) > 64:
        return None
    if not _valid_peer_host(raw.get("host"), allow_loopback=True):
        return None
    numbers = {}
    for field in ("port", "policy_port", "issued_at", "expires_at"):
        numbers[field] = _ascii_int(raw.get(field))
        if numbers[field] is None:
            return None
    if not _valid_port(numbers["port"]) or not _valid_port(numbers["policy_port"]):
        return None
    if numbers["expires_at"] - numbers["issued_at"] != INVITE_TTL_S:
        return None
    now = int(time.time())
    if numbers["issued_at"] > now + 30 or numbers["expires_at"] <= now:
        return None
    core = {
        "invite_version": 1,
        "issuer": raw.get("issuer"),
        "token": token,
        "challenge": raw.get("challenge"),
        "host": raw.get("host"),
        "port": numbers["port"],
        "policy_port": numbers["policy_port"],
        "name": name,
        "issued_at": numbers["issued_at"],
        "expires_at": numbers["expires_at"],
    }
    key = _invite_expected_key(issuer)
    if not key:
        return None
    if not hmac.compare_digest(raw.get("signature"), _invite_signature(core, key)):
        return None
    return core


def invite_proof(url, node):
    """Доказательство владения приглашением (токен по сети не передаётся)."""
    parsed = parse_invite(url)
    if parsed is None:
        return None
    endpoint = _invite_node(node)
    if endpoint is None:
        return None
    payload = {
        "challenge": parsed["challenge"],
        "issuer": parsed["issuer"],
        "name": endpoint["name"],
        "region": endpoint["region"],
        "host": endpoint["host"],
        "port": endpoint["port"],
        "policy_port": endpoint["policy_port"],
    }
    return _hmac_hex(parsed["token"], _canonical_bytes(payload))


# --- v1.8.0: авто-имя сервера и авто-вступление в меш головного сервера ---

def join(data):
    """Принимает узел в СВОЮ подсеть по приглашению (A-265).

    Обратная сторона join_via_invite: узел шлёт нам свой invite+proof, мы проверяем
    подпись локальным ключом, токен этой подсети и антиреплей, затем добавляем узел.
    Права головного не выдаются, внешних политик узел не получает.
    """
    local_issuer, _local_key = _local_issuer()
    if not local_issuer:
        return None, "join unavailable"
    if not isinstance(data, dict) or set(data) != {
            "invite", "proof", "name", "region", "host", "port", "policy_port"}:
        return None, "invalid invite"
    endpoint = _invite_node({key: data.get(key) for key in
                             ("name", "region", "host", "port", "policy_port")})
    parsed = parse_invite(data.get("invite"))
    proof = data.get("proof")
    if (not endpoint or not parsed or parsed.get("issuer") != local_issuer
            or not isinstance(proof, str) or not re.fullmatch(r"[0-9a-f]{64}", proof)):
        return None, "invalid invite"
    expected = invite_proof(data.get("invite"), endpoint)
    if not expected or not hmac.compare_digest(proof, expected):
        return None, "invalid invite"
    token = _local_token()
    if not token or not hmac.compare_digest(parsed["token"], token):
        return None, "invalid invite"
    with _LOCK:
        if parsed["challenge"] in _used_challenges():
            return None, "invalid invite"
    node, err = add(endpoint["name"], endpoint["region"], endpoint["host"],
                    endpoint["port"], "node", auto_name=False,
                    policy_port=endpoint["policy_port"])
    if err or not node:
        return None, "invalid invite"
    if not _remember_challenge(parsed["challenge"], parsed["expires_at"]):
        return None, "invalid invite"
    return node, ""


def ensure_unique_name():
    """Если имя сервера пусто/дефолтно/занято нодой меша — присваивает случайное уникальное.

    Возвращает итоговое имя."""
    # A-760: all_nodes() начинается с hub(), а hub() отдаёт имя САМОГО СЕБЯ
    # (server_name). Поэтому cur всегда находился в taken, условие «имя свободно»
    # не выполнялось никогда, и при КАЖДОМ старте сервер получал новое
    # случайное имя — отсюда плывущие «Тёплый-Кот/Пушистый-Кот».
    # Проверяем занятость только по ЧУЖИМ нодам, свой хаб из выборки убираем.
    with _LOCK:
        others = [_mask(n) for n in _NODES]
    taken = [n.get("name", "") for n in others]
    cur = (config.get("server_name") or "").strip()
    low = [str(x).strip().lower() for x in taken]
    if cur and cur not in ("Home", "-") and cur.lower() not in low:
        return cur
    name = config.random_server_name(taken=low)
    config.set("server_name", name)
    config.log("mesh: серверу присвоено уникальное имя '%s'" % name)
    return name


def _openers():
    """Запрос к локальному пиру: напрямую, при необходимости через свой xray."""
    from urllib.request import ProxyHandler, build_opener
    out = [build_opener(ProxyHandler({}))]
    try:
        port = int(getattr(config, "XRAY_PORT", 0) or 0)
    except (TypeError, ValueError):
        port = 0
    if 0 < port < 65536:
        url = "http://127.0.0.1:%d" % port
        try:
            out.append(build_opener(ProxyHandler({"http": url, "https": url})))
        except Exception:
            pass
    return out


def _fetch_post(scheme, host, port, path, data, timeout=5.0, headers=None):
    from urllib.request import Request
    try:
        body = json.dumps(data).encode("utf-8")
        hdr = {"Content-Type": "application/json", "X-Aurora-Request": "1"}
        if headers:
            hdr.update(headers)
        target = "[%s]" % host if ":" in host else host
        req = Request("%s://%s:%s%s" % (scheme, target, port, path),
                      data=body, headers=hdr, method="POST")
    except Exception:
        return None
    for opener in _openers():
        try:
            with opener.open(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except Exception:
            continue
    return None


def auto_join():
    """Совместимость со старым вызовом из run.py: автоматического вступления нет."""
    return None


def join_via_invite(url, name=None, region="RU", timeout=5.0):
    """Одноразовое вступление в меш по подписанному invite."""
    inv = parse_invite(url)
    if not inv:
        return False, "неверный invite"
    with _LOCK:
        replayed = inv["challenge"] in _used_challenges()
    if replayed:
        return False, "invite уже использован"
    host = _local_host()
    if not host:
        return False, "неверный собственный адрес"
    payload = {
        "name": str(name or inv.get("name") or "").strip()[:40] or "Client",
        "region": str(region or "RU").strip()[:20] or "RU",
        "host": host,
        "port": int(config.XRAY_PORT),
        "policy_port": int(config.UI_PORT),
    }
    proof = invite_proof(url, payload)
    if not proof:
        return False, "недействительный invite"
    payload = {
        "invite": url,
        "proof": proof,
        "name": payload["name"],
        "region": payload["region"],
        "host": payload["host"],
        "port": payload["port"],
        "policy_port": payload["policy_port"],
    }
    reg = _fetch_post("http", inv["host"], inv["policy_port"],
                      "/api/mesh/join", payload, timeout=timeout)
    if not (reg and reg.get("ok")):
        return False, "головной сервер не принял узел"
    if not _remember_challenge(inv["challenge"], inv["expires_at"]):
        return False, "invite уже использован"
    with _LOCK:
        present = any(n.get("host") == inv["host"]
                      and n.get("port") == inv["port"] for n in _NODES)
    if not present:
        node, err = add(inv.get("name") or "Головной", "RU",
                        inv["host"], inv["port"], role="hub",
                        policy_port=inv["policy_port"])
        if err:
            return False, err
    node_info = reg.get("node") or {}
    if node_info.get("name") and not str(name or "").strip():
        config.set("server_name", node_info["name"])
    config.log("mesh: вступление по invite %s:%d OK (id=%s, role=node)" % (
        inv["host"], inv["policy_port"], node_info.get("id") or "?"))
    return True, None





# --- локальная политика (совместимость с панелью) ---

def policy():
    """Только локальные флаги: меш доступен всегда."""
    return {
        "ok": True,
        "show_mesh": bool(config.get("show_mesh", True)),
    }


def apply_policy_raw(raw, source=""):
    """Совместимость: внешних политик больше нет."""
    return False


def policy_autonomy():
    """Совместимость: автономия не нужна, всё локально."""
    return {"cached": False, "age_s": -1, "autonomy_s": 0, "seen_at": 0}


def start_policy_loop():
    """Фоновый опрос внешней политики не запускается."""
    return None


load()
