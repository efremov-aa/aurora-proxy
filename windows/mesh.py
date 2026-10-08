# Aurora v1.4.0 — меш: ноды сети, invite-ссылка, пинги доступности.
# Хранение: data/mesh_nodes.json. Хаб = текущий сервер; внешние ноды добавляются
# из invite-ссылок других серверов Aurora (или вручную через UI).

import concurrent.futures
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
_POLICY_STARTED = False


INVITE_TTL_S = 300
MAX_INVITE_CHALLENGES = 1024
MAX_POLICY_BYTES = 64 * 1024
MAX_CATALOG_BYTES = 32 * 1024  # A-109: каталог цен и описаний от мастера
_CATALOG_FIELDS = ("catalog", "buy_url", "master_id")
_CATALOG_MARK = ""
_POLICY_MAX_NONCES = 256
_POLICY_NONCES = {}
_POLICY_NONCES_LOCK = threading.Lock()
_POLICY_FIELDS = ("policy_version", "master_id", "master", "show_mesh",
                  "show_subs", "issued_at", "expires_at", "nonce")
_INVITE_FIELDS = ("invite_version", "issuer", "token", "challenge", "host",
                  "port", "policy_port", "name", "issued_at", "expires_at")
INVITE_USED_FILE = os.path.join(config.DATA_DIR, "mesh_invite_used.json")


# --- A-265 (вариант Б): корень своей подсети ---------------------------------
# Публичная сборка НИКОГДА не бывает головным сервером меша: mesh_master жёстко
# False, политику мастера она только читает. Но корень своей подсети ей можно:
# приглашение подписывается ОТДЕЛЬНЫМ локальным ключом, а не мастерским ключом
# политики, поэтому такой invite не принимает настоящий мастер и не выдаёт узлу
# прав головного. Ключ и идентификатор лежат в data/mesh_local.json (0600).
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


def _is_master_build():
    """A-266: в клиентской сборке роли "master" нет (она есть только у
    мастера). Роль берём из env честно: пусто - узел, и приглашение выпускаем."""

    if str(os.environ.get("AURORA_MESH_MASTER", "") or "").strip():
        return True
    return str(os.environ.get("AURORA_ROLE", "") or "").strip().lower() == "master"


def _invite_expected_key(issuer):
    """Ключ подписи по домену: мастерский - для приглашений мастера, локальный - для своих."""
    issuer = str(issuer or "").strip().lower()
    if issuer:
        master_id = _policy_master_id()
        if master_id and issuer == master_id.strip().lower():
            return _policy_key()
        local_id, local_key = _local_issuer()
        if local_id and issuer == local_id:
            return local_key
    return ""


def _policy_key():
    try:
        key = str(config.mesh_policy_key() or "")
    except Exception:
        return ""
    return key if len(key.encode("utf-8")) >= 32 else ""


def _policy_master_id():
    try:
        value = str(config.mesh_master_id() or "")
    except Exception:
        return ""
    if not value or len(value) > 64:
        return ""
    for ch in value:
        if not (ch.isalnum() or ch in "._-"):
            return ""
    return value


def _canonical_bytes(core):
    return json.dumps(core, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _signed_bytes(core, fields):
    return _canonical_bytes({field: core.get(field) for field in fields})


def _hmac_hex(key, payload):
    return hmac.new(str(key).encode("utf-8"), payload, hashlib.sha256).hexdigest()


def _invite_bytes(core):
    return _signed_bytes(core, _INVITE_FIELDS)


def _invite_signature(core, key=None):
    secret = key or _policy_key()
    return _hmac_hex(secret, _invite_bytes(core)) if secret else ""


def _policy_signature(core, key=None):
    secret = key or _policy_key()
    if secret:
        return _hmac_hex(secret, _signed_bytes(core, _POLICY_FIELDS))
    return ""


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


def _policy_valid(value):
    """Проверяет подпись, срок и одноразовость политики головного сервера."""
    if not isinstance(value, dict):
        return None
    key = _policy_key()
    master_id = _policy_master_id()
    if not key or not master_id:
        return None
    version = value.get("policy_version")
    if isinstance(version, bool) or version != 1:
        return None
    if value.get("master_id") != master_id:
        return None
    if value.get("master") is not True:
        return None
    for flag in ("show_mesh", "show_subs"):
        if not isinstance(value.get(flag), bool):
            return None
    issued = value.get("issued_at")
    expires = value.get("expires_at")
    for stamp in (issued, expires):
        if isinstance(stamp, bool) or not isinstance(stamp, int):
            return None
    now = int(time.time())
    if expires <= issued or (expires - issued) > 300:
        return None
    if issued > now + 30 or expires <= now:
        return None
    nonce = value.get("nonce")
    if not _is_hex(nonce, 32):
        return None
    signature = value.get("signature")
    if not _is_hex(signature, 64):
        return None
    if not hmac.compare_digest(signature, _policy_signature(value, key)):
        return None
    with _POLICY_NONCES_LOCK:
        for known in [k for k, t in _POLICY_NONCES.items() if t <= now]:
            _POLICY_NONCES.pop(known, None)
        if nonce in _POLICY_NONCES:
            return None
        if len(_POLICY_NONCES) >= _POLICY_MAX_NONCES:
            return None
        _POLICY_NONCES[nonce] = now + (expires - now)
    return {"master": True, "master_id": master_id,
            "show_mesh": value.get("show_mesh"),
            "show_subs": value.get("show_subs")}


def _local_host():
    """Собственный адрес узла для объявления головному серверу."""
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
        # Служебные узлы релью быть не могут НИКОГДА (дорожная карта §5).
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
    """Записать или снять профиль внешнего VLESS узла (мастер шлёт, узел читает)."""
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
    """Приглашение для СВОЕЙ подсети (A-265).

    Публичная сборка не бывает головным: если вдруг mesh_master стал True,
    приглашение не выдаётся. Иначе подписывает его локальным ключом подсети -
    настоящий мастер такое приглашение не примет, и узел не получит прав головного.
    """
    if _is_master_build():
        return None
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
    if _is_master_build():
        return None
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
    Права головного не выдаются, политику мастера узел не получает.
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


def _host_port_from_url(url):
    """Парсит URL master_addr и возвращает scheme, host и port."""
    if not url:
        return None, None, None
    from urllib.parse import urlparse
    try:
        u = urlparse(url if "://" in url else "http://" + url)
        host = u.hostname
        port = u.port or (443 if u.scheme == "https" else 80)
    except (TypeError, ValueError):
        return None, None, None
    if u.scheme not in ("http", "https") or not host:
        return None, None, None
    return u.scheme, host, port


def _openers():
    """A-289: сначала напрямую, потом через собственный прокси Aurora.

    Mixed-инбаунд xray (http+socks) на 127.0.0.1:XRAY_PORT - единственный
    маршрут узла к мастеру, если прямой доступ закрыт (NAT, чужой провайдер).
    Без второй попытки узел вообще не может вступить в меш и не видит
    show_mesh/show_subs от головного сервера."""
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
    if not config.get("auto_join"):
        return
    scheme, host, port = _host_port_from_url(config.get("master_addr") or "")
    tok = (config.get("master_token") or "").strip()
    if not host or not port:
        config.log("mesh: auto_join включён, но master_addr не задан — пропуск")
        return
    role = "test" if config.get("master_only", False) else "node"
    # A-761: объявляем СВОЁ устойчивое имя. Раньше здесь всегда уходило
    # auto_name=True с пустым именем, и мастер при каждой регистрации выдавал
    # новое случайное («Тёплый-Кот/Пушистый-Кот»). ensure_unique_name() уже
    # отработал в run.py ДО старта этой нити, так что имя к этому моменту есть.
    own = str(config.get("server_name") or "").strip()[:40]
    if not own or own in ("Home", "-"):
        own = ensure_unique_name()
    payload = {
        "name": own,
        "auto_name": not bool(own),
        "role": role,
        "host": config.VM_HOST,
        "port": config.XRAY_PORT,
        "policy_port": config.UI_PORT,
        "region": "RU",
    }
    reg = None
    for attempt in range(3):
        reg = _fetch_post(scheme, host, port, "/api/mesh/node/add", payload,
                          headers={"X-Auth": tok} if tok else None)
        if not (reg and reg.get("ok")):
            payload.pop("auto_name", None)
            payload["token"] = tok
            reg = _fetch_post(scheme, host, port, "/api/mesh/register", payload)
        if reg and reg.get("ok"):
            break
        if attempt < 2:
            time.sleep(attempt + 1)
    if not (reg and reg.get("ok")):
        config.log("mesh: авто-вступление в меш головного %s:%s не удалось" % (
            host, port))
        return
    with _LOCK:
        present = any(n.get("host") == host and n.get("port") == port
                      for n in _NODES)
    if not present:
        node, err = add("Головной", "RU", host, port, role="hub",
                          policy_port=int(port))
        if err:
            config.log("mesh: авто-добавление головного не удалось: %s" % err)
            return
    node_info = reg.get("node") or {}
    cur = (config.get("server_name") or "").strip()
    if node_info.get("name") and cur in ("", "Home", "-"):
        config.set("server_name", node_info["name"])
    secret = reg.get("secret")
    if secret:
        config.set("mesh_own_secret", secret)
    config.log("mesh: авто-вступление в меш головного %s:%s OK (id=%s, "
               "name='%s', role=%s)" % (
        host, port, node_info.get("id") or reg.get("id") or "?",
        node_info.get("name") or config.get("server_name"), role))


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




# --- политика головного сервера (видимость меш/магазина у клиентов) ---
MESH_POLICY_MS = 15 * 1000  # интервал опроса узлом политики мастера


def policy():
    """Локальная политика клиента. master=True только у головного."""
    return {
        "ok": True,
        "master": False,
        "show_mesh": bool(config.get("show_mesh", False)),
        "show_subs": bool(config.get("show_subs", False)),
    }


def _policy_port(node):
    value = node.get("policy_port") or getattr(config, "UI_PORT", 0)
    return value if _valid_port(value) else None


def _fetch_policy(host, port, timeout=3.0):
    """Читает политику далёкого сервера. Возвращает dict или None."""
    if not _valid_peer_host(host) or not _valid_port(port):
        return None
    target = "[%s]" % host if ":" in host else host
    body = b""
    for opener in _openers():
        try:
            from urllib.request import Request
            request = Request("http://%s:%d/api/mesh/policy" % (target, port),
                              headers={"X-Aurora-Request": "1"})
            with opener.open(request, timeout=timeout) as response:
                body = response.read(MAX_POLICY_BYTES + 1)
        except Exception:
            continue
        break
    else:
        return None
    if len(body) > MAX_POLICY_BYTES:
        return None
    try:
        value = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _catalog_signature(catalog, buy_url, master_id, key=None):
    """Подпись каталога мастера: цены и описания защищены тем же ключом, что и политика."""
    secret = key or _policy_key()
    if not secret or not isinstance(catalog, dict):
        return ""
    body = _signed_bytes({"catalog": catalog, "buy_url": buy_url,
                          "master_id": master_id}, _CATALOG_FIELDS)
    return _hmac_hex(secret, body)


def _catalog_valid(value):
    """Каталог мастера: тарифы, прайс витрины и ссылка оплаты.
    Проверка идёт отдельно от политики, поэтому подписи флагов не ломаются."""
    if not isinstance(value, dict):
        return None
    catalog = value.get("catalog")
    if not isinstance(catalog, dict):
        return None
    key = _policy_key()
    master_id = _policy_master_id()
    if not key or not master_id or value.get("master_id") != master_id:
        return None
    buy_url = value.get("buy_url")
    if not isinstance(buy_url, str) or not buy_url.strip() or len(buy_url) > 200:
        return None
    signature = value.get("catalog_signature")
    if not _is_hex(signature, 64):
        return None
    if not hmac.compare_digest(signature,
                               _catalog_signature(catalog, buy_url, master_id, key)):
        return None
    plans = catalog.get("plans")
    extras = catalog.get("extras")
    if not isinstance(plans, dict) or not plans or len(plans) > 32:
        return None
    if not isinstance(extras, dict) or not extras or len(extras) > 32:
        return None
    return {"plans": plans, "extras": extras, "buy_url": buy_url.strip()}


def _policy_targets():
    """A-289: узлы-hub из своего списка плюс запасной AURORA_MESH_POLICY_ADDR
    (host:port панели головного). Без запасного свежий узел, у которого ещё
    нет записи hub, вообще не знает адреса головного и молча ждёт флагов."""
    targets = []
    try:
        for node in all_nodes():
            if node.get("id") != "hub" and node.get("role") != "hub":
                continue
            port = _policy_port(node)
            if port and node.get("host"):
                targets.append((str(node.get("host")), port))
    except Exception:
        pass
    value = str(os.environ.get("AURORA_MESH_POLICY_ADDR", "") or "").strip()
    if not value:
        try:
            value = str(config.get("mesh_policy_addr", "") or "").strip()
        except Exception:
            value = ""
    if value and "://" not in value:
        host, _, port_text = value.partition(":")
        host = host.strip()
        if host and _valid_peer_host(host):
            port = int(port_text) if port_text.strip().isdigit() else 0
            if not _valid_port(port):
                port = _policy_port({})
            if port:
                targets.append((host, port))
    return targets


def apply_policy_raw(raw, source=""):
    """A-291: единая точка применения политики мастера (HTTP или туннель).
    A-755: после успешной проверки подпись кладётся в кэш на диск (30 суток),
    поэтому сеть переживает мёртвого мастера, и ведётся время последней встречи
    с мастером для честной плашки в панели.

    Сначала строгая проверка подписи и master_id (_policy_valid), потом флаги
    show_mesh/show_subs, потом каталог. Всё fail-closed: невалидная политика
    не трогает настройки. source - только для честного лога.
    """
    where = source or "http"
    if not isinstance(raw, dict):
        config.log("mesh: политика (%s) отброшена: не объект" % where)
        return False
    core = _policy_valid(raw)
    if not core:
        config.log("mesh: политика (%s) отброшена: подпись не прошла проверку" % where)
        return False
    changed = False
    for key in ("show_mesh", "show_subs"):
        if core[key] != config.get(key):
            config.set(key, bool(core[key]))
            changed = True
    global _POLICY_SEEN_AT
    with _POLICY_CACHE_LOCK:
        _POLICY_SEEN_AT = time.time()
    _policy_cache_store(raw)
    if changed:
        config.log("mesh: применена политика мастера (%s)" % where)
    catalog = _catalog_valid(raw)
    if catalog:
        mark = "%s|%s|%s" % (
            sorted(catalog["plans"].keys()),
            sorted(catalog["extras"].keys()), catalog["buy_url"])
        if mark != _CATALOG_MARK:
            globals()["_CATALOG_MARK"] = mark
            if config.save_catalog(catalog["plans"], catalog["extras"],
                                   catalog.get("buy_url")):
                config.log("mesh: каталог мастера принят (тарифов %d, позиций %d)" % (
                    len(catalog["plans"]), len(catalog["extras"])))
    return True


POLICY_CACHE_FILE = os.path.join(config.DATA_DIR, "mesh_policy_cache.json")
POLICY_AUTONOMY_DAYS = 30
_POLICY_AUTONOMY_S = POLICY_AUTONOMY_DAYS * 86400
_POLICY_CACHE_LOCK = threading.RLock()
_POLICY_SEEN_AT = 0.0


def _policy_cache_schema(value):
    """Кэш: ровно проверенная подпись плюс время её получения."""
    if not isinstance(value, dict):
        return None
    received = value.get("received_at")
    if isinstance(received, bool) or not isinstance(received, (int, float)):
        return None
    if not 0 < float(received) <= time.time() + 60:
        return None
    policy = value.get("policy")
    if not isinstance(policy, dict):
        return None
    return {"received_at": float(received), "policy": policy}


def _policy_cache_load():
    """Читает кэш с диска. Молчание тут допустимо только вместе с честным логом
    вызывающего: файл может отсутствовать (первый запуск) — это не ошибка."""
    try:
        raw = json.load(open(POLICY_CACHE_FILE, "r", encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return _policy_cache_schema(raw)


def _policy_cache_store(policy):
    """Сохраняет ПРОВЕРЕННУЮ подпись. Ошибка записи не должна ломать применение:
    флаги уже применены, кэш — это про выживание при мёртвом мастере."""
    with _POLICY_CACHE_LOCK:
        payload = {"received_at": time.time(), "policy": policy}
        tmp = POLICY_CACHE_FILE + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=True)
            os.replace(tmp, POLICY_CACHE_FILE)
            return True
        except OSError as exc:
            config.log("mesh: кэш подписи не записан: %s" % exc)
            try:
                os.unlink(tmp)
            except OSError:
                pass
            return False


def policy_autonomy():
    """Честная сводка для панели: сколько живём на кэше и когда видели мастера.

    A-756: возраст берётся как max(время в памяти, время файла кэша). Иначе
    после перезапуска узла память пуста, _POLICY_SEEN_AT = 0, и панель писала
    «мастер не отвечает» с нуля — хотя кэш на диске свежий и сеть жива.

    Возвращает {"cached", "age_s", "autonomy_s", "master_seen_at"} — панель
    показывает «работаю на кэше, мастер не отвечает с 14:32», а не врёт.
    """
    now = time.time()
    with _POLICY_CACHE_LOCK:
        seen = float(_POLICY_SEEN_AT or 0.0)
    cached = _policy_cache_load()
    file_seen = float(cached["received_at"]) if cached else 0.0
    if file_seen > seen:
        seen = file_seen
    return {"cached": bool(cached),
            "age_s": int(max(0.0, now - seen)) if seen else -1,
            "autonomy_s": _POLICY_AUTONOMY_S,
            "master_seen_at": int(seen) if seen else 0}


def apply_cached_policy():
    """Поднимает флаги из кэша, когда мастер недоступен.

    Кэш переживает 30 суток и при этом НЕ пересекается со свежестью: подпись
    всё равно проверяется тем же _policy_valid(), то есть подделать кэш на
    диске нельзя — HMAC тот же ключ.
    """
    cached = _policy_cache_load()
    if not cached:
        return False
    age = time.time() - cached["received_at"]
    if age > _POLICY_AUTONOMY_S:
        config.log("mesh: кэш подписи старше %d суток (%d с) — игнорирую"
                   % (POLICY_AUTONOMY_DAYS, int(age)))
        return False
    # Повторная проверка подписи обязательна: файл на диске могли подменить.
    # _policy_valid откажет и по протухшему expires_at (это правильно: значит
    # мастер был жив недавно, но кэш мы всё равно храним), поэтому для
    # автономного режима проверяем подпись и master_id напрямую, а срок берём
    # свой — 30 суток с момента получения.
    policy = cached["policy"]
    master_id = _policy_master_id()
    key = _policy_key()
    if not key or not master_id or policy.get("master_id") != master_id:
        config.log("mesh: кэш подписи от чужого мастера — игнорирую")
        return False
    signature = policy.get("signature")
    if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-f]{64}", signature):
        config.log("mesh: в кэше нет корректной подписи — игнорирую")
        return False
    core = {field: policy.get(field) for field in _POLICY_FIELDS}
    if not hmac.compare_digest(signature, _policy_signature(core)):
        config.log("mesh: подпись в кэше не сходится — игнорирую")
        return False
    changed = False
    for flag in ("show_mesh", "show_subs"):
        value = policy.get(flag)
        if not isinstance(value, bool):
            config.log("mesh: в кэше флаг %s не bool — игнорирую кэш" % flag)
            return False
        if value != config.get(flag):
            config.set(flag, value)
            changed = True
    if changed:
        config.log("mesh: работаю на кэше подписи мастера (ей %d суток)"
                   % max(1, int(age // 86400)))
    return True


_POLICY_OFFLINE = False


def _policy_autonomy_toggle(offline):
    """A-756: переход между «живая политика» и «работаю на кэше», лог только на
    СМЕНУ состояния.

    Цикл живёт MESH_POLICY_MS (15 с) — четыре раза в минуту. Без троттлинга это
    240 одинаковых строк в час, и настоящие события снова вытесняются из журнала
    (та же грабля, что уже закрыта для игрового контура, ROADMAP §2.4).

    offline=True  — мастер не дал применимой политики: поднимаем флаги из кэша.
    offline=False — мастер ответил и политика принята: возвращаемся к живому режиму.

    Кэш применяется ТОЛЬКО когда мастер не дал применимой политики. Если мастер
    жив, но подпись не сошлась — это не «сеть жива», а «неизвестно что скачено»:
    неизвестное указание мы не исполняем и держим последнее подтверждённое
    состояние, а сам факт виден в логе apply_policy_raw.
    """
    global _POLICY_OFFLINE
    if bool(offline) == bool(_POLICY_OFFLINE):
        return _POLICY_OFFLINE
    _POLICY_OFFLINE = bool(offline)
    if _POLICY_OFFLINE:
        got = apply_cached_policy()
        info = policy_autonomy()
        if got:
            config.log("mesh: мастер не дал применимой политики — работаю на кэше "
                       "подписи (ей %d с, автономия %d суток)"
                       % (info["age_s"], POLICY_AUTONOMY_DAYS))
        else:
            config.log("mesh: мастер не дал применимой политики, применимого кэша "
                       "нет — флаги оставлены как есть")
    else:
        config.log("mesh: политика мастера получена, вышел из автономии")
    return _POLICY_OFFLINE


def _policy_loop():
    """Фоновый опрос мастера: узел применяет подписанные show_mesh/show_subs.

    A-756: при недоступном мастере поднимаем флаги из кэша — сеть живёт, когда
    мастер мёртв (пункт 3 ФУНДАМЕНТА).
    """
    while True:
        got = False
        try:
            for host, port in _policy_targets():
                if apply_policy_raw(_fetch_policy(host, port),
                                    "http %s:%d" % (host, port)):
                    got = True
                    break
        except Exception:
            got = False
        try:
            _policy_autonomy_toggle(not got)
        except Exception as exc:
            config.log("mesh: переход в автономию не удался: %s: %s"
                       % (type(exc).__name__, exc))
        time.sleep(MESH_POLICY_MS / 1000.0)


def start_policy_loop():
    global _POLICY_STARTED
    with _LOCK:
        if _POLICY_STARTED:
            return False
        _POLICY_STARTED = True
    threading.Thread(target=_policy_loop, daemon=True).start()
    return True


load()