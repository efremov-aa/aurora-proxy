# Aurora v1.4.0 — меш: ноды сети, invite-ссылка, пинги доступности.
# Хранение: data/mesh_nodes.json. Хаб = текущий сервер; внешние ноды добавляются
# из invite-ссылок других серверов Aurora (или вручную через UI).

import json
import os
import socket
import threading
import time
import uuid as _uuid

import config

MESH_FILE = os.path.join(config.DATA_DIR, "mesh_nodes.json")

_LOCK = threading.RLock()
_NODES = []


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


def load():
    """Загрузка data/mesh_nodes.json. Молчаливый фолбэк на пустой список."""
    global _NODES
    with _LOCK:
        try:
            with open(MESH_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            _NODES = data if isinstance(data, list) else []
        except (OSError, ValueError):
            _NODES = []


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
        _atomic_write(MESH_FILE, _NODES)


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


def add(name, region, host, port, role=None, auto_name=False):
    """Добавляет внешнюю ноду. Возвращает (node, error).

    auto_name=True или пустое имя — головной генерирует рандомное уникальное имя.
    Занятое имя (хаб/другие ноды) тоже уходит в авто-генерацию без ошибки.
    role=test — эксклюзивный узел: используется ТОЛЬКО головным сервером,
    при добавлении генерируется secret доверия, который отдаётся один раз.
    """
    raw_name = str(name or "").strip()
    if auto_name or not raw_name:
        raw_name = generate_name()
    region = str(region or "").strip() or "—"
    host = str(host or "").strip()
    role = str(role or "").strip() or "node"
    if role not in ("hub", "node", "test"):
        role = "node"
    try:
        port = int(port or 0)
    except (TypeError, ValueError):
        return None, "неверный порт"
    if not host or port <= 0 or port > 65535:
        return None, "host/port обязательны"
    with _LOCK:
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
        "added": int(time.time()),
    }
    if role == "test":
        import secrets
        node["secret"] = secrets.token_hex(16)
    with _LOCK:
        _NODES.append(node)
        _save()
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


def remove(node_id):
    """Удаляет внешнюю ноду по id. Возвращает True при удалении."""
    global _NODES
    with _LOCK:
        before = len(_NODES)
        _NODES = [n for n in _NODES if n.get("id") != node_id]
        if len(_NODES) != before:
            _save()
            config.log("mesh: удалён узел %s" % node_id)
            return True
    return False


def _tcp_ping(host, port, timeout=2.0):
    """Проверка TCP-доступности host:port. Возвращает bool."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False


def ping(host, port, timeout=2.0):
    """Замер доступности. Возвращает (ok, latency_ms)."""
    t0 = time.time()
    ok = _tcp_ping(host, port, timeout)
    ms = int((time.time() - t0) * 1000)
    return ok, ms


def ping_all(timeout=2.0):
    """Пинги всех нод (хаб + внешние). Возвращает список со статусом."""
    out = []
    for n in all_nodes():
        ok, ms = ping(n.get("host"), n.get("port"), timeout)
        out.append({
            "id": n.get("id"),
            "name": n.get("name"),
            "region": n.get("region"),
            "host": n.get("host"),
            "port": n.get("port"),
            "role": n.get("role"),
            "ok": ok,
            "ping_ms": ms,
        })
    return out


def _urlsafe(s):
    from urllib.parse import quote
    return quote(str(s or ""), safe="")


def _token():
    """Токен invite (генерируется при первом обращении)."""
    with _LOCK:
        tok = config.get("mesh_token", "")
        if not tok:
            import secrets
            tok = secrets.token_urlsafe(9)
            config.set("mesh_token", tok)
        return tok


def invite():
    """Invite-ссылка для подключения узлов в меш (роль hub у источника)."""
    host = config.VM_HOST
    name = _urlsafe(config.get("server_name") or "Home")
    return "aurora://invite?token=%s&host=%s&port=%d&name=%s&role=hub" % (
        _token(), host, config.UI_PORT, name)


def regenerate():
    """Перегенерирует invite-токен. Возвращает новую invite-ссылку."""
    import secrets
    config.set("mesh_token", secrets.token_urlsafe(9))
    return invite()


def parse_invite(url):
    """Парсит aurora://invite?token=... Возвращает dict или None."""
    if not url or "invite?" not in url:
        return None
    from urllib.parse import parse_qs, urlparse
    u = urlparse(url)
    q = parse_qs(u.query)
    if not q.get("token"):
        return None
    return {
        "token": (q.get("token") or [""])[0],
        "host": (q.get("host") or [""])[0],
        "port": int((q.get("port") or ["0"])[0] or 0),
        "name": (q.get("name") or [""])[0],
        "role": (q.get("role") or ["node"])[0],
    }


# --- v1.8.0: авто-имя сервера и авто-вступление в меш головного сервера ---

def ensure_unique_name():
    """Если имя сервера пусто/дефолтно/занято нодой меша — присваивает случайное уникальное.

    Возвращает итоговое имя."""
    taken = [n.get("name", "") for n in all_nodes()]
    cur = (config.get("server_name") or "").strip()
    low = [str(x).strip().lower() for x in taken]
    if cur and cur not in ("Home", "-") and cur.lower() not in low:
        return cur
    name = config.random_server_name(taken=low)
    config.set("server_name", name)
    config.log("mesh: серверу присвоено уникальное имя '%s'" % name)
    return name


def _host_port_from_url(url):
    """Парсит http://host:port → (host, port). Невалидный → (None, None)."""
    if not url:
        return None, None
    from urllib.parse import urlparse
    u = urlparse(url if "://" in url else "http://" + url)
    host = u.hostname
    port = u.port or (443 if u.scheme == "https" else 80)
    return host, port


def _fetch_post(host, port, path, data, timeout=5.0, headers=None):
    """POST JSON на http://host:port/path (опц. доп. заголовки). Возвращает dict или None."""
    try:
        from urllib.request import Request, urlopen
        body = json.dumps(data).encode("utf-8")
        hdr = {"Content-Type": "application/json"}
        if headers:
            hdr.update(headers)
        req = Request("http://%s:%s%s" % (host, port, path),
                      data=body, headers=hdr, method="POST")
        with urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception:
        return None


def auto_join():
    """Авто-вступление в меш головного сервера (config.auto_join + master_addr).

    Локально добавляет головного как hub-ноду (чтобы policy-цикл применял его
    флаги) и регистрирует этот сервер у головного. Сначала пробуется контракт
    домашнего эталона: POST /api/mesh/node/add {name:"", auto_name:true,
    role:test} с X-Auth: master_token (токен панели головного); при недоступности
    — fallback на /api/mesh/register GitHub-контракта."""
    if not config.get("auto_join"):
        return
    host, port = _host_port_from_url(config.get("master_addr") or "")
    tok = (config.get("master_token") or "").strip()
    if not host or not port:
        config.log("mesh: auto_join включён, но master_addr не задан — пропуск")
        return
    with _LOCK:
        for n in _NODES:
            if n.get("host") == host and n.get("port") == port:
                config.log("mesh: головной %s:%s уже в меше" % (host, port))
                return
        node, err = add("Головной", "RU", host, port, role="hub")
        if err:
            config.log("mesh: авто-добавление головного не удалось: %s" % err)
            return
    role = "test" if config.get("master_only", False) else "node"
    payload = {
        "name": "",                          # авто-имя даёт головной
        "auto_name": True,
        "role": role,
        "host": config.VM_HOST,
        "port": config.XRAY_PORT,
        "region": "RU",
    }
    reg = _fetch_post(host, port, "/api/mesh/node/add", payload,
                      headers={"X-Auth": tok} if tok else None)
    if not (reg and reg.get("ok")):
        # fallback: наш контракт (головной на GitHub-сборке)
        payload.pop("auto_name", None)
        payload["token"] = tok
        reg = _fetch_post(host, port, "/api/mesh/register", payload)
    if reg and reg.get("ok"):
        node_info = reg.get("node") or {}
        if node_info.get("name"):
            config.set("server_name", node_info["name"])
        secret = reg.get("secret")
        if secret:
            config.set("mesh_own_secret", secret)
        config.log("mesh: авто-вступление в меш головного %s:%s OK (id=%s, "
                   "name='%s', role=%s)" % (
            host, port, node_info.get("id") or reg.get("id") or "?",
            config.get("server_name"), role))
    else:
        config.log("mesh: авто-вступление в меш головного %s:%s не удалось" % (
            host, port))


# --- политика головного сервера (видимость меш/магазина у клиентов) ---
MESH_POLICY_MS = 15 * 1000  # интервал опроса узлом политики мастера


def policy():
    """Публичная политика сервера. master=True только у головного сервера."""
    return {
        "ok": True,
        "master": False,
        "show_mesh": config.get("show_mesh", True),
        "show_subs": config.get("show_subs", True),
    }


def _fetch_policy(host, port, timeout=3.0):
    """Читает политику далёкого сервера. Возвращает dict или None."""
    try:
        from urllib.request import urlopen
        url = "http://%s:%s/api/mesh/policy" % (host, port)
        with urlopen(url, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception:
        return None


def _policy_loop():
    """Фоновый опрос мастера: узел применяет show_mesh/show_subs мастера."""
    while True:
        try:
            nodes = [dict(n) for n in _NODES]
            for n in nodes:
                if n.get("id") == "hub" or n.get("role") == "hub":
                    j = _fetch_policy(n.get("host"), n.get("port"))
                    if j and j.get("master") is True:
                        changed = False
                        for key in ("show_mesh", "show_subs"):
                            if key in j and j[key] != config.get(key):
                                config.set(key, bool(j[key]))
                                changed = True
                        if changed:
                            config.log("mesh: применена политика мастера %s:%s" % (
                                n.get("host"), n.get("port")))
                        break
        except Exception:
            pass
        time.sleep(MESH_POLICY_MS / 1000.0)


# самодостаточный модуль: ноды загружаются при импорте
load()
threading.Thread(target=_policy_loop, daemon=True).start()