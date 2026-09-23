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


def all_nodes():
    """Хаб + внешние ноды (копии)."""
    with _LOCK:
        return [hub()] + [dict(n) for n in _NODES]


def node_count():
    """Всего нод (хаб + внешние)."""
    with _LOCK:
        return len(_NODES) + 1


def add(name, region, host, port, role=None):
    """Добавляет внешнюю ноду. Возвращает (node, error)."""
    name = str(name or "").strip() or "Узел"
    region = str(region or "").strip() or "—"
    host = str(host or "").strip()
    role = str(role or "").strip() or "node"
    if role not in ("hub", "node"):
        role = "node"
    try:
        port = int(port or 0)
    except (TypeError, ValueError):
        return None, "неверный порт"
    if not host or port <= 0 or port > 65535:
        return None, "host/port обязательны"
    node = {
        "id": _uuid.uuid4().hex[:4],
        "name": name[:40],
        "region": region[:20],
        "host": host,
        "port": port,
        "role": role,
        "added": int(time.time()),
    }
    with _LOCK:
        for n in _NODES:
            if n.get("host") == host and n.get("port") == port:
                return None, "узел уже есть"
        _NODES.append(node)
        _save()
    config.log("mesh: добавлен узел %s (%s:%d)" % (node["name"], host, port))
    return dict(node), None


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


# --- политика головного сервера (видимость меш/магазина у клиентов) ---
MESH_POLICY_MS = 15 * 1000  # интервал опроса узлом политики мастера


def policy():
    """Публичная политика сервера. master=True только у головного сервера."""
    return {
        "ok": True,
        "master": bool(config.get("mesh_master", False)),
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
    if config.get("mesh_master", False):
        return  # сам являюсь головным — политику не применяю
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