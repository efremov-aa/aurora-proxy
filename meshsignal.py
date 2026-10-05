# -*- coding: utf-8 -*-
"""A-557: сигналинг для клиентов mesh (чат/голос): offer/answer/ICE между двумя узлами.

Контракт для наших клиентов (Windows/Android): узел кладёт SDP/ICE в ящик, пир забирает.
Ящик одноразовый и с TTL: сообщение, которое не забрали за TTL_S, исчезает.
Хранилище зашифровано AURORA2 (crypt.save_json), изоляция групп — по полю group.
"""
import os
import threading
import time
import uuid

import config

try:
    import crypt
except Exception:            # A-071: crypt импортируется на уровне модуля
    crypt = None

SIGNAL_KINDS = ("offer", "answer", "candidate")
MAX_PAYLOAD = 8192          # SDP с ICE-кандидатами укладывается с запасом
MAX_ID = 64
MAX_GROUP = 64
MAX_TOTAL = 512             # сообщений во всём ящике
TTL_S = 120.0               # не забрали за две минуты - сообщение мертво
RATE_WINDOW_S = 60.0
# A-557: частота равна вместимости ящика на пира. Иначе подрезка ящика стирает
# счётчик частоты и флуд проходит: лимит должен срабатывать раньше, чем подрезка.
MAX_BOX_PEER = 24           # сообщений на одного пира за окно частоты
RATE_MAX = MAX_BOX_PEER     # сообщений от узла к пиру за RATE_WINDOW_S
_ID_OK = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-")

_LOCK = threading.RLock()
_STORE_VERSION = 1
_SIGNAL_FILE = None


def store_path():
    """Путь ящика сигналов (ленивый, чтобы DATA_DIR успел определиться)."""
    global _SIGNAL_FILE
    if _SIGNAL_FILE is None:
        _SIGNAL_FILE = os.path.join(config.DATA_DIR, "mesh_signal.json")
    return _SIGNAL_FILE


def _valid_id(value):
    text = str(value or "").strip()
    if not text or len(text) > MAX_ID:
        return ""
    if any(ch not in _ID_OK for ch in text):
        return ""
    return text


def _valid_group(value):
    text = str(value or "").strip()
    if not text:
        return ""
    if len(text) > MAX_GROUP or any(ch not in _ID_OK for ch in text):
        return ""
    return text


def _valid_payload(value):
    if not isinstance(value, str):
        return None
    if not value or len(value) > MAX_PAYLOAD:
        return None
    for ch in value:
        if ord(ch) < 32 and ch not in "\r\n\t":
            return None
    return value


def _empty_box():
    return {"v": _STORE_VERSION, "msgs": []}


def load_box():
    """Читаем ящик. Любая проблема хранилища = пустой ящик (fail-closed)."""
    if crypt is None:
        return _empty_box()
    try:
        raw = crypt.load_json(store_path(), _empty_box())
    except Exception:
        return _empty_box()
    if not isinstance(raw, dict) or not isinstance(raw.get("msgs"), list):
        return _empty_box()
    box = raw
    box["v"] = _STORE_VERSION
    return box


def save_box(box):
    if crypt is None:
        return False
    try:
        crypt.save_json(store_path(), box)
        return True
    except Exception:
        return False


def _prune(msgs, now):
    """Выкидывает протухшее и подрезает по лимитам. Возвращает новый список."""
    fresh = [m for m in msgs
             if isinstance(m, dict) and (now - float(m.get("ts") or 0)) <= TTL_S]
    peers = {}
    for m in fresh:
        peers.setdefault(m.get("to"), []).append(m)
    for peer, rows in peers.items():
        if len(rows) > MAX_BOX_PEER:
            rows.sort(key=lambda r: float(r.get("ts") or 0))
            drop = set(id(r) for r in rows[:len(rows) - MAX_BOX_PEER])
            fresh = [r for r in fresh if id(r) not in drop]
    if len(fresh) > MAX_TOTAL:
        fresh.sort(key=lambda r: float(r.get("ts") or 0))
        fresh = fresh[-MAX_TOTAL:]
    return fresh


def put(src, dst, group, kind, payload, now=None):
    """Кладёт сообщение для пира. Возвращает (code, err, info)."""
    now = time.time() if now is None else float(now)
    src = _valid_id(src)
    dst = _valid_id(dst)
    if not src or not dst:
        return 400, "неверный узел", {}
    if src == dst:
        return 400, "нельзя писать самому себе", {}
    group = _valid_group(group)
    kind = str(kind or "").strip().lower()
    if kind not in SIGNAL_KINDS:
        return 400, "неверный kind", {}
    payload = _valid_payload(payload)
    if payload is None:
        return 400, "неверный payload", {}
    with _LOCK:
        box = load_box()
        raw = [m for m in (box.get("msgs") or []) if isinstance(m, dict)]
        # лимит частоты считаем по НЕПРОРЕЖЕННОМУ списку: иначе подрезка по лимиту
        # ящика обнуляла бы счётчик и пропускала бы флуд
        same_peer = [m for m in raw
                     if m.get("from") == src and m.get("to") == dst
                     and (now - float(m.get("ts") or 0)) <= RATE_WINDOW_S]
        if len(same_peer) >= RATE_MAX:
            box["msgs"] = _prune(raw, now)
            save_box(box)
            return 429, "слишком много сообщений этому пиру", {"retry_after": RATE_WINDOW_S}
        msgs = _prune(raw, now)
        row = {"id": uuid.uuid4().hex[:8], "from": src, "to": dst, "group": group,
               "kind": kind, "payload": payload, "ts": now}
        msgs.append(row)
        box["msgs"] = _prune(msgs, now)
        if not save_box(box):
            return 500, "не удалось сохранить сигнал", {}
        return 200, None, {"id": row["id"], "queued": len(box["msgs"])}


def take(dst, group, src=None, limit=32, now=None):
    """Забирает сообщения, адресованные узлу dst (одноразово). (code, err, body)"""
    now = time.time() if now is None else float(now)
    dst = _valid_id(dst)
    if not dst:
        return 400, "неверный узел", {}
    group = _valid_group(group)
    src = _valid_id(src)
    try:
        limit = max(1, min(64, int(limit)))
    except (TypeError, ValueError):
        limit = 32
    with _LOCK:
        box = load_box()
        msgs = _prune(box.get("msgs") or [], now)
        out = []
        rest = []
        for m in msgs:
            mine = (m.get("to") == dst
                    and (not src or m.get("from") == src)
                    and (not group or m.get("group") in ("", group)))
            # лимит ответа НЕ выбрасывает лишнее: остаток ждёт следующего забора
            if mine and len(out) < limit:
                out.append({"id": m.get("id"), "from": m.get("from"), "kind": m.get("kind"),
                            "payload": m.get("payload"), "ts": int(float(m.get("ts") or 0))})
            else:
                rest.append(m)
        out.sort(key=lambda r: r["ts"])
        box["msgs"] = rest
        save_box(box)
        return 200, None, {"messages": out, "left": len(rest)}


def stats(now=None):
    now = time.time() if now is None else float(now)
    with _LOCK:
        msgs = _prune(load_box().get("msgs") or [], now)
        return {"total": len(msgs),
                "peers": len(set(m.get("to") for m in msgs))}


def clear():
    with _LOCK:
        return save_box(_empty_box())
