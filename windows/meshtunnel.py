# -*- coding: utf-8 -*-
"""Канал данных меша Aurora: защищённый relay внутри VLESS Reality.

Модуль даёт два режима:
  * узел (клиентская сборка) — локальный SOCKS5, который пересылает запрос
    на головной сервер через уже установленный VLESS-канал;
  * мастер (head) — приём соединения от узла, HMAC-аутентификация меш-секретом,
    локальный SOCKS5 на 127.0.0.1 для xray (цепочка freedom -> socks).

Транспорт: узел за серым IP/NAT сам инициирует соединение, поэтому мастер
не обязан быть публично видимым по UDP. Поверх VLESS Reality (TLS 1.3, реальный
SNI) идёт второй независимый слой: keystream BLAKE2b + HMAC-SHA256 на кадр,
nonce-антиреплей и фрагментация с padding.
"""

import errno
import hmac
import hashlib
import ipaddress
import json
import os
import re
import socket
import struct
import threading
import time

try:
    from . import config
except ImportError:
    import config

MESH_NET = str(os.environ.get("AURORA_MESH_NET", "10.254.0.0/16")
                 or "10.254.0.0/16").strip()
MESH_NET_OBJ = ipaddress.ip_network(MESH_NET, strict=False)
MESH_BASE = 0x0A400000 + 1

# A-766: порт туннеля из окружения. Мастер обязан слушать на порту, который УЖЕ
# проброшен на роутере (8444/8445) — проброса 51821 нет, и с жёсткой константой
# переехать туда было нечем. Ничего нового наружу не открываем.
# Читаем напрямую: _int_env() в этом файле определён ниже по модулю.
try:
    MESH_PORT = max(1, min(65535, int(
        str(os.environ.get("AURORA_MESH_PORT", "") or "51821").strip())))
except (TypeError, ValueError):
    MESH_PORT = 51821
HEARTBEAT_S = 25
PEER_TTL_S = 180
ANNOUNCE_S = 60
MAX_PEERS = 64
HANDSHAKE_TIMEOUT_S = 20
BUF = 65536
FRAG_MAX = 1200
FRAG_PAD_MIN = 0
FRAG_PAD_MAX = 512
REPLAY_WINDOW = 256

MAGIC = b"\xa7\xa1"
VER = 1

T_HELLO = 1
T_OK = 2
T_DATA = 3
T_PING = 4
T_PONG = 5
T_BYE = 6
T_FRAG = 7
# A-191 (variant B): multepleksirovanie - master prosit pira otkryt
# potok k celi i peredast trafik po etomu zhe sokety.
T_PIPE_OPEN = 8
T_PIPE_OK = 9
T_PIPE_ERR = 10
T_PIPE_DATA = 11
T_PIPE_BYE = 12
# A-291: политика головного сервера едет по туннелю (тот же 51821), поэтому
# узлу не нужен доступ к панели мастера. Без подписи клиент её не примет.
T_POLICY = 13
MAX_POLICY_PAYLOAD = 16384
# A-307: license of the node (PRO features) rides the same tunnel 51821 -
# the master UI port is closed outside, so HTTP there is impossible.
T_LICENSE = 14
MAX_LICENSE_PAYLOAD = 16384

_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")

_LOCK = threading.RLock()
_STATE = {"peers": {}, "secret": "", "node_id": "", "srv": None,
          "announce": 0, "last_error": "", "stop": 0,
          "up": {}}


def _int_env(name, default, low, high):
    try:
        value = int(str(os.environ.get(name, "") or default).strip())
    except (TypeError, ValueError):
        return default
    return max(low, min(high, value))

DIRECT_IDLE_S = _int_env("AURORA_MESH_DIRECT_IDLE", 300, 30, 3600)
DIRECT_INTERVAL_S = _int_env("AURORA_MESH_DIRECT_INTERVAL", 5, 1, 60)
DIRECT_RETRY_MAX_S = _int_env("AURORA_MESH_DIRECT_RETRY_MAX", 300, 30, 3600)
DIRECT_RETRY_MIN_S = _int_env("AURORA_MESH_DIRECT_RETRY_MIN", 15, 5, 600)
DIRECT_UDP_MAX = _int_env("AURORA_MESH_DIRECT_UDP_MAX", 1200, 576, 1400)
FLINKER_S = _int_env("AURORA_MESH_FLANKER", 10, 2, 300)
GAME_DIAG_PERIOD_S = _int_env("AURORA_MESH_DIAG_S", 300, 0, 86400)
GAME_GROUP = _int_env("AURORA_MESH_GROUP", 1, 1, 254)
GAME_MTU = _int_env("AURORA_MESH_GAME_MTU", 1500, 576, 9000)
MAX_RAW_PAYLOAD = 65535
MESH_DIAG_REASONS = (
    "bad-id", "bad-proof", "no-net-key", "not-master",
    "no-addr", "no-adder", "refused", "short-hello",
    # A-455: node-side view of the master's game-peer list
    "game-inbox",
    # A-453: master-side view of the game-peer list (diagnostics only)
    "game-announce",
    # A-459: why direct_publish() published nothing / what the master received
    # A-459
    "game-publish", "game-pub-recv",
    # A-395: parsed HELLO head, so an empty addr field is visible as-is
    "hello-parse",
)
MESH_DIAG_REJECTS = (
    "bad-id", "bad-proof", "no-net-key", "not-master",
    "no-addr", "no-adder", "refused", "short-hello",
)
REDIAL_S = _int_env("AURORA_MESH_REDIAL", 2, 1, 30)
RELAY_MAX = _int_env("AURORA_MESH_RELAY_MAX", MAX_RAW_PAYLOAD,
                      DIRECT_UDP_MAX, MAX_RAW_PAYLOAD)
T_DIRECT = 17
T_GAME_PEERS = 16
T_RAW = 15
_GAME_DIAG_LAST = {}
_GAME_DIAG_LOCK = threading.Lock()
_NO_GAME_IDS = ("aurora-home", "aurora-test", "master", "hub")


FRAG_SIZE = _int_env("AURORA_MESH_FRAG", FRAG_MAX, 256, 1400)
PAD_MAX = _int_env("AURORA_MESH_PAD", FRAG_PAD_MAX, 0, 4096)
HEARTBEAT = _int_env("AURORA_MESH_HEARTBEAT", HEARTBEAT_S, 5, 300)
TTL = _int_env("AURORA_MESH_PEER_TTL", PEER_TTL_S, 30, 3600)
ANNOUNCE = _int_env("AURORA_MESH_ANNOUNCE", ANNOUNCE_S, 10, 3600)
# A-191: limit odnovremennyh potokov v ODNOM soedinenii pira i
# pokoi, posle kotorogo masterskoe soedinenie pikaet (povtor).
MAX_STREAMS = _int_env("AURORA_MESH_MAX_STREAMS", 32, 1, 256)
PEER_IDLE_S = _int_env("AURORA_MESH_PEER_IDLE", 300, 30, 3600)


RTT_S = 30
RTT_INTERVAL = _int_env("AURORA_MESH_RTT_INTERVAL", RTT_S, 10, 600)
RTT_TTL = _int_env("AURORA_MESH_RTT_TTL", RTT_S * 2, 15, 900)
RTT_FAIL_TTL = _int_env("AURORA_MESH_RTT_FAIL_TTL", RTT_S * 2, 15, 900)


def enabled():
    try:
        return bool(config.get("mesh_tunnel", False))
    except Exception:
        return False


def node_address(node_id):
    node_id = str(node_id or "").strip()
    if not _ID_RE.match(node_id):
        return ""
    digest = hashlib.sha256(("aurora-mesh:" + node_id).encode("utf-8")).digest()
    # A-305: адрес обязан попадать в MESH_NET (10.254.0.0/16 (own mesh net)). Раньше тут был
    # MESH_BASE | (digest & 0x3FFFFF), а потом (value >> 16) & 0x3F - у MESH_BASE
    # (0x0A400001) это 0x0A40, и 0x0A40 & 0x3F == 0, поэтому второй окет всегда
    # был 0..63, а не 64..127: адреса выходили ВНЕ /10, и мастер честно отклонял
    # регистрацию узла (register_by_secret требует адрес из 10.254.0.0/16 (own mesh net)).
    # A-388: address is built from MESH_NET (our own range).
    raw = int.from_bytes(digest[:3], "big") & 0xFFFFFF
    base = int(MESH_NET_OBJ.network_address)
    size = int(MESH_NET_OBJ.num_addresses)
    return str(ipaddress.ip_address(base + 1 + (raw % (size - 1))))


def tunnel_name(node_id):
    node_id = str(node_id or "").strip()
    if not _ID_RE.match(node_id):
        return ""
    return "mesh-%s" % re.sub(r"[^A-Za-z0-9_-]", "-", node_id)


def _keybytes(value):
    """Ключ всегда bytes: hmac/blake2b не принимают str (найдено тестом A-108)."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if value is None:
        return b""
    return str(value).encode("utf-8")


def _stream(key, nonce, size):
    key = _keybytes(key)
    nonce = _keybytes(nonce)[:16]
    out = bytearray()
    counter = 0
    while len(out) < size:
        out += hashlib.blake2b(key, digest_size=64,
                               salt=nonce, person=b"aurora-mt-%d" % (counter % 256)).digest()
        counter += 1
    return bytes(out[:size])


def _mac(key, header, payload):
    return hmac.new(_keybytes(key), _keybytes(header) + _keybytes(payload),
                    hashlib.sha256).digest()[:8]


def _seen(nonce):
    with _LOCK:
        seen = _STATE.setdefault("seen", [])
        if nonce in seen:
            return False
        seen.append(nonce)
        del seen[:-REPLAY_WINDOW]
        return True


def _pack(msg_type, payload, key):
    key = _keybytes(key)
    payload = _keybytes(payload)
    nonce = os.urandom(4)
    length = len(payload)
    header = MAGIC + bytes([VER, msg_type]) + nonce + struct.pack("!I", length)
    stream = _stream(key, nonce, length)
    body = bytes(a ^ b for a, b in zip(payload, stream))
    return header + _mac(key, header, body) + body


def _unpack(buf, key=None):
    head = 12
    if len(buf) < head + 8:
        return None, None, buf
    if buf[0:2] != MAGIC or buf[2] != VER:
        return None, None, b""
    msg_type = buf[3]
    nonce = buf[4:8]
    length = struct.unpack("!I", buf[8:head])[0]
    if length > 4 * 1024 * 1024:
        return None, None, b""
    total = head + 8 + length
    if len(buf) < total:
        return None, None, buf
    body = buf[head + 8:total]
    key = _keybytes(key if key is not None else (_STATE.get("secret") or ""))
    if not hmac.compare_digest(_mac(key, buf[0:head], body), buf[head:head + 8]):
        return None, None, b""
    if not _seen(nonce):
        return None, None, buf[total:]
    stream = _stream(key, nonce, length)
    return msg_type, bytes(a ^ b for a, b in zip(body, stream)), buf[total:]


def _oversize(buf):
    """A-160: bufer ne dolzhen rasti nichem. Dve granicy:
    1) fakticheskiy razmer > BUF (A-158/A-159);
    2) OBYAVLENNAYA dlina kadra > BUF - ramka takaneet BUF ne snizhaetsya
       voobshche, poetomu zhdat ee smokyachno i opasno: pisatel zavis v sendall,
       chitatel - v recv (vzaimnaya blokirovka / DoS po pamyati).
    Rabin kak tolko zagolovok kadra izvesten - reshim srazu, ne skachivaya telo."""
    if len(buf) > BUF:
        return True
    if len(buf) < 12 or buf[0:2] != MAGIC:
        return False
    try:
        length = struct.unpack("!I", buf[8:12])[0]
    except struct.error:
        return False
    return 12 + 8 + int(length) > BUF


def _send(sock, msg_type, payload, key):
    sock.sendall(_pack(msg_type, payload, key))


def _fragment(payload):
    """Режет полезную нагрузку на фрагменты. Первые 4 байта потока хранят
    реальную длину, поэтому padding не портит данные у получателя."""
    payload = bytes(payload or b"")
    stream = struct.pack("!I", len(payload)) + payload
    size = FRAG_SIZE
    chunks = [stream[index:index + size] for index in range(0, len(stream), size)] or [stream]
    total = len(chunks)
    frames = []
    for index, chunk in enumerate(chunks):
        body = struct.pack("!HH", index, total) + chunk
        if index == total - 1:
            # Небольшая набивка в ПОСЛЕДНЕМ фрагменте, чтобы не было зазора
            # посередине потока (паттерн не читается DPI).
            pad = os.urandom(PAD_MAX) if PAD_MAX else b""
            body += pad
        frames.append(body)
    return frames

def _defrag(state, blob):
    """Собирает фрагменты по порядку. Счётчик хранится ОТДЕЛЬНО от кусков,
    иначе ключ 'total' попадает в карту и сборка ломается (KeyError)."""
    if not isinstance(blob, (bytes, bytearray)) or len(blob) < 4:
        return b""
    index, total = struct.unpack("!HH", blob[0:4])
    if total == 0 or index >= total:
        return b""
    store = state.get("frags")
    if not isinstance(store, dict) or state.get("total") != total:
        store = {}
        state["frags"] = store
        state["total"] = total
    store[index] = bytes(blob[4:])
    if len(store) < total:
        return b""
    try:
        data = b"".join(store[key] for key in range(total))
    except KeyError:
        return b""
    store.clear()
    state["total"] = 0
    if len(data) < 4:
        return b""
    # Первые 4 байта собранного потока - реальная длина полезной нагрузки.
    # Остальное (padding) отбрасываем, иначе получатель принял бы мусор.
    size = struct.unpack("!I", data[0:4])[0]
    if size > len(data) - 4:
        return b""
    return data[4:4 + size]


def _secret():
    with _LOCK:
        if _STATE.get("secret"):
            return _STATE["secret"]
    value = ""
    try:
        value = str(config.get("mesh_secret", "") or "")
    except Exception:
        value = ""
    if not value:
        value = str(os.environ.get("AURORA_MESH_SECRET", "") or "")
    if not value:
        try:
            import mesh
            value = str(mesh.node_secret() or "")
        except Exception:
            value = ""
    with _LOCK:
        _STATE["secret"] = value
    return value


def _self_policy_port():
    """A-296: port paneli uzla dlya golovnogo servera (pyatoe pole HELLO)."""
    try:
        return int(getattr(config, "UI_PORT", 0) or 0)
    except (TypeError, ValueError):
        return 0


_MASTER_ID_RE = re.compile(
    r"(?:[0-7][0-9A-HJKMNP-TV-Z]{25}"
    r"|[0-9a-fA-F]{32}"
    r"|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
    r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"|[0-9a-f]{4,8})"
)


def _strict_node_id(value):
    """A-305: golovnoy server v reestr beret tol'ko ULID / hex32 / UUID / hex4-8.

    Nashi starie imena ("mesh-aurora-home", "aurora-test-01") v etot spisok ne
    popadayut, i avtoregistraciya po obщemu sekretu seti zavershalas otkazom.
    Poetomu nevalidnoe imya deterministichesko prevoditsya v hex32 iz ego
    SHA-256: id uzla ostaetsya postoyannym (kak i ranshe), no stanet validnym
    dlya mesh._valid_node_id na golovnom servere.
    """
    text = str(value or "").strip()
    if not text:
        return ""
    if _MASTER_ID_RE.fullmatch(text):
        return text
    if not _ID_RE.match(text):
        return ""
    return hashlib.sha256(("aurora-mesh-id:" + text).encode("utf-8")).hexdigest()[:32]


def _node_id():
    with _LOCK:
        if _STATE.get("node_id"):
            return _STATE["node_id"]
    # A-447: явный AURORA_MESH_ID из окружения ВАЖНЕЕ дефолта из
    # settings.json - иначе два игровых узла получали один и тот же id, а
    # значит один и тот же игровой адрес 10.<группа>.<узел>.1.
    value = str(os.environ.get("AURORA_MESH_ID", "") or "").strip()
    if not value:
        try:
            value = str(config.get("mesh_id", "") or "")
        except Exception:
            value = ""
    # A-160/A-305: строгая валидация id обязательна и в клиентской сборке.
    value = _strict_node_id(value)
    if not value:
        value = "mesh-aurora-home"
    with _LOCK:
        _STATE["node_id"] = value


def _peer_secret(node_id):
    """Lichnyy sekret pira: svoy uzla ili iz mesh-registry."""
    if node_id == _node_id():
        value = _STATE.get("secret") or ""
        if value:
            return value
    try:
        import mesh
        return str(mesh.node_secret(node_id) or "")
    except Exception:
        return ""


def _expected_proof(secret, nonce, node_id):
    """Edinyy istochnik istiny dla proof: schitaet i klient, i master."""
    return hmac.new(_keybytes(secret),
                    b"aurora-mesh-hello" + _keybytes(nonce) + _keybytes(node_id),
                    hashlib.sha256).hexdigest().encode("ascii")


def _network_proof_ok(node_id, proof, nonce):
    """A-296: proof po OBSHCHEMU sekretu seti (AURORA_MESH_SECRET)."""
    secret = _secret()
    if not secret:
        _diag("no-net-key", node_id, "network secret is empty")
        return False
    ok = hmac.compare_digest(_expected_proof(secret, nonce, node_id),
                            _keybytes(proof))
    if not ok:
        _diag("no-net-key", node_id, "network proof mismatch")
    return ok


def _register_from_hello(node_id, host, port, policy_port=0):
    """A-296: avtoregistraciya uzla, prishedshego po obщему sekretu seti.

    Ranee neizvestnyj uzel molchal otrabыvalsya: lichnyj sekret est tolko v
    reestre, a reestr napolnyaetsya cherez /api/mesh/*, panel golovnogo
    servera snaruzhi zakryta - rukopozhatie v tunnele vsegda obrivalos.
    Teper uzel s korrektnym proof po AURORA_MESH_SECRET prinimaetsya i
    zanositsya v reestr (mesh.register_by_secret). Postoronnie bez sekreta
    otbrasyvayutsya kak i ranshe - fail-closed. Log vedet mesh.py."""
    if str(_STATE.get("started", "") or "") != "master":
        _diag("not-master", node_id, "started=%s" % str(_STATE.get("started", ""))[:16])
        return False
    if not host or not port:
        _diag("no-addr", node_id, "host=%s port=%s" % (str(host)[:32], port))
        return False
    try:
        import mesh
        adder = getattr(mesh, "register_by_secret", None)
        if not callable(adder):
            _diag("no-adder", node_id, "mesh.register_by_secret missing")
            return False
        ok = bool(adder(node_id, host, port, policy_port or None))
        if not ok:
            _diag("refused", node_id, "%s:%s policy_port=%s" % (
                str(host)[:40], port, policy_port))
        return ok
    except Exception as exc:
        _diag("no-adder", node_id, "register raised %s" % type(exc).__name__)
        return False


def _known(node_id, proof, nonce):
    if not _ID_RE.match(str(node_id or "").strip()) or not proof or not nonce:
        _diag("bad-id", node_id, "proof=%s nonce=%s" % (bool(proof), bool(nonce)))
        return False
    node = str(node_id).strip()
    secret = _peer_secret(node)
    if secret:
        ok = hmac.compare_digest(_expected_proof(secret, nonce, node),
                                  _keybytes(proof))
        if not ok:
            _diag("bad-proof", node, "personal secret mismatch")
        return ok
    # A-296: lichnogo sekreta v reestre eshche net (uzel pervyj raz).
    return _network_proof_ok(node, proof, nonce)


def status():
    """A-126: heartbeatov net i byt ne mozhet - sessiya odna i korotkaya,
    zhivost uzla opredelyaetsya dialom na kazhdyy zapros. Otdayom chestno."""
    with _LOCK:
        peers = _STATE.get("peers", {})
        now = time.time()
        fresh = [row for row in peers.values()
                 if now - row.get("seen", 0) < TTL]
        # A-398: ranee "peer_count" schital tolko svezhie po "seen", a piry s
        # ZHIVYM socketom no bez trafika (legalno molchashchie po A-191
        # variant B) v nego ne popadali => panel pokazyval "pirov 0" pri
        # zivom soedinenii. Teper tri schetchika, i kazhdyy chestnyy:
        #   peers_fresh    - viden nedavno (est trafik),
        #   peer_sessions  - zhivoy socket pira,
        #   peer_count     - oba sluchaya (uzel zhiv, esli zhiv lyuboy iz nikh).
        sessions = [row for row in peers.values()
                    if isinstance(row, dict) and row.get("sock") is not None]
        return {"enabled": enabled(), "node_id": _node_id(), "peers": sorted(peers),
                "peer_count": len(set(id(r) for r in fresh + sessions)),
                "peers_fresh": len(fresh), "peer_sessions": len(sessions),
                "liveness": "socket or fresh-seen",
                "sessions": int(_STATE.get("sessions", 0) or 0),
                "announce": int(_STATE.get("announce", 0) or 0),
                "announce_s": int(ANNOUNCE),
                "rtt": int(_STATE.get("rtt", 0) or 0),
                "rtt_interval": int(RTT_INTERVAL),
                "rtt_ttl": int(RTT_TTL),
                "pick": "rtt",
                "last_pick": dict(_STATE.get("last_pick", {}) or {}),
                "peer_rtt": dict((rid, int(rw.get("rtt_ms", 0) or 0))
                                 for rid, rw in peers.items()
                                 if _rtt_fresh(rw)),
                # A-429c: schyotchiki pingu/ponga po kazhdomu piru - pozvolyayut
                # otlichit "ping ne otvechaet" ot "RTT prosto ne izmeren".
                "peer_ping": dict(
                    (rid, [int(rw.get("ping_sent", 0) or 0),
                           int(rw.get("pong_seen", 0) or 0)])
                    for rid, rw in peers.items()),
                "last_error": str(_STATE.get("last_error", "") or ""),
                "last_reader_end": str(_STATE.get("last_reader_end", "") or ""),
                "net": MESH_NET, "frag": FRAG_SIZE, "pipes": _active_pipes(), "peer_conns": _live_conns(), "mode": "relay"}


def _peer(node_id, addr="", sock=None):
    """A-128: reestr pirov. A-191: teper ryad MOZHET derzhat postoyannoe
    soedinenie pira (sock) - master ne dialit pira, aProsit potok po nemu.
    Starye sokety ne lezhim v stroke: dva potoka na odnom sokete lomali
    parallelnye zaprosy."""
    with _LOCK:
        peers = _STATE.setdefault("peers", {})
        if len(peers) >= MAX_PEERS and node_id not in peers:
            return None
        row = peers.get(node_id)
        if row is None:
            row = {"node_id": node_id, "addr": "", "seen": 0.0, "rtt_ms": 0,
                   "sock": None, "streams": {}, "waiters": {},
                   "tx": threading.Lock(), "sid": 0,
                   # A-200: obratnyy tunnel (variant B) eshche ne nachalsya.
                   "b_used": False}
            peers[node_id] = row
        value = str(addr or "").strip()
        if value:
            row["addr"] = value[:120]
        if (sock is not None and row.get("sock") is not None
                and row.get("b_used")
                and row.get("sock") is not sock):
            # A-201: u pira UZHE est zhivoy obratnyy tunnel (b_used).
            # Odnorazovyy HELLO-announce starogo A1 ne dolzhen ego
            # podmenyat i zatyvat: soket odnorazovogo soedineniya srazu
            # umret, a master ostanetsya bez zhivogo kanala (SOCKS otkaz
            # 05 01), hotya tunnel realno zhiv.
            pass
        elif sock is not None and row.get("sock") is not sock:
            # A-197: staroe soedinenie NE zakryvaem i potoki/waitery NE chistim.
            # Inache vtoraya sessiya togo zhe uzla ubivaet pervuyu: parallelnye
            # zaprosy klienta idut cherez RAZNYE TCP-soedineniya odnoi
            # reestr zapisi, a v A1 kazhdoe soedinenie bylo odnorazovym.
            # Svoy reader sam zakroet svoy soket, kogda peer ottaynetsya.
            row["sock"] = sock
        elif sock is not None:
            row["sock"] = sock
        row["seen"] = time.time()
        return row


def _touch(node_id):
    """Obozhat "vidim" pira na vremya zhivoy sessii."""
    with _LOCK:
        row = _STATE.get("peers", {}).get(node_id)
        if row is not None:
            row["seen"] = time.time()
            return row
    return None


def _drop(node_id, why=""):
    """A-191: pIR otskazyvaetsya (soedinenie umerlo) - ryad i soedinenie
    udalyayutsya, a vse ozhidayushchie otkrytiya potokov poluchayut oshibku,
    chtoby master ne vis beskonechno."""
    with _LOCK:
        row = _STATE.get("peers", {}).pop(node_id, None)
    if row is None:
        return False
    stream = row.get("streams") or {}
    waiters = row.get("waiters") or {}
    row["streams"] = {}
    row["waiters"] = {}
    for waiter in waiters.values():
        waiter["ok"] = False
        waiter["error"] = why or "peer connection is gone"
        waiter["event"].set()
    for sid in list(stream):
        _close_stream(row, sid, why or "peer connection is gone")
    sock = row.get("sock")
    if sock is not None:
        try:
            sock.close()
        except OSError:
            pass
    return True


def _socks_read(sock):
    """Privet SOCKS5: VER + NMETHODS + METHODS -> otvet 05 00.

    A-139: ranee otveta na privet ne bylo voobshche, a NMETHODS smeshalsya s CMD
    (ver, cmd = head[0], head[1]) - obychnyy klient (privet -> zhdem 05 00 ->
    CONNECT) poluchal nichego i vysylal nam v tunnel musor. Chtenie tolko po
    _recv_exact: recv(1) mozhet vernut b"" (obryv) -> staraya versiya padala
    s IndexError na potoke."""
    head = _recv_exact(sock, 2)
    if len(head) < 2 or head[0] != 5:
        return None
    nmethods = head[1]
    methods = _recv_exact(sock, nmethods)
    if len(methods) < nmethods:
        return None
    try:
        if nmethods and 0 not in methods:
            sock.sendall(b"\x05\xff")
            return None
        sock.sendall(b"\x05\x00")
    except OSError:
        return None
    return head


def _socks_request(sock):
    if _socks_read(sock) is None:
        return None
    head = _recv_exact(sock, 4)
    if len(head) < 4 or head[0] != 5:
        return None
    cmd = head[1]
    if cmd != 1:
        try:
            sock.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        except OSError:
            pass
        return None
    atyp = head[3:4]
    if atyp == b"\x03":
        size_raw = _recv_exact(sock, 1)
        if not size_raw:
            return None
        raw = _recv_exact(sock, size_raw[0])
        if len(raw) < size_raw[0]:
            return None
        host = raw.decode("utf-8", "replace")
    elif atyp == b"\x01":
        raw = _recv_exact(sock, 4)
        if len(raw) < 4:
            return None
        host = socket.inet_ntoa(raw)
    else:
        sock.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
        return None
    raw = _recv_exact(sock, 2)
    if len(raw) < 2:
        return None
    return host, struct.unpack("!H", raw)[0]


def _forward(src, dst, key):
    """A-141: peredacha potoka MEZHDU UZLY. Obvezhno storony - kadrovoe
    soedinenie, poetomu nuzhno: _unpack -> _defrag (sobrat potok) -> _fragment
    -> _pack(T_FRAG) (snova upakovat). _pipe zdes byl nevern: on chital iz src
    syrye kadry i pakoval ih eshche raz - poluchatel videla 0xa7a1 vmesto
    dannyh. Raboet v otdelnom potoke vozvrashchaya True, inache False."""
    state = {}
    buf = b""
    while True:
        try:
            chunk = src.recv(65536)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        # A-158: oborona ot neogranichennogo buffera. Zagolovok kadra s
        # length=0xFFFFFFFF + medlennaya dokladka = bufer rastet do OOM.
        if _oversize(buf):
            return False
        while True:
            msg_type, payload, buf = _unpack(buf, key)
            if msg_type is None:
                break
            if msg_type == T_FRAG:
                data = _defrag(state, payload)
                if not data:
                    continue
                for body in _fragment(data):
                    try:
                        dst.sendall(_pack(T_FRAG, body, key))
                    except OSError:
                        return False
            elif msg_type == T_BYE:
                try:
                    _send(dst, T_BYE, b"", key)
                except OSError:
                    pass
                return True
    try:
        dst.shutdown(socket.SHUT_WR)
    except OSError:
        pass
    return True


def _socks5_open(sock, dest_host, dest_port):
    """A-168: SOCKS5 CONNECT cherez lokalnyi socks-inbound xray.

    Govorit tolko s xray, kotoryj zdes zhe na etoi zhe mashine, poetu cel
    vsegda 127.0.0.1 - nikogda ne podverzhdaem dst-adres iz vneshnego mira.
    """
    try:
        dest_ip = socket.inet_aton(dest_host)
    except OSError:
        raise OSError("A-168: dest host must be IPv4 literal")
    sock.sendall(b"\x05\x01\x00")
    if _recv_exact(sock, 2) != b"\x05\x00":
        raise OSError("A-168: socks5 greeting rejected")
    sock.sendall(b"\x05\x01\x00\x01" + dest_ip
                 + struct.pack("!H", int(dest_port)))
    reply = _recv_exact(sock, 4)
    if len(reply) != 4 or reply[0] != 0x05 or reply[1] != 0x00:
        raise OSError("A-168: socks5 connect refused")
    if reply[3] == 0x01:
        _recv_exact(sock, 4 + 2)
    elif reply[3] == 0x03:
        # A-169: LEN chitaem ROVNO odin raz. Bylo `_recv_exact(sock, 1)` +
        # vtoroe `_recv_exact(sock, 1)[0]` - pervyy bayt (sam LEN) glotalos,
        # dalee schitalsya sleduyushchiy bayt kak "dlina", i my libo visim na
        # timeout, libo chitaem chuzhie dannye.
        raw_len = _recv_exact(sock, 1)
        _recv_exact(sock, (raw_len[0] if raw_len else 0) + 2)
    else:
        _recv_exact(sock, 16 + 2)
    return sock


def _peer_dial_target(node_id):
    """A-168: (inbound_host, inbound_port, dest_host, dest_port).

    Pusto, esli lokalnyi xray ne podnyal socks-inbound dlya etogo pira.
    """
    try:
        import core
        peers = core._mesh_peers()
    except Exception:
        return (None, 0, "", 0)
    try:
        index = None
        for peer in peers or []:
            if str(peer.get("node_id") or "") == str(node_id or ""):
                index = peer.get("index")
                break
        if index is None:
            return (None, 0, "", 0)
        host, port = core._peer_dial_addr(node_id, index)
        dest_port = int(core._peer_dial_dest_port())
    except Exception:
        return (None, 0, "", 0)
    if not host or not port or not dest_port:
        return (None, 0, "", 0)
    return (host, int(port), "127.0.0.1", dest_port)


def _dial_via_socks(host, port, dest_host, dest_port):
    """A-168: soedinenie k piru cherez SOCKS5-inbound (REALITY-cepochka)."""
    sock = socket.create_connection((host, int(port)), HANDSHAKE_TIMEOUT_S)
    try:
        sock.settimeout(HANDSHAKE_TIMEOUT_S)
        _socks5_open(sock, dest_host, dest_port)
    except (OSError, ValueError):
        try:
            sock.close()
        except OSError:
            pass
        raise
    return sock


def _dial_via_http_proxy(host, port, dest_host, dest_port):
    """A-294: HTTP CONNECT through the local http-inbound of xray.

    The local inbound is protocol "http" and NOT "mixed", so a SOCKS5 greeting
    is rejected by xray ("malformed HTTP request") and the A-289 fallback could
    never work. CONNECT is the transport xray understands on that inbound, and
    the returned raw socket keeps working as the mesh tunnel.
    """
    sock = socket.create_connection((host, int(port)), HANDSHAKE_TIMEOUT_S)
    try:
        sock.settimeout(HANDSHAKE_TIMEOUT_S)
        target = "%s:%d" % (dest_host, int(dest_port))
        request = ("CONNECT %s HTTP/1.1\r\nHost: %s\r\n"
                   "User-Agent: aurora-mesh\r\n\r\n" % (target, target))
        sock.sendall(request.encode("ascii"))
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = sock.recv(256)
            if not chunk:
                raise OSError("proxy closed during CONNECT")
            head += chunk
            if len(head) > 4096:
                raise OSError("proxy CONNECT response too long")
        first = head.split(b"\r\n", 1)[0].decode("ascii", "replace")
        parts = first.split(" ")
        if len(parts) < 2 or parts[1] != "200":
            raise OSError("proxy CONNECT refused: %s" % first[:60])
    except (OSError, ValueError):
        try:
            sock.close()
        except OSError:
            pass
        raise
    return sock


def _recv_exact(sock, size):
    out = b""
    while len(out) < size:
        chunk = sock.recv(size - len(out))
        if not chunk:
            return b""
        out += chunk
    return out


def _pipe(a, b, key):
    """Dvunapravlennaya perekachka: iz a v b - syroe, iz b v a - T_FRAG."""
    threading.Thread(target=_pump, args=(a, b, key), daemon=True).start()
    _pump(b, a, key)


def _connect_out(sock, host, port, key):
    """Pir po komande mastera otkryvaet soedinenie k celi (relay-vyhod)."""
    try:
        target = socket.create_connection((host, int(port)), HANDSHAKE_TIMEOUT_S)
    except (OSError, ValueError):
        return False
    target.settimeout(None)
    # A-141/A-144: cel - CHISTYY potok, sock - kadrovoe uzlovoe soedinenie.
    #   cel  -> sock: _pump   (syroe -> T_FRAG)
    #   sock -> cel : _recv   (kadry -> syroe + reassembler), a NE _forward:
    #   _forward pakuet eshche raz i v cel shli syrye kadry 0xa7a1 vmesto
    #   dannyh (test: klient poluchil magnitudy, echo videlo prefiks 4 bayta).
    threading.Thread(target=_pump, args=(target, sock, key),
                     name="mesh-out-up", daemon=True).start()
    _recv(sock, target, key)
    return True


def _recv(sock_from_peer, out_sock, key):
    """out_sock ne None: master prinimaet trafik pira v lokalnyy SOCKS.
    out_sock None: A-135 - edinyy marshrut, delo `_relay` (inache zdes
    poluchalis dva potoka na odnom sokete - rovno oshibka A-128)."""
    if out_sock is None:
        return _relay(sock_from_peer, None, key)
    state = {}
    buf = b""
    while True:
        try:
            chunk = sock_from_peer.recv(65536)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        # A-158: tot zhe cht i v _forward - sm. kommentariy tam.
        if _oversize(buf):
            return
        while True:
            msg_type, payload, buf = _unpack(buf, key)
            if msg_type is None:
                break
            if msg_type == T_FRAG:
                data = _defrag(state, payload)
                if data and out_sock is not None:
                    try:
                        out_sock.sendall(data)
                    except OSError:
                        return
            elif msg_type == T_DATA:
                # A-135: T_DATA obrabatyvaet tolko _relay. Zdes lyuboy
                # otkrytyy cel byl by VTORIM chiteniem etogo zhe soketa.
                continue
            elif msg_type == T_PING:
                try:
                    _send(sock_from_peer, T_PONG, payload, key)
                except OSError:
                    return
            elif msg_type == T_BYE:
                if out_sock is not None:
                    try:
                        out_sock.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                return
    if out_sock is not None:
        try:
            out_sock.close()
        except OSError:
            pass


def _pump(sock_to_node, sink, key):
    while True:
        try:
            data = sock_to_node.recv(BUF)
        except OSError:
            break
        if not data:
            break
        try:
            for piece in _fragment(data):
                sink.sendall(_pack(T_FRAG, piece, key))
        except OSError:
            break
    try:
        sink.sendall(_pack(T_BYE, b"", key))
    except OSError:
        pass


def _parse_addr(value):
    """A-128: adres pira edet v HELLO; imenno po nemu master dialit zanovo."""
    text = str(value or "").strip()
    if not text or " " in text:
        return "", 0
    host, sep, port = text.rpartition(":")
    if not sep:
        # A-396: rpartition() puts the WHOLE string into the third element and
        # leaves the first one empty, so "return host" returned "" for every
        # address given without a port (AURORA_MESH_PUBLIC_ADDR=79.110.253.10).
        # The master then refused each HELLO with no-addr. Return the text.
        return text, MESH_PORT
    try:
        number = int(port)
    except ValueError:
        return "", 0
    if not host or not (0 < number < 65536):
        return "", 0
    return host, number


def _self_addr():
    """Adres, po kotoromu master dolzhen dialit etot uzel. Seti 100.64/10
    (WireGuide) bolshe net, poetomu nashodimyay adres zadaet operator cherez
    AURORA_MESH_PUBLIC_ADDR / config mesh_public_addr; inache soobshchaem
    adres uzla v mesh-seti (budet rabotat, kogda tunnel prisvoen emu)."""
    value = str(os.environ.get("AURORA_MESH_PUBLIC_ADDR", "") or "").strip()
    if not value:
        try:
            value = str(config.get("mesh_public_addr", "") or "").strip()
        except Exception:
            value = ""
    if not value:
        value = "%s:%d" % (node_address(_node_id()) or "127.0.0.1", MESH_PORT)
    return value[:120]


def _bind_addr():
    """A-185: adres, na kotorom slushayet tunnel. Po umolchaniyu - tolko
    loopback, kak i ranshe (naru zhe nikogda ne otkryvalsya). Esli vladelets
    zadast AURORA_MESH_BIND (naprimer, Tailscale-adres 100.x), master
    slushayet NA E TOM chastnomu adresu: piry dostugayut tonnell napryamuyu,
    a ne cherez 0.0.0.0. 0.0.0.0 beretsya tolko iz yavnogo zhelaniya
    vladeltsa (AURORA_MESH_BIND=0.0.0.0) - inache nikogda.
    Nicheso pokhodit na obshchuyu set - ne prinimaem."""
    value = str(os.environ.get("AURORA_MESH_BIND", "") or "").strip()
    if not value:
        try:
            value = str(config.get("mesh_bind", "") or "").strip()
        except Exception:
            value = ""
    if not value:
        return "127.0.0.1"
    if value == "0.0.0.0":
        return "0.0.0.0"
    try:
        import ipaddress

        parsed = ipaddress.ip_address(value)
    except Exception:
        return "127.0.0.1"
    if parsed.version != 4:
        # tolko IPv4: _listen() sozdast socket.AF_INET
        return "127.0.0.1"
    return str(parsed)


def _listen(port):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((_bind_addr(), port))
    listener.listen(16)
    return listener


# A-770: окно ожидания занятого порта. На старте aurora и xray поднимаются вместе,
# и кто первый занял порт — тот и выиграл. Раньше EADDRINUSE ронял поток
# молча: туннель просто не появлялся, и в панели это выглядело как «меш выключен».
# Теперь ждём освобождения и ЧЕСТНО пишем об этом в диагностику.
LISTEN_RETRY_S = 45
_LISTEN_WAIT_MAX = 5.0
# Занятый порт сообщается по-разному: Linux — EADDRINUSE, Windows — EACCES
# (WSAEACCES 10013). Оба означают одно и то же, и оба лечатся ожиданием.
_LISTEN_BUSY_ERRNOS = frozenset(
    x for x in (getattr(errno, "EADDRINUSE", None),
                getattr(errno, "EACCES", None)) if x is not None)


def _listen_wait(port):
    """_listen с ожиданием занятого порта. Не-«занят» пробрасывает как есть."""
    deadline = time.time() + LISTEN_RETRY_S
    delay = 1.0
    waited = False
    while True:
        try:
            listener = _listen(port)
        except OSError as exc:
            if getattr(exc, "errno", None) not in _LISTEN_BUSY_ERRNOS:
                _note("listen-fail", "port %d: %s" % (port, exc.__class__.__name__),
                      level="error")
                raise
            if time.time() >= deadline:
                _note("listen-busy", "порт %d занят дольше %d с, туннель не поднят"
                      % (port, LISTEN_RETRY_S), level="error")
                raise
            if not waited:
                waited = True
                _note("listen-wait", "порт %d занят другим сервисом, ждём освобождения"
                      % port)
            time.sleep(delay)
            delay = min(delay * 1.5, _LISTEN_WAIT_MAX)
            continue
        if waited:
            _note("listen-ok", "порт %d освобождён, туннель поднят" % port)
        return listener


def _accept_loop(listener, handler):
    while True:
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        handler(conn)


def _serve_dispatch(conn, key, peer_id, master):
    """A-117/A-128: odin slushatel - dva tipa klientov po PERVOMU baytu.
    0x05 = lokalnyy SOCKS5-zapros ot xray, 0xa7 = MAGIC = HELLO drugogo uzla."""
    try:
        conn.settimeout(HANDSHAKE_TIMEOUT_S)
        head = conn.recv(1, socket.MSG_PEEK)
    except OSError:
        head = b""
    if not head:
        try:
            conn.close()
        except OSError:
            pass
        return
    if head[0] == 0x05:
        handler = _socks_session if master else _client_session
        args = (conn, key) if master else (conn, key, peer_id)
    elif head[0] == MAGIC[0]:
        handler = _peer_session
        args = (conn, key)
    else:
        try:
            conn.close()
        except OSError:
            pass
        return
    threading.Thread(target=handler, args=args, daemon=True).start()


def _master_proxy_port():
    """A-439 + A-289 (ported): port mixed-inbounda xray etogo uzla. Cherez
    nego mozhno dostuchatsya do mastera, dazhe esli pryamoy marshrut zakryt
    (NAT, chuzhoy provayder)."""
    # A-450: yavno zadannyy v okruzhenii port proksi VAZHNEE konstanty
    # config.XRAY_PORT. Uzlu, u kotorogo sobstvennyy xray slushaet ne na
    # XRAY_PORT (n-primer, testovyy most slushaet 50541, a config dlya etogo
    # uzla soobshchaet 8899), connect uhodil v pustotu i padal na pryamoy
    # socket.create_connection, kotoryy u mastera slushaet tolko loopback.
    # Teper port mozhno zadat yavno: AURORA_MESH_PROXY_PORT, zatem
    # AURORA_XRAY_PORT, i tolako potom - sobstvennyy xray uzla.
    for var in ("AURORA_MESH_PROXY_PORT", "AURORA_XRAY_PORT"):
        raw = str(os.environ.get(var, "") or "").strip()
        if not raw:
            continue
        try:
            port = int(raw)
        except (TypeError, ValueError):
            continue
        if 0 < port < 65536:
            return port
    try:
        port = int(getattr(config, "XRAY_PORT", 0) or 0)
    except (TypeError, ValueError):
        return 0
    return port if 0 < port < 65536 else 0


def _connect_master():
    """A-289: соединение с мастером - сначала напрямую, потом через собственный
    прокси Aurora. Раньше был только прямой коннект, поэтому узел без маршрута
    к адресу мастера не вступал в меш и не видел show_mesh/show_subs."""
    host, port = _master_addr()
    if host not in ("127.0.0.1", "::1", "localhost"):
        try:
            return socket.create_connection((host, port),
                                            timeout=HANDSHAKE_TIMEOUT_S)
        except OSError:
            pass
        proxy_port = _master_proxy_port()
        if proxy_port:
            # A-294: CONNECT first (http-inbound understands CONNECT), SOCKS5 as
            # a second chance for a mixed/socks-only inbound.
            for dial in (_dial_via_http_proxy, _dial_via_socks):
                try:
                    return dial("127.0.0.1", proxy_port, host, port)
                except (OSError, ValueError):
                    continue
    return socket.create_connection((host, port), timeout=HANDSHAKE_TIMEOUT_S)


def _announce_loop(key):
    """A-147: periodicheskiy anons sebya masteru (registraciya pira).
    A-191 (variant B): posle T_OK soket NE zakryvaem - po nemu master
    otkryvaet potoki, a my ih obsluzhivaem (_peer_pump). Peredacha inache
    trebovala by, chtoby master dostichal 8443 pira (NAT)."""
    backoff = 0
    up_since = None
    while True:
        sock = None
        handed = False
        try:
            # A-439: snachala napryamuyu, potom cherez sobstvennyy
            # proksi Aurora (public sborka: _connect_master).
            sock = _connect_master()
            sock.settimeout(HANDSHAKE_TIMEOUT_S)
            _nonce, payload = _hello_frame(_node_id(), _secret(),
                                           _self_addr(), key)
            _send(sock, T_HELLO, payload, key)
            if not _wait_ok(sock, key):
                raise OSError("master did not confirm the announcement")
            _STATE["last_error"] = ""
            _STATE["up"] = {"sock": sock, "at": time.time()}
            pump = threading.Thread(target=_peer_pump, args=(sock, key),
                                    name="mesh-up", daemon=True)
            pump.start()
            handed = True
            up_since = time.time()
            sock = None
            while not _STATE.get("stop") and pump.is_alive():
                time.sleep(0.5)
        except Exception as exc:
            _STATE["last_error"] = "announce: %s" % (exc.__class__.__name__,)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            _STATE["up"] = {}
        if _STATE.get("stop"):
            return
        if handed:
            # A-426: healthy link - just wait for it to drop.
            # A-726: no more blind 60 s wait here. It is NOT an announce period
            # (the loop above only exits when the pump died), it was pure dead
            # time before we re-dialled. After an xray restart on the master that
            # is a full minute of dropped game traffic plus a window where the
            # master counts writes to a dead socket as `sent`.
            # Long-lived link => the master restarted, not a refusal => fast
            # re-dial. Short-lived link => master is flapping/refusing => keep
            # the A-426 exponential backoff so we never hammer it.
            if up_since is not None and (time.time() - up_since) >= FLINKER_S:
                backoff = 0
                time.sleep(REDIAL_S)
            else:
                backoff = min(backoff + 1, 6)
                time.sleep(min(60, 2 ** backoff))
        else:
            # A-426: broken handoff used to retry every second and hammer a
            # flickering master. Exponential backoff instead: 2, 4, 8 ... 60s.
            backoff = min(backoff + 1, 6)
            time.sleep(min(60, 2 ** backoff))


def _publish_profile():
    """A-163: my own VLESS client params -> my mesh node record.

    The master needs them to build a vless outbound and dial our tunnel
    port through xray, so a peer behind NAT stays reachable (variant A1).
    Values never go to the log."""
    try:
        import mesh as _mesh
        vln = getattr(config, "VLESS_PUBLIC", {}) or {}
        if not vln.get("enabled") or not vln.get("uuid"):
            return False
        block = {"uuid": vln["uuid"],
                 "pbk": vln.get("public_key", ""),
                 "short_id": vln.get("short_id") or "",
                 "sni": vln.get("sni") or vln.get("host", ""),
                 "host": vln.get("host", ""),
                 "port": int(vln.get("port", 8443))}
        return bool(_mesh.set_vless_client(_node_id(), block))
    except Exception:
        return False


def _client_serve():
    key = _secret()
    peer_id = _node_id()
    listener = _listen_wait(MESH_PORT)
    _STATE["srv"] = listener
    with _LOCK:
        first = not _STATE.get("announce")
        if first:
            _STATE["announce"] = 1
    if first:
        threading.Thread(target=_announce_loop, args=(key,),
                         name="mesh-announce", daemon=True).start()
    _publish_profile()
    _accept_loop(listener, lambda conn: _serve_dispatch(conn, key, peer_id, False))


def _server_serve():
    key = _secret()
    listener = _listen_wait(MESH_PORT)
    _STATE["srv"] = listener
    with _LOCK:
        first_rtt = not _STATE.get("rtt")
        if first_rtt:
            _STATE["rtt"] = 1
    if first_rtt:
        threading.Thread(target=_rtt_loop, name="mesh-rtt",
                         daemon=True).start()
    _accept_loop(listener, lambda conn: _serve_dispatch(conn, key, _node_id(), True))


def _master_addr():
    """Adres tunnelya mastera. Ranee stoial config.VM_HOST:config.UI_PORT - eto
    PORT PANELI Aurora, protokolnoy nesovpad; i VM_HOST klienta = ego IP."""
    value = str(os.environ.get("AURORA_MESH_MASTER_ADDR", "") or "").strip()
    if not value:
        try:
            value = str(config.get("mesh_master_addr", "") or "").strip()
        except Exception:
            value = ""
    host, port = _parse_addr(value)
    return (host or "127.0.0.1"), (port or MESH_PORT)


def _license_identity():
    """A-307: token/credential of this node, taken from the ext-gate module.

    Empty when the build is not licensed - the master then answers fail-closed.
    """
    try:
        import extgate
        token, credential = extgate.identity()
    except Exception:
        return "", ""
    return str(token or "").strip()[:128], str(credential or "").strip()[:256]


def _apply_tunnel_license(payload):
    """A-307: license from the tunnel goes through the ext-gate path as is."""
    if not payload or len(payload) > MAX_LICENSE_PAYLOAD:
        return False
    try:
        raw = json.loads(bytes(payload).decode("utf-8", "replace"))
    except Exception:
        return False
    if not isinstance(raw, dict):
        return False
    try:
        import extgate
        return bool(extgate.apply_tunnel_license(raw))
    except Exception:
        return False


def _hello_frame(node_id, secret, addr, key):
    """Edinyy format HELLO: node_id|proof|nonce|addr (adres optsionalny)."""
    # A-137: nonce idet cherez tekstovyj kadr "node_id|proof|nonce|addr",
    # poetomu tolko hex-ascii. Syrye 16 bayt lomali proof na ~99.9997% ranzov
    # (master chitaet payload kak utf-8) i ryadom na bayte 0x7C ("|").
    nonce = os.urandom(16).hex().encode("ascii")
    proof = _expected_proof(secret, nonce, node_id)
    # A-296: pyatoe pole - port paneli uzla (policy_port), chtoby golovnoj
    # server ne pridumyval ego. Staryj master ego prosto ignoriruet.
    # A-307: shestoe i pyatoe pole - token/credential licenzii PRO-fitur.
    # Kadr uzh zashishchjon obshchim sekretom seti (keystream + MAC), a
    # master otvechaet tem zhe kadrom, no s resheniem o licenzii.
    lic_token, lic_cred = _license_identity()
    payload = (_keybytes(node_id) + b"|" + proof + b"|" + nonce + b"|"
               + _keybytes(addr) + b"|" + _keybytes(str(_self_policy_port()))
               + b"|" + _keybytes(lic_token) + b"|" + _keybytes(lic_cred))
    return nonce, payload


def _send_policy(conn, key):
    """A-291: мастер кладёт подписанную политику прямо в туннель.

    Узлу не нужен доступ к панели головного сервера: политика приходит по
    тому же 51821, который уже поднят. Без роли master, без mesh.policy()
    или без подписи молча ничего не шлём - клиент всё равно применит только
    валидную политику (см. mesh.apply_policy_raw).
    """
    if _STATE.get("started") != "master":
        return False
    try:
        import mesh
        raw = mesh.policy()
    except Exception:
        return False
    if not isinstance(raw, dict) or not raw.get("signature"):
        return False
    body = json.dumps(raw, ensure_ascii=True).encode("utf-8")
    if len(body) > MAX_POLICY_PAYLOAD:
        return False
    _send(conn, T_POLICY, body, key)
    return True


def _apply_tunnel_policy(payload):
    """A-291: приём политики из туннеля: только разбор и передача в mesh.

    A-755: широкий `except Exception: return False` был причиной молчаливой
    потери политики — отсутствие apply_policy_raw() в mesh.py выглядело как
    «мастер не прислал», и по диагностике это не отличить. Теперь отказ виден.

    ЛОГ ЗДЕСЬ ЗАПРЕЩЁН ПО КОНТРАКТУ: в модуле циркулирует AURORA_MESH_SECRET,
    config не импортируется (проверяет test_a160_relay_tunnel). Поэтому отказ
    пишется в last_error — по A-202 это «честная диагностика, панель покажет
    ошибку там, где всё в порядке», а не отдельный канал логирования.
    """
    if not payload or len(payload) > MAX_POLICY_PAYLOAD:
        return False
    try:
        raw = json.loads(bytes(payload).decode("utf-8", "replace"))
    except Exception:
        return False
    if not isinstance(raw, dict):
        return False
    try:
        import mesh
    except Exception as exc:
        _STATE["last_error"] = "policy-tunnel: mesh import %s" % exc.__class__.__name__
        return False
    receiver = getattr(mesh, "apply_policy_raw", None)
    if not callable(receiver):
        _STATE["last_error"] = "policy-tunnel: apply_policy_raw отсутствует"
        return False
    try:
        return bool(receiver(raw, "tunnel"))
    except Exception as exc:
        _STATE["last_error"] = "policy-tunnel: %s" % exc.__class__.__name__
        return False


def _wait_ok(sock, key):
    """Zhdem T_OK ot mastera, inache fail-closed (A-116).
    A-156: nedostatochno dannuh v kadre - etNe OTKAZ, a RAZRYV: nado
    dobrat ostatok. Otkazyvali tolko pustoi bufer/konec потока/musor
    svyshe BUF bайт (fail-closed, pamyat ne techet)."""
    buf = b""
    while True:
        if buf:
            msg_type, _payload, buf = _unpack(buf, key)
            if msg_type == T_OK:
                return True
            if msg_type == T_POLICY:
                # A-291: политика головного приходит по туннелю, а не по HTTP
                _apply_tunnel_policy(_payload)
                continue
            if msg_type == T_LICENSE:
                # A-307: license of the node rides the same tunnel (HTTP to
                # the master UI port is closed outside).
                _apply_tunnel_license(_payload)
                continue
            if msg_type is not None:
                # A-157: drugoy tip kadra (T_HELLO/T_PING/...) - prosto ignorim,
                # ostatok uzhe lezhit v buf. Ranee my shli v recv i poteryali
                # sleduyushhiy T_OK iz etogo zhe paketa - rukopozhatie loyalos.
                continue
            if not buf:
                # A-157: kadr otvergnut _unpack (mushor/NEGILNYY KLICH/MAC),
                # ostatka net - fail-closed srazu, inache bufer "ochishchalsya"
                # i my chitali by sleduyushchiy kusok do beskonechnosti.
                return False
        try:
            chunk = sock.recv(65536)
        except OSError:
            return False
        if not chunk:
            return False
        buf += chunk
        if _oversize(buf):
            return False


def _client_session(conn, key, peer_id):
    # 1) Lokalnyy SOCKS5-zapros ot xray SRAZU: bez razbora v tunnel ushel by
    #    musor, a master poluchil by ne-CHISTYY trafik.
    conn.settimeout(HANDSHAKE_TIMEOUT_S)
    target = _socks_request(conn)
    if target is None:
        conn.close()
        return
    host, port = target
    upstream = None
    try:
        # A-439: kak i v _announce_loop - cherez proksi, a ne napryamuyu.
        upstream = _connect_master()
    except OSError:
        conn.close()
        return
    upstream.settimeout(None)
    _nonce, hello = _hello_frame(peer_id, _peer_secret(peer_id) or key, _self_addr(), key)
    _send(upstream, T_HELLO, hello, key)
    if not _wait_ok(upstream, key):
        conn.close()
        upstream.close()
        return
    conn.settimeout(None)
    # 2) Prosim mastera soedinit sya s celyu, otvechaem lokalnomu SOCKS-klientu.
    try:
        conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        _send(upstream, T_DATA, ("%s:%d" % (host, port)).encode("utf-8"), key)
    except OSError:
        conn.close()
        upstream.close()
        return
    # 3) A-140: napravleniya ASIMETRICHNY. S lokalnym xray govorim chistym
    #    potokom, s masterom - kadromi T_FRAG. _pipe pakuet OBE storony, poetomu
    #    klient otdaval xray syrye kadry (a7 a1 01 07 ...) vmesto dannyh, a
    #    ranee _recv(upstream, None, key) voobshche nichego ne pisal v SOCKS
    #    (T_FRAG pri out_sock=None otbrasyvalsya) i sam otkryval cel.
    #    Teper: xray -> master eto _pump (syroe -> kadry),
    #           master -> xray eto _recv (kadry -> syroe, s reassemblerom).
    threading.Thread(target=_pump, args=(conn, upstream, key),
                     name="mesh-cli-out", daemon=True).start()
    _recv(upstream, conn, key)
    conn.close()
    upstream.close()


def _dial_peer(row, key):
    """A-128/A-129: master sam iniciruet sootedenie s peerom. Odno
    soedinenie - odin zapros, poetomu sokety v reestre ne khranim."""
    node_id = str(row.get("node_id") or "")
    # A-168: esli lokalnyi xray podnyal socks-inbound pira - idem cherez nego
    # (REALITY-cepochka), inache pryamoy dial po announced adresu.
    in_host, in_port, dest_host, dest_port = _peer_dial_target(node_id)
    if in_host and in_port:
        sock = _dial_via_socks(in_host, in_port, dest_host, dest_port)
    else:
        host, port = _parse_addr(row.get("addr"))
        if not host:
            raise OSError("peer address is not reachable")
        sock = socket.create_connection((host, port), HANDSHAKE_TIMEOUT_S)
    sock.settimeout(HANDSHAKE_TIMEOUT_S)
    try:
        secret = _peer_secret(node_id) or key
        _nonce, hello = _hello_frame(node_id, secret, _self_addr(), key)
        _send(sock, T_HELLO, hello, key)
        if not _wait_ok(sock, key):
            raise OSError("peer did not answer")
    except (OSError, ValueError):
        try:
            sock.close()
        except OSError:
            pass
        raise
    sock.settimeout(None)
    return sock


def _streams(row):
    """A-191: potoki odnogo soedineniya pira."""
    if not isinstance(row, dict):
        return {}
    value = row.get("streams")
    if not isinstance(value, dict):
        value = {}
        row["streams"] = value
    return value


def _live_conns():
    with _LOCK:
        peers = _STATE.get("peers", {})
        return len([row for row in peers.values()
                    if isinstance(row, dict) and row.get("sock") is not None])


def peer_info():
    """A-397: sostoianie kazhdogo pira dlya paneli i /api/nodes.

    Dial po adresu iz HELLO - edinyy istochnik zhistoty po A-388, no u uzla
    port 51821 slushaet TOLKO loopback, poetomu pryamoy dial v ego adres
    nikogda ne proydet, poka sessiya tunnelya zhiva. Zdes my otdayom CHESTNOE:
    zhivoy li soket pira i svek li ego "seen". Sekretov zdes net."""
    now = time.time()
    out = {}
    with _LOCK:
        peers = _STATE.get("peers", {})
        for rid, row in peers.items():
            if not isinstance(row, dict):
                continue
            try:
                seen = float(row.get("seen", 0) or 0)
            except (TypeError, ValueError):
                seen = 0.0
            age = int(now - seen) if seen else -1
            out[str(rid)] = {
                "sock": row.get("sock") is not None,
                "age": age if age >= 0 else -1,
                "fresh": bool(seen and now - seen < TTL),
                "streams": len(_streams(row)),
                "rtt_ms": int(row.get("rtt_ms", 0) or 0),
                "addr": str(row.get("addr", "") or "")[:64],
            }
    return out


def _active_pipes():
    total = 0
    with _LOCK:
        for row in _STATE.get("peers", {}).values():
            if isinstance(row, dict):
                total += len(_streams(row))
    return total


def _send_row(row, msg_type, payload, key):
    """A-191: otpravka po postoyannomu soedineniyu pira pod ego zapustom
    - inache dva potoka smeshayut svoi sdalki v odnom TCP."""
    sock = (row or {}).get("sock")
    if sock is None:
        raise OSError("peer has no live connection")
    with row["tx"]:
        _send(sock, msg_type, payload, key)


def _new_sid(row):
    with _LOCK:
        used = _streams(row)
        for _ in range(0, 65536):
            row["sid"] = (int(row.get("sid", 0)) + 1) % 0x100000000
            if row["sid"] != 0 and row["sid"] not in used:
                return row["sid"]
    raise OSError("no free stream id")


def _close_stream(row, sid, why=""):
    """A-191: potok zakryt - lokalny soket klienta otpuskaem (SHUT_WR)."""
    with _LOCK:
        stream = _streams(row).pop(sid, None)
    if not isinstance(stream, dict):
        return False
    out = stream.get("out")
    if out is not None:
        try:
            out.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        try:
            out.close()
        except OSError:
            pass
    return True


def _pipe_open(row, key, target, out=None, timeout=None):
    """A-191: masterProsit pira otkryt potok k "host:port". Zhdet T_PIPE_OK
    ili T_PIPE_ERR. Registriruem potok DO otpravki, inache prislyannye dannye
    mogut prityti do nashey zapisi v spiske potokov.
    A-196: "out" peredavaetsya srazu - pir mozhet prislat pervye dannye
    TSERZ (dlya bystroi celi) do vozvrata, i ranee out byl None => tihaya
    poterya pervikh baytov otveta."""
    limit = HANDSHAKE_TIMEOUT_S if timeout is None else float(timeout)
    sid = _new_sid(row)
    waiter = {"ok": None, "error": "", "event": threading.Event()}
    with _LOCK:
        _streams(row)[sid] = {"out": out, "state": {}}
        row.setdefault("waiters", {})[sid] = waiter
    try:
        text = str(target or "").encode("ascii", "ignore")
        _send_row(row, T_PIPE_OPEN, struct.pack("!I", sid) + text, key)
        with _LOCK:
            row["b_used"] = True
        if not waiter["event"].wait(limit):
            raise OSError("peer did not open the stream")
        if not waiter["ok"]:
            raise OSError(waiter["error"] or "peer refused the stream")
        return sid
    except (OSError, ValueError):
        with _LOCK:
            _streams(row).pop(sid, None)
        raise
    finally:
        with _LOCK:
            row.get("waiters", {}).pop(sid, None)


def _pump_frames(local_sock, row, key, sid):
    """A-191: syrye bayty lokalnoy sessii -> T_PIPE_DATA s id potoka."""
    while True:
        try:
            chunk = local_sock.recv(65536)
        except OSError:
            break
        if not chunk:
            break
        for body in _fragment(chunk):
            _send_row(row, T_PIPE_DATA, struct.pack("!I", sid) + body, key)


def _pump_pipe(target, sid, send):
    """A-191 (storona pira): syrye bayty otkrytoy celi -> T_PIPE_DATA."""
    try:
        while True:
            try:
                chunk = target.recv(65536)
            except OSError:
                break
            if not chunk:
                break
            for body in _fragment(chunk):
                send(T_PIPE_DATA, struct.pack("!I", sid) + body)
        try:
            send(T_PIPE_BYE, struct.pack("!I", sid))
        except OSError:
            pass
    finally:
        try:
            target.close()
        except OSError:
            pass


def _release_peer_sock(node_id, conn):
    """A-194: osvobodit soket pira, no NE zabyvaet ego metadannye.
    Nuzhno dlya starykh (A1) ob'yavleniy: pirok posylal odin HELLO i zakryl
    soket, a v registre emu nuzhno ostat'sya kak kandidat na vyxod
    (inache _pick_peer ego ne vidit i trafic ne idet nikuda)."""
    with _LOCK:
        row = _STATE.get("peers", {}).get(node_id)
        if not isinstance(row, dict):
            return False
        if row.get("sock") is conn:
            row["sock"] = None
        else:
            # A-197: eto sostarеvshee soedinenie, a v reestre uzhe novyi
            # soket - potoki i waiter'y novogo zabrosa ne trogaem.
            return False
        for waiter in (row.get("waiters") or {}).values():
            if isinstance(waiter, dict) and waiter.get("event") is not None:
                waiter["ok"] = False
                waiter["error"] = "peer connection is gone"
                waiter["event"].set()
        row["waiters"] = {}
        for stream in (row.get("streams") or {}).values():
            if isinstance(stream, dict) and stream.get("target") is not None:
                try:
                    stream["target"].close()
                except OSError:
                    pass
        row["streams"] = {}
        row["seen"] = time.time()
    return True


def _peer_reader(conn, key, node_id):
    """A-191 (storona mastera): ODIN potok chityaet postoyannoe soedinenie
    pira i razbirayet potoki po identifikatoru. Nikogda ne chitaet T_PIPE_OK
    "dlya sebya" - idet v waiter zaprosa, kotoryy zhdet _pipe_open.
    A-194: esli po soedineniyu ne bylo realnogo trafika - ryad pira
    ostaetsya v reestre (bez soketa), chtoby ego videl _pick_peer."""
    with _LOCK:
        row = _STATE.get("peers", {}).get(node_id)
    if not isinstance(row, dict):
        try:
            conn.close()
        except OSError:
            pass
        return
    buf = b""
    last = time.time()
    used = False
    # A-429: when we ask the peer T_PING we remember the moment, and its
    # T_PONG turns that pair into a real round-trip time for the panel.
    ping_sent = 0.0
    # A-426b: the master keeps the permanent link up by itself. Any peer build
    # answers T_PING with T_PONG (handler exists since A-191), so even a node
    # that predates the client-side keepalive stops tripping PEER_IDLE_S.
    ping_every = _int_env("AURORA_MESH_PING_S", 60, 10, 600)
    try:
        conn.settimeout(None)
        while not _STATE.get("stop"):
            try:
                conn.settimeout(float(ping_every))
                try:
                    chunk = conn.recv(65536)
                finally:
                    conn.settimeout(None)
            except socket.timeout:
                # silence is not death: ask the peer, do not hang up
                try:
                    _send_row(row, T_PING, b"", key)
                except OSError:
                    break
                # A-429c: schyotchik, skolko raz master sprashil ping u pira.
                # Esli on rastet, a pongov net - uzel ne otvechaet na ping
                # (staraya sborka ili tonnel zapeschitan); panel pokazhet eto
                # chestno, a ne pridumaet RTT.
                row["ping_sent"] = int(row.get("ping_sent", 0) or 0) + 1
                # A-429: the answer is timed against this exact moment.
                ping_sent = time.time()
                # A-426c: `last` is NOT refreshed here on purpose. It only
                # moves when the peer actually answers (T_PONG or any frame),
                # so a peer that died silently still trips PEER_IDLE_S and is
                # reaped instead of lingering as a zombie peer forever.
                continue
            except OSError:
                break
            if not chunk:
                break
            last = time.time()
            buf += chunk
            if _oversize(buf):
                break
            while True:
                msg_type, payload, buf = _unpack(buf, key)
                if msg_type is None:
                    break
                if msg_type == T_BYE:
                    raise OSError("peer closed the tunnel")
                if msg_type == T_PING:
                    used = True
                    try:
                        _send_row(row, T_PONG, b"", key)
                    except OSError:
                        pass
                    continue
                if msg_type == T_PONG:
                    # A-429: real measured RTT of the live tunnel. `last` is
                    # NOT touched here - it moved already when the frame
                    # arrived (line above), so A-426c reaping still works.
                    if ping_sent > 0.0:
                        rtt = int(max(0.0, time.time() - ping_sent) * 1000)
                        ping_sent = 0.0
                        with _LOCK:
                            row["rtt_ms"] = rtt
                            # A-429b: status() otdayet peer_rtt tolko dlya
                            # svezhih snimkov (_rtt_fresh smotrit na
                            # "rtt_at"), poetomu bez etoy metki RTT,
                            # izmerennyy cherez tunnel, ne vidno voobshe.
                            row["rtt_at"] = time.time()
                            # A-429c: schyotchik poluchennyh pongov.
                            row["pong_seen"] = int(row.get("pong_seen", 0) or 0) + 1
                    continue
                # A-456: sosed soobshchayet svoy pryamoy UDP-endpoint cherez
                # tunnel. Bez etogo v spiske bytol tolko mesh-adres.
                if msg_type == T_DIRECT:
                    raw = bytes(payload or b"")
                    if raw.startswith(b"MINE|"):
                        ep = raw[5:].decode("utf-8", "replace").strip()[:80]
                        if ep and _parse_addr(ep)[0]:
                            _direct_pub_set(node_id, ep)
                            _game_stat("direct_pub_seen")
                            # A-459: master vidit chego otkuda
                            _diag("game-pub-recv", node_id,
                                  "endpoint=%s len=%d" % (ep, len(raw)))
                        else:
                            _game_stat("dropped_bad_len")
                            _diag("game-pub-recv", node_id,
                                  "rejected raw=%r" % (raw[:64],))
                    continue
                if msg_type == T_RAW:
                    # A-461: uzel otdal syroy paket masteru, pryamogo kanala
                    # net. Master rassylaet paket vsem ostalnym u zlam.
                    used = True
                    # A-744 (A-744_MARK): na igrovom uzle etot kanal
                    # obsluzhivaet GOSTYA, a ne mastera. `_relay_raw` na uzle
                    # raznosit po SVOIM piram, a mastera v peerah uzla net (do
                    # mastera idem cherez `_STATE["up"]`/`_relay_up`), tak chto
                    # spisok poluchatelei byl pust i paket dropalsya. Smerka
                    # A-742: master vsegda videl 0 relay-fwd s bytes=123.
                    # Teper syroy paket gostya idet VVERH tem zhe putem, chto i
                    # sobstvennye pakety uzla iz TUN: `raw_send` - pryamyj
                    # sosed, inache `_relay_up`. Na master ne menyaetsya.
                    if (game_enabled()
                            and str(_STATE.get("started", "") or "") != "master"):
                        raw_send(bytes(payload or b""))
                    else:
                        _relay_raw(node_id, bytes(payload or b""))
                    continue
                if msg_type == T_DATA:
                    # A-193: staryi klient (protokol A1) prosit relay.
                    used = True
                    try:
                        _legacy_hub_from_data(conn, key, node_id, payload)
                    except (OSError, ValueError):
                        pass
                    return
                if msg_type in (T_PIPE_OK, T_PIPE_ERR):
                    used = True
                    if len(payload) < 4:
                        continue
                    sid = struct.unpack("!I", payload[:4])[0]
                    with _LOCK:
                        waiter = (row.get("waiters") or {}).get(sid)
                    if waiter is not None:
                        waiter["ok"] = (msg_type == T_PIPE_OK)
                        if msg_type != T_PIPE_OK:
                            waiter["error"] = "peer refused the stream"
                        waiter["event"].set()
                    continue
                if msg_type == T_PIPE_DATA:
                    used = True
                    if len(payload) < 4:
                        continue
                    sid = struct.unpack("!I", payload[:4])[0]
                    with _LOCK:
                        stream = _streams(row).get(sid)
                    if not isinstance(stream, dict):
                        continue
                    state = stream.setdefault("state", {})
                    data = _defrag(state, payload[4:])
                    if not data:
                        continue
                    out = stream.get("out")
                    if out is None:
                        continue
                    try:
                        out.sendall(data)
                    except OSError:
                        _close_stream(row, sid, "client is gone")
                    continue
                if msg_type == T_PIPE_BYE:
                    used = True
                    if len(payload) < 4:
                        continue
                    _close_stream(row, struct.unpack("!I", payload[:4])[0],
                                 "peer closed the stream")
                    continue
            if time.time() - last > PEER_IDLE_S:
                break
    except OSError:
        pass
    finally:
        with _LOCK:
            current = _STATE.get("peers", {}).get(node_id)
            mine = isinstance(current, dict) and current.get("sock") is conn
            tunnel = bool(current.get("b_used")) if isinstance(current, dict) else False
            # A-202: cheстnaya diagnostika v status() - kakim obrazom zavershilsya
            # reader pira (pomogayet nayti poteryu obratnogo kanala v zhivom teste).
            # A-398: "peer-reader end" - eto SHTAATNOE zavershenie (idle break
            # ili obрыв zakrytogo soketa), a ne polomka. Ranee ono pisalos v
            # last_error, i panel pokazyval oshibku tam, gde vse v poryadke.
            # Diagnostika idet v otdelnoe pole, last_error - tolko realnyi sboi.
            _STATE["last_reader_end"] = ("peer-reader end: mine=%s tunnel=%s used=%s"
                                         % (mine, tunnel, used))
        if mine and tunnel:
            # A-199: reshaem po `mine`, a NE po `used`. V variante B
            # soedinenie pira postoyannoe i mozhet legalno molchat (idle),
            # a `used` stanovilsya True tolko na T_PING/T_DATA. Iz-za etogo
            # A-194::_release_peer_sok obrashchal ZHIVOY obratnyy soket
            # (row['sock'] = None) i master ego terjal: peer_conns: 0,
            # a variant B vzhivyu ne rabotal. Soedinenie zavershilos -
            # znachit ono mertvo: snimaem uzhel celikom.
            _drop(node_id, "peer connection is gone")
        elif mine:
            # A-200: odnorazovyy HELLO-announce pira (A1). Zapis pira
            # NADO sotranit: master dialit pira po adresu iz HELLO.
            # Tolko osvobozhdaem soket - inache _pick_peer ne vidit pira
            # i klienty poluchayut otkaz, a zapis myagsko ischezayet.
            _release_peer_sock(node_id, conn)
        else:
            # A-197: sostarеvshee soedinenie - reestr zaniat novym,
            # nichego v nyom ne trogaem.
            pass
        try:
            conn.close()
        except OSError:
            pass


def _peer_pump(conn, key):
    """A-191 (storona pira): zhdem komandu mastera (T_PIPE_OPEN) i kazhdyy
    potok obsluzhivaem v svoikh dvukh potokakh. Odno masterskoe soedinenie
    mozhet nest skolko ugodno potokov, no ne bolshe MAX_STREAMS."""
    streams = {}
    tx = threading.Lock()
    buf = b""
    last = time.time()
    # A-426: the master's _peer_reader drops a peer after PEER_IDLE_S of
    # silence. The client never spoke while idle, so the link died every
    # ~5 minutes even though it was perfectly healthy. We now recv with a
    # timeout and emit our own T_PING (the master already answers T_PONG).
    ping_every = _int_env("AURORA_MESH_PING_S", 60, 10, 600)

    def send(msg_type, payload):
        with tx:
            _send(conn, msg_type, payload, key)

    def close_stream(sid):
        stream = streams.pop(sid, None)
        if not isinstance(stream, dict):
            return False
        target = stream.get("target")
        if target is not None:
            try:
                target.close()
            except OSError:
                pass
        return True

    def open_stream(sid, text):
        if len(streams) >= MAX_STREAMS:
            # A-191: chestnyi otkaz, a ne bezkonechnoe nakoplenie potokov.
            send(T_PIPE_ERR, struct.pack("!I", sid) + b"\x02")
            return
        host, _sep, port = str(text or "").rpartition(":")
        if not host or not port.isdigit():
            send(T_PIPE_ERR, struct.pack("!I", sid) + b"\x01")
            return
        try:
            target = socket.create_connection((host, int(port)),
                                              HANDSHAKE_TIMEOUT_S)
        except (OSError, ValueError):
            send(T_PIPE_ERR, struct.pack("!I", sid) + b"\x01")
            return
        target.settimeout(None)
        streams[sid] = {"target": target, "state": {}}
        send(T_PIPE_OK, struct.pack("!I", sid))
        threading.Thread(target=_pump_pipe, args=(target, sid, send),
                         name="mesh-pipe-%d" % int(sid), daemon=True).start()

    try:
        conn.settimeout(None)
        while not _STATE.get("stop"):
            try:
                # A-426: recv under a timeout so an idle tunnel still emits a
                # keepalive. socket.timeout is a subclass of OSError, so it
                # MUST be caught first. The timeout is dropped again right
                # after recv so a blocking send can never half-write a frame.
                conn.settimeout(float(ping_every))
                try:
                    chunk = conn.recv(65536)
                finally:
                    conn.settimeout(None)
            except socket.timeout:
                send(T_PING, b"")
                continue
            except OSError:
                break
            if not chunk:
                break
            last = time.time()
            buf += chunk
            if _oversize(buf):
                break
            while True:
                msg_type, payload, buf = _unpack(buf, key)
                if msg_type is None:
                    break
                if msg_type == T_PING:
                    send(T_PONG, b"")
                    continue
                if msg_type == T_BYE:
                    raise OSError("master closed the tunnel")
                # A-433 (Ш1.1): syroy IP-paket ot soseda po pryamomu kanalu
                # idet v virtualnyj adapter; staruyu sobstvennuyu sety ne trogaem.
                if msg_type == T_RAW:
                    raw_inject(payload)
                    continue
                # A-435: signaly pryamogo kanala ot mastera i rukopozhatie
                # na pryamom kanale ot soseda - obrabotchik v etoy zhe petle.
                if msg_type in (T_GAME_PEERS, T_DIRECT):
                    direct_inbox(msg_type, payload, key)
                    continue
                if msg_type == T_PIPE_OPEN:
                    if len(payload) < 4:
                        continue
                    open_stream(struct.unpack("!I", payload[:4])[0],
                                payload[4:].decode("utf-8", "replace"))
                    continue
                if msg_type == T_PIPE_DATA:
                    if len(payload) < 4:
                        continue
                    sid = struct.unpack("!I", payload[:4])[0]
                    stream = streams.get(sid)
                    if not isinstance(stream, dict):
                        continue
                    state = stream.setdefault("state", {})
                    data = _defrag(state, payload[4:])
                    if not data:
                        continue
                    try:
                        stream["target"].sendall(data)
                    except OSError:
                        close_stream(sid)
                    continue
                if msg_type == T_PIPE_BYE:
                    if len(payload) < 4:
                        continue
                    close_stream(struct.unpack("!I", payload[:4])[0])
                    continue
            if time.time() - last > PEER_IDLE_S:
                break
    except OSError:
        pass
    finally:
        for sid in list(streams):
            close_stream(sid)
        try:
            conn.close()
        except OSError:
            pass


def _peer_stream(row, key, text, local_sock):
    """A-191: otkryt potok k "host:port" na pIRE i zalit v nego syrye
    bayty lokalnoy sessii. Obratnoe napravlenie pishet tot zhe potok cherez
    _peer_reader, poetomu zdes nichego ne zhdem."""
    # A-196: "out" peredavaetsya v _pipe_open - pervye bayty otveta mogut
    # prityti do zaversheniya rukopozhatiya, i nichego ne dolzno byt poteryano.
    sid = _pipe_open(row, key, text, local_sock)
    _touch(row.get("node_id"))
    try:
        _pump_frames(local_sock, row, key, sid)
    finally:
        try:
            _send_row(row, T_PIPE_BYE, struct.pack("!I", sid), key)
        except OSError:
            pass
        _close_stream(row, sid, "local session is finished")
    return True

def _relay(sock, key, out_sock=None):
    """A-127/A-128: odna sessiya - odno soedinenie - odin zapros.
    out_sock задан: my sami otpravili T_DATA i chitaem fragmenty v out_sock.
    out_sock None: pir sam zakazal cel (T_DATA) - my ego vyhod."""
    with _LOCK:
        _STATE["sessions"] = int(_STATE.get("sessions", 0) or 0) + 1
    try:
        if out_sock is not None:
            _recv(sock, out_sock, key)
            return
        buf = b""
        while True:
            try:
                chunk = sock.recv(65536)
            except OSError:
                chunk = b""
            if not chunk:
                return False
            buf += chunk
            # A-158: sm. takzhe v _forward/_recv - bufer ne dolzhen rasti beskonechno.
            if _oversize(buf):
                return False
            msg_type, payload, rest = _unpack(buf, key)
            buf = rest
            if msg_type is None:
                if not buf:
                    return False
                continue
            if msg_type == T_BYE:
                return False
            if msg_type != T_DATA:
                continue
            try:
                host, port = payload.decode("utf-8", "replace").rsplit(":", 1)
            except ValueError:
                return False
            sock.settimeout(None)
            # A-133: _connect_out peredast etot zhe soket v _pipe (dva _pump),
            # poetomu bolshe NE chitaem iz nego i NE zakryvaem - inache trubka
            # menyat obryvaetsya sразу posle ustanovki soedineniya.
            return bool(_connect_out(sock, host, port, key))
    finally:
        with _LOCK:
            _STATE["sessions"] = max(0, int(_STATE.get("sessions", 0) or 0) - 1)


def _legacy_hub_stream(client_conn, key, text, row):
    """A-193: staroe odnorazovoe soedinenie s pirem (protokol A1).
    Master SAM dialit pira, shlet T_DATA i kachaet dva napravleniya
    _forward. V variante B eto fallback i obrabotka starykh klientov,
    kotorye ne umeyut T_PIPE_OPEN."""
    peer_sock = None
    try:
        peer_sock = _dial_peer(row, key)
    except (OSError, ValueError):
        return False
    _touch(row.get("node_id"))
    try:
        _send(peer_sock, T_DATA, text.encode("utf-8"), key)
    except OSError:
        try:
            peer_sock.close()
        except OSError:
            pass
        return False
    up = threading.Thread(target=_forward, args=(client_conn, peer_sock, key),
                          name="mesh-hub-c2p", daemon=True)
    down = threading.Thread(target=_forward, args=(peer_sock, client_conn, key),
                            name="mesh-hub-p2c", daemon=True)
    up.start()
    down.start()
    up.join()
    down.join()
    try:
        peer_sock.close()
    except OSError:
        pass
    return True


def _legacy_hub_from_data(client_conn, key, requester_id, payload):
    """A-193: T_DATA ot uzla v masterskuyu storonu = prosba na relay A1.
    Soedinenie odnorazovoe: posle obrabotki ego zamykaet vypolnyayushchiy
    potok. Myi umyashlenno NE predpochitaem zdes _peer_stream: T_DATA -
    eto staryi protokol, a variant B tseli otkryvaet cherez T_PIPE_OPEN."""
    text = payload.decode("utf-8", "replace")
    if ":" not in text:
        return False
    row = _pick_peer(exclude=requester_id)
    if row is None:
        return False
    try:
        client_conn.settimeout(None)
    except OSError:
        pass
    return bool(_legacy_hub_stream(client_conn, key, text, row))


def _relay_hub(client_conn, key, requester_id=""):
    """A-191 (variant B): master NE dialit pira. Beret ego postoyannoe
    soedinenie iz reestra i prosit otkryt potok k celi. A1 sohranen kak
    fallback (estli u pira net zhivogo soedineniya)."""
    buf = b""
    target = b""
    try:
        client_conn.settimeout(HANDSHAKE_TIMEOUT_S)
        while not target:
            try:
                chunk = client_conn.recv(65536)
            except OSError:
                return False
            if not chunk:
                return False
            buf += chunk
            if _oversize(buf):
                return False
            while True:
                msg_type, payload, buf = _unpack(buf, key)
                if msg_type is None:
                    break
                if msg_type == T_BYE:
                    return False
                if msg_type != T_DATA:
                    continue
                target = payload
                break
        client_conn.settimeout(None)
        text = target.decode("utf-8", "replace")
        if ":" not in text:
            return False
        row = _pick_peer(exclude=requester_id)
        if row is None:
            return False
        if row.get("sock") is not None:
            try:
                _peer_stream(row, key, text, client_conn)
            except (OSError, ValueError):
                _drop(row.get("node_id"), "stream refused")
                return False
            return True
        # A-193: obshchiy legacy-helper vmesto dublirovaniya koda.
        return bool(_legacy_hub_stream(client_conn, key, text, row))
    finally:
        try:
            client_conn.settimeout(None)
        except OSError:
            pass
        try:
            client_conn.close()
        except OSError:
            pass


def _peer_session(conn, key):
    """A-191 (variant B): soedinenie pira ostaetsya POSTOYANNym. Master
    registriruet ego s soketom i zapechkivaet ODNIM potokom _peer_reader,
    a potom prosto vozvrashchaetsya - peredacha idet po etomu zhe kanalu."""
    node_id = ""
    host = ""
    port = 0
    try:
        conn.settimeout(HANDSHAKE_TIMEOUT_S)
        buf = b""
        while True:
            try:
                chunk = conn.recv(65536)
            except OSError:
                chunk = b""
            if not chunk:
                return
            buf += chunk
            if _oversize(buf):
                return
            msg_type, payload, rest = _unpack(buf, key)
            buf = rest
            if msg_type is None:
                if not buf:
                    return
                continue
            if msg_type != T_HELLO:
                return
            parts = str(payload.decode("utf-8", "replace")).split("|", 5)
            if len(parts) < 3:
                _diag("short-hello", "", "fields=%d" % len(parts))
                return
            node_id, proof, nonce = parts[0], parts[1], parts[2]
            # A-296: hvost kadra - "addr|policy_port" (pyatoe pole). Starye
            # uzly shlyut tolko addr, togda policy_port ostaetsya 0.
            tail = (parts[3] if len(parts) > 3 else "").split("|", 3)
            # A-307: pyatoe i shestoe pole - token i credential licenzii uzla
            lic_token = tail[2].strip() if len(tail) > 2 else ""
            lic_cred = tail[3].strip() if len(tail) > 3 else ""
            host, port = _parse_addr(tail[0])
            policy_port = 0
            if len(tail) > 1 and tail[1].isdigit():
                policy_port = int(tail[1])
            # A-395: log the raw HELLO head once per connection: how many
            # fields arrived and what exactly sits in the address field. A
            # client and a master must agree on the frame layout, otherwise
            # the address is parsed out of the wrong slot and stays empty.
            _diag("hello-parse", node_id, "fields=%d tail=%d addr=%r" % (
                len(parts), len(tail), tail[0][:48]))
            if not _known(node_id, proof, nonce):
                return
            # A-392: _known logs its own reason; _register_from_hello logs
            # its own refusal, so a silent drop is now impossible.
            _register_from_hello(node_id, host, port, policy_port)
            # A-307: snachala politika i licenziya, potom T_OK - klient v
            # _wait_ok vozvrashchaetsya na T_OK i poteryal by hvos buffer.
            _send_policy(conn, key)
            _send_license(conn, key, lic_token, lic_cred)
            _send(conn, T_OK, hmac.new(_keybytes(key),
                                       b"aurora-mesh-ok" + _keybytes(nonce),
                                       hashlib.sha256).hexdigest().encode("ascii"), key)
            # A-291: сразу после T_OK отдаём подписанную политику - клиент
            # применит её тем же fail-closed путём, что и HTTP-политику.
            break
    finally:
        try:
            conn.settimeout(None)
        except OSError:
            pass
    if not node_id:
        # A-113: ranee posle "timeout" s pustymi dannymi registralsya pir "".
        conn.close()
        return
    addr = ("%s:%d" % (host, port)) if host else ""
    if _peer(node_id, addr, sock=conn) is None:
        conn.close()
        return
    # A-743: pump vybiralsya NE po roli, a po tomu, CHTO eto za peer.
    # Master obsluzhivaet vhodyashchih cherez _peer_reader. Uzly igry ranee
    # otdavali vsyakoe ne-master soedinenie v `_relay` (legacy relay-hub),
    # a `_relay` ne obsluzhivaet T_RAW - i gost s T_OK vsegda molchal: ego
    # igrovye pakety ne uhodili nikuda (proverka A-742: master ne uvidel
    # relay-fwd s bytes=123, vsego 0).
    # Teper: master - kak bylo; uzol igry - tozhe cherez _peer_reader, CHTOBY
    # host, podklyuchivshijsya k etomu uzlu, poluchal realnyj T_RAW v svoem TUN.
    # Sostoyanie mastera ne menyaetsya voobshche.
    if (str(_STATE.get("started", "") or "") == "master"
            or game_enabled()):
        threading.Thread(target=_peer_reader, args=(conn, key, node_id),
                         name="mesh-peer-%s" % node_id, daemon=True).start()
        return
    if not _relay(conn, key, None):
        conn.close()


def _ensure_socks(key):
    """A-115: ranee kazhdyy pir sozdaval SVOY listener na tom zhe porte;
    vtoroy bind na zanyatom listen-portu s SO_REUSEADDR padaet na Linux i
    tred umiral. Teper listener odin obshchiy na vsekh xray-zaprosy."""
    with _LOCK:
        listener = _STATE.get("socks")
        if listener is not None:
            return
    try:
        listener = _listen_wait(MESH_PORT + 1)
    except OSError:
        return
    with _LOCK:
        _STATE["socks"] = listener
    # A-138: _accept_loop zovet handler(conn), a _socks_session trebuet key -
    # ranee zdes prosto peredavalasya chistaya funciya i kazhdoe soedenie
    # padalo s TypeError (master ne prinimal SOCKS-zapros xray voobshche).
    threading.Thread(target=_accept_loop,
                     args=(listener, lambda conn: _socks_session(conn, key)),
                     name="mesh-socks", daemon=True).start()


def _rtt_fresh(row):
    """A-151: RTT-svesh, a ne staryi snimok."""
    try:
        return (time.time() - float(row.get("rtt_at", 0) or 0)) < RTT_TTL
    except (TypeError, ValueError):
        return False


def set_rtt(rows):
    """A-151: prinimaem mesh.ping_all() i skladyvaem RTT v reyestr pirov.
    Sopostavlenie snachala po id, potom po imeni (id v mesh byvaet UUID)."""
    if not isinstance(rows, (list, tuple)):
        return 0
    now = time.time()
    applied = 0
    with _LOCK:
        peers = _STATE.setdefault("peers", {})
        for item in rows:
            if not isinstance(item, dict):
                continue
            try:
                ms = int(item.get("ping_ms"))
            except (TypeError, ValueError):
                ms = 0
            ok = bool(item.get("ok")) and 0 < ms < 60000
            for key_id in (str(item.get("id") or "").strip(),
                           str(item.get("name") or "").strip()):
                if not key_id:
                    continue
                row = peers.get(key_id)
                if not isinstance(row, dict):
                    continue
                if ok:
                    row["rtt_ms"] = ms
                    row["rtt_at"] = now
                    row["rtt_fail"] = 0.0
                    applied += 1
                else:
                    # A-152: pira net - RTT snachayut srazu, ne cherez TTL
                    # A-154: zapominaem "merTV" svezhim - piron idet v konец
                    # A-429d: sobstvennyi dial mastera mozhet ne otvechat, poka
                    # zhivaya sessiya tunnela est (u pira 5181 sluchaet tolko
                    # na loopback). Staryi kod zdes stiral izmerennyy po
                    # tunnelu RTT, i poetomu peer_rtt ostalos pustym. Svehiy
                    # snimok ne trogaem - otkaz diala uzhe zapisan v rtt_fail.
                    if not _rtt_fresh(row):
                        row["rtt_ms"] = 0
                        row["rtt_at"] = 0.0
                    row["rtt_fail"] = now
                break
    return applied


def _rtt_fail_fresh(row):
    """A-154: "etot piron ne otvechaet" svezhih zamerov."""
    try:
        return (time.time() - float(row.get("rtt_fail", 0) or 0)) < RTT_FAIL_TTL
    except (TypeError, ValueError):
        return False


def _pick_sort_key(row):
    """A-151: snachala uzly s izvestnym svezhim RTT (men'shij = blizhe),
    potom uzly bez RTT - po svezhosti obnovleniya.
    A-154: piron s "mertvym" RTT tol'ko v KONCE - inache on zanimaet
    mesto zhivogo, prosto potomu chto ego `seen` sveshee."""
    seen = 0.0
    try:
        seen = float(row.get("seen", 0) or 0)
    except (TypeError, ValueError):
        seen = 0.0
    if _rtt_fresh(row):
        rtt = 0
        try:
            rtt = int(row.get("rtt_ms", 0) or 0)
        except (TypeError, ValueError):
            rtt = 0
        if rtt > 0:
            return (0, rtt, -seen)
    if _rtt_fail_fresh(row):
        return (2, 0, -seen)
    return (1, 0, -seen)


def _rtt_loop():
    """A-151: master oprobivet pirov cherez mesh.ping_all() i skladyvaet RTT."""
    while True:
        try:
            import mesh as _mesh
            rows = _mesh.ping_all()
            if isinstance(rows, list):
                set_rtt(rows)
        except Exception as exc:
            _STATE["last_error"] = "rtt: %s" % exc.__class__.__name__
        if _STATE.get("stop"):
            return
        time.sleep(max(5, int(RTT_INTERVAL)))


def _pick_peer(exclude=None):
    """A-129: berem pira po svezhosti "vidim" i dialim zanovo (A-128).
    A-134: exclude - zaprosivshiy uzol, on ne mozhet byt vyxodom dlya sebya."""
    skip = str(exclude or "").strip()
    with _LOCK:
        rows = [row for row in _STATE.get("peers", {}).values()
                if str(row.get("node_id") or "") != skip
                and _parse_addr(row.get("addr"))[0]
                and time.time() - row.get("seen", 0) < TTL]
    if not rows:
        return None
    rows.sort(key=_pick_sort_key)
    best = rows[0]
    fresh = bool(_rtt_fresh(best))
    with _LOCK:
        _STATE["last_pick"] = {
            "node_id": str(best.get("node_id") or ""),
            "rtt_ms": int(best.get("rtt_ms", 0) or 0) if fresh else 0,
            "fresh_rtt": fresh,
            "at": time.time()}
    return best


def _socks_session(conn, key):
    """A-191: snachala probuem obratnoe soedinenie (potok po zhivomu
    soedineniyu pira), tolko potom - staruyu shemu A1 s dialom."""
    target = _socks_request(conn)
    if target is None:
        conn.close()
        return
    conn.settimeout(None)
    text = "%s:%d" % target
    row = _pick_peer()
    if row is not None and row.get("sock") is not None:
        try:
            conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        except OSError:
            conn.close()
            return
        try:
            _peer_stream(row, key, text, conn)
        except (OSError, ValueError):
            _drop(row.get("node_id"), "stream refused")
        conn.close()
        return
    peer_sock = None
    if row is not None:
        try:
            peer_sock = _dial_peer(row, key)
        except (OSError, ValueError):
            peer_sock = None
        else:
            _touch(row.get("node_id"))
    if peer_sock is None:
        try:
            conn.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
        except OSError:
            pass
        conn.close()
        return
    try:
        conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        _send(peer_sock, T_DATA, text.encode("utf-8"), key)
    except OSError:
        conn.close()
        peer_sock.close()
        return
    threading.Thread(target=_pump, args=(conn, peer_sock, key), daemon=True).start()
    _relay(peer_sock, key, conn)
    conn.close()
    peer_sock.close()


MESH_ROLES = ("master", "client")


def start(role=None):
    if not enabled():
        return False
    role = str(role or os.environ.get("AURORA_MESH_ROLE", "") or "").strip().lower()
    # A-278: fail-closed на привилегированную роль. Раньше пустая роль превращалась
    # в "master", и узел молча поднимал серверную сторону (слушал 51821) для чужих.
    # Модуль по контракту не пишет в лог (в нём циркулирует секрет сети), поэтому
    # молча трактуем неизвестную роль как "client" - хуже всего лишний клиент.
    if role not in MESH_ROLES:
        role = "client"
    with _LOCK:
        if _STATE.get("started"):
            return True
        _STATE["started"] = role
    key = _secret()
    if not key:
        # A-263: старт не состоялся - снимаем метку, иначе следующий
        # start() вернул бы True, хотя туннель не поднят.
        with _LOCK:
            _STATE.pop("started", None)
        return False
    master = role == "master"
    target = _server_serve if master else _client_serve
    threading.Thread(target=target, name="mesh-relay", daemon=True).start()
    # A-435: прямой канал между игровыми узлами. Мастер здесь только
    # сигналит списком соседей, сами пакеты идут напрямую.
    try:
        direct_loop()
    except Exception:
        pass
    if master:
        threading.Thread(target=_ensure_socks, args=(key,),
                         name="mesh-socks", daemon=True).start()
    return True


_DIAG_MAX = 200
_DIAG = []


def _note(reason, text="", level="info"):
    """A-291 в клиентской сборке: модуль НЕ пишет в лог сам - в нём циркулирует
    секрет сети. Диагностика кладётся в ограниченный буфер и в _STATE, откуда её
    читает панель. Ни печати в консоль, ни вызовов логгера, ни файлов."""
    try:
        item = {"t": int(time.time()), "reason": str(reason)[:40],
                "level": str(level)[:8], "text": str(text)[:200]}
        _DIAG.append(item)
        if len(_DIAG) > _DIAG_MAX:
            del _DIAG[:len(_DIAG) - _DIAG_MAX]
        with _LOCK:
            _STATE["diag"] = item
            if str(level) == "error":
                _STATE["last_error"] = item["text"]
        return True
    except Exception:
        # A-498: и сам ход диагностики не должен ронять туннель.
        return False


def _diag(reason, node_id="", extra=""):
    """A-392: log a peer rejection reason. Never raises, never blocks."""
    try:
        # A-482: prefiks zavisit ot prichiny - otkaz ili prostaya diag.
        tag = "peer rejected" if reason in MESH_DIAG_REJECTS else "diag"
        _note(reason, "%s node=%s%s" % (
            tag, str(node_id or "")[:40], (" " + extra) if extra else ""))
    except Exception:
        pass


def _diag_throttled(reason, node_id="", extra=""):
    """A-498: _diag(), no tolko pri IZMENENII sostoyaniya.

    Podpisyvaetsya na signaturu (reason + extra). Pervy yhod vsegda pishetsya,
    daleyshe - tolko esli podpis izmenilis ili proshlo GAME_DIAG_PERIOD_S
    (togda dobavlyaetsya "(same)"). GAME_DIAG_PERIOD_S = 0 = staroe povedenie,
    kazhdyy cykl. Nichego ne glotaet i ne podmenyaet: _diag() vsyu zapis
    propisyvaet cherez config.log, zdes toloto reshenie, KOGDA pisat."""
    try:
        sig = "%s|%s" % (str(reason), str(extra))
        now = time.time()
        with _GAME_DIAG_LOCK:
            prev = _GAME_DIAG_LAST.get(sig)
            if prev is not None and prev[0] == sig:
                same = True
                if GAME_DIAG_PERIOD_S and (now - prev[1]) < GAME_DIAG_PERIOD_S:
                    return False
            else:
                same = False
            _GAME_DIAG_LAST[sig] = (sig, now)
        _diag(reason, node_id, ("%s (same)" % extra) if same else extra)
        return True
    except Exception as exc:
        # A-498: ne molchать, esli sam hod diagnostiki svalilsya.
        try:
            _note("diag-throttle-fail", "%s: %s"
                 % (type(exc).__name__, exc), level="error")
        except Exception:
            pass
        return False


def _direct_accept(nid, sender):
    """Responder: sozdaet svoy UDP-soket i zapuskaet reader dlya sosededa,
    kotoryy pozval po pryamomu kanalu. Vypolnyaetsya tolko dlya uzla, naznannogo
    masterom nashim sosedom (proverka grant/known_nonce v _direct_handshake)."""
    st = _direct_state()
    with _LOCK:
        info = dict(st.get(nid) or {})
    if info.get("sock") is None:
        try:
            sock = _direct_socket()
        except OSError:
            return 0
        info["sock"] = sock
    else:
        sock = info.get("sock")
    info["addr"] = sender
    info["last"] = time.time()
    with _LOCK:
        st[nid] = info
    th = threading.Thread(target=_direct_reader, args=(sock, nid, sender),
                          name="mesh-direct-%s" % nid[:8], daemon=True)
    th.start()
    _game_stat("direct_accepted")
    return 1


def _direct_dispatch(pkt, key=None, dst=None):
    """A-475: otpravka po ZHIVym pryamym UDP-kanalam.

    Relay-folbyaka zdes NET - ego dobavlyayut caller'y (`direct_send` i
    `raw_send`), chtoby reshenie A-432 p.3 ("snachala pryamoy UDP, tolko potom
    rely") zhilo v odnom meste, a pryamoy kanal realno uchastvoval v obmene.
    """
    if dst is None:
        _src, dst = _raw_endpoints(pkt)
    if not dst:
        return 0
    bcast, own_segment, targets = _direct_targets(dst)
    if not targets:
        return 0
    # A-483: pryamoy UDP idet v internet cherez NAT - paket bolshe
    # DIRECT_UDP_MAX tam ne dostavit, a relay (cherez _relay_up) dostavit.
    if len(pkt or b"") > DIRECT_UDP_MAX:
        _game_stat("dropped_direct_len")
        return 0
    if key is None or not isinstance(key, (bytes, bytearray)):
        try:
            key = _keybytes(_secret())
        except Exception:
            key = b""
    frame = _pack(T_RAW, bytes(pkt), key)
    sent = 0
    st = _direct_state()
    for nid, info in targets:
        sock = info.get("sock")
        addr = info.get("addr")
        if sock is None or not addr:
            continue
        try:
            sock.sendto(frame, addr)
            sent += 1
            with _LOCK:
                cur = dict(st.get(nid) or {})
                cur["sent"] = int(cur.get("sent", 0) or 0) + 1
                cur["last"] = time.time()
                st[nid] = cur
        except OSError:
            _game_stat("send_failed")
    if sent:
        _game_stat("sent", sent)
        _game_stat("direct_bcast" if bcast else
                    ("direct_segment" if own_segment else "direct_unicast"))
    return sent


def _direct_grant(node_id, nonce):
    """Podpis mastera po sety seti. Eto NE granica bezopasnosti (setu znaet ves
    mesh), a tolko otsekaet sluchainnyh posetiteley: podpisannymi dannymi
    polzovatsya mozhno tolko izvesnym uzlam seti."""
    try:
        key = _keybytes(_secret())
    except Exception:
        key = b""
    raw = "aurora-direct:%s:%s" % (str(node_id), str(nonce))
    return hmac.new(key, raw.encode("utf-8"), hashlib.sha256).hexdigest()[:32]


def _direct_handshake(payload, sender=None):
    """HI -> otvet OK s podpisom; OK -> proverka podpisi i "kanal gotov"."""
    try:
        text = payload.decode("utf-8", "replace")
    except Exception:
        return True
    bits = text.split("|")
    if not bits:
        return True
    tag = bits[0].strip().upper()
    me = str(_STATE.get("node_id", "") or "")
    st = _direct_state()
    if tag == "HI" and len(bits) >= 3:
        nid = bits[1].strip()
        nonce = bits[2].strip()
        if not nid or nid == me or nid in _NO_GAME_IDS:
            return True
        with _LOCK:
            info = dict(st.get(nid) or {})
        # otvechat tolko tomu, kogo master nazval nashim sosedom
        if not nonce or not info.get("known_grant") or not nonce == info.get("known_nonce"):
            return True
        sock = info.get("sock")
        addr = info.get("addr")
        if sock is None:
            if sender is None:
                return True
            _direct_accept(nid, sender)
            with _LOCK:
                info = dict(st.get(nid) or {})
            sock = info.get("sock")
            addr = info.get("addr")
        if sock is None or not addr:
            return True
        try:
            sig = _direct_grant(me, nonce)
            reply = ("OK|%s|%s|%s" % (me, nonce, sig)).encode("utf-8")
            sock.sendto(_pack(T_DIRECT, reply, _keybytes(_secret())), addr)
            with _LOCK:
                info["rtt_ms"] = 0
                info["last"] = time.time()
                info["up"] = 1
                # A-474: kanal podnyalsya - schyotchik neudachnykh popytok snul
                info["retries"] = 0
                st[nid] = info
        except (OSError, TypeError, ValueError):
            pass
        return True
    if tag == "OK" and len(bits) >= 4:
        nid = bits[1].strip()
        nonce = bits[2].strip()
        sig = bits[3].strip()
        # A-435-fix: "OK" neset id OTVETCHIKA, poetomu kanal ishemy po nid,
        # a ne po svoemu id - inache kanal nikogda ne podnimalsya by.
        with _LOCK:
            info = dict(st.get(nid) or {})
        if (info.get("sock") is not None and nid != me and nonce
                and nonce == info.get("nonce") and sig
                and sig == _direct_grant(nid, nonce)):
            with _LOCK:
                info["up"] = 1
                info["last"] = time.time()
                info["rtt_ms"] = 0
                # A-474: kanal podnyalsya - schyotchik neudachnykh popytok snul
                info["retries"] = 0
                st[nid] = info
            _game_stat("direct_up")
        return True
    return True


def _direct_initiate(nid, addr, nonce):
    """Initsiator (men'shiiy id) otkryvaet UDP-soket i posylayet HI."""
    import socket
    host, port = _parse_addr(addr)
    if not host:
        return 0
    try:
        sock = _direct_socket()
        me = str(_STATE.get("node_id", "") or "")
        hi = ("HI|%s|%s" % (me, nonce)).encode("utf-8")
        sock.sendto(_pack(T_DIRECT, hi, _keybytes(_secret())), (host, int(port or MESH_PORT)))
    except (OSError, TypeError, ValueError):
        return 0
    st = _direct_state()
    with _LOCK:
        info = dict(st.get(nid) or {})
        old = info.get("sock")
        info.update({"sock": sock, "addr": (host, int(port or MESH_PORT)),
                     "nonce": nonce, "up": 0, "sent": 0, "recv": 0,
                     "started": time.time(), "last": time.time()})
        st[nid] = info
    try:
        if old is not None:
            old.close()
    except (OSError, AttributeError):
        pass
    th = threading.Thread(target=_direct_reader, args=(sock, nid, (host, int(port or MESH_PORT))),
                          name="mesh-direct-%s" % nid[:8], daemon=True)
    th.start()
    _game_stat("direct_started")
    return 1


def _direct_known(payload):
    """Razbor spiska ot mastera: {'known': {nid: {addr, grant}}, 'peers': [...]}"""
    try:
        text = bytes(payload).decode("utf-8", "replace")
    except Exception:
        return [], {}
    known = {}
    order = []
    for chunk in text.split(";"):
        bits = chunk.split("|")
        if len(bits) < 4:
            continue
        nid, addr, nonce, grant = bits[0].strip(), bits[1].strip(), bits[2].strip(), bits[3].strip()
        if not nid or not addr or nid in _NO_GAME_IDS:
            continue
        known[nid] = {"addr": addr, "nonce": nonce, "grant": grant}
        order.append(nid)
    return order, known


def _direct_nat_shared(addr):
    """A-474: moy i sosedin opublikovannyi endpoint s ODNIM publichnym IP ->
    pryamoy UDP mezhdu nimi nevozmozhen (odin NAT), znachit tolko relej."""
    me = str(_STATE.get("node_id", "") or "")
    my_host, _ = _parse_addr(_direct_pub_get(me) or "")
    host, _ = _parse_addr(addr or "")
    return bool(my_host and host and my_host == host)


def _direct_pub_get(node_id):
    with _LOCK:
        return str((_STATE.get("direct_pub", {}) or {}).get(str(node_id), "") or "")


def _direct_pub_local():
    """Svoy pryamoy endpoint: host iz _self_addr() + port sobstvennogo UDP-soketa."""
    me = str(_STATE.get("node_id", "") or "")
    with _LOCK:
        st = dict(_STATE.get("direct", {}) or {})
    port = 0
    # A-457: snachala own endpoint, zapisannyy pri sozdanii soketa.
    with _LOCK:
        local = dict(_STATE.get("direct_local", {}) or {})
    try:
        port = int(local.get("port", 0) or 0)
    except (TypeError, ValueError):
        port = 0
    if not port:
        # fallback: lyuboy zhivoy pryamoy soket etogo uzla
        for nid, info in st.items():
            if not isinstance(info, dict):
                continue
            sock = info.get("sock")
            if sock is None:
                continue
            try:
                port = int(sock.getsockname()[1])
            except (OSError, IndexError, TypeError, ValueError):
                port = 0
            if port:
                break
    if not port:
        return ""
    host = _parse_addr(_self_addr())[0]
    if not host:
        return ""
    return "%s:%d" % (host, port)


def _direct_pub_set(node_id, endpoint):
    with _LOCK:
        pub = dict(_STATE.get("direct_pub", {}) or {})
        pub[str(node_id)] = str(endpoint)
        _STATE["direct_pub"] = pub
        return str(endpoint)


def _direct_reader(sock, nid, addr):
    """Potok pryamogo kanala: prinimaet T_DIRECT i T_RAW ot soseda."""
    import socket
    key = None
    while not _STATE.get("stop"):
        try:
            sock.settimeout(1.0)
            data, sender = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            key = _keybytes(_secret())
            msg_type, payload, _rest = _unpack(data, key)
        except Exception:
            continue
        if msg_type is None:
            continue
        if msg_type == T_DIRECT:
            _direct_handshake(bytes(payload), sender)
            continue
        if msg_type == T_RAW:
            st = _direct_state()
            with _LOCK:
                info = dict(st.get(nid) or {})
                info["recv"] = int(info.get("recv", 0) or 0) + 1
                info["last"] = time.time()
                info["addr"] = "%s:%d" % sender
                st[nid] = info
            _game_stat("direct_received")
            raw_inject(bytes(payload))
    try:
        sock.close()
    except OSError:
        pass


def _direct_retry(nid, info, addr, nonce):
    # A-461: novyy HI po uzhe otkrytomu UDP-soketu, bez peresozdaniya socketa.
    sock = info.get("sock")
    host, port = _parse_addr(addr)
    if sock is None or not host or not (0 < int(port or 0) < 65536):
        return 0
    me = str(_STATE.get("node_id", "") or "")
    try:
        key = _keybytes(_secret())
    except Exception:
        return 0
    frame = _pack(T_DIRECT, ("HI|%s|%s" % (me, nonce)).encode("ascii", "replace"), key)
    try:
        sock.sendto(frame, (host, int(port)))
    except OSError:
        return 0
    st = _direct_state()
    with _LOCK:
        cur = dict(st.get(nid) or {})
        cur["started"] = time.time()
        cur["retries"] = int(cur.get("retries", 0) or 0) + 1
        cur["up"] = 0
        st[nid] = cur
    _game_stat("direct_retry")
    return 1


def _direct_retry_wait(info):
    """A-474: eksponencialnyi backoff mezhdu popytkami HI (15..300 s)."""
    tries = int(info.get("retries", 0) or 0)
    if tries < 0:
        tries = 0
    return min(float(DIRECT_RETRY_MAX_S),
               float(DIRECT_RETRY_MIN_S) * (2 ** min(tries, 4)))


def _direct_socket(bind_addr=""):
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except OSError:
        pass
    if bind_addr:
        try:
            s.bind((bind_addr, 0))
        except OSError:
            pass
    # A-457: zapоминаem SVOY sobstvennyy UDP-endpoint. Ranee port vyshis'
    # po zapisi kanala v _STATE["direct"], a tam klyuch - id SOSEDA, poetomu
    # zapisi pod "ya" nikogda ne bylo, port ne nahodilsya i publichnyy
    # endpoint ne ukhodil masteru (T_DIRECT MINE|...), a pryamoy kanal ne
    # podnimalsya: HI ukhodil na mesh-port vmeshesto pryamogo UDP.
    try:
        _port = int(s.getsockname()[1])
    except (OSError, IndexError, TypeError, ValueError):
        _port = 0
    if _port:
        with _LOCK:
            _STATE["direct_local"] = {"port": _port, "at": time.time()}
    return s


def _direct_state():
    """{nid: {sock, addr, nonce, up, down, sent, recv, rtt_ms, last, known}}"""
    with _LOCK:
        st = _STATE.setdefault("direct", {})
        if not isinstance(st, dict):
            st = {}
            _STATE["direct"] = st
        return st


def _direct_targets(dst):
    """Kakie pryamye kanaly dolzhny poluchit' etot paket: unicast - tolko
    vladeletsu adresa, broadcast/multicast/svoy segment - vsem zhivym."""
    me = str(_STATE.get("node_id", "") or "")
    bcast = _raw_is_bcast(dst)
    prefix = "10.%d." % GAME_GROUP
    my_addr = game_address(me)
    # A-435-fix3: VSE igrovye adresa konchayutsya na ".1" (10.<gruppa>.<uzel>.1),
    # poetomu staraya proverka na ".1" schitala LYUBOY unicast "svoim segmentom"
    # i rassylala paket VSEM kanalam gruppy. Segmentom schitaetsya tolko
    # broadcast/setevoy adres gruppy (10.<gruppa>.<x>.0 ili .255).
    own_segment = (bool(my_addr) and dst.startswith(prefix)
                   and dst != my_addr and _is_segment_addr(dst))
    out = []
    with _LOCK:
        st = dict(_STATE.get("direct", {}) or {})
    for nid, info in st.items():
        if not isinstance(info, dict) or nid == me or nid in _NO_GAME_IDS:
            continue
        if not info.get("up") or info.get("sock") is None:
            continue
        if not bcast and not own_segment and game_address(nid) != dst:
            continue
        out.append((nid, info))
    return bcast, own_segment, out


def _game_peers_now():
    """Zhivye igrovye sosedy po sostoyaniyu sebe: id -> {addr, rtt}. Sluzhebnye
    uzly (master/test) i uzly bez zhivogo soketa isklyuchayutsya."""
    me = str(_STATE.get("node_id", "") or "")
    out = {}
    with _LOCK:
        rows = dict(_STATE.get("peers", {}) or {})
    for nid, row in rows.items():
        if nid == me or nid in _NO_GAME_IDS:
            continue
        if not isinstance(row, dict) or row.get("sock") is None:
            continue
        addr = _parse_addr(str(row.get("addr") or ""))
        if not addr or not addr[0]:
            continue
        endpoint = "%s:%d" % (addr[0], int(addr[1] or MESH_PORT))
        # A-456: esli sosed opublikoval svoy pryamoy UDP-endpoint, berem ego,
        # a ne mesh-adres: inache HI-datagramma ushla by v port tunnelya.
        pub = _direct_pub_get(nid)
        if pub and _parse_addr(pub)[0]:
            endpoint = pub
        out[str(nid)] = {"addr": endpoint,
                         "rtt": int(row.get("rtt_ms", 0) or 0),
                         "mesh": endpoint != pub}
    return out


def _game_stat(name, delta=1):
    with _LOCK:
        st = _STATE.setdefault("game", {})
        st[name] = int(st.get(name, 0) or 0) + delta
        return st[name]


def _guest_row_for(body):
    """A-745 (A-745_MARK): lokalnyi pir, kotoromu adresovan paket - gost,
    podklyuchivshiysya k etomu uzlu. vozvrashchaet (node_id, row, dst) libo None.

    Tolko dlya paketov, adresovannyh NE nam: sobstvennye adresa, kak i ranshe,
    inzhektitsya v nash adapter."""
    try:
        _src, dst = _raw_endpoints(bytes(body or b""))
    except Exception:
        return None
    if not dst:
        return None
    me = str(_STATE.get("node_id", "") or "")
    if dst == game_address(me):
        return None
    try:
        with _LOCK:
            rows = dict(_STATE.get("peers", {}) or {})
    except Exception:
        return None
    for nid, row in rows.items():
        nid = str(nid)
        if nid == me or nid in _NO_GAME_IDS:
            continue
        if not isinstance(row, dict) or row.get("sock") is None:
            continue
        if game_address(nid) != dst:
            continue
        return nid, row, dst
    return None


def _is_segment_addr(dst):
    """Broadcast/setevoy adres igrovoj gruppy (10.<gruppa>.<x>.0 ili .255).
    VSE igrovye adresa uzlov konchayutsya na .1, poetomu oni NE segment -
    inache unicast k sosedu rassylalsya by VSEM kanalam (A-435-fix3)."""
    octets = str(dst or "").split(".")
    if len(octets) != 4:
        return False
    for o in octets:
        if not o.isdigit():
            return False
    # A-435-fix4: "0" v poslednem oktete - eto setevoy adres /24
    # (10.<gruppa>.<uzel>.0), on takzhe rassylaetsya vsem, a ne tolko vladeltsu.
    return octets[2] == "0" or octets[3] in ("0", "255")


def _raw_endpoints(pkt):
    """A-433: (src, dst) iz IPv4-zagolovka. Pusto, esli paket ne IPv4 / korotkij."""
    if len(pkt) < 20:
        return "", ""
    if ((pkt[0] >> 4) & 0x0F) != 4:
        return "", ""
    return (socket.inet_ntoa(pkt[12:16]), socket.inet_ntoa(pkt[16:20]))


def _raw_is_bcast(dst):
    """A-433: broadcast/multicast ili adres svoyey podseti — takoy paket
    rassylaetsya VSEM uzelam gruppy (reshenie vladelca «broadcast yes»)."""
    if not dst:
        return False
    parts = dst.split(".")
    if len(parts) != 4:
        return False
    try:
        oktets = [int(x) for x in parts]
    except ValueError:
        return False
    if oktets[3] == 255:
        return True
    return oktets[0] >= 224          # multicast 224.0.0.0/4


def _raw_mine(pkt):
    # A-461: etot syryj paket mozhno vpustit v nash virtualnyj adapter?
    # Reley cherez master prinodit vse, chto master rassylal, a master ne znaet,
    # komu imenno paket. Bez proverki chuzhie unicast-pakety prishli by v nashi
    # adaptery (i uzhe v sistemnuyu set game-processa).
    body = bytes(pkt or b"")
    if len(body) < 20:
        return False
    _src, dst = _raw_endpoints(body)
    if not dst:
        return False
    my_addr = game_address(str(_STATE.get("node_id", "") or ""))
    if not my_addr:
        return False
    if dst == my_addr:
        return True
    if _raw_is_bcast(dst) or _is_segment_addr(dst):
        return dst.startswith("10.%d." % GAME_GROUP)
    return False


def _relay_raw(from_id, pkt, key=None):
    # A-461: master prinimaet syroy paket uzla i rassylaet vsem ostalnym
    # u zlam krugy otpravitelya. Master v adapter ne pishet - on sluzhebnyy
    # uzel, igrovykh adresov ne imeet.
    body = bytes(pkt or b"")
    # A-483: rely, a ne pryamoy UDP - svist limit DIRECT_UDP_MAX.
    if not body or len(body) > RELAY_MAX:
        _game_stat("dropped_bad_len")
        return 0
    _src, dst = _raw_endpoints(body)
    if not dst:
        _game_stat("dropped_not_ipv4")
        return 0
    try:
        if key is None:
            key = _keybytes(_secret())
    except Exception:
        return 0
    me = str(_STATE.get("node_id", "") or "")
    # A-489: master rassylaet tolko adresatu - kak na uzle v raw_send (A-433b).
    # Bez etogo lyuboy unicast-paket sholsya vseomu pivu (pri N>2 uzlach trafik
    # mnozhilsya na N-1) i master ne proveral, chto dst voobshche iz gruppy
    # 10.<GAME_GROUP>.* - to est proverka adresata byla tolko na prieme uzla.
    bcast = _raw_is_bcast(dst)
    # A-490: gruppa beretsya iz SAMOGO dst, a ne iz GAME_GROUP mastera:
    # u mastera svoey igrovoy gruppy net (env AURORA_MESH_GROUP zadayotsya na
    # uzle), a dst mozhet prinadlezhat lyuboy gruppe.
    grp = game_group_of(dst)
    segment = bcast or _is_segment_addr(dst)
    with _LOCK:
        peers = dict(_STATE.get("peers", {}) or {})
    cand = [nid for nid in peers
            if nid != me and nid != from_id and nid not in _NO_GAME_IDS
            and isinstance(peers.get(nid), dict)
            and peers[nid].get("sock") is not None]
    # A-827 (Ш8): ЗДЕСЬ галка allow_relay НЕ проверяется, и это не oversight.
    # _relay_raw доставляет пакет ВЛАДЕЛЬЦУ адреса dst — то есть адресат
    # в списке targets и есть тот самый узел. Это ПРЯМАЯ доставка через
    # мастера, а не транзит чужого трафика. Гейт по галке здесь убил бы
    # всю игру (нет галки => сеть молчит), и это была бы моя регрессия.
    # Настоящий транзит (узел как выход для группы) в коде отсутствует —
    # см. mesh.relay_eligible() и честный долг в SYNC.md.
    targets = []
    if segment or not grp:
        # broadcast / setevoy adres / vneshniy server - vsem, kak do A-489.
        targets = cand
    else:
        targets = [nid for nid in cand if game_address_in(nid, grp) == dst]
        if not targets:
            # A-490: vladeleca adresa sredi_peerov net - NE RVM RELEY, otdayom
            # vsem (kak do A-489). Priem uzlа otfiltruyet chuzhoy unicast
            # cherez _raw_mine, a trafik ne pogibayet iz-za metadannyh.
            targets = cand
            _game_stat("relay_owner_unknown")
    sent = 0
    for nid in targets:
        row = peers[nid]
        try:
            _send_row(row, T_RAW, body, key)
            sent += 1
        except OSError:
            _game_stat("relay_failed")
            # A-730: soket pira myortv. Ranee zdes byl tolko schetchik, a sam
            # soket ostavalsya v peerah navsegda, i kazhdyy sleduyushchiy paket
            # snova pisalsya v nego, schetchik "sent" rast, hotya trafik
            # nichego ne dostaval. Teper osvobozhdaem soket po uzhe zavedennoy v
            # proekte semantike A-194/A-200: zapis pira ostaetsya (ee vidit
            # panel), no pisat v nego bolshe nechego.
            try:
                _release_peer_sock(nid, row.get("sock"))
            except Exception:
                pass
            _game_stat("relay_peer_gone")
            # A-730b: na uzlah takuyu diagnostiku dala A-697 (relay-nosock,
            # relay-failed), a master pro otkaz molchal VOOBSHCHE - iz-za etogo
            # schetchiki _game_stat nevidimy i fix neproverim v loge.
            _diag_throttled("relay-peer-gone", nid,
                            "soket pira myortv, paket %d B poteryan" % len(body))
    if sent > 0:
        _game_stat("relayed")
    else:
        # A-730: `relayed` bolshe ne rostet, kogda nikto nichego ne poluchil.
        # Raneto schetchik uspeha kruzhal pusto. Teper eto chitayemyj otkaz.
        _game_stat("relay_no_target")
        # A-730b: i etot otkaz viden v loge, a ne tolko v schetchike.
        _diag_throttled("relay-no-target", from_id,
                        "net poluchatelya, %d B poteryano (peers=%d)"
                        % (len(body), len(peers)))
    _game_stat("relay_forwarded", sent)
    _diag("relay-fwd", from_id,
          "dst=%s bytes=%d sent=%d peers=%d" % (dst, len(body), sent, len(peers)))
    return sent


def _relay_up(pkt, key=None):
    # A-461: pryamogo kanala net (NAT ne probroshen) - ne voryuem "net marshruta",
    # a chestno otdayom syryj paket masteru cherez uzhe otkrytyy tunel.
    # A-697: body schitaem SRAZU, do proverki soketa. Inache novaya diagnostika
    # v vetve otkaza obrashchalas' k peremennoy, kotoraya eshche ne ob'yavlenа,
    # i padala s NameError imenno tam, gde dolzhna byla pomogat' s otkazom.
    body = bytes(pkt or b"")
    up = _STATE.get("up", {}) or {}
    sock = up.get("sock")
    if sock is None:
        _game_stat("no_relay")
        # A-697: раньше это был МОЛЧАЛИВЫЙ отказ — только счётчик, ни одной
        # строки в лог. При обрыве туннеля к мастеру пакеты умирали молча, и
        # 800 пакетов флуда выглядели как «транзит не работает», хотя причина
        # была в отсутствии сокета (05.10.2026 измерено: no_relay=800 ровно
        # по объёму флуда, relayed за это время не вырос). Отказ делаем видимым.
        _diag_throttled("relay-nosock", _STATE.get("node_id", ""),
                        "net soketa k masteru, %d Б otbrosheno" % len(body))
        return 0
    # A-483: rely, a ne pryamoy UDP - svist limit DIRECT_UDP_MAX.
    if not body or len(body) > RELAY_MAX:
        _game_stat("dropped_bad_len")
        return 0
    try:
        if key is None:
            key = _keybytes(_secret())
    except Exception:
        _game_stat("no_relay")
        return 0
    try:
        _send(sock, T_RAW, body, key)
    except OSError:
        _game_stat("relay_failed")
        # A-697: kak i no_relay, sdacha na master ne voskresla molcha.
        _diag_throttled("relay-failed", _STATE.get("node_id", ""),
                        "sdacha masteru ne udalas, %d Б poteryano" % len(body))
        return 0
    _game_stat("relayed")
    _diag("relay-up", _STATE.get("node_id", ""), "bytes=%d" % len(body))
    return 1


def _send_license(conn, key, token, credential):
    """A-307: otdayot licenziyu uzla po tomu zhe tonnelu, chto i politiku.

    Tolko rol master, i tolko s zaprosom samogo uzla: komercicheskaya logika
    uzela ne dubliiruetsya - beretsya gotovaya api._ext_config (fail-closed).
    """
    if _STATE.get("started") != "master":
        return False
    token = str(token or "").strip()[:128]
    credential = str(credential or "").strip()[:256]
    if not token:
        return False
    try:
        import api
        code, payload = api._ext_config(token, credential)
    except Exception:
        payload = None
    if not isinstance(payload, dict):
        payload = {"ok": False, "plan": "free", "blocked": False}
    try:
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    except (TypeError, ValueError):
        return False
    if len(body) > MAX_LICENSE_PAYLOAD:
        return False
    _send(conn, T_LICENSE, body, key)
    return True


def direct_announce_peers():
    """Master: rassylayet spisok igrovykh sosedey vsem igrovym uzlam. Spisok
    podpisan grant-tokenom, starye/pozhiee sosedya otpadayut samostoyatel'no."""
    # A-453: master-side diagnostics. Until this was logged we only saw
    # peers_live=0 on the nodes and could not tell whether the master has
    # no game peers at all, or filters them out, or is "no_game" itself.
    # A-498: sostoyanie sobiraem odno, pishem tolko pri izmenenii.
    try:
        with _LOCK:
            allp = sorted((_STATE.get("peers", {}) or {}).keys())
            socks = sum(1 for r in (_STATE.get("peers", {}) or {}).values()
                        if isinstance(r, dict) and r.get("sock") is not None)
    except Exception as exc:
        allp, socks = [], 0
        _note("peer-list", "ne prochitan: %s" % exc, level="error")
    peers = _game_peers_now()
    # A-691: `all=`/`socks=` выше меряют ПИРЫ MESH-ТУННЕЛЯ (_STATE["peers"]),
    # а игровые прямые каналы живут в _direct_state(). Поэтому на игровом узле
    # all=0 — это НЕ поломка контура, а просто другой счётчик, и по нему нельзя
    # судить о транзите. 05.10.2026 на этой строке ловили ложную тревогу двое
    # (приёмка «peers_live=0» и мой разбор extgate). Добавляю настоящие числа
    # по прямому контуру; старые поля не убираю, чтобы ничего не сломать.
    try:
        _dst = dict(_direct_state() or {})
        d_all = len(_dst)
        d_up = sum(1 for i in _dst.values()
                   if isinstance(i, dict) and i.get("up"))
        d_sock = sum(1 for i in _dst.values()
                     if isinstance(i, dict) and i.get("sock") is not None)
        d_nat = sum(1 for i in _dst.values()
                    if isinstance(i, dict) and i.get("nat_shared"))
    except Exception as exc:
        d_all = d_up = d_sock = d_nat = -1
        _note("direct-state", "ne prochitan: %s" % exc, level="error")
    _diag_throttled("game-announce", "",
                    "enabled=%s no_game=%s role=%s me=%s peers=%d all=%d socks=%d"
                    " direct=%d d_up=%d d_sock=%d d_nat=%d" % (
                        game_enabled(), no_game(),
                        str(_STATE.get("started", "") or "")[:12],
                        str(_STATE.get("node_id", "") or "")[:24],
                        len(peers), len(allp), socks,
                        d_all, d_up, d_sock, d_nat))
    if not peers:
        return 0
    try:
        key = _keybytes(_secret())
    except Exception:
        key = b""
    # A-480: STABILNYI nonce na paru master<->uzel. Ranee master generiroval
    # novyy nonce (os.urandom(8)) na KAZHDYY anonim, t.e. kazhdye
    # DIRECT_INTERVAL_S (5 s). _direct_handshake() na storone uzla otvechaet
    # tolko na nonce, ravnyy TEKUSHCHEY known_nonce (stroka proverki "not
    # nonce == info.get("known_nonce)"), a uzel otpravlyaet HI pryamo v
    # direct_inbox() -> direct_try(). HI uzla mog pryti k sosedu ran'she,
    # chem sosed obrabotit svoy spisok s tem zhe nonce => otkaz, pryamoy
    # kanal ne podnimaetsya do ocherdnogo backoff-a (15..300 s).
    # Teper nonce zhivyet v keshe _STATE["direct_nonce"] pod klyuchem
    # "<nid>|<addr>" i menyetsya TOLKO pri smene addr soseda; grant
    # schitaetsya ot (nid, nonce), tak chto ostaetsya validnym.
    nonce_cache = _STATE.setdefault("direct_nonce", {})
    parts = []
    fresh_nonce = 0
    need_pub = []
    for nid in sorted(peers):
        addr = str(peers[nid].get("addr") or "")
        ckey = "%s|%s" % (nid, addr)
        nonce = str(nonce_cache.get(ckey, "") or "")
        if len(nonce) != 16:
            nonce = os.urandom(8).hex()
            try:
                with _LOCK:
                    stale = [k for k in list(nonce_cache.keys())
                             if str(k).split("|", 1)[0] == nid and k != ckey]
                    for k in stale:
                        nonce_cache.pop(k, None)
                    nonce_cache[ckey] = nonce
            except Exception:
                pass
            fresh_nonce += 1
            _game_stat("direct_nonce_new")
        else:
            _game_stat("direct_nonce_reuse")
        # A-481: uzel ne opublikoval svoy pryamoy UDP-endpoint (posle restarta
        # mastera kesh _direct_pub pust) => prosim perеopublikovat.
        if peers[nid].get("mesh"):
            need_pub.append(nid)
        parts.append("%s|%s|%s|%s" % (nid, addr, nonce,
                                      _direct_grant(nid, nonce)))
    text = ";".join(parts).encode("utf-8")
    if len(text) > MAX_RAW_PAYLOAD:
        return 0
    me = str(_STATE.get("node_id", "") or "")
    sent = 0
    asked = 0
    with _LOCK:
        rows = dict(_STATE.get("peers", {}) or {})
    for nid, row in rows.items():
        if nid == me or nid in _NO_GAME_IDS:
            continue
        if not isinstance(row, dict) or row.get("sock") is None:
            continue
        try:
            _send_row(row, T_GAME_PEERS, text, key)
            sent += 1
            # A-481: prosba perеopublikovat' pryamoy UDP-endpoint
            if nid in need_pub:
                _send_row(row, T_DIRECT, b"MINE?", key)
                asked += 1
        except OSError:
            pass
    if fresh_nonce or asked:
        _diag_throttled("game-announce", "",
                        "peers=%d fresh_nonce=%d ask_republish=%d" % (
                            len(peers), fresh_nonce, asked))
    if asked:
        _game_stat("direct_republish_asked")
    return sent


def direct_inbox(msg_type, payload, key=None):
    """Obrabotka T_GAME_PEERS / T_DIRECT na storone uzla."""
    # A-455: log what the master actually sent us. Until now the nodes
    # only reported peers_live=0, so it was impossible to tell whether
    # the list never arrived, arrived empty, or was rejected.
    if msg_type == T_GAME_PEERS:
        try:
            _kn = _direct_known(payload)[1]
            _one = list(_kn.values())[0] if _kn else {}
            _diag_throttled("game-inbox", "",
                            "payload=%d known=%d sample_addr=%s me=%s" % (
                                len(bytes(payload)), len(_kn),
                                str((_one or {}).get("addr", ""))[:32],
                                str(_STATE.get("node_id", "") or "")[:16]))
        except Exception as exc:
            # A-498: ranee zdes bylo `except Exception: pass` - myagkoe zakrytie
            # skryvalo polomku samoy diagnostiki. Pishem prichinu.
            _note("game-inbox", "razbor ne udalsya: %s" % exc, level="error")
        order, known = _direct_known(payload)
        if not order:
            return True
        st = _direct_state()
        with _LOCK:
            for nid, info in known.items():
                st.setdefault(nid, {}).update(
                    {"known_addr": info["addr"], "known_nonce": info["nonce"],
                     "known_grant": info["grant"], "known_at": time.time()})
        direct_try()
        return True
    if msg_type == T_DIRECT:
        raw = bytes(payload)
        # A-481: master prosit perеopublikovat' pryamoy UDP-endpoint
        # (soobshchenie "MINE?"). Bez etogo master posle restarta ne znaet
        # pryamogo adresa uzla i otpravlyaet HI v mesh-port 51821, a pryamoy
        # kanal mezh igrovymi uzlami ne podnimaetsya voobshche.
        try:
            if raw[:5].upper() == b"MINE?":
                _diag("game-republish", "",
                      "asked by master me=%s" % (
                          str(_STATE.get("node_id", "") or "")[:24],))
                direct_publish(None, force=True)
                return True
        except Exception:
            pass
        return _direct_handshake(raw)
    return False


def direct_info():
    """Bezopasnaya svodka pryamyh kanalov (bez sekretov).

    A-755: каждый канал теперь несёт ещё age_master — сколько секунд назад узел
    последний раз видел мастера (из политики туннеля). Это НЕ примешивается
    отдельной записью в список пиров: список остаётся списком пиров, иначе
    потребители, которые ищут запись по node_id, получат чужой элемент.
    Плашка «работаю на кэше, мастер не отвечает с 14:32» собирается из этих
    чисел плюс autonomy из mesh.policy_autonomy() (см. game_info).
    """
    now = time.time()
    out = []
    with _LOCK:
        st = dict(_STATE.get("direct", {}) or {})
    me = str(_STATE.get("node_id", "") or "")
    age_master = -1
    try:
        import mesh as _mesh
        age_master = int(_mesh.policy_autonomy().get("age_s", -1))
    except Exception:
        # Сводка не должна падать из-за необязательной связи с mesh.
        age_master = -1
    for nid in sorted(st):
        if nid == me:
            continue
        info = st.get(nid)
        if not isinstance(info, dict):
            continue
        last = float(info.get("last", 0) or 0)
        up = bool(info.get("up"))
        out.append({"id": nid, "up": up,
                    "mode": "direct" if up else "relay",
                    "retries": int(info.get("retries", 0) or 0),
                    "sent": int(info.get("sent", 0) or 0),
                    "recv": int(info.get("recv", 0) or 0),
                    "age": int(max(0.0, now - last)),
                    "age_master": age_master,
                    "rtt_ms": int(info.get("rtt_ms", 0) or 0)})
    return out


def direct_loop():
    """Fonovy potok: obnovlyaet pryamye kanaly, a na mastere - rassylayet spisok
    sosedey. Odin potok na process, start idetempotentno."""
    global _DIRECT_LOOP
    with _LOCK:
        if _STATE.get("direct_loop"):
            return False
        _STATE["direct_loop"] = True
    def run():
        while not _STATE.get("stop"):
            try:
                # A-454: master samiy ne igrovoj uzel (no_game = True po roli),
                # no imenno on znaet VSEH igrovykh sosedey i imenno on
                # rassylaet ikh spisok. Staraya proverka "if not no_game()"
                # propuskala etot shag, i T_GAME_PEERS voobsche ne uhodila -
                # pryamoy kanal mezh igrovymi uzlami ne podnimalsya.
                if not no_game() or str(_STATE.get("started", "") or "") == "master":
                    direct_announce_peers()
                direct_try()
                # A-827 (Ш7): сервер группы переключается ЗДЕСЬ, а не по кнопке
                # в панели: панель могут закрыть, а переключиться всё равно надо.
                if game_enabled():
                    try:
                        game_server_maybe_switch()
                    except Exception as exc:
                        _note("game-server-fail",
                              "%s: %s" % (type(exc).__name__, exc), level="error")
                # A-456: kazhdyy tsikl soobshchaem svoy pryamoy endpoint
                # (idempotentno - tozhe, i vspyatku ne shlem).
                try:
                    direct_publish()
                except Exception:
                    pass
            except Exception:
                pass
            time.sleep(DIRECT_INTERVAL_S)
        with _LOCK:
            _STATE["direct_loop"] = False
    threading.Thread(target=run, name="mesh-direct", daemon=True).start()
    return True


def direct_publish(key=None, force=False):
    """Uzel soobshchaet masteru svoy pryamoy UDP-endpoint (T_DIRECT MINE|...)."""
    if not game_enabled():
        return 0
    me = str(_STATE.get("node_id", "") or "")
    endpoint = _direct_pub_local()
    if not endpoint:
        # A-459: net socketa ili net svoyego porta => nichego publikovat nelzya
        _diag("game-publish", me, "skip=no-endpoint direct_local=%s" % (
            _STATE.get("direct_local"),))
        return 0
    if _direct_pub_get(me) == endpoint and not force:
        # A-459: idempotentnyj vyhod, uzhe opublikovano - eto norma, ne bug
        # A-481: no s "force" eta vetv blokirovala otvet na prosbu mastera
        # "MINE?" - master posle restarta poteryal _direct_pub i ne znal
        # pryamogo UDP-adresa uzla, a uzlu bylo nevozmozhno soobshchit'
        # endpoint snova.
        _diag("game-publish", me, "skip=already endpoint=%s" % (endpoint,))
        return 0
    if key is None:
        try:
            key = _secret()
        except Exception:
            key = b""
    if not key:
        return 0
    text = ("MINE|%s" % endpoint).encode("ascii", "replace")
    with _LOCK:
        rows = dict(_STATE.get("peers", {}) or {})
    sent = 0
    cand = 0
    nogo = 0
    for nid, row in rows.items():
        if nid == me or nid in _NO_GAME_IDS:
            continue
        cand += 1
        if not isinstance(row, dict) or row.get("sock") is None:
            nogo += 1
            continue
        try:
            _send_row(row, T_DIRECT, text, key)
            sent += 1
        except OSError:
            continue
    # A-460: uzel-KLIENT ne imeet pryamykh mesh-soketov k sosedyam, vse igrovye
    # uzly - tozhe klienty: _STATE["peers"] u nikh pusto (rows=0 v A-459),
    # poetemu rassylat MINE| sosedam prosto nechego i pryamoy kanal mezh
    # igrovymi uzlami nikogda ne podnimalsya. No u uzla VSEGDA est otkrytyy
    # tunnel k masteru - _STATE["up"]["sock"] (sohranyaetsya v _announce_loop
    # posle T_HELLO/T_OK). Shlem endpoint emu: master prinimaet T_DIRECT
    # "MINE|..." v _peer_reader, sohranyaet _direct_pub_set(node_id, ep) i
    # podstavlyaet opublikovannye adresa v spisok sosedey (T_GAME_PEERS).
    sent_up = 0
    up = _STATE.get("up", {}) or {}
    upsock = up.get("sock") if isinstance(up, dict) else None
    have_up = 1 if upsock is not None else 0
    if upsock is not None:
        try:
            _send(upsock, T_DIRECT, text, key)
            sent_up = 1
        except OSError:
            sent_up = 0
    # A-459/A-460: vsegda odna stroka diagnostiki, chtoby bylo vidno PRICHINU
    _diag("game-publish", me,
          "endpoint=%s rows=%d cand=%d no_sock=%d sent=%d up=%d sent_up=%d" % (
              endpoint, len(rows), cand, nogo, sent, have_up, sent_up))
    if sent or sent_up:
        _direct_pub_set(me, endpoint)
        _game_stat("direct_published")
    return sent + sent_up


def direct_send(pkt, key=None):
    """Otpravit syryy IP-paket PO PRYAMYM KANALAM, a esli pryamogo kanala net
    (NAT ne probroshen) - chestno cherez master (A-461 rely)."""
    if not game_enabled():
        _game_stat("dropped_not_game")
        return 0
    if not pkt or len(pkt) > DIRECT_UDP_MAX:
        _game_stat("dropped_bad_len")
        return 0
    _src, dst = _raw_endpoints(pkt)
    if not dst:
        _game_stat("dropped_not_ipv4")
        return 0
    # A-475: snachala pryamye UDP-kanaly, tolko potom rely cherez master
    # (reshenie A-432 p.3).
    sent = _direct_dispatch(pkt, key, dst)
    if sent:
        return sent
    # Ranee zdes bylo "no_route" i myalo - mezh dvumya NAT-uzlami trafik
    # voobsche ne kholodil.
    sent_relay = _relay_up(pkt, key)
    if sent_relay:
        return sent_relay
    _game_stat("no_route")
    return 0


def direct_try():
    """Initsiator nachinaet pryamye kanaly k tem uzlam, kotorye nas zovut."""
    if not game_enabled():
        return 0
    me = str(_STATE.get("node_id", "") or "")
    st = _direct_state()
    started = 0
    with _LOCK:
        items = [(nid, dict(info)) for nid, info in st.items() if isinstance(info, dict)]
    for nid, info in items:
        if nid in _NO_GAME_IDS or nid == me:
            continue
        # A-461: staryy gate "me >= nid" znal tolko odin initsiator na paru
        # ("men'shiy" id zvonit). Esli u nego kanal ne podnyalsya - nikto
        # bolshe ne probil, a direct_try zhdal DIRECT_IDLE_S (300 s) i pri
        # zhivom sokete voobsche ne posylal novyy HI. Teper kazhdyy uzel
        # probivayet svoy kanal, a esli soket uzhe est - prosto posylayet
        # novyy HI po zhivomu soketu (de-sinxronizatsiya hole punching).
        if info.get("up") and (time.time() - float(info.get("last", 0) or 0)) < DIRECT_IDLE_S:
            continue
        addr = info.get("known_addr") or ""
        nonce = info.get("known_nonce") or ""
        if not addr or not nonce:
            continue
        # A-474: ranee HI posylalsya KAZHDYH 5 s poka kanal ne podnyalsya,
        # a pryamoy UDP za odnim NAT nevozmozhen voobsche -> beskonechnyi shum.
        # Teper: obshchii publichnyi IP -> chestnaya metka "relay only" i bez
        # popytok; inache eksponencialnyi backoff.
        if not info.get("up"):
            if _direct_nat_shared(addr):
                if not info.get("nat_shared"):
                    with _LOCK:
                        cur = dict(st.get(nid) or {})
                        cur["nat_shared"] = 1
                        st[nid] = cur
                    _game_stat("direct_nat_shared")
                    _diag("direct-nat", nid, "odin publichnyi IP - pryamoy UDP nevozmozhen, tolko relej")
                continue
            if info.get("nat_shared"):
                # A-476: staryy setchik "odin NAT" bolshe ne vernost - publichnyy
                # IP sosedа ili moy izmenilsya, pryamoy UDP snova v proze.
                with _LOCK:
                    cur = dict(st.get(nid) or {})
                    cur.pop("nat_shared", None)
                    st[nid] = cur
                _game_stat("direct_nat_cleared")
                _diag("direct-nat-clear", nid, "obshchego publichnogo IP net - pryamoy UDP snova proveryaetsya")
                info = cur
            wait = _direct_retry_wait(info)
            if (time.time() - float(info.get("started", 0) or 0)) < wait:
                continue
        if info.get("sock") is not None:
            started += _direct_retry(nid, info, addr, nonce)
            continue
        started += _direct_initiate(nid, addr, nonce)
    return started


def _relay_allowed(nid):
    """A-827 (Ш8): узел ИМЕЕТ ПРАВО релеить чужой игровой трафик.

    Fail-closed по трём причинам разом. Первая — узла нет в реестре. Вторая —
    галка не выставлена (владелец её не давал). Третья — узел служебный.

    Модуль НЕ знает про mesh.py (иначе круговой импорт: mesh тянет эту же
    подсистему), поэтому источник галок внедряется через mesh_optins(). Если
    подсистема не подключена или узел не найден — отказ, а не «разрешить»."""
    getter = _STATE.get("mesh_optins")
    if not callable(getter):
        return False
    try:
        flags = getter(nid)
    except Exception:
        return False
    if not isinstance(flags, dict):
        return False
    if flags.get("no_relay") is True:
        return False
    return flags.get("allow_relay") is True


# A-827 (Ш7): игровой сервер группы. Узел помнит, ЧЕЙ сервер выбран, сам
# переключается при перегрузе и честно показывает причину смены.
# Ключи состояния — в _STATE["game_server"], чтобы не плодить глобалы.
_GAME_SERVER_KEYS = ("host", "since", "switches", "reason")


def game_server_state():
    """Текущий игровой сервер группы + счётчики. Без секретов."""
    with _LOCK:
        st = dict(_STATE.get("game_server", {}) or {})
    for key in _GAME_SERVER_KEYS:
        st.setdefault(key, 0 if key != "host" else "")
    hosts = dict(_STATE.get("game_hosts", {}) or {})
    st["candidates"] = sorted(hosts)
    st["hosts"] = hosts
    return st


def game_server_candidates():
    """Узлы группы, годные в игровые серверы: живые, не я, не служебные.

    Сортируются по измеренному RTT (0 = не измерен -> в конец, чтобы
    непомеченное не обгоняло замеренное по счастливой сортировке)."""
    me = str(_STATE.get("node_id", "") or "")
    with _LOCK:
        rows = dict(_STATE.get("peers", {}) or {})
    out = []
    for nid, row in rows.items():
        if nid == me or nid in _NO_GAME_IDS or nid.startswith(_NO_GAME_IDS):
            continue
        if not isinstance(row, dict) or row.get("sock") is None:
            continue
        rtt = int(row.get("rtt_ms", 0) or 0)
        out.append({"node_id": nid, "address": game_address(nid), "rtt_ms": rtt,
                    "measured": rtt > 0})
    out.sort(key=lambda r: (0 if r["measured"] else 1, r["rtt_ms"] or 10 ** 6, r["node_id"]))
    return out


def game_server_set(host):
    """Выбрать игровой сервер. Возвращает (ok, error).

    Fail-closed: несуществующий/служебный/мёртвый узел не принимается,
    потому что «сервер выбран, а играть не с кем» хуже, чем честный отказ."""
    host = str(host or "").strip()
    if not host:
        return False, "не указан узел"
    # A-827 (Ш4): свой игровой сервер есть только у владельца группы.
    # В сценарии «свой прокси» и «гость» сервер выбрать нельзя — иначе
    # панель показала бы сервер, на котором этот узел играть не будет.
    if _scenario() != "friends":
        return False, "свой игровой сервер доступен только в сценарии «играть с друзьями»"
    with _LOCK:
        me = str(_STATE.get("node_id", "") or "")
    if host == me:
        return False, "свой узел игровым сервером быть не может"
    if host in _NO_GAME_IDS or host.startswith(_NO_GAME_IDS):
        return False, "служебный узел игровым сервером быть не может"
    cand = game_server_candidates()
    row = next((c for c in cand if c["node_id"] == host), None)
    if row is None:
        return False, "узел не в игровой группе"
    with _LOCK:
        st = _STATE.setdefault("game_server", {})
        st["host"] = host
        st["since"] = int(time.time())
        st["reason"] = "выбрано вручную"
    return True, None


def _server_overloaded(host, rows=None):
    """A-827 (Ш7): перегружен ли выбранный сервер.

    Основание — ИЗМЕРЕННЫЕ числа, не настроение: rtt выбранного сервера
    хуже лучшего кандидата более чем в SERVER_OVERLOAD_RATIO раз. Если
    кандидатов нет или измерений нет — перегрузки не утверждаем."""
    ratio = _int_env("AURORA_MESH_GAME_OVERLOAD_RATIO", 2, 1, 10)
    best = 0
    cur = 0
    for cand in game_server_candidates():
        rtt = int(cand.get("rtt_ms", 0) or 0)
        if rtt <= 0:
            continue
        if not best or rtt < best:
            best = rtt
        if cand["node_id"] == host:
            cur = rtt
    if not best or not cur:
        return False, ""
    if cur <= best * ratio:
        return False, ""
    return True, "rtt %d мс против лучших %d мс" % (cur, best)


def game_server_maybe_switch():
    """Переключить сервер, если выбранный перегружен. Возвращает (ok, msg).

    Вызывать из цикла игрового контура, а не из панели: панель может быть
    закрыта, а переключение всё равно обязано случиться."""
    with _LOCK:
        host = str((_STATE.get("game_server", {}) or {}).get("host", "") or "")
    if not host:
        cand = game_server_candidates()
        if not cand:
            return False, ""
        pick = cand[0]
        with _LOCK:
            st = _STATE.setdefault("game_server", {})
            st["host"] = pick["node_id"]
            st["since"] = int(time.time())
            st["reason"] = "выбран автоматически"
        _diag_throttled("game-server", pick["node_id"],
                        "avtovybor rtt=%d" % pick.get("rtt_ms", 0))
        return True, "автовыбор сервера %s" % pick["node_id"]
    over, why = _server_overloaded(host)
    if not over:
        return False, ""
    for cand in game_server_candidates():
        if cand["node_id"] == host or not cand["measured"]:
            continue
        with _LOCK:
            st = _STATE.setdefault("game_server", {})
            st["host"] = cand["node_id"]
            st["since"] = int(time.time())
            st["switches"] = int(st.get("switches", 0) or 0) + 1
            st["reason"] = why
        _diag_throttled("game-server", cand["node_id"],
                        "pereklyuchenie: %s" % why)
        return True, "сервер переключён на %s (%s)" % (cand["node_id"], why)
    return False, ""


SCENARIOS = ("friends", "proxy", "guest")
_SCENARIO_LABELS = {
    "friends": "играть с друзьями",
    "proxy": "свой прокси",
    "guest": "подключили к чужой Aurora",
}
_SCENARIO_HINTS = {
    "friends": "поднимает игровую TUN-подсеть, ждёт группу и выбирает игровой сервер",
    "proxy": "только прокси: туннель и ключи, игровой адаптер не поднимается",
    "guest": "работает в чужой группе как гость: свой игровой сервер выбрать нельзя",
}


def _scenario():
    """Текущий сценарий. Пусто = ещё не выбран (стартовый экран)."""
    value = ""
    try:
        value = str(config.get("game_scenario", "") or "").strip().lower()
    except Exception:
        value = ""
    return value if value in SCENARIOS else ""


def game_scenarios():
    """Все три сценария с честными подписями для панели."""
    cur = _scenario()
    out = []
    for name in SCENARIOS:
        out.append({"id": name, "label": _SCENARIO_LABELS[name],
                    "hint": _SCENARIO_HINTS[name], "current": name == cur,
                    # Гость не может быть своим игровым сервером — это право
                    # владельца группы, а не гостя.
                    "may_host": name != "guest"})
    return out


def game_scenario_set(name):
    """Выбрать сценарий. Возвращает (ok, error).

    Смена сценария меняет ТОЛЬКО этот узел: чужие Aurora он не трогает и
    чужим узлам ничего не диктует."""
    name = str(name or "").strip().lower()
    if name not in SCENARIOS:
        return False, "неизвестный сценарий: %s" % (name or "пусто")
    if _scenario() == name:
        return True, None
    try:
        config.set("game_scenario", name)
    except Exception as exc:
        return False, "не сохранился сценарий: %s" % exc
    # A-291: модуль НЕ логирует сам (в нём циркулирует секрет сети).
    # Диагностика идёт в буфер _note, откуда её читает панель.
    _note("game-scenario", "сценарий '%s' (%s)"
          % (name, _SCENARIO_LABELS[name]))
    with _LOCK:
        st = _STATE.setdefault("game_scenario", {})
        st["name"] = name
        st["since"] = int(time.time())
        # Смена сценария сбрасывает выбор сервера: «свой прокси» вообще не
        # про сервер, а «гость» не имеет права им владеть. Оставить старый
        # выбор значило бы показать панели сервер, на который нельзя играть.
        if name != "friends":
            _STATE["game_server"] = {}
    return True, None


def game_scenario_state():
    """Состояние сценария + что из этого реально включено (а не обещано)."""
    cur = _scenario()
    return {"name": cur, "label": _SCENARIO_LABELS.get(cur, "не выбран"),
            "chosen": bool(cur), "tunnel": bool(enabled()),
            "game": bool(game_enabled()), "server": game_server_state(),
            "no_game": bool(no_game())}


def game_address(node_id):
    """A-433: 10.<gruppa>.<uzel>.1 — trebovanie vladelca «10.Gruppa.Uzel.1».
    Stabilno (sha256 ot id) i ne vMESH_NET, poetomu ne putaetsya s servisami."""
    node_id = str(node_id or "").strip()
    if not _ID_RE.match(node_id):
        return ""
    digest = hashlib.sha256(("aurora-game:" + node_id).encode("utf-8")).digest()
    return "10.%d.%d.1" % (GAME_GROUP, 1 + (int.from_bytes(digest[:2], "big") % 254))


def game_address_in(node_id, group):
    """A-490: igrovoy adres uzla v LYUBOY gruppe, ne tolko v svoyey GAME_GROUP.

    Master obsluzhivaet uzly raznyh grupp (AURORA_MESH_GROUP zadayotsya na
    UZLE, u mastera env obychno net => tam GAME_GROUP=1). Esli master
    schitaet adres uzla voyey gruppoy, unicast ne sootvetstvuet dst i paket
    otbrasyvaetsya - imenno eto slomalo rely v A-489."""
    try:
        grp = int(group)
    except (TypeError, ValueError):
        return ""
    if not (1 <= grp <= 254):
        return ""
    node_id = str(node_id or "").strip()
    if not _ID_RE.match(node_id):
        return ""
    digest = hashlib.sha256(("aurora-game:" + node_id).encode("utf-8")).digest()
    return "10.%d.%d.1" % (grp, 1 + (int.from_bytes(digest[:2], "big") % 254))


def game_enabled():
    """A-433: igry razresheny tolko tam, gde tunnel vklyuchen i uzel NE sluzhebnyj."""
    return bool(enabled()) and not no_game()


def game_group_of(dst):
    """A-490: gruppa iz samogo adresa naznacheniya (10.<gr>.<uzel>.1) ili 0.

    0 = eto ne adres igrovogo uzla (vneshniy igrovoj server, broadcast
    224.x, mul'tikast i t.p.) - takuyu paketrelay ne klassificiruet."""
    octets = str(dst or "").split(".")
    if len(octets) != 4:
        return 0
    for o in octets:
        if not o.isdigit():
            return 0
    try:
        first, grp, node = int(octets[0]), int(octets[1]), int(octets[2])
    except ValueError:
        return 0
    if first != 10 or octets[3] != "1":
        return 0
    if not (1 <= grp <= 254) or not (1 <= node <= 254):
        return 0
    return grp


def game_info():
    """A-433: честное состояние игрового режима для панели.

    A-755: добавлен блок policy — сколько секунд назад мы видели мастера и на
    сколько суток вообще можем работать без него. Панель по этим числам пишет
    «работаю на кэше, мастер не отвечает с 14:32» вместо тишины.
    """
    with _LOCK:
        peers = dict(_STATE.get("peers", {}) or {})
        me = str(_STATE.get("node_id", "") or "")
    live = [n for n, r in peers.items()
            if n != me and (r or {}).get("sock") is not None]
    policy = None
    try:
        import mesh as _mesh
        policy = _mesh.policy_autonomy()
    except Exception:
        policy = None
    return {"enabled": bool(game_enabled()), "group": GAME_GROUP,
            "mtu": GAME_MTU, "me": me, "my_address": game_address(me),
            "peers_live": sorted(live), "peers_live_count": len(live),
            "no_game": bool(no_game()), "stats": game_stats(),
            "policy": policy}


def game_sink(fn):
    """A-433: adapter (meshtun) registriruet priemnik syryh paketov. Net
    adaptera — pakety schitayutsya, no nikuda ne idut (cheстno, ne tiho)."""
    with _LOCK:
        _STATE.setdefault("game", {})["sink"] = fn
    return True


def game_stats():
    with _LOCK:
        return dict(_STATE.get("game", {}))


def group_addresses(node_ids):
    """A-433: vse adresa gruppy + spisok koliziy (odin adres u dvukh uzlov —
    sozdanie gruppy dolzhno byt' zablokirovano RANO)."""
    out, seen, dupes = {}, set(), []
    for nid in node_ids or ():
        addr = game_address(nid)
        if not addr:
            continue
        if addr in seen:
            dupes.append(addr)
            continue
        seen.add(addr)
        out[nid] = addr
    return out, sorted(set(dupes))


def no_game():
    """A-433: sluzhebnyj uzel NE igrovoj. Sluzhebnye - master, test, yavno
    zadannye v AURORA_MESH_NO_GAME (perechislenie cherez zapyatuyu)."""
    flag = str(os.environ.get("AURORA_MESH_NO_GAME", "") or "").strip()
    if flag:
        return True
    role = str(os.environ.get("AURORA_MESH_ROLE", "") or "").strip().lower()
    if role in ("master", "hub", "test"):
        return True
    try:
        nid = str(_STATE.get("node_id", "") or "").strip().lower()
    except Exception:
        nid = ""
    return nid.startswith(_NO_GAME_IDS)


def raw_inject(pkt):
    """A-433: prinyat syryy paket s pita — v virtualnyj adapter (ili schitaem
    i otpuskaem, esli adaptera net)."""
    if len(pkt or b"") > MAX_RAW_PAYLOAD:
        _game_stat("dropped_bad_len")
        return False
    # A-745 (A-745_MARK_INJECT): snachala sprashivaem, komu ETO adresovan.
    # Esli eto ne my, a podklyuchivshiysya k nam gost - otdayom paket emu
    # po yego sobstvennomu tunnelu, a ne v svoj adapter.
    _guest = _guest_row_for(bytes(pkt or b""))
    if _guest is not None:
        _gid, _grow, _dst = _guest
        try:
            _gkey = _keybytes(_secret())
        except Exception:
            return False
        try:
            _send_row(_grow, T_RAW, bytes(pkt or b""), _gkey)
        except OSError:
            _game_stat("guest_forward_failed")
            _diag_throttled("guest-fwd-failed", _gid, "dst=%s" % _dst)
            return False
        _game_stat("guest_forwarded")
        _diag_throttled("guest-fwd", _gid, "dst=%s bytes=%d" % (_dst, len(pkt or b"")))
        return True
    # A-461: rely prinodit pakety ot VSEKH uzlov, a master ne znaet adresata.
    # Bez proverki "paket moy?" unicast chuzhogo uzla sidel by v nashem
    # adaptere i ukhodil v set game-processa.
    if not _raw_mine(bytes(pkt or b"")):
        _game_stat("relay_not_mine")
        return False
    with _LOCK:
        sink = _STATE.get("game", {}).get("sink")
    if not callable(sink):
        _game_stat("no_adapter")
        return False
    try:
        sink(bytes(pkt))
    except Exception:
        _game_stat("sink_error")
        return False
    _game_stat("received")
    return True


def raw_send(pkt, key=None):
    """A-433: otpravit syryy IP-paket v igrovuyu podsiet. Unicast — odnoy
    celi, broadcast/multicast/svoy segment — veerom po VSEM zhe zivym piram
    (krome sebya). NICHego ne idet cherez master."""
    if not game_enabled():
        _game_stat("dropped_not_game")
        return 0
    if not pkt or len(pkt) > MAX_RAW_PAYLOAD:
        _game_stat("dropped_bad_len")
        return 0
    _src, dst = _raw_endpoints(pkt)
    if not dst:
        _game_stat("dropped_not_ipv4")
        return 0
    if key is None:
        try:
            key = _STATE.get("secret") or _secret()
        except Exception:
            key = b""
    me = str(_STATE.get("node_id", "") or "")
    my_addr = game_address(me)
    bcast = _raw_is_bcast(dst)
    prefix = "10.%d." % GAME_GROUP
    # A-433c: "svoy segment" - eto adres gruppy 10.<gruppa>.<uzel>.1, a ne lyuboj
    # 10.<gruppa>.*: inache chuzhoy adres 10.7.99.9 rassylalsya by vsem.
    # A-435-fix3: VSE igrovye adresa konchayutsya na ".1" (10.<gruppa>.<uzel>.1),
    # poetomu staraya proverka na ".1" schitala LYUBOY unicast "svoim segmentom"
    # i rassylala paket VSEM kanalam gruppy. Segmentom schitaetsya tolko
    # broadcast/setevoy adres gruppy (10.<gruppa>.<x>.0 ili .255).
    own_segment = (bool(my_addr) and dst.startswith(prefix)
                   and dst != my_addr and _is_segment_addr(dst))
    sent = 0
    with _LOCK:
        peers = dict(_STATE.get("peers", {}) or {})
    for nid, row in peers.items():
        if nid == me or nid in _NO_GAME_IDS:
            continue
        if (row or {}).get("sock") is None:
            continue
        # A-433b: unicast idet TOLKO vladeltsu adresa naznacheniya, a veer
        # (broadcast / multicast / svoy segment) - vsem zhivym uzlam gruppy,
        # krome sebya. Inache kazhdyy kazhdomu poluchal by chuzhoy trafik.
        # A-827 (Ш8): eto PRAMAYA DOSTAVKA (adresat - etot uzel), a ne rely,
        # poetu zdes galka allow_relay NE proveryaetsya. Galka - eto pravo
        # uzla byt VYHODOM dlya gruppy, reshaetsya v relay_candidates()/
        # game_server, a ne zdes.
        if not bcast and not own_segment and game_address(nid) != dst:
            continue
        try:
            _send_row(row, T_RAW, bytes(pkt), key)
            sent += 1
        except OSError:
            _game_stat("send_failed")
    _game_stat("sent", sent)
    _game_stat("bcast" if bcast else ("segment" if own_segment else "unicast"))
    # A-468: TUN vhodit v syroye obmen cherez raw_send, a ne cherez
    # direct_send (tot s relyem v kode EST, no ne vyzyvalsya NI ODIN RAZ).
    # U igrovykh uzlov net zhivykh peer-soketov mezhdu soboy, poetomu sent
    # vsegda 0, a paket shel molcha v nikhde - releya ne bylo chego vklyuchit.
    # Teper pri pustom sent paket otdayotsya masteru, a master (_relay_raw)
    # razoslet ego vsem ostalnym zhilym uzlam gruppy.
    if sent == 0:
        # A-475: snachala PRYAMYE UDP-kanaly uzla, i tolko potom rely cherez
        # master. Do A-475 pryamye kanaly voobsche ne uchastvovali v obmene:
        # `raw_send` znal tolko mesh peer-sokety, kotorykh u klientov net.
        sent += _direct_dispatch(bytes(pkt), key, dst)
    if sent == 0:
        sent += _relay_up(bytes(pkt), key)
    return sent