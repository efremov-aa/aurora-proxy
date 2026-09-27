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

import hmac
import hashlib
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

MESH_NET = "100.64.0.0/10"
MESH_BASE = 0x0A400000 + 1
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
    value = MESH_BASE | (int.from_bytes(digest[:3], "big") & 0x003FFFFF)
    return "100.%d.%d.%d" % ((value >> 16) & 0x3F, (value >> 8) & 0xFF, value & 0xFF)


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


def _node_id():
    with _LOCK:
        if _STATE.get("node_id"):
            return _STATE["node_id"]
    value = ""
    try:
        value = str(config.get("mesh_id", "") or "")
    except Exception:
        value = ""
    if not value:
        value = str(os.environ.get("AURORA_MESH_ID", "") or "")
    with _LOCK:
        _STATE["node_id"] = value
    return value


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


def _known(node_id, proof, nonce):
    if not _ID_RE.match(str(node_id or "").strip()) or not proof or not nonce:
        return False
    secret = _peer_secret(str(node_id).strip())
    if not secret:
        return False
    return hmac.compare_digest(_expected_proof(secret, nonce, str(node_id).strip()),
                               _keybytes(proof))


def status():
    """A-126: heartbeatov net i byt ne mozhet - sessiya odna i korotkaya,
    zhivost uzla opredelyaetsya dialom na kazhdyy zapros. Otdayom chestno."""
    with _LOCK:
        peers = _STATE.get("peers", {})
        live = [row for row in peers.values() if time.time() - row.get("seen", 0) < TTL]
        return {"enabled": enabled(), "node_id": _node_id(), "peers": sorted(peers),
                "peer_count": len(live), "liveness": "per-request dial",
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
                "last_error": str(_STATE.get("last_error", "") or ""),
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
        return host, MESH_PORT
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
    """A-289: порт mixed-инбаунда xray этого узла. Через него можно достучаться
    до мастера, даже если прямой маршрут закрыт (NAT, чужой провайдер)."""
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
            try:
                return _dial_via_socks("127.0.0.1", proxy_port, host, port)
            except (OSError, ValueError):
                pass
    return socket.create_connection((host, port), timeout=HANDSHAKE_TIMEOUT_S)


def _announce_loop(key):
    """A-147: periodicheskiy anons sebya masteru (registraciya pira).
    A-191 (variant B): posle T_OK soket NE zakryvaem - po nemu master
    otkryvaet potoki, a my ih obsluzhivaem (_peer_pump). Peredacha inache
    trebovala by, chtoby master dostichal 8443 pira (NAT)."""
    while True:
        sock = None
        handed = False
        try:
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
        time.sleep(1 if handed else max(1, int(ANNOUNCE)))


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
    listener = _listen(MESH_PORT)
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
    listener = _listen(MESH_PORT)
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


def _hello_frame(node_id, secret, addr, key):
    """Edinyy format HELLO: node_id|proof|nonce|addr (adres optsionalny)."""
    # A-137: nonce idet cherez tekstovyj kadr "node_id|proof|nonce|addr",
    # poetomu tolko hex-ascii. Syrye 16 bayt lomali proof na ~99.9997% ranzov
    # (master chitaet payload kak utf-8) i ryadom na bayte 0x7C ("|").
    nonce = os.urandom(16).hex().encode("ascii")
    proof = _expected_proof(secret, nonce, node_id)
    payload = (_keybytes(node_id) + b"|" + proof + b"|" + nonce + b"|" + _keybytes(addr))
    return nonce, payload


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
    try:
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
    try:
        conn.settimeout(None)
        while not _STATE.get("stop"):
            try:
                chunk = conn.recv(65536)
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
            _STATE["last_error"] = ("peer-reader end: mine=%s tunnel=%s used=%s"
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
                chunk = conn.recv(65536)
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
            parts = str(payload.decode("utf-8", "replace")).split("|", 3)
            if len(parts) < 3:
                return
            node_id, proof, nonce = parts[0], parts[1], parts[2]
            host, port = _parse_addr(parts[3] if len(parts) > 3 else "")
            if not _known(node_id, proof, nonce):
                return
            _send(conn, T_OK, hmac.new(_keybytes(key),
                                       b"aurora-mesh-ok" + _keybytes(nonce),
                                       hashlib.sha256).hexdigest().encode("ascii"), key)
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
    if str(_STATE.get("started", "") or "") == "master":
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
        listener = _listen(MESH_PORT + 1)
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
    if master:
        threading.Thread(target=_ensure_socks, args=(key,),
                         name="mesh-socks", daemon=True).start()
    return True
