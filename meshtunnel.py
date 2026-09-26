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

_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")

_LOCK = threading.RLock()
_STATE = {"peers": {}, "secret": "", "node_id": "", "srv": None,
           "announce": 0, "last_error": "", "stop": 0, "rtt": 0,
           "last_pick": {}}


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
                "net": MESH_NET, "frag": FRAG_SIZE, "mode": "relay"}


def _peer(node_id, addr=""):
    """A-128: reestr pirov BEZ soketa. Odnо soedinenie - odin zapros,
    poetomu derzhat postoyannye sokety v stroke nevozmozhno: dva potoka
    _recv na odnom sokete lomali parallelnye zaprosy."""
    with _LOCK:
        peers = _STATE.setdefault("peers", {})
        if len(peers) >= MAX_PEERS and node_id not in peers:
            return None
        row = peers.get(node_id)
        if row is None:
            row = {"node_id": node_id, "addr": "", "seen": 0.0, "rtt_ms": 0}
            peers[node_id] = row
        value = str(addr or "").strip()
        if value:
            row["addr"] = value[:120]
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


def _drop(node_id):
    with _LOCK:
        _STATE.get("peers", {}).pop(node_id, None)


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


def _listen(port):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
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


def _announce_loop(key):
    """A-147: periodicheskiy anons sebya masteru (registraciya pira)."""
    while True:
        sock = None
        try:
            host, port = _master_addr()
            sock = socket.create_connection((host, port),
                                            timeout=HANDSHAKE_TIMEOUT_S)
            sock.settimeout(HANDSHAKE_TIMEOUT_S)
            _nonce, payload = _hello_frame(_node_id(), _secret(),
                                           _self_addr(), key)
            _send(sock, T_HELLO, payload, key)
            _wait_ok(sock, key)
            _STATE["last_error"] = ""
        except Exception as exc:
            _STATE["last_error"] = "announce: %s" % (exc.__class__.__name__,)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        if _STATE.get("stop"):
            return
        time.sleep(max(1, int(ANNOUNCE)))


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
    upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    upstream.settimeout(HANDSHAKE_TIMEOUT_S)
    try:
        upstream.connect(_master_addr())
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
    host, port = _parse_addr(row.get("addr"))
    if not host:
        raise OSError("peer address is not reachable")
    node_id = str(row.get("node_id") or "")
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


def _relay_hub(conn, key, requester_id=""):
    """A-131: master prinyal T_DATA s celyu ot klenta - peredavaet zapros
    piru-vyhodu i nakatyvaet trafik T_FRAG v obe storony. Bez pirov nichego
    ne otkryvaem: fail-closed, klient poluchit obryv."""
    buf = b""
    target = b""
    while True:
        try:
            chunk = conn.recv(65536)
        except OSError:
            return False
        if not chunk:
            return False
        buf += chunk
        # A-158: sm. takzhe v _forward/_recv.
        if _oversize(buf):
            return False
        msg_type, payload, buf = _unpack(buf, key)
        if msg_type is None:
            if not buf:
                return False
            continue
        if msg_type == T_BYE:
            return False
        if msg_type != T_DATA:
            continue
        target = payload
        break
    row = _pick_peer(exclude=requester_id)
    if row is None:
        return False
    try:
        peer_sock = _dial_peer(row, key)
    except (OSError, ValueError):
        return False
    _touch(row.get("node_id"))
    try:
        _send(peer_sock, T_DATA, target, key)
    except OSError:
        try:
            peer_sock.close()
        except OSError:
            pass
        return False
    # A-141: obe storony zdes - uzly (kadry), _pipe by perapakoval kadry.
    # A-143: nuzhny OBA napravleniya. Ranee byl tolko pir -> klient, poetomu
    # zapros klenta do pira ne dostaval voobshche (test: echo conns=1 got=0):
    # klient -> pir (zapros) i pir -> klient (otvet).
    up = threading.Thread(target=_forward, args=(conn, peer_sock, key),
                          name="mesh-hub-c2p", daemon=True)
    down = threading.Thread(target=_forward, args=(peer_sock, conn, key),
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


def _peer_session(conn, key):
    """Master prinyal HELLO uzla: proverka, T_OK, dalee - vyhod dlya zaprosa
    (A-127: ranee soket pira ne chitalsya voobshche, otvety visitali)."""
    conn.settimeout(HANDSHAKE_TIMEOUT_S)
    buf = b""
    node_id = ""
    try:
        while True:
            try:
                chunk = conn.recv(65536)
            except OSError:
                chunk = b""
            if not chunk:
                return
            buf += chunk
            if _oversize(buf):
                # A-159: piryom vsyo, chto prishlo, i "dolit" ochen bolshoy
                # length v bufer - bufer ros net do beskonechnosti (DoS po
                # pamyati). Otkaz fail-closed kak v _wait_ok/_recv/_forward.
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
    if _peer(node_id, ("%s:%d" % (host, port)) if host else "") is None:
        conn.close()
        return
    if str(_STATE.get("started", "") or "") == "master":
        # A-131: my - hab. Cel my ne otkryvaem: peredavaem zapros piru i
        # nakatyvaem trafik T_FRAG v obe storony ("kto blizhe" - po svezhosti).
        _relay_hub(conn, key, node_id)
        conn.close()
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
    target = _socks_request(conn)
    if target is None:
        conn.close()
        return
    conn.settimeout(None)
    row = _pick_peer()
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
        _send(peer_sock, T_DATA, ("%s:%d" % target).encode("utf-8"), key)
    except OSError:
        conn.close()
        peer_sock.close()
        return
    threading.Thread(target=_pump, args=(conn, peer_sock, key), daemon=True).start()
    _relay(peer_sock, key, conn)
    conn.close()
    peer_sock.close()


def start(role=None):
    if not enabled():
        return False
    role = str(role or os.environ.get("AURORA_MESH_ROLE", "") or "").strip()
    with _LOCK:
        if _STATE.get("started"):
            return True
        _STATE["started"] = role or "master"
    key = _secret()
    if not key:
        return False
    master = (role or "master") == "master"
    target = _server_serve if master else _client_serve
    threading.Thread(target=target, name="mesh-relay", daemon=True).start()
    if master:
        threading.Thread(target=_ensure_socks, args=(key,),
                         name="mesh-socks", daemon=True).start()
    return True
