from __future__ import annotations

import os
import sys
import time
import stat
import struct
import asyncio
import hashlib
import argparse
import logging
import logging.handlers
import signal
import ipaddress
import math
import socket as _socket

from typing import Dict, Optional, Tuple


if __name__ == '__main__' and (__package__ is None or __package__ == ''):
    _repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _repo_root not in sys.path:
        sys.path.insert(0, _repo_root)
    __package__ = 'proxy'

from .utils import *
from .stats import stats
from .config import (
    proxy_config,
    parse_dc_ip_list,
    start_cfproxy_domain_refresh,
    stop_cfproxy_domain_refresh,
    coerce_domain_list,
)
from .bridge import MsgSplitter, CryptoCtx, do_fallback, bridge_ws_reencrypt
from .raw_websocket import RawWebSocket, WsHandshakeError, set_sock_opts
from .fake_tls import (
    proxy_to_masking_domain,
    verify_client_hello,
    build_server_hello,
    FakeTlsStream,
    TLS_RECORD_HANDSHAKE,
)
from .balancer import balancer
from .pool import ws_pool, cf_worker_pool
from ._aes import Cipher, algorithms, modes


log = logging.getLogger('tg-mtproto-proxy')

IP_FAIL_COOLDOWN = 3600.0
DC_FAIL_COOLDOWN = 60.0
WS_FAIL_TIMEOUT = 2.0
LISTENER_CHECK_INTERVAL = 5.0
LISTENER_RESTART_DELAY = 1.0
SECRET_HEX_LEN = 32
SECRET_SOURCE_MAX = 4096
PROXY_HEADER_MAX = 4096
ws_blacklist: set[str] = set()
dc_fail_until: Dict[str, float] = {}
ip_fail_until: Dict[str, float] = {}


def _decode_secret(raw: bytes) -> str:
    try:
        value = raw.decode('ascii').strip()
    except UnicodeDecodeError:
        raise ValueError('Secret must contain ASCII hexadecimal characters') from None
    if len(value) != SECRET_HEX_LEN:
        raise ValueError('Secret must contain exactly 32 hexadecimal characters')
    if any(ch not in '0123456789abcdefABCDEF' for ch in value):
        raise ValueError('Secret must contain exactly 32 hexadecimal characters')
    return value.lower()


def _read_fd_bounded(fd: int, close_fd: bool = False) -> bytes:
    chunks = bytearray()
    try:
        while len(chunks) <= SECRET_SOURCE_MAX:
            chunk = os.read(fd, min(4096, SECRET_SOURCE_MAX + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
    finally:
        if close_fd:
            os.close(fd)
    if len(chunks) > SECRET_SOURCE_MAX:
        raise ValueError('Secret source is too large')
    return bytes(chunks)


def _read_secret_file(path: str) -> str:
    flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0)
    flags |= getattr(os, 'O_NOFOLLOW', 0)
    flags |= getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('Secret file must be a regular file')
        raw = _read_fd_bounded(fd)
    finally:
        os.close(fd)
    return _decode_secret(raw)


def _read_secret_fd(fd: int) -> str:
    if not isinstance(fd, int) or fd < 0:
        raise ValueError('Secret file descriptor must be non-negative')
    raw = _read_fd_bounded(fd, close_fd=True)
    return _decode_secret(raw)


def _select_secret(args) -> Tuple[str, str]:
    legacy_secret = getattr(args, 'secret', None)
    if legacy_secret is not None:
        return _decode_secret(legacy_secret.encode('ascii')), 'legacy argument'
    if args.secret_file is not None:
        return _read_secret_file(args.secret_file), 'file'
    if args.secret_fd is not None:
        return _read_secret_fd(args.secret_fd), 'file descriptor'
    return os.urandom(16).hex(), 'generated in memory'


def _try_handshake(handshake: bytes, secret: bytes) -> Optional[Tuple[int, bool, bytes, bytes]]:
    dec_prekey_and_iv = handshake[SKIP_LEN:SKIP_LEN + PREKEY_LEN + IV_LEN]
    dec_prekey = dec_prekey_and_iv[:PREKEY_LEN]
    dec_iv = dec_prekey_and_iv[PREKEY_LEN:]

    dec_key = hashlib.sha256(dec_prekey + secret).digest()

    dec_iv_int = int.from_bytes(dec_iv, 'big')
    decryptor = Cipher(
        algorithms.AES(dec_key), modes.CTR(dec_iv_int.to_bytes(16, 'big'))
    ).encryptor()
    decrypted = decryptor.update(handshake)

    proto_tag = decrypted[PROTO_TAG_POS:PROTO_TAG_POS + 4]
    if proto_tag not in (PROTO_TAG_ABRIDGED, PROTO_TAG_INTERMEDIATE,
                         PROTO_TAG_SECURE):
        return None

    dc_idx = int.from_bytes(
        decrypted[DC_IDX_POS:DC_IDX_POS + 2], 'little', signed=True)

    dc_id = abs(dc_idx)
    is_media = dc_idx < 0

    return dc_id, is_media, proto_tag, dec_prekey_and_iv


def _generate_relay_init(proto_tag: bytes, dc_idx: int) -> bytes:
    while True:
        rnd = bytearray(os.urandom(HANDSHAKE_LEN))
        if rnd[0] in RESERVED_FIRST_BYTES:
            continue
        if bytes(rnd[:4]) in RESERVED_STARTS:
            continue
        if rnd[4:8] == RESERVED_CONTINUE:
            continue
        break

    rnd_bytes = bytes(rnd)

    enc_key = rnd_bytes[SKIP_LEN:SKIP_LEN + PREKEY_LEN]
    enc_iv = rnd_bytes[SKIP_LEN + PREKEY_LEN:SKIP_LEN + PREKEY_LEN + IV_LEN]

    encryptor = Cipher(
        algorithms.AES(enc_key), modes.CTR(enc_iv)
    ).encryptor()

    dc_bytes = struct.pack('<h', dc_idx)
    tail_plain = proto_tag + dc_bytes + os.urandom(2)

    encrypted_full = encryptor.update(rnd_bytes)
    keystream_tail = bytes(
        encrypted_full[i] ^ rnd_bytes[i] for i in range(56, 64))
    encrypted_tail = bytes(
        tail_plain[i] ^ keystream_tail[i] for i in range(8))

    result = bytearray(rnd_bytes)
    result[PROTO_TAG_POS:HANDSHAKE_LEN] = encrypted_tail
    return bytes(result)


async def _read_client_init(reader, writer, secret, label, masking,
                            deadline: Optional[float] = None):
    async def _read_exact(size: int) -> bytes:
        timeout = remaining_timeout(deadline)
        if timeout is not None and timeout <= 0:
            raise TimeoutError('client handshake deadline exceeded')
        if timeout is None:
            return await reader.readexactly(size)
        return await asyncio.wait_for(reader.readexactly(size), timeout=timeout)

    if proxy_config.proxy_protocol:
        timeout = remaining_timeout(deadline)
        if timeout is not None and timeout <= 0:
            raise TimeoutError('client handshake deadline exceeded')
        try:
            if timeout is None:
                pp_line = await reader.readline()
            else:
                pp_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            log.debug("[%s] disconnected or exceeded PROXY header limit", label)
            return None
        if len(pp_line) > PROXY_HEADER_MAX:
            log.warning("[%s] oversized PROXY header", label)
            return None
        pp_text = pp_line.decode('ascii', errors='replace').strip()
        if pp_text.startswith('PROXY '):
            parts = pp_text.split()
            if len(parts) >= 6:
                label = f"{parts[2]}:{parts[4]}"
            log.debug("[%s] PROXY protocol accepted", label)
        else:
            log.debug("[%s] expected PROXY header, got: %r", label,
                      pp_text[:60])

    try:
        first_byte = await _read_exact(1)
    except asyncio.IncompleteReadError:
        log.debug("[%s] client disconnected before handshake", label)
        return None

    if first_byte[0] == TLS_RECORD_HANDSHAKE and masking:
        try:
            hdr_rest = await _read_exact(4)
        except asyncio.IncompleteReadError:
            log.debug("[%s] incomplete TLS record header", label)
            return None

        tls_header = first_byte + hdr_rest
        record_len = struct.unpack('>H', tls_header[3:5])[0]

        try:
            record_body = await _read_exact(record_len)
        except asyncio.IncompleteReadError:
            log.debug("[%s] incomplete TLS record body", label)
            return None

        client_hello = tls_header + record_body

        tls_result = verify_client_hello(client_hello, secret)

        if tls_result is None:
            log.debug("[%s] Fake TLS verify failed (size=%d rec=%d) "
                      "-> masking",
                      label, len(client_hello), record_len)
            await proxy_to_masking_domain(
                reader, writer, client_hello, masking, label,
                deadline=deadline)
            return None

        client_random, session_id, ts = tls_result
        log.debug("[%s] Fake TLS handshake ok (ts=%d)", label, ts)

        server_hello = build_server_hello(secret, client_random, session_id)
        writer.write(server_hello)
        await await_with_deadline(writer.drain(), deadline)

        tls_stream = FakeTlsStream(reader, writer)

        try:
            handshake = await _read_exact(HANDSHAKE_LEN)
        except asyncio.IncompleteReadError:
            log.debug("[%s] incomplete obfs2 init inside TLS", label)
            return None

        return handshake, tls_stream, tls_stream, label

    if masking:
        log.debug("[%s] non-TLS byte 0x%02X -> HTTP redirect", label,
                  first_byte[0])
        redirect = (
            f"HTTP/1.1 301 Moved Permanently\r\n"
            f"Location: https://{masking}/\r\n"
            f"Content-Length: 0\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        writer.write(redirect)
        await await_with_deadline(writer.drain(), deadline)
        return None

    try:
        rest = await _read_exact(HANDSHAKE_LEN - 1)
    except asyncio.IncompleteReadError:
        log.debug("[%s] client disconnected before handshake", label)
        return None
    return first_byte + rest, reader, writer, label


def _build_crypto_ctx(client_dec_prekey_iv, secret, relay_init):
    clt_dec_prekey = client_dec_prekey_iv[:PREKEY_LEN]
    clt_dec_iv = client_dec_prekey_iv[PREKEY_LEN:]
    clt_dec_key = hashlib.sha256(clt_dec_prekey + secret).digest()

    clt_enc_prekey_iv = client_dec_prekey_iv[::-1]
    clt_enc_key = hashlib.sha256(
        clt_enc_prekey_iv[:PREKEY_LEN] + secret).digest()
    clt_enc_iv = clt_enc_prekey_iv[PREKEY_LEN:]

    clt_decryptor = Cipher(
        algorithms.AES(clt_dec_key), modes.CTR(clt_dec_iv)
    ).encryptor()
    clt_encryptor = Cipher(
        algorithms.AES(clt_enc_key), modes.CTR(clt_enc_iv)
    ).encryptor()

    clt_decryptor.update(ZERO_64)

    relay_enc_key = relay_init[SKIP_LEN:SKIP_LEN + PREKEY_LEN]
    relay_enc_iv = relay_init[SKIP_LEN + PREKEY_LEN:
                              SKIP_LEN + PREKEY_LEN + IV_LEN]

    relay_dec_prekey_iv = relay_init[SKIP_LEN:
                                     SKIP_LEN + PREKEY_LEN + IV_LEN][::-1]
    relay_dec_key = relay_dec_prekey_iv[:KEY_LEN]
    relay_dec_iv = relay_dec_prekey_iv[KEY_LEN:]

    tg_encryptor = Cipher(
        algorithms.AES(relay_enc_key), modes.CTR(relay_enc_iv)
    ).encryptor()
    tg_decryptor = Cipher(
        algorithms.AES(relay_dec_key), modes.CTR(relay_dec_iv)
    ).encryptor()

    tg_encryptor.update(ZERO_64)

    return CryptoCtx(clt_decryptor, clt_encryptor, tg_encryptor, tg_decryptor)


async def _close_client_writer(writer) -> None:
    transport = getattr(writer, 'transport', None)
    try:
        writer.close()
    except BaseException:
        pass
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
    except BaseException:
        if transport is not None:
            transport.abort()


async def _handle_client(reader, writer, secret: bytes):
    peer = writer.get_extra_info('peername')
    label = f"{peer[0]}:{peer[1]}" if peer else "?"
    accepted_at = time.monotonic()
    handshake_deadline = accepted_at + proxy_config.handshake_timeout
    setup_deadline = accepted_at + proxy_config.setup_timeout
    if setup_deadline < handshake_deadline:
        handshake_deadline = setup_deadline
    ws = None

    set_sock_opts(writer.transport, proxy_config.buffer_size)

    try:
        init = await _read_client_init(
            reader,
            writer,
            secret,
            label,
            proxy_config.fake_tls_domain,
            deadline=handshake_deadline,
        )
        if init is None:
            return

        handshake, clt_reader, clt_writer, label = init

        result = _try_handshake(handshake, secret)
        if result is None:
            stats.connections_bad += 1
            log.warning("[%s] bad handshake (wrong secret or proto)", label)
            return

        dc, is_media, proto_tag, client_dec_prekey_iv = result

        is_test_dc = proxy_config.force_test_dc or dc >= 10000
        if dc >= 10000:
            log.info("[%s] test DC%d -> DC%d", label, dc, dc - 10000)
            dc -= 10000

        if proto_tag == PROTO_TAG_ABRIDGED:
            proto_int = PROTO_ABRIDGED_INT
        elif proto_tag == PROTO_TAG_INTERMEDIATE:
            proto_int = PROTO_INTERMEDIATE_INT
        else:
            proto_int = PROTO_PADDED_INTERMEDIATE_INT

        dc_idx = -dc if is_media else dc

        log.debug("[%s] handshake ok: DC%d%s proto=0x%08X",
                  label, dc, ' media' if is_media else '', proto_int)

        relay_init = _generate_relay_init(proto_tag, dc_idx)
        ctx = _build_crypto_ctx(client_dec_prekey_iv, secret, relay_init)

        dc_key = f'{dc}{"t" if is_test_dc else ""}{"m" if is_media else ""}'
        media_tag = " media" if is_media else ""
        now = time.monotonic()
        ws_path = WS_PATH_TEST if is_test_dc else WS_PATH
        target = proxy_config.dc_redirects.get(dc)
        is_any_cf_fallback = bool(
            proxy_config.fallback_cfproxy
            or proxy_config.cfproxy_worker_domains
            or proxy_config.tcp_fallback
        )

        if (dc not in proxy_config.dc_redirects
            or dc_key in ws_blacklist
            or (now < ip_fail_until.get(target, 0)
                and is_any_cf_fallback)):

            if dc not in proxy_config.dc_redirects:
                log.info("[%s] DC%d not in config -> fallback",
                         label, dc)
            elif dc_key in ws_blacklist:
                log.info("[%s] DC%d%s WS blacklisted -> fallback",
                         label, dc, media_tag)
            else:
                log.info("[%s] DC%d%s WS connect was timed out -> fallback",
                         label, dc, media_tag)
            splitter = None
            try:
                splitter = MsgSplitter(relay_init, proto_int)
            except Exception:
                pass
            ok = await do_fallback(
                clt_reader, clt_writer, relay_init, label,
                dc, is_test_dc, is_media, media_tag,
                ctx, splitter=splitter, deadline=setup_deadline)
            if not ok:
                log.warning("[%s] DC%d%s no fallback available",
                            label, dc, media_tag)
            return

        base_timeout = WS_FAIL_TIMEOUT if now < dc_fail_until.get(dc_key, 0) else 5.0

        domains = ws_domains(dc, is_media)
        ws_failed_redirect = False
        ws_timed_out = False
        all_redirects = True

        allow_pool_refill = now >= ip_fail_until.get(target, 0)
        ws = await ws_pool.get(
            dc, is_media, target, domains,
            allow_refill=allow_pool_refill,
        ) if not is_test_dc else None
        if ws:
            log.info("[%s] DC%d%s -> pool hit via %s",
                     label, dc, media_tag, target)
        else:
            for domain in domains:
                remaining = remaining_timeout(setup_deadline)
                if remaining is not None and remaining <= 0:
                    raise TimeoutError('upstream setup deadline exceeded')
                url = f'wss://{domain}{ws_path}'
                log.info("[%s] DC%d%s -> %s via %s",
                         label, dc, media_tag, url, target)
                try:
                    ws = await RawWebSocket.connect(
                        target,
                        domain,
                        timeout=min(base_timeout, remaining)
                        if remaining is not None else base_timeout,
                        path=ws_path,
                    )
                    all_redirects = False
                    break
                except WsHandshakeError as exc:
                    stats.ws_errors += 1
                    if exc.is_redirect:
                        ws_failed_redirect = True
                        log.warning("[%s] DC%d%s got redirect %d from %s",
                                    label, dc, media_tag,
                                    exc.status_code, domain)
                        continue
                    all_redirects = False
                    log.warning("[%s] DC%d%s WS handshake: %s",
                                label, dc, media_tag, exc.status_line)
                except asyncio.TimeoutError:
                    stats.ws_errors += 1
                    ws_timed_out = True
                    log.warning("[%s] DC%d%s WS connect timed out via %s",
                                label, dc, media_tag, domain)
                    break
                except Exception as exc:
                    stats.ws_errors += 1
                    all_redirects = False
                    log.warning("[%s] DC%d%s WS connect failed: %s",
                                label, dc, media_tag, repr(exc))

        if ws is None:
            failed_at = time.monotonic()
            if ws_timed_out:
                ip_fail_until[target] = failed_at + IP_FAIL_COOLDOWN
                log.info("[%s] DC%d%s WS connect to %s timed out, cooldown for %ds",
                         label, dc, media_tag, target, int(IP_FAIL_COOLDOWN))

            if ws_failed_redirect and all_redirects:
                ws_blacklist.add(dc_key)
                log.warning("[%s] DC%d%s blacklisted for WS (all 302)",
                            label, dc, media_tag)
            else:
                dc_fail_until[dc_key] = failed_at + DC_FAIL_COOLDOWN
                log.info("[%s] DC%d%s WS cooldown for %ds",
                         label, dc, media_tag, int(DC_FAIL_COOLDOWN))

            splitter_fb = None
            try:
                splitter_fb = MsgSplitter(relay_init, proto_int)
            except Exception:
                pass
            ok = await do_fallback(
                clt_reader, clt_writer, relay_init, label,
                dc, is_test_dc, is_media, media_tag,
                ctx, splitter=splitter_fb, deadline=setup_deadline)
            if ok:
                log.info("[%s] DC%d%s fallback closed",
                         label, dc, media_tag)
            return

        dc_fail_until.pop(dc_key, None)
        ip_fail_until.pop(target, None)
        ws_pool.report_success(dc, is_media)
        stats.connections_ws += 1

        splitter = None
        try:
            splitter = MsgSplitter(relay_init, proto_int)
            log.debug("[%s] MsgSplitter activated for proto 0x%08X",
                      label, proto_int)
        except Exception:
            pass

        await await_with_deadline(ws.send(relay_init), setup_deadline)

        await bridge_ws_reencrypt(clt_reader, clt_writer, ws, label, ctx,
                                   dc=dc, is_media=is_media,
                                   splitter=splitter)

    except TimeoutError:
        log.warning("[%s] setup or handshake deadline exceeded", label)
    except asyncio.IncompleteReadError:
        log.debug("[%s] client disconnected", label)
    except asyncio.CancelledError:
        raise
    except ConnectionResetError:
        log.debug("[%s] connection reset", label)
    except OSError as exc:
        if getattr(exc, 'winerror', None) == 1236:
            log.debug("[%s] connection aborted by local system", label)
        else:
            log.error("[%s] unexpected OS error: %s", label, repr(exc))
    except Exception as exc:
        log.error("[%s] unexpected: %s", label, exc, exc_info=True)
    finally:
        if ws is not None:
            try:
                await ws.close()
            except BaseException:
                pass
        await _close_client_writer(writer)


_server_instance = None
_server_stop_event = None
_client_tasks: Dict[asyncio.Task, str] = {}
_client_writers: Dict[asyncio.Task, object] = {}
_client_peer_counts: Dict[str, int] = {}
_accepting = False


def _peer_key(writer) -> str:
    peer = writer.get_extra_info('peername')
    if not peer:
        return 'unknown'
    value = str(peer[0]).split('%', 1)[0]
    try:
        address = ipaddress.ip_address(value)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            return address.ipv4_mapped.compressed
        return address.compressed
    except ValueError:
        return value


def _try_reserve_client(peer: str) -> bool:
    if len(_client_tasks) >= proxy_config.max_connections:
        return False
    if _client_peer_counts.get(peer, 0) >= proxy_config.max_connections_per_ip:
        return False
    _client_peer_counts[peer] = _client_peer_counts.get(peer, 0) + 1
    return True


def _release_client(peer: str) -> None:
    count = _client_peer_counts.get(peer, 0)
    if count <= 1:
        _client_peer_counts.pop(peer, None)
    else:
        _client_peer_counts[peer] = count - 1


def _client_task_done(task: asyncio.Task) -> None:
    _client_writers.pop(task, None)
    peer = _client_tasks.pop(task, None)
    if peer is not None:
        _release_client(peer)
        stats.connections_active = max(0, stats.connections_active - 1)
    if task.cancelled():
        return
    try:
        exc = task.exception()
    except asyncio.CancelledError:
        return
    if exc is not None:
        log.error("Client task failed: %s", type(exc).__name__)


def _reject_client(writer) -> None:
    try:
        writer.close()
    except BaseException:
        pass
    transport = getattr(writer, 'transport', None)
    if transport is not None:
        try:
            transport.abort()
        except BaseException:
            pass


def _admit_client(reader, writer) -> None:
    global _accepting
    if not _accepting:
        _reject_client(writer)
        return
    peer = _peer_key(writer)
    if not _try_reserve_client(peer):
        _reject_client(writer)
        return
    try:
        task = asyncio.create_task(_handle_client(reader, writer, bytes.fromhex(proxy_config.secret)))
    except BaseException:
        _release_client(peer)
        _reject_client(writer)
        raise
    _client_tasks[task] = peer
    _client_writers[task] = writer
    stats.connections_total += 1
    stats.connections_active += 1
    task.add_done_callback(_client_task_done)


async def _close_server(server) -> None:
    if server is None:
        return
    try:
        server.close()
        await asyncio.wait_for(server.wait_closed(), timeout=1.0)
    except BaseException:
        pass


async def _drain_client_tasks(timeout: float) -> None:
    tasks = list(_client_tasks)
    if not tasks:
        return
    timeout = max(0.0, float(timeout))
    _, pending = await asyncio.wait(tasks, timeout=timeout)
    if not pending:
        return
    for task in pending:
        if not task.done():
            task.cancel()
        writer = _client_writers.get(task)
        if writer is None:
            continue
        try:
            writer.close()
        except BaseException:
            pass
        transport = getattr(writer, 'transport', None)
        if transport is not None:
            try:
                transport.abort()
            except BaseException:
                pass
    await asyncio.wait(pending, timeout=1.0)


async def _quiet_cancel(task) -> None:
    if task is None:
        return
    if not task.done():
        task.cancel()
    try:
        await asyncio.wait_for(task, timeout=1.0)
    except BaseException:
        pass


async def _run(stop_event: Optional[asyncio.Event] = None):
    global _server_instance, _server_stop_event, _accepting
    stop_event = stop_event or asyncio.Event()
    _server_stop_event = stop_event
    _accepting = False
    if _client_tasks:
        await _drain_client_tasks(0.0)
    _client_tasks.clear()
    _client_writers.clear()
    _client_peer_counts.clear()

    await ws_pool.close()
    await cf_worker_pool.close()
    ws_blacklist.clear()
    dc_fail_until.clear()
    ip_fail_until.clear()

    user_cf_domains = proxy_config.cfproxy_user_domains
    if user_cf_domains:
        balancer.update_domains_list(user_cf_domains)
    else:
        start_cfproxy_domain_refresh()

    secret_bytes = bytes.fromhex(proxy_config.secret)
    server = None
    serve_task = None
    watchdog_task = None
    stop_task = None
    log_stats_task = None

    try:
        server = await asyncio.start_server(
            _admit_client,
            proxy_config.host,
            proxy_config.port,
            backlog=min(1024, max(1, proxy_config.max_connections)),
            limit=PROXY_HEADER_MAX,
        )
        _server_instance = server
        _accepting = True

        for sock in server.sockets:
            try:
                sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
            except (OSError, AttributeError):
                pass

        log.info("=" * 60)
        log.info("  Telegram MTProto WS Bridge Proxy")
        log.info("  Listening on   %s:%d", proxy_config.host, proxy_config.port)
        log.info("  Secret source: %s", 'configured')
        if proxy_config.fake_tls_domain:
            log.info("  Fake TLS:      %s", proxy_config.fake_tls_domain)
        log.info("  Limits:        global=%d per_ip=%d",
                 proxy_config.max_connections,
                 proxy_config.max_connections_per_ip)
        log.info("  Deadlines:     handshake=%.1fs setup=%.1fs drain=%.1fs",
                 proxy_config.handshake_timeout,
                 proxy_config.setup_timeout,
                 proxy_config.drain_timeout)
        log.info("  TCP fallback:  %s",
                 'enabled' if proxy_config.tcp_fallback else 'disabled')
        log.info("  Target DC IPs:")
        for dc in sorted(proxy_config.dc_redirects.keys()):
            ip = proxy_config.dc_redirects.get(dc)
            log.info("    DC%d: %s", dc, ip)
        if proxy_config.fallback_cfproxy:
            user_domain = ", ".join(proxy_config.cfproxy_user_domains) if proxy_config.cfproxy_user_domains else "auto"
            log.info("  CF proxy:      enabled (%s)", user_domain)
        if proxy_config.cfproxy_worker_domains:
            log.info("  CF worker:     enabled (%s)",
                     ", ".join(proxy_config.cfproxy_worker_domains))
        log.info("=" * 60)

        async def log_stats():
            try:
                while True:
                    await asyncio.sleep(60)
                    blocked = ', '.join(
                        f'DC{key}' for key in sorted(ws_blacklist)) or 'none'
                    log.info("stats: %s | ws_bl: %s",
                             stats.summary(), blocked)
            except asyncio.CancelledError:
                raise

        log_stats_task = asyncio.create_task(log_stats())

        await ws_pool.warmup()
        await cf_worker_pool.warmup()

        while True:
            serve_task = asyncio.create_task(server.serve_forever())
            stop_task = asyncio.create_task(stop_event.wait())

            async def _listener_watchdog():
                while True:
                    await asyncio.sleep(LISTENER_CHECK_INTERVAL)
                    socks = server.sockets
                    if not socks or all(s.fileno() < 0 for s in socks):
                        return

            watchdog_task = asyncio.create_task(_listener_watchdog())
            done, _ = await asyncio.wait(
                (serve_task, watchdog_task, stop_task),
                return_when=asyncio.FIRST_COMPLETED,
            )

            if stop_task in done:
                _accepting = False
                await _quiet_cancel(serve_task)
                await _close_server(server)
                await _drain_client_tasks(proxy_config.drain_timeout)
                break

            await _quiet_cancel(watchdog_task)
            await _quiet_cancel(serve_task)
            await _quiet_cancel(stop_task)
            _accepting = False
            if watchdog_task in done:
                log.warning("Listening socket died, restarting server")
            else:
                log.warning("Server loop stopped unexpectedly, restarting")
            await _close_server(server)
            await asyncio.sleep(LISTENER_RESTART_DELAY)
            if stop_event.is_set():
                break
            server = await asyncio.start_server(
                _admit_client,
                proxy_config.host,
                proxy_config.port,
                backlog=min(1024, max(1, proxy_config.max_connections)),
                limit=PROXY_HEADER_MAX,
            )
            _server_instance = server
            _accepting = True
            for sock in server.sockets:
                try:
                    sock.setsockopt(
                        _socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
                except (OSError, AttributeError):
                    pass
            log.warning("Server restored, listening on %s:%d",
                        proxy_config.host, proxy_config.port)
    finally:
        _accepting = False
        await _close_server(server)
        await _quiet_cancel(serve_task)
        await _quiet_cancel(watchdog_task)
        await _quiet_cancel(stop_task)
        await _drain_client_tasks(proxy_config.drain_timeout)
        if log_stats_task is not None:
            await _quiet_cancel(log_stats_task)
        stop_cfproxy_domain_refresh()
        await ws_pool.close()
        await cf_worker_pool.close()
        _server_instance = None
        _server_stop_event = None


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError('must be positive')
    return parsed


def _positive_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError('must be positive and finite')
    return parsed


def _build_log_handler(path: str, max_mb: float, backups: int):
    max_bytes = max(1, int(max_mb * 1024 * 1024))
    return logging.handlers.RotatingFileHandler(
        path,
        maxBytes=max_bytes,
        backupCount=max(1, backups),
        encoding='utf-8',
    )


async def _run_with_signals():
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()
    loop_handlers = []
    signal_handlers = []

    def request_stop():
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, request_stop)
            loop_handlers.append(sig)
        except (NotImplementedError, RuntimeError):
            try:
                previous = signal.getsignal(sig)
                signal.signal(
                    sig,
                    lambda _signum, _frame: loop.call_soon_threadsafe(
                        request_stop),
                )
                signal_handlers.append((sig, previous))
            except (OSError, ValueError):
                pass

    try:
        await _run(stop_event)
    finally:
        for sig in loop_handlers:
            loop.remove_signal_handler(sig)
        for sig, previous in signal_handlers:
            signal.signal(sig, previous)


def run_proxy(stop_event: Optional[asyncio.Event] = None):
    if stop_event is None:
        asyncio.run(_run_with_signals())
    else:
        asyncio.run(_run(stop_event))


def main():
    ap = argparse.ArgumentParser(
        description='Telegram MTProto WebSocket Bridge Proxy')
    ap.add_argument('--port', type=int, default=1443,
                    help='Listen port (default 1443)')
    ap.add_argument('--host', type=str, default='127.0.0.1',
                    help='Listen host (default 127.0.0.1)')
    secret_group = ap.add_mutually_exclusive_group()
    secret_group.add_argument('--secret-file', type=str, default=None,
                              metavar='PATH',
                              help='Read the 32-character secret from a file')
    secret_group.add_argument('--secret-fd', type=int, default=None,
                              metavar='FD',
                              help='Read and close the secret from a file descriptor')
    ap.add_argument('--dc-ip', metavar='DC:IP', action='append',
                    help='Target IP for a DC, e.g. --dc-ip 2:149.154.167.220')
    ap.add_argument('-v', '--verbose', action='store_true',
                    help='Debug logging')
    ap.add_argument('--log-file', type=str, default=None, metavar='PATH',
                    help='Log to file with rotation (default: stderr only)')
    ap.add_argument('--log-max-mb', type=_positive_float, default=5, metavar='MB',
                    help='Max log file size in MB before rotation (default 5)')
    ap.add_argument('--log-backups', type=_positive_int, default=1, metavar='N',
                    help='Number of rotated log files to keep (min 1; '
                         'rotation needs at least one backup to bound size)')
    ap.add_argument('--buf-kb', type=int, default=256, metavar='KB',
                    help='Socket send/recv buffer size in KB (default 256)')
    ap.add_argument('--pool-size', type=int, default=4, metavar='N',
                    help='WS connection pool size per DC (default 4, min 0)')
    ap.add_argument('--cfproxy-domain', action='append', default=None,
                    metavar='DOMAIN',
                    help='User defined Cloudflare-proxied domain for WS fallback '
                         '(repeatable for multiple domains)')
    ap.add_argument('--cfproxy-worker-domain', action='append', default=None,
                    metavar='DOMAIN',
                    help='Cloudflare Worker domain for WS fallback '
                         '(tried before other fallback methods, '
                         'repeatable for multiple domains)')
    ap.add_argument('--no-cfproxy', action='store_true',
                    help='Disable Cloudflare proxy fallback')
    ap.add_argument('--enable-tcp-fallback', action='store_true',
                    help='Explicitly enable direct TCP fallback')
    ap.add_argument('--fake-tls-domain', type=str, default='',
                    metavar='DOMAIN',
                    help='Enable Fake TLS masking with the given SNI domain')
    ap.add_argument('--force-test-dc', action='store_true',
                    help='Force all traffic to Telegram TEST datacenters')
    ap.add_argument('--proxy-protocol', action='store_true',
                    help='Accept PROXY protocol v1 header')
    ap.add_argument('--max-connections', type=_positive_int, default=512,
                    metavar='N', help='Global active connection cap')
    ap.add_argument('--max-connections-per-ip', type=_positive_int, default=32,
                    metavar='N', help='Per-IP active connection cap')
    ap.add_argument('--handshake-timeout', type=_positive_float, default=10.0,
                    metavar='SECONDS', help='Absolute client handshake deadline')
    ap.add_argument('--setup-timeout', type=_positive_float, default=30.0,
                    metavar='SECONDS', help='Absolute upstream setup deadline')
    ap.add_argument('--drain-timeout', type=_positive_float, default=15.0,
                    metavar='SECONDS', help='Graceful client drain deadline')
    args = ap.parse_args()

    if args.max_connections_per_ip > args.max_connections:
        ap.error('--max-connections-per-ip cannot exceed --max-connections')
    if args.setup_timeout < args.handshake_timeout:
        ap.error('--setup-timeout cannot be less than --handshake-timeout')

    if not args.dc_ip:
        args.dc_ip = ['2:149.154.167.220', '4:149.154.167.220']

    try:
        dc_redirects = parse_dc_ip_list(args.dc_ip)
    except ValueError as exc:
        ap.error(str(exc))

    try:
        secret_hex, _ = _select_secret(args)
    except (OSError, ValueError, UnicodeError):
        ap.error('Unable to load proxy secret from configured source')

    proxy_config.port = args.port
    proxy_config.host = args.host
    proxy_config.secret = secret_hex
    proxy_config.dc_redirects = dc_redirects
    proxy_config.buffer_size = max(4, args.buf_kb) * 1024
    proxy_config.pool_size = max(0, args.pool_size)
    proxy_config.fallback_cfproxy = not args.no_cfproxy
    proxy_config.cfproxy_user_domains = coerce_domain_list(args.cfproxy_domain)
    proxy_config.cfproxy_worker_domains = coerce_domain_list(args.cfproxy_worker_domain)
    proxy_config.fake_tls_domain = args.fake_tls_domain.strip()
    proxy_config.proxy_protocol = args.proxy_protocol
    proxy_config.force_test_dc = args.force_test_dc
    proxy_config.max_connections = args.max_connections
    proxy_config.max_connections_per_ip = args.max_connections_per_ip
    proxy_config.handshake_timeout = args.handshake_timeout
    proxy_config.setup_timeout = args.setup_timeout
    proxy_config.drain_timeout = args.drain_timeout
    proxy_config.tcp_fallback = args.enable_tcp_fallback

    log_level = logging.DEBUG if args.verbose else logging.INFO
    log_fmt = logging.Formatter('%(asctime)s  %(levelname)-5s  %(message)s',
                                datefmt='%H:%M:%S')
    root = logging.getLogger()
    root.setLevel(log_level)

    console = logging.StreamHandler()
    console.setFormatter(log_fmt)
    root.addHandler(console)

    if args.log_file:
        fh = _build_log_handler(
            args.log_file, args.log_max_mb, args.log_backups)
        fh.setFormatter(log_fmt)
        root.addHandler(fh)

    logging.getLogger('asyncio').setLevel(logging.WARNING)

    try:
        asyncio.run(_run_with_signals())
    except KeyboardInterrupt:
        log.info("Shutting down. Final stats: %s", stats.summary())


if __name__ == '__main__':
    main()
