import os
import ssl
import logging
import base64
import hashlib
import hmac
import struct
import asyncio
import math
import socket as _socket

from typing import List, Optional, Tuple
from .config import proxy_config

log = logging.getLogger('tg-mtproto-proxy')


_st_BB = struct.Struct('>BB')
_st_BBH = struct.Struct('>BBH')
_st_BBQ = struct.Struct('>BBQ')
_st_BB4s = struct.Struct('>BB4s')
_st_BBH4s = struct.Struct('>BBH4s')
_st_BBQ4s = struct.Struct('>BBQ4s')
_st_H = struct.Struct('>H')
_st_Q = struct.Struct('>Q')

_ssl_ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
_WS_GUID = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
_HEADER_NAME_CHARS = frozenset("!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")


class WsHandshakeError(Exception):
    def __init__(self, status_code: int, status_line: str,
                 headers: Optional[dict] = None, location: Optional[str] = None):
        self.status_code = status_code
        self.status_line = ''.join(
            ch if 32 <= ord(ch) < 127 else '?' for ch in status_line
        ).strip()[:256] or 'invalid response'
        self.headers = headers or {}
        self.location = location
        super().__init__(f"HTTP {status_code}: {self.status_line}")

    @property
    def is_redirect(self) -> bool:
        return self.status_code in (301, 302, 303, 307, 308)


def _xor_mask(data: bytes, mask: bytes) -> bytes:
    if not data:
        return data
    n = len(data)
    mask_rep = (mask * (n // 4 + 1))[:n]
    return (int.from_bytes(data, 'big') ^
            int.from_bytes(mask_rep, 'big')).to_bytes(n, 'big')


def _has_token(value: str, token: str) -> bool:
    return any(part.strip().lower() == token
               for part in value.split(','))


async def _close_writer(writer: asyncio.StreamWriter) -> None:
    transport = getattr(writer, 'transport', None)
    try:
        writer.close()
    except BaseException:
        pass
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
    except BaseException:
        if transport is not None:
            try:
                transport.abort()
            except BaseException:
                pass


def set_sock_opts(transport, buffer_size):
    sock = transport.get_extra_info('socket')
    if sock is None:
        return
    
    try:
        sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
    except (OSError, AttributeError):
        pass
    
    try:
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_RCVBUF, buffer_size)
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_SNDBUF, buffer_size)
    except OSError:
        pass


class RawWebSocket:
    __slots__ = ('reader', 'writer', '_closed', '_frag')

    OP_CONT = 0x0
    OP_BINARY = 0x2
    OP_CLOSE = 0x8
    OP_PING = 0x9
    OP_PONG = 0xA

    MAX_MESSAGE_LEN = 16 * 1024 * 1024
    MAX_HTTP_HEADER_BYTES = 32 * 1024
    MAX_HTTP_HEADERS = 64
    CLOSE_TIMEOUT = 1.0

    def __init__(self, reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self._closed = False
        self._frag = bytearray()

    @staticmethod
    def _parse_upgrade_response(
            response_lines: List[str], ws_key: str
            ) -> Tuple[int, str, dict[str, str]]:
        total = 0
        for line in response_lines:
            total += len(line.encode('ascii', errors='ignore')) + 2
        if total > RawWebSocket.MAX_HTTP_HEADER_BYTES:
            raise WsHandshakeError(0, 'response headers too large')
        if not response_lines:
            raise WsHandshakeError(0, 'empty response')

        status_line = response_lines[0]
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in status_line):
            raise WsHandshakeError(0, 'invalid status line')
        parts = status_line.split(' ', 2)
        if len(parts) < 2 or parts[0] != 'HTTP/1.1':
            raise WsHandshakeError(0, 'invalid status line')
        try:
            status_code = int(parts[1])
        except ValueError:
            raise WsHandshakeError(0, 'invalid status code') from None
        if status_code < 100 or status_code > 999:
            raise WsHandshakeError(0, 'invalid status code')

        headers: dict[str, str] = {}
        if len(response_lines) - 1 > RawWebSocket.MAX_HTTP_HEADERS:
            raise WsHandshakeError(status_code, 'too many response headers')
        for line in response_lines[1:]:
            if not line or line[0] in ' \t' or ':' not in line:
                raise WsHandshakeError(
                    status_code, 'invalid response header')
            name, value = line.split(':', 1)
            if not name or any(ch not in _HEADER_NAME_CHARS for ch in name):
                raise WsHandshakeError(
                    status_code, 'invalid response header name')
            key = name.lower()
            value = value.strip()
            if any((ord(ch) < 32 and ch != '\t') or ord(ch) == 127
                   for ch in value):
                raise WsHandshakeError(
                    status_code, 'invalid response header value')
            if key in headers:
                headers[key] = f"{headers[key]}, {value}"
            else:
                headers[key] = value

        if status_code != 101:
            return status_code, status_line, headers

        if not _has_token(headers.get('upgrade', ''), 'websocket'):
            raise WsHandshakeError(101, 'missing websocket upgrade')
        if not _has_token(headers.get('connection', ''), 'upgrade'):
            raise WsHandshakeError(101, 'missing connection upgrade')
        expected = base64.b64encode(
            hashlib.sha1((ws_key + _WS_GUID.decode('ascii')).encode('ascii')).digest()
        ).decode('ascii')
        supplied = headers.get('sec-websocket-accept', '')
        if not supplied or not hmac.compare_digest(supplied, expected):
            raise WsHandshakeError(101, 'invalid websocket accept')
        protocol = headers.get('sec-websocket-protocol', '')
        if protocol and not _has_token(protocol, 'binary'):
            raise WsHandshakeError(101, 'invalid websocket protocol')
        return status_code, status_line, headers

    @staticmethod
    async def _read_http_response(
            reader: asyncio.StreamReader, ws_key: str
            ) -> Tuple[int, str, dict[str, str]]:
        response_lines: list[str] = []
        total = 0
        while True:
            try:
                line = await reader.readline()
            except asyncio.LimitOverrunError:
                raise WsHandshakeError(0, 'response headers too large') from None
            total += len(line)
            if total > RawWebSocket.MAX_HTTP_HEADER_BYTES:
                raise WsHandshakeError(0, 'response headers too large')
            if line == b'':
                if response_lines:
                    raise WsHandshakeError(0, 'truncated response headers')
                break
            if not line.endswith(b'\r\n'):
                raise WsHandshakeError(0, 'invalid response line ending')
            if line == b'\r\n':
                break
            try:
                response_lines.append(line[:-2].decode('ascii'))
            except UnicodeDecodeError:
                raise WsHandshakeError(0, 'non-ascii response header') from None
        return RawWebSocket._parse_upgrade_response(response_lines, ws_key)

    @staticmethod
    async def connect(host: str, domain: str, timeout: float = 10.0,
                      path: str = '/apiws', *,
                      sni: Optional[str] = None) -> 'RawWebSocket':
        timeout = float(timeout)
        if not math.isfinite(timeout):
            raise ValueError('WebSocket timeout must be finite')
        timeout = max(0.001, timeout)
        if sni is None:
            sni = domain
        if (not isinstance(sni, str) or not sni
                or not isinstance(host, str) or not host
                or not isinstance(domain, str) or not domain
                or not isinstance(path, str) or not path
                or any(ch in host or ch in domain or ch in path or ch in sni
                       for ch in '\r\n')):
            raise ValueError('invalid WebSocket endpoint')

        async def _open() -> 'RawWebSocket':
            reader, writer = await asyncio.open_connection(
                host,
                443,
                ssl=_ssl_ctx,
                server_hostname=sni,
                ssl_handshake_timeout=min(timeout, 5.0),
                limit=RawWebSocket.MAX_HTTP_HEADER_BYTES + 1,
            )
            try:
                set_sock_opts(writer.transport, proxy_config.buffer_size)
                ws_key = base64.b64encode(os.urandom(16)).decode('ascii')
                req = (
                    f'GET {path} HTTP/1.1\r\n'
                    f'Host: {domain}\r\n'
                    f'Upgrade: websocket\r\n'
                    f'Connection: Upgrade\r\n'
                    f'Sec-WebSocket-Key: {ws_key}\r\n'
                    f'Sec-WebSocket-Version: 13\r\n'
                    f'Sec-WebSocket-Protocol: binary\r\n'
                    f'\r\n'
                )
                writer.write(req.encode('ascii'))
                await writer.drain()
                status_code, status_line, headers = (
                    await RawWebSocket._read_http_response(reader, ws_key))
                if status_code != 101:
                    raise WsHandshakeError(
                        status_code,
                        status_line,
                        headers,
                        location=headers.get('location'),
                    )
                return RawWebSocket(reader, writer)
            except BaseException:
                await _close_writer(writer)
                raise

        try:
            async with asyncio.timeout(timeout):
                return await _open()
        except TimeoutError as exc:
            raise TimeoutError('WebSocket setup deadline exceeded') from exc

    async def send(self, data: bytes):
        if self._closed:
            raise ConnectionError("WebSocket closed")
        frame = self._build_frame(self.OP_BINARY, data, mask=True)
        self.writer.write(frame)
        await self.writer.drain()

    async def send_batch(self, parts: List[bytes]):
        if self._closed:
            raise ConnectionError("WebSocket closed")
        for part in parts:
            self.writer.write(
                self._build_frame(self.OP_BINARY, part, mask=True))
        await self.writer.drain()

    async def recv(self) -> Optional[bytes]:
        while not self._closed:
            opcode, payload, fin = await self._read_frame()

            if opcode == self.OP_CLOSE:
                self._closed = True
                code, reason = self._parse_close(payload)
                log.debug("WS OP_CLOSE from upstream: code=%s reason=%r",
                          code, reason)
                try:
                    self.writer.write(self._build_frame(
                        self.OP_CLOSE,
                        payload[:2] if payload else b'', mask=True))
                    await self.writer.drain()
                except Exception:
                    pass
                return None

            if opcode == self.OP_PING:
                try:
                    self.writer.write(
                        self._build_frame(self.OP_PONG, payload, mask=True))
                    await self.writer.drain()
                except Exception:
                    pass
                continue

            if opcode == self.OP_PONG:
                continue

            if opcode in (self.OP_CONT, 0x1, self.OP_BINARY):
                if fin and not self._frag:
                    return payload
                self._frag.extend(payload)
                if len(self._frag) > self.MAX_MESSAGE_LEN:
                    raise ConnectionError(
                        f"WS message too large: {len(self._frag)} bytes")
                if not fin:
                    continue
                message = bytes(self._frag)
                self._frag.clear()
                return message
            continue
        return None

    async def close(self):
        was_closed = self._closed
        self._closed = True
        if not was_closed:
            try:
                self.writer.write(
                    self._build_frame(self.OP_CLOSE, b'', mask=True))
                await asyncio.wait_for(
                    self.writer.drain(), timeout=self.CLOSE_TIMEOUT)
            except (Exception, asyncio.CancelledError):
                pass
        await _close_writer(self.writer)

    _WS_CLOSE_REASONS = {
        1000: 'normal', 1001: 'going_away', 1002: 'protocol_error',
        1003: 'unsupported_data', 1006: 'abnormal', 1007: 'bad_data',
        1008: 'policy_violation', 1009: 'too_big', 1010: 'missing_extension',
        1011: 'internal_error',
    }

    @classmethod
    def _parse_close(cls, payload: Optional[bytes]) -> Tuple[Optional[int], str]:
        if not payload or len(payload) < 2:
            return None, ''
        try:
            code = int.from_bytes(payload[:2], 'big')
            text = payload[2:].decode('utf-8', errors='replace')
            name = cls._WS_CLOSE_REASONS.get(code)
            return code, f"{text} ({name})" if name else text
        except Exception:
            return None, ''

    @staticmethod
    def _build_frame(opcode: int, data: bytes,
                     mask: bool = False) -> bytes:
        length = len(data)
        fb = 0x80 | opcode
        if not mask:
            if length < 126:
                return _st_BB.pack(fb, length) + data
            if length < 65536:
                return _st_BBH.pack(fb, 126, length) + data
            return _st_BBQ.pack(fb, 127, length) + data
        mask_key = os.urandom(4)
        masked = _xor_mask(data, mask_key)
        if length < 126:
            return _st_BB4s.pack(fb, 0x80 | length, mask_key) + masked
        if length < 65536:
            return _st_BBH4s.pack(fb, 0x80 | 126, length, mask_key) + masked
        return _st_BBQ4s.pack(fb, 0x80 | 127, length, mask_key) + masked

    async def _read_frame(self) -> Tuple[int, bytes, bool]:
        hdr = await self.reader.readexactly(2)
        fin = bool(hdr[0] & 0x80)
        opcode = hdr[0] & 0x0F
        length = hdr[1] & 0x7F
        if length == 126:
            length = _st_H.unpack(await self.reader.readexactly(2))[0]
        elif length == 127:
            length = _st_Q.unpack(await self.reader.readexactly(8))[0]
        if length > self.MAX_MESSAGE_LEN:
            raise ConnectionError(f"WS frame too large: {length} bytes")
        if hdr[1] & 0x80:
            mask_key = await self.reader.readexactly(4)
            payload = await self.reader.readexactly(length)
            return opcode, _xor_mask(payload, mask_key), fin
        payload = await self.reader.readexactly(length)
        return opcode, payload, fin
