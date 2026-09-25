# Aurora release signature (Ed25519, RFC 8032), only stdlib.
# Detached signature of the release manifest: repo, version, asset name, sha256.
# Fail-closed: without a pinned public key the update is never applied.

import base64
import hashlib
import hmac
import os
import re

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)
_G_Y = 4 * pow(5, _P - 2, _P) % _P
_IDENTITY = (0, 1, 1, 0)

PUBKEY_ENV = "AURORA_UPDATE_PUBKEY"
PUBKEY_BYTES = 32
SEED_BYTES = 32
SIG_BYTES = 64
SIGNATURE_CONTEXT = b"aurora-release-v1"


class SignatureError(ValueError):
    pass


def _sha512(data):
    return hashlib.sha512(data).digest()


def _sha512_int(data):
    return int.from_bytes(_sha512(data), "little")


def _inv(x):
    return pow(x, _P - 2, _P)


def _x_recover(y):
    xx = (y * y - 1) * _inv(_D * y * y + 1) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = x * _SQRT_M1 % _P
    if x % 2 != 0:
        x = _P - x
    return x


_G_X = _x_recover(_G_Y)
_G = (_G_X, _G_Y, 1, _G_X * _G_Y % _P)


def _point_add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = t1 * 2 * _D * t2 % _P
    dd = z1 * 2 * z2 % _P
    e = b - a
    f = dd - c
    g = dd + c
    h = b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _point_mul(s, p):
    q = _IDENTITY
    while s > 0:
        if s & 1:
            q = _point_add(q, p)
        p = _point_add(p, p)
        s >>= 1
    return q


def _point_equal(p, q):
    x1, y1, z1, _t1 = p
    x2, y2, z2, _t2 = q
    if (x1 * z2 - x2 * z1) % _P != 0:
        return False
    return (y1 * z2 - y2 * z1) % _P == 0


def _point_compress(p):
    x, y, z, _t = p
    zinv = _inv(z)
    x = x * zinv % _P
    y = y * zinv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _point_decompress(data):
    if len(data) != 32:
        return None
    value = int.from_bytes(data, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    if y >= _P:
        return None
    x = _x_recover(y)
    if x & 1 != sign:
        x = _P - x
    point = (x, y, 1, x * y % _P)
    if not _point_equal(_point_mul(_L, point), _IDENTITY):
        return None
    return point


def _secret_expand(seed):
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != SEED_BYTES:
        raise SignatureError("seed Ed25519 должен быть %d байт" % SEED_BYTES)
    h = _sha512(bytes(seed))
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(seed):
    a, _prefix = _secret_expand(seed)
    return _point_compress(_point_mul(a, _G))


def sign(seed, message):
    a, prefix = _secret_expand(seed)
    pub = _point_compress(_point_mul(a, _G))
    r = _sha512_int(prefix + bytes(message)) % _L
    big_r = _point_compress(_point_mul(r, _G))
    k = _sha512_int(big_r + pub + bytes(message)) % _L
    s = (r + k * a) % _L
    return big_r + int.to_bytes(s, 32, "little")


def verify(pub, message, signature):
    if not isinstance(pub, (bytes, bytearray)) or len(pub) != PUBKEY_BYTES:
        return False
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != SIG_BYTES:
        return False
    pub = bytes(pub)
    signature = bytes(signature)
    big_r = _point_decompress(signature[:32])
    if big_r is None:
        return False
    point_a = _point_decompress(pub)
    if point_a is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    k = _sha512_int(signature[:32] + pub + bytes(message)) % _L
    return _point_equal(_point_mul(s, _G), _point_add(big_r, _point_mul(k, point_a)))


def generate_keypair():
    seed = os.urandom(SEED_BYTES)
    return seed, public_key(seed)


def parse_pubkey(value):
    text = str(value or "").strip()
    if not text:
        return b""
    if re.fullmatch(r"[0-9a-fA-F]{64}", text):
        return bytes.fromhex(text)
    try:
        raw = base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
    except Exception:
        raise SignatureError("публичный ключ задан в неизвестном формате")
    if len(raw) != PUBKEY_BYTES:
        raise SignatureError("публичный ключ должен быть %d байт" % PUBKEY_BYTES)
    return raw


def encode_pubkey(pub):
    return base64.b64encode(bytes(pub)).decode("ascii")


def load_pubkey(configured=None):
    raw = os.environ.get(PUBKEY_ENV) or str(configured or "")
    if not raw.strip():
        return b""
    return parse_pubkey(raw)


def fingerprint(pub):
    return hashlib.sha256(bytes(pub)).hexdigest()[:16]


def manifest(repo, version, asset, digest):
    lines = [SIGNATURE_CONTEXT.decode("ascii")]
    for key, value in (("repo", repo), ("version", version), ("asset", asset), ("sha256", digest)):
        text = str(value if value is not None else "")
        if "\n" in text or "\r" in text:
            raise SignatureError("поле манифеста содержит перевод строки: %s" % key)
        lines.append("%s=%s" % (key, text))
    return ("\n".join(lines) + "\n").encode("utf-8")


def sign_release(seed, repo, version, asset, data):
    digest = hashlib.sha256(bytes(data)).hexdigest()
    raw = sign(seed, manifest(repo, version, asset, digest))
    return base64.b64encode(raw).decode("ascii")


def verify_release(data, signature, pubkey=None, repo="", version="", asset=""):
    if signature is None or (isinstance(signature, (bytes, bytearray)) and not signature):
        raise SignatureError("у релиза отсутствует файл подписи")
    pub = load_pubkey(pubkey)
    if not pub:
        raise SignatureError("не задан публичный ключ подписи (%s)" % PUBKEY_ENV)
    if isinstance(signature, str):
        raw = signature.strip()
        if raw.lower().startswith("ed25519:"):
            raw = raw.split(":", 1)[1].strip()
        try:
            sig = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True)
        except Exception:
            raise SignatureError("подпись релиза повреждена")
    else:
        sig = bytes(signature)
    if len(sig) != SIG_BYTES:
        raise SignatureError("подпись релиза неверной длины")
    digest = hashlib.sha256(bytes(data)).hexdigest()
    if not verify(pub, manifest(repo, version, asset, digest), sig):
        raise SignatureError("подпись релиза недействительна")
    return {"digest": digest, "key": fingerprint(pub), "asset": str(asset or "")}


def verify_pair(pub, message, signature):
    return verify(parse_pubkey(pub) if isinstance(pub, str) else pub, message, signature)


def compare(a, b):
    return hmac.compare_digest(str(a).encode(), str(b).encode())
