# Aurora v1.7.0 «Кот в законе» — шифрование данных на диске.
# Только stdlib: HMAC-SHA256 потоковый шифр (CTR-подобный) + аутентификация.
# Защита от чтения файлов данных (subs.json, keys.json) вне панели.
# Формат файла: AURORA1 + nonce(16) + ciphertext + tag(32, HMAC-SHA256).
# Легаси-чтение: если файл начинается с '{' — читается как обычный JSON.

import hashlib
import hmac
import json
import os
import secrets
import threading

try:
    from config import DATA_DIR, log
except Exception:  # изолированное использование модуля
    DATA_DIR = "."
    def log(msg):
        pass

_MAGIC = b"AURORA1"
_NONCE_LEN = 16
_TAG_LEN = 32
_KEY_FILE = os.path.join(DATA_DIR, ".aurora_key")

_key = None
_KEY_LOCK = threading.Lock()


def _load_key():
    """Загружает или создаёт файл-ключ (32 байта, chmod 600)."""
    global _key
    if _key:
        return _key
    with _KEY_LOCK:
        if _key:
            return _key
        try:
            with open(_KEY_FILE, "rb") as f:
                raw = f.read(64)
            _key = raw if len(raw) == 32 else None
        except OSError:
            _key = None
        if not _key:
            _key = secrets.token_bytes(32)
            tmp = _KEY_FILE + ".tmp"
            with open(tmp, "wb") as f:
                f.write(_key)
            os.replace(tmp, _KEY_FILE)
            if os.name != "nt":
                try:
                    os.chmod(_KEY_FILE, 0o600)
                except OSError:
                    pass
            log("crypt: файл-ключ создан (%s)" % _KEY_FILE)
        return _key


def _stream(key, nonce, length):
    """Генерирует keystream DB_ blocks (SHA-256 CTR)."""
    out = b""
    counter = 0
    while len(out) < length:
        block = hashlib.sha256(key + nonce + counter.to_bytes(8, "big")).digest()
        out += block
        counter += 1
    return out[:length]


def encrypt_bytes(plain):
    """Шифрует байты: magic + nonce + ciphertext + tag."""
    key = _load_key()
    nonce = secrets.token_bytes(_NONCE_LEN)
    ct = bytes(a ^ b for a, b in zip(plain, _stream(key, nonce, len(plain))))
    tag = hmac.new(key, nonce + ct, hashlib.sha256).digest()
    return _MAGIC + nonce + ct + tag


def decrypt_bytes(data):
    """Расшифровывает байты; ValueError при повреждении."""
    if not isinstance(data, bytes) or not data.startswith(_MAGIC):
        raise ValueError("не зашифрованные данные")
    key = _load_key()
    nonce = data[len(_MAGIC):len(_MAGIC) + _NONCE_LEN]
    body = data[len(_MAGIC) + _NONCE_LEN:]
    if len(body) <= _TAG_LEN:
        raise ValueError("короткое тело")
    ct, tag = body[:-_TAG_LEN], body[-_TAG_LEN:]
    expect = hmac.new(key, nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expect):
        raise ValueError("контрольная сумма не совпадает")
    return bytes(a ^ b for a, b in zip(ct, _stream(key, nonce, len(ct))))


def load_json(filepath, default=None):
    """Читает JSON: зашифрованный формат (v1.7.0) или легаси-плейн. default при ошибке."""
    if default is None:
        default = {}
    try:
        with open(filepath, "rb") as f:
            raw = f.read()
        if raw.startswith(_MAGIC):
            plain = decrypt_bytes(raw)
        else:
            plain = raw
        return json.loads(plain.decode("utf-8"))
    except Exception as e:
        log("crypt: не читается %s: %s" % (os.path.basename(filepath), e))
        return default


def save_json(filepath, obj):
    """Атомарно пишет JSON в зашифрованном виде (tmp + os.replace)."""
    plain = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
    data = encrypt_bytes(plain)
    tmp = filepath + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, filepath)