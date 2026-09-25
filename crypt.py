# Aurora v1.9.0 «Кот-правозащитник» — шифрование данных на диске.
# Только stdlib: ChaCha20-Poly1305 (RFC 8439), формат AURORA2.
# Защита от чтения файлов данных (subs.json, keys.json) вне панели.
# Формат файла: AURORA2 + nonce(12) + ciphertext + tag(16, Poly1305).
# Легаси-чтение: AURORA1 (HMAC-SHA256) и открытый JSON; миграция в AURORA2.

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import struct
import subprocess as _subprocess
from subprocess import SubprocessError

_ICACLS_RUN = _subprocess.run
_DACL_DONE = set()
import tempfile
import time
import threading

try:
    from config import DATA_DIR, log
except Exception:
    DATA_DIR = "."
    def log(msg):
        pass

STORAGE_VERSION = 2
_CHACHA_CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
_MAGIC = b"AURORA2"
_MAGIC_LEGACY = b"AURORA1"
_MAGIC_PREFIX_LEN = len(_MAGIC)
_NONCE_LEN = 12
_TAG_LEN = 16
_LEGACY_NONCE_LEN = 16
_LEGACY_TAG_LEN = 32
_MASK32 = 0xFFFFFFFF
_POLY_MODULUS = (1 << 130) - 5
_KEY_FILE = os.path.join(DATA_DIR, ".aurora_key")
_KEY_LOCK_FILE = os.path.join(DATA_DIR, ".aurora_key.lock")

_key = None
_KEY_LOCK = threading.Lock()


class StorageError(ValueError):
    pass


class KeyFileError(StorageError):
    pass


def _dacl_owner_only(path, directory=False):
    """Windows DACL: только владелец, SYSTEM и Administrators, без наследования."""
    if os.name != "nt":
        return False
    key = str(path) + ("/d" if directory else "")
    if key in _DACL_DONE:
        return True
    grants = ["*S-1-5-18:(F)", "*S-1-5-32-544:(F)"]
    user = str(os.environ.get("USERNAME") or "").strip()
    if user:
        grants.insert(0, "%s:(F)" % user)
    args = ["icacls", str(path), "/inheritance:r", "/grant:r"] + grants
    if directory:
        args.append("/T")
    try:
        proc = _ICACLS_RUN(args, capture_output=True, timeout=30)
    except (OSError, ValueError, SubprocessError):
        return False
    if proc.returncode != 0:
        return False
    _DACL_DONE.add(key)
    return True


def restrict_file(path):
    """Доступ к файлу только владельцу: 0600 в POSIX, DACL в Windows."""
    if not path:
        return False
    if os.name == "nt":
        if _dacl_owner_only(path):
            return True
        try:
            import stat
            os.chmod(str(path), stat.S_IREAD | stat.S_IWRITE)
        except OSError:
            return False
        return True
    try:
        os.chmod(str(path), 0o600)
    except OSError:
        return False
    return True


def restrict_dir(path):
    """Каталог данных: 0700 в POSIX, DACL без наследования в Windows."""
    if not path:
        return False
    if os.name == "nt":
        if _dacl_owner_only(path, directory=True):
            return True
    try:
        os.chmod(str(path), 0o700)
    except OSError:
        return False
    return True


_restrict_file = restrict_file


def _sync_directory(directory):
    if os.name == "nt":
        return
    try:
        fd = os.open(directory or ".", os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


TEMP_MAX_AGE_S = 3600
TEMP_SWEEP_CAP = 64
_TEMP_NAME_RE = re.compile(r"^(?:\.xray-.*\.tmp|\.xray-test-.*\.json|keytest_cfg_.*\.json)$")


def secure_temp_path(directory, prefix, suffix=""):
    directory = os.path.abspath(directory or ".")
    os.makedirs(directory, exist_ok=True)
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=directory)
    try:
        _restrict_file(path)
    finally:
        os.close(fd)
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    return path


def sweep_stale_temps(dirs=None, max_age=TEMP_MAX_AGE_S):
    if dirs is None:
        dirs = (DATA_DIR,)
    elif isinstance(dirs, (str, bytes, os.PathLike)):
        dirs = (dirs,)
    cutoff = time.time() - max(0.0, float(max_age))
    removed = 0
    for directory in dirs:
        try:
            entries = os.scandir(directory)
        except OSError:
            continue
        with entries:
            for entry in entries:
                if removed >= TEMP_SWEEP_CAP:
                    return removed
                if not _TEMP_NAME_RE.match(entry.name):
                    continue
                try:
                    if not entry.is_file(follow_symlinks=False):
                        continue
                    if entry.stat(follow_symlinks=False).st_mtime >= cutoff:
                        continue
                    os.unlink(entry.path)
                    removed += 1
                except OSError:
                    continue
    return removed


def unlink_quiet(path, what="temporary file"):
    try:
        os.unlink(path)
    except FileNotFoundError:
        return False
    except OSError as e:
        try:
            log("crypt: не удалось удалить %s: %s" % (what, e))
        except Exception:
            pass
        return False
    return True


def _atomic_write(path, data):
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".%s." % os.path.basename(path), suffix=".tmp", dir=directory)
    closed = False
    try:
        with os.fdopen(fd, "wb") as f:
            closed = True
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        _restrict_file(tmp)
        os.replace(tmp, path)
        _restrict_file(path)
        _sync_directory(directory)
    except Exception:
        if not closed:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _write_exclusive(path, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    fd = os.open(path, flags, 0o600)
    closed = False
    try:
        with os.fdopen(fd, "wb") as f:
            closed = True
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        _restrict_file(path)
        _sync_directory(os.path.dirname(os.path.abspath(path)))
    except Exception:
        if not closed:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


def _quarantine_key(raw):
    candidate = _KEY_FILE + ".corrupt"
    index = 1
    while os.path.exists(candidate):
        candidate = "%s.corrupt.%d" % (_KEY_FILE, index)
        index += 1
    _write_exclusive(candidate, raw)
    try:
        log("crypt: файл-ключ помещён в карантин (%s)" % os.path.basename(candidate))
    except Exception:
        pass


def _encrypted_payload_exists():
    try:
        entries = os.scandir(DATA_DIR)
    except OSError as e:
        raise KeyFileError("не удалось проверить зашифрованные данные: %s" % e) from e
    with entries:
        for entry in entries:
            if entry.name in (".aurora_key", ".aurora_key.lock", ".vless-public.lock") or not entry.is_file(follow_symlinks=False):
                continue
            try:
                with open(entry.path, "rb") as f:
                    prefix = f.read(len(_MAGIC))
            except FileNotFoundError:
                continue
            except OSError as e:
                raise KeyFileError("не удалось проверить файл данных %s: %s" % (entry.name, e)) from e
            if prefix in (_MAGIC, _MAGIC_LEGACY):
                return True
    return False


def _lock_key_file():
    os.makedirs(DATA_DIR, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    fd = os.open(_KEY_LOCK_FILE, flags, 0o600)
    try:
        if os.name == "nt":
            import msvcrt
            if os.fstat(fd).st_size < 1:
                os.write(fd, b"\0")
                os.fsync(fd)
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX)
    except Exception:
        os.close(fd)
        raise
    return fd


def _unlock_key_file(fd):
    try:
        if os.name == "nt":
            import msvcrt
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _load_key():
    global _key
    if _key is not None:
        return _key
    with _KEY_LOCK:
        if _key is not None:
            return _key
        try:
            lock_fd = _lock_key_file()
        except OSError as e:
            raise KeyFileError("не удалось заблокировать файл-ключ: %s" % e) from e
        try:
            try:
                with open(_KEY_FILE, "rb") as f:
                    raw = f.read()
            except FileNotFoundError:
                if _encrypted_payload_exists():
                    raise KeyFileError("файл-ключ отсутствует, но найдены зашифрованные данные")
                key = secrets.token_bytes(32)
                try:
                    _atomic_write(_KEY_FILE, key)
                except OSError as e:
                    raise KeyFileError("не удалось создать файл-ключ: %s" % e) from e
                _key = key
                log("crypt: файл-ключ создан (%s)" % _KEY_FILE)
                return _key
            except OSError as e:
                raise KeyFileError("не удалось прочитать файл-ключ: %s" % e) from e
            if len(raw) != 32:
                try:
                    _quarantine_key(raw)
                except OSError as e:
                    raise KeyFileError("файл-ключ повреждён; карантин не создан: %s" % e) from e
                raise KeyFileError("файл-ключ повреждён и сохранён в карантин")
            _key = raw
            return _key
        finally:
            _unlock_key_file(lock_fd)


def _rotl32(value, count):
    return ((value << count) | (value >> (32 - count))) & _MASK32


def _quarter_round(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & _MASK32
    state[d] = _rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & _MASK32
    state[b] = _rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & _MASK32
    state[d] = _rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & _MASK32
    state[b] = _rotl32(state[b] ^ state[c], 7)


def _chacha20_stream(key, nonce, counter, length):
    if length <= 0:
        return b""
    base = list(_CHACHA_CONSTANTS) + list(struct.unpack("<8I", key))
    base += [counter & _MASK32] + list(struct.unpack("<3I", nonce))
    out = bytearray()
    for index in range((length + 63) // 64):
        base[12] = (counter + index) & _MASK32
        state = list(base)
        for _ in range(10):
            _quarter_round(state, 0, 4, 8, 12)
            _quarter_round(state, 1, 5, 9, 13)
            _quarter_round(state, 2, 6, 10, 14)
            _quarter_round(state, 3, 7, 11, 15)
            _quarter_round(state, 0, 5, 10, 15)
            _quarter_round(state, 1, 6, 11, 12)
            _quarter_round(state, 2, 7, 8, 13)
            _quarter_round(state, 3, 4, 9, 14)
        out += struct.pack("<16I", *[(state[i] + base[i]) & _MASK32 for i in range(16)])
    return bytes(out[:length])


def _xor_bytes(left, right):
    size = len(left)
    if size == 0:
        return b""
    return (int.from_bytes(left, "big") ^ int.from_bytes(right, "big")).to_bytes(size, "big")


def _poly1305(one_time_key, message):
    r = int.from_bytes(one_time_key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(one_time_key[16:32], "little")
    acc = 0
    for offset in range(0, len(message), 16):
        block = int.from_bytes(message[offset:offset + 16] + b"\x01", "little")
        acc = ((acc + block) * r) % _POLY_MODULUS
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(data):
    remainder = len(data) % 16
    return b"" if remainder == 0 else b"\x00" * (16 - remainder)


def _aead_mac_input(aad, ciphertext):
    return (aad + _pad16(aad) + ciphertext + _pad16(ciphertext)
            + struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ciphertext)))


def _aead_key(key):
    return hashlib.sha512(b"aurora2" + key).digest()[:32]


def _aead_otk(aead_key, nonce):
    return _chacha20_stream(aead_key, nonce, 0, 64)[:32]


def _aead_seal(key, nonce, plain, aad):
    aead_key = _aead_key(key)
    ciphertext = _xor_bytes(plain, _chacha20_stream(aead_key, nonce, 1, len(plain)))
    return ciphertext + _poly1305(_aead_otk(aead_key, nonce), _aead_mac_input(aad, ciphertext))


def _aead_open(key, nonce, body, aad):
    if len(body) < _TAG_LEN + 1:
        raise StorageError("короткое зашифрованное тело")
    aead_key = _aead_key(key)
    ciphertext = body[:-_TAG_LEN]
    tag = body[-_TAG_LEN:]
    expect = _poly1305(_aead_otk(aead_key, nonce), _aead_mac_input(aad, ciphertext))
    if not hmac.compare_digest(tag, expect):
        raise StorageError("контрольная сумма не совпадает")
    return _xor_bytes(ciphertext, _chacha20_stream(aead_key, nonce, 1, len(ciphertext)))


def _legacy_stream(key, nonce, length):
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(key + nonce + counter.to_bytes(8, "big")).digest()
        counter += 1
    return out[:length]


def _decrypt_legacy(data):
    if len(data) < _MAGIC_PREFIX_LEN + _LEGACY_NONCE_LEN + _LEGACY_TAG_LEN + 1:
        raise StorageError("короткое зашифрованное тело")
    key = _load_key()
    nonce = data[_MAGIC_PREFIX_LEN:_MAGIC_PREFIX_LEN + _LEGACY_NONCE_LEN]
    body = data[_MAGIC_PREFIX_LEN + _LEGACY_NONCE_LEN:]
    ciphertext = body[:-_LEGACY_TAG_LEN]
    tag = body[-_LEGACY_TAG_LEN:]
    if not hmac.compare_digest(tag, hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()):
        raise StorageError("контрольная сумма не совпадает")
    return _xor_bytes(ciphertext, _legacy_stream(key, nonce, len(ciphertext)))


def is_encrypted(data):
    if not isinstance(data, (bytes, bytearray)):
        return False
    return data.startswith(_MAGIC) or data.startswith(_MAGIC_LEGACY)


def encrypt_bytes(plain):
    key = _load_key()
    plain = bytes(plain)
    nonce = secrets.token_bytes(_NONCE_LEN)
    return _MAGIC + nonce + _aead_seal(key, nonce, plain, _MAGIC)


def decrypt_bytes(data):
    if not isinstance(data, (bytes, bytearray)):
        raise StorageError("не зашифрованные данные")
    data = bytes(data)
    if data.startswith(_MAGIC):
        nonce = data[_MAGIC_PREFIX_LEN:_MAGIC_PREFIX_LEN + _NONCE_LEN]
        if len(nonce) != _NONCE_LEN:
            raise StorageError("короткое зашифрованное тело")
        return _aead_open(_load_key(), nonce, data[_MAGIC_PREFIX_LEN + _NONCE_LEN:], _MAGIC)
    if data.startswith(_MAGIC_LEGACY):
        return _decrypt_legacy(data)
    raise StorageError("не зашифрованные данные")


def storage_version(data):
    if not isinstance(data, (bytes, bytearray)) or not data:
        return 0
    if data.startswith(_MAGIC):
        return STORAGE_VERSION
    if data.startswith(_MAGIC_LEGACY):
        return 1
    return 0


def needs_migration(data):
    return storage_version(data) == 1


def migrate_bytes(data):
    version = storage_version(data)
    if version == STORAGE_VERSION:
        return bytes(data)
    if version == 1:
        return encrypt_bytes(_decrypt_legacy(bytes(data)))
    return bytes(data)


def encrypted_storage_files(directory=None):
    directory = directory or DATA_DIR
    reserved = (os.path.basename(_KEY_FILE), os.path.basename(_KEY_LOCK_FILE), ".vless-public.lock")
    found = []
    try:
        entries = os.scandir(directory)
    except OSError:
        return found
    with entries:
        for entry in entries:
            if entry.name in reserved or not entry.is_file(follow_symlinks=False):
                continue
            try:
                with open(entry.path, "rb") as f:
                    prefix = f.read(_MAGIC_PREFIX_LEN)
            except OSError:
                continue
            if prefix in (_MAGIC, _MAGIC_LEGACY):
                found.append(entry.path)
    return found


def migrate_file(filepath):
    try:
        with open(filepath, "rb") as f:
            raw = f.read()
    except FileNotFoundError:
        return False
    except OSError as e:
        raise StorageError("не удалось прочитать %s: %s" % (os.path.basename(filepath), e)) from e
    if not needs_migration(raw):
        return False
    _atomic_write(filepath, migrate_bytes(raw))
    return True


def migrate_all(paths=None, strict=False):
    if paths is None:
        paths = encrypted_storage_files()
    migrated = []
    for path in paths:
        try:
            if migrate_file(path):
                migrated.append(os.path.basename(path))
        except StorageError as e:
            if strict:
                raise
            log("crypt: миграция %s не выполнена: %s" % (os.path.basename(path), e))
    return migrated


def opaque_id(value, domain):
    if not isinstance(value, str) or not value:
        raise ValueError("opaque id value is invalid")
    if not isinstance(domain, str) or not domain:
        raise ValueError("opaque id domain is invalid")
    key = _load_key()
    message = ("aurora:%s\0" % domain).encode("ascii") + value.encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def is_opaque_id(value):
    return (isinstance(value, str) and len(value) == 64
            and all(ch in "0123456789abcdef" for ch in value))


def load_bytes(filepath, default=None):
    try:
        with open(filepath, "rb") as f:
            raw = f.read()
    except FileNotFoundError:
        return default
    except OSError as e:
        raise StorageError("не удалось прочитать %s: %s" % (os.path.basename(filepath), e)) from e
    try:
        return decrypt_bytes(raw) if is_encrypted(raw) else raw
    except StorageError:
        raise


def save_bytes(filepath, data, exclusive=False):
    encoded = encrypt_bytes(bytes(data))
    if exclusive:
        _write_exclusive(filepath, encoded)
    else:
        _atomic_write(filepath, encoded)


def load_json(filepath, default=None):
    if default is None:
        default = {}
    try:
        with open(filepath, "rb") as f:
            raw = f.read()
    except FileNotFoundError:
        return default
    except OSError as e:
        raise StorageError("не удалось прочитать %s: %s" % (os.path.basename(filepath), e)) from e
    plain = decrypt_bytes(raw) if is_encrypted(raw) else raw
    try:
        return json.loads(plain.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise StorageError("не удалось разобрать JSON %s: %s" % (os.path.basename(filepath), e)) from e


def save_json(filepath, obj):
    plain = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
    data = encrypt_bytes(plain)
    _atomic_write(filepath, data)


def storage_version_name(data):
    version = storage_version(data)
    if version == 0:
        return "plaintext"
    if version == 1:
        return "aurora1-legacy"
    return "aurora2-aead"
