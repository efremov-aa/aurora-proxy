import os
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TREES = (ROOT / "windows", ROOT)

WORKER = r"""
import os, sys, hmac, hashlib

data = sys.argv[2]
os.environ["AURORA_DATA_DIR"] = data
sys.path.insert(0, sys.argv[1])
import crypt

crypt.DATA_DIR = data
crypt._KEY_FILE = os.path.join(data, ".aurora_key")
crypt._KEY_LOCK_FILE = os.path.join(data, ".aurora_key.lock")
crypt._key = None


def xor(left, right):
    size = len(left)
    return (int.from_bytes(left, "big") ^ int.from_bytes(right, "big")).to_bytes(size, "big")


def legacy_payload(key, plain):
    nonce = b"\x11" * 16
    stream = crypt._legacy_stream(key, nonce, len(plain))
    body = xor(plain, stream)
    tag = hmac.new(key, nonce + body, hashlib.sha256).digest()
    return b"AURORA1" + nonce + body + tag


rfc_key = bytes(range(32))
rfc_nonce = bytes.fromhex("000000090000004a00000000")
ks = crypt._chacha20_stream(rfc_key, rfc_nonce, 1, 64)
assert ks.hex() == (
    "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
    "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"), ks[:16].hex()
assert crypt._chacha20_stream(rfc_key, rfc_nonce, 1, 0) == b""

poly_key = bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
poly_msg = b"Cryptographic Forum Research Group"
assert crypt._poly1305(poly_key, poly_msg).hex() == "a8061dc1305136c6c22b8baf0c0127a9"
assert len(crypt._poly1305(poly_key, poly_msg)) == 16

ae_key = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
ae_nonce = bytes.fromhex("070000004041424344454647")
ae_aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
ae_plain = (
    b"Ladies and Gentlemen of the class of '99: If I could offer you "
    b"only one tip for the future, sunscreen would be it."
)
ae_ct_hex = (
    "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d"
    "63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3"
    "692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3"
    "ff4def08e4b7a9de576d26586cec64b6116"
)
ae_tag_hex = "1ae10b594f09e26a7e902ecbd0600691"
assert len(ae_plain) * 2 == len(ae_ct_hex)
ae_ct = xor(ae_plain, crypt._chacha20_stream(ae_key, ae_nonce, 1, len(ae_plain)))
assert ae_ct.hex() == ae_ct_hex
ae_otk = crypt._chacha20_stream(ae_key, ae_nonce, 0, 64)[:32]
assert crypt._poly1305(ae_otk, crypt._aead_mac_input(ae_aad, ae_ct)).hex() == ae_tag_hex
long_ks = crypt._chacha20_stream(ae_key, ae_nonce, 5, 200)
assert long_ks[:64] == crypt._chacha20_stream(ae_key, ae_nonce, 5, 64)
assert long_ks[64:128] == crypt._chacha20_stream(ae_key, ae_nonce, 6, 64)
assert long_ks[128:192] == crypt._chacha20_stream(ae_key, ae_nonce, 7, 64)
assert long_ks[192:] == crypt._chacha20_stream(ae_key, ae_nonce, 8, 8)
own = crypt._aead_seal(crypt._load_key(), b"\x02" * 12, b"ping", b"AURORA2")
assert len(own) == len(b"ping") + 16
assert crypt._aead_open(crypt._load_key(), b"\x02" * 12, own, b"AURORA2") == b"ping"
try:
    crypt._aead_open(crypt._load_key(), b"\x02" * 12, own, b"AURORA3")
    raise AssertionError("aead: wrong aad accepted")
except crypt.StorageError:
    pass
try:
    crypt._aead_open(crypt._load_key(), b"\x02" * 12, b"short", b"AURORA2")
    raise AssertionError("aead: short body accepted")
except crypt.StorageError:
    pass
nonce_a = b"\x04" * 12
sealed_a = crypt._aead_seal(crypt._load_key(), nonce_a, ae_plain, ae_aad)
sealed_b = crypt._aead_seal(crypt._load_key(), nonce_a, ae_plain, ae_aad)
assert sealed_a == sealed_b
assert crypt._aead_open(crypt._load_key(), nonce_a, sealed_a, ae_aad) == ae_plain
assert crypt.encrypt_bytes(b"same") != crypt.encrypt_bytes(b"same")
assert crypt.decrypt_bytes(crypt.encrypt_bytes(b"same")) == b"same"

assert crypt.STORAGE_VERSION == 2
assert crypt._aead_key(b"k") == hashlib.sha512(b"aurora2" + b"k").digest()[:32]
assert crypt._aead_otk(crypt._aead_key(b"k"), b"\x03" * 12) == \
    crypt._chacha20_stream(crypt._aead_key(b"k"), b"\x03" * 12, 0, 64)[:32]
assert crypt._pad16(b"1234567890123456") == b""
assert len(crypt._pad16(b"12345")) == 11
assert crypt._aead_mac_input(b"", b"") == b"\x00" * 16
assert crypt._MAGIC == b"AURORA2"
assert crypt._MAGIC_LEGACY == b"AURORA1"
assert crypt._NONCE_LEN == 12 and crypt._TAG_LEN == 16

assert crypt.is_encrypted(b'{"a": 1}') is False
assert crypt.storage_version(b'{"a": 1}') == 0
assert crypt.storage_version(b"") == 0
assert crypt.storage_version_name(b'{"a": 1}') == "plaintext"
assert crypt.needs_migration(b'{"a": 1}') is False

path = os.path.join(data, "state.json")
payload = {"a": 1, "b": "тест", "c": [1, 2, 3]}
crypt.save_json(path, payload)
raw = open(path, "rb").read()
assert raw.startswith(b"AURORA2"), raw[:8]
assert crypt.storage_version(raw) == 2
assert crypt.storage_version_name(raw) == "aurora2-aead"
assert crypt.is_encrypted(raw) is True
assert crypt.needs_migration(raw) is False
assert crypt.load_json(path) == payload
assert crypt.decrypt_bytes(crypt.encrypt_bytes(b"ping")) == b"ping"

legacy = legacy_payload(crypt._load_key(), b'{"a": 7, "b": "legacy"}')
legacy_path = os.path.join(data, "legacy.json")
open(legacy_path, "wb").write(legacy)
assert legacy.startswith(b"AURORA1")
assert crypt.storage_version(legacy) == 1
assert crypt.storage_version_name(legacy) == "aurora1-legacy"
assert crypt.needs_migration(legacy) is True
assert crypt.is_encrypted(legacy) is True
assert crypt.load_json(legacy_path) == {"a": 7, "b": "legacy"}
assert crypt._encrypted_payload_exists() is True
assert legacy_path in crypt.encrypted_storage_files()
assert os.path.join(data, ".aurora_key") not in crypt.encrypted_storage_files()
assert crypt.migrate_file(legacy_path) is True
migrated = open(legacy_path, "rb").read()
assert migrated.startswith(b"AURORA2"), migrated[:8]
assert crypt.load_json(legacy_path) == {"a": 7, "b": "legacy"}
assert crypt.storage_version(migrated) == 2
assert crypt.migrate_file(legacy_path) is False
assert crypt.migrate_bytes(migrated) == migrated
assert crypt.migrate_bytes(b'{"a": 1}') == b'{"a": 1}'

auto = os.path.join(data, "auto.json")
open(auto, "wb").write(legacy_payload(crypt._load_key(), b'{"a": 9}'))
plain_path = os.path.join(data, "plain.json")
open(plain_path, "w", encoding="utf-8").write('{"a": 0}')
names = crypt.migrate_all([auto, plain_path, os.path.join(data, "missing.json")])
assert names == ["auto.json"], names
assert open(auto, "rb").read().startswith(b"AURORA2")
assert crypt.load_json(plain_path) == {"a": 0}

bad_tag = bytearray(raw)
bad_tag[-1] ^= 0x01
try:
    crypt.decrypt_bytes(bytes(bad_tag))
    raise AssertionError("tag tamper accepted")
except crypt.StorageError:
    pass
bad_body = bytearray(raw)
bad_body[20] ^= 0x01
try:
    crypt.decrypt_bytes(bytes(bad_body))
    raise AssertionError("ciphertext tamper accepted")
except crypt.StorageError:
    pass
try:
    crypt.decrypt_bytes(b'{"a": 1}')
    raise AssertionError("plaintext accepted by decrypt_bytes")
except crypt.StorageError:
    pass
open(os.path.join(data, "bad.json"), "wb").write(b"AURORA2" + b"\x00" * 4)
try:
    crypt.load_json(os.path.join(data, "bad.json"))
    raise AssertionError("short payload accepted")
except crypt.StorageError:
    pass

oid = crypt.opaque_id("vless://x@y:443", "status")
assert crypt.is_opaque_id(oid) is True
assert oid == crypt.opaque_id("vless://x@y:443", "status")
assert oid != crypt.opaque_id("vless://x@y:443", "dead")
assert crypt.is_opaque_id("zz") is False

print("A067_CHILD_OK")
"""


def run_tree(tree, data):
    proc = subprocess.run(
        [sys.executable, "-c", WORKER, str(tree), str(data)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if proc.returncode != 0 or "A067_CHILD_OK" not in (proc.stdout or ""):
        raise AssertionError("%s a067 failed: %s %s" % (tree, proc.stdout, proc.stderr))
    return True


def main():
    for tree in TREES:
        assert (tree / "crypt.py").is_file(), tree
        base = tempfile.mkdtemp(prefix="aurora_a067_")
        data = os.path.join(base, "data")
        os.makedirs(data)
        run_tree(tree, data)
    print("A067_STORAGE_OK")


if __name__ == "__main__":
    main()
