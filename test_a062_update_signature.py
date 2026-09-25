# Aurora A-062 — подпись релизов Ed25519 (только stdlib)
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TREES = (ROOT / "windows", ROOT)

WORKER = r'''
import base64
import hashlib
import sys
sys.path.insert(0, sys.argv[1])
import release_sign as rs

failed = []


def check(name, cond):
    if not cond:
        failed.append(name)


def raises(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except rs.SignatureError:
        return True
    except Exception:
        return False
    return False


def rfc_vectors():
    cases = [
        ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
         "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
        ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
         "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
        ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
         "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
         "af82",
         "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    ]
    for i, (seed_hex, pub_hex, msg_hex, sig_hex) in enumerate(cases):
        seed = bytes.fromhex(seed_hex)
        pub = bytes.fromhex(pub_hex)
        msg = bytes.fromhex(msg_hex)
        sig = bytes.fromhex(sig_hex)
        check("rfc%d pub" % i, rs.public_key(seed) == pub)
        check("rfc%d sign" % i, rs.sign(seed, msg) == sig)
        check("rfc%d verify" % i, rs.verify(pub, msg, sig) is True)
        bad = bytearray(sig)
        bad[0] ^= 0x01
        check("rfc%d verify bad" % i, rs.verify(pub, msg, bytes(bad)) is False)


def roundtrip():
    seed = hashlib.sha256(b"aurora-a062-roundtrip").digest()
    pub = rs.public_key(seed)
    for size in (0, 1, 32, 64, 65, 255, 4096):
        block = hashlib.sha512(b"msg%d" % size).digest()
        msg = (block * (size // 64 + 1))[:size]
        sig = rs.sign(seed, msg)
        check("roundtrip %d" % size, rs.verify(pub, msg, sig) is True)
        check("roundtrip %d msg" % size, rs.verify(pub, msg + b"x", sig) is False)
        flipped = bytearray(sig)
        flipped[-1] ^= 0x80
        check("roundtrip %d sig" % size, rs.verify(pub, msg, bytes(flipped)) is False)
    other = rs.public_key(hashlib.sha256(b"other").digest())
    check("wrong key", rs.verify(other, b"x", rs.sign(seed, b"x")) is False)
    check("short sig", rs.verify(pub, b"x", b"\x00" * 63) is False)
    check("long sig", rs.verify(pub, b"x", b"\x00" * 65) is False)
    check("non point", rs.verify(pub, b"x", b"\xff" * 64) is False)


def release_flow():
    seed = hashlib.sha256(b"aurora-a062-release").digest()
    pub = rs.public_key(seed)
    data = b"Aurora-v1.9.0-linux.zip" + b"payload" * 64
    asset = "Aurora-v1.9.0-linux.zip"
    repo = "efremov-aa/aurora-proxy"
    version = "1.9.0"
    sig = rs.sign_release(seed, repo, version, asset, data)
    key = pub.hex()
    good = rs.verify_release(data, sig, pubkey=key, repo=repo, version=version, asset=asset)
    check("release ok", good["digest"] == hashlib.sha256(data).hexdigest())
    check("release key", good["key"] == rs.fingerprint(pub))
    check("release asset", good["asset"] == asset)
    check("release b64 key", rs.verify_release(data, sig, pubkey=base64.b64encode(pub).decode(),
                                               repo=repo, version=version, asset=asset)["key"] == rs.fingerprint(pub))
    check("release raw sig", rs.verify_release(data, base64.b64decode(sig), pubkey=key,
                                               repo=repo, version=version, asset=asset)["digest"] == good["digest"])
    check("release prefixed sig", rs.verify_release(data, "ed25519:" + sig, pubkey=key,
                                                    repo=repo, version=version, asset=asset)["digest"] == good["digest"])
    check("verify_pair", rs.verify_pair(key, b"msg", rs.sign(seed, b"msg")) is True)

    check("tamper data", raises(rs.verify_release, data + b"x", sig, pubkey=key, repo=repo, version=version, asset=asset))
    check("wrong repo", raises(rs.verify_release, data, sig, pubkey=key, repo="evil/repo", version=version, asset=asset))
    check("wrong version", raises(rs.verify_release, data, sig, pubkey=key, repo=repo, version="1.9.1", asset=asset))
    check("wrong asset", raises(rs.verify_release, data, sig, pubkey=key, repo=repo, version=version, asset="other.zip"))
    check("empty sig", raises(rs.verify_release, data, "", pubkey=key, repo=repo, version=version, asset=asset))
    check("none sig", raises(rs.verify_release, data, None, pubkey=key, repo=repo, version=version, asset=asset))
    check("garbage sig", raises(rs.verify_release, data, "!!!!", pubkey=key, repo=repo, version=version, asset=asset))
    check("short raw sig", raises(rs.verify_release, data, b"\x00" * 40, pubkey=key, repo=repo, version=version, asset=asset))
    check("no pubkey", raises(rs.verify_release, data, sig, pubkey="", repo=repo, version=version, asset=asset))
    check("bad pubkey", raises(rs.verify_release, data, sig, pubkey="aabb", repo=repo, version=version, asset=asset))
    other_pub = rs.public_key(hashlib.sha256(b"other-key").digest())
    other = other_pub.hex()
    check("other pubkey", raises(rs.verify_release, data, sig, pubkey=other, repo=repo, version=version, asset=asset))
    foreign = rs.sign_release(hashlib.sha256(b"z").digest(), repo, version, asset, data)
    check("foreign sig", raises(rs.verify_release, data, foreign, pubkey=key, repo=repo, version=version, asset=asset))

    pair = rs.generate_keypair()
    check("keypair", len(pair[0]) == 32 and len(pair[1]) == 32)
    check("parse hex", rs.parse_pubkey(pub.hex()) == pub)
    check("parse b64", rs.parse_pubkey(base64.b64encode(pub).decode()) == pub)
    check("parse prefixed raises", raises(rs.parse_pubkey, "ed25519:" + pub.hex()))
    check("parse empty", rs.parse_pubkey("") == b"")
    check("parse short raises", raises(rs.parse_pubkey, "aabb"))
    check("fingerprint", len(rs.fingerprint(pub)) == 16)
    check("fingerprint stable", rs.fingerprint(pub) == rs.fingerprint(pub))
    check("fingerprint differs", rs.fingerprint(pub) != rs.fingerprint(other_pub))
    body = rs.manifest(repo, version, asset, good["digest"])
    check("manifest context", body.startswith(b"aurora-release-v1\n"))
    check("manifest digest", good["digest"].encode() in body)
    check("manifest newline raises", raises(rs.manifest, repo, "1.9\n0", asset, "aa"))
    check("manifest cr raises", raises(rs.manifest, repo, version, "a\rb", "aa"))
    check("compare", rs.compare("a", "a") is True and rs.compare("a", "b") is False)


def main():
    rfc_vectors()
    roundtrip()
    release_flow()
    if failed:
        for name in failed:
            print("FAIL", name)
        return 1
    print("A062_CHILD_OK")
    return 0


sys.exit(main())
'''


def read(path):
    return Path(path).read_text(encoding="utf-8-sig")


def region(text, start, end):
    i = text.index(start)
    j = text.index(end, i)
    return text[i:j]


def child(tree):
    return subprocess.run([sys.executable, "-c", WORKER, str(tree)],
                          capture_output=True, text=True, encoding="utf-8", errors="replace")


def updater_contract(tree):
    text = read(tree / "updater.py")
    assert "import release_sign" in text, tree
    mods = region(text, "_MODULES = [", "]")
    assert '"release_sign.py"' in mods, tree
    dl = region(text, "def _download_release_zip(", "def _verify_sha256(")
    assert ".sig" in dl, tree
    assert "_asset_url" in dl, tree
    assert "signature" in dl, tree
    helper = region(text, "def _pubkey()", "def _set_state(")
    assert "load_pubkey" in helper, tree
    ver = region(text, "def _verify_signature(", "def _download_release_zip(")
    assert "verify_release" in ver, tree
    assert "repo=_REPO" in ver, tree
    ext = region(text, "def _extract_and_replace(", "AUTO_INTERVAL")
    assert "signature" in ext, tree
    si = ext.index("_verify_signature(")
    di = ext.index("_verify_sha256(")
    assert si < di, "%s: signature must be verified before sha256" % tree
    assert "hmac_compare" in ext, tree
    st = region(text, "def status(", "def _http_json(")
    assert "signature_required" in st, tree
    assert "pubkey" in st, tree
    ap = region(text, "def apply(", "def _extract_and_replace(")
    assert "signature" in ap, tree
    if tree.parent.name.lower() == "windows":
        ins = region(text, "def _download_release_installer(", "def _save_installer(")
        assert ".sig" in ins, tree
        assert "_verify_signature" in ins, tree
        assert ins.index("_verify_signature") < ins.index("_verify_sha256"), tree
    return True


def config_contract(tree):
    text = read(tree / "config.py")
    m = re.search(r'UPDATE_PUBKEY\s*=\s*"([0-9a-fA-F]{64})"', text)
    assert m, "%s: UPDATE_PUBKEY missing" % tree
    return m.group(1).lower()


def parity():
    keys = set()
    regions = set()
    for tree in TREES:
        keys.add(config_contract(tree))
        updater = read(tree / "updater.py")
        regions.add(region(updater, "def _pubkey()", "def _set_state("))
        regions.add(region(updater, "def _verify_signature(", "def _download_release_zip("))
        sign = read(tree / "release_sign.py")
        regions.add(region(sign, "def parse_pubkey(", "def encode_pubkey("))
        regions.add(region(sign, "def verify_release(", "def verify_pair("))
    assert len(keys) == 1, "UPDATE_PUBKEY differs between trees: %s" % keys
    assert len(regions) == 4, "signature helpers differ between trees"
    return keys.pop()


def main():
    for tree in TREES:
        assert (tree / "release_sign.py").exists(), "%s: release_sign.py missing" % tree
        src = read(tree / "release_sign.py")
        assert "import cryptography" not in src, tree
        assert "AURORA_UPDATE_PUBKEY" in src, tree
        assert "class SignatureError(ValueError)" in src, tree
        updater_contract(tree)
        result = child(tree)
        assert result.returncode == 0, "%s child failed:\n%s\n%s" % (tree, result.stdout, result.stderr)
        assert "A062_CHILD_OK" in result.stdout, "%s child marker missing:\n%s" % (tree, result.stdout)
    pubkey = parity()
    print("A062_UPDATE_SIGNATURE_OK", pubkey)


if __name__ == "__main__":
    main()
