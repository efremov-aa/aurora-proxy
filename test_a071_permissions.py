import os
import pathlib
import subprocess
import sys
import tempfile
import textwrap

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = pathlib.Path(__file__).resolve().parent
TREES = (ROOT / "windows", ROOT)

WORKER = textwrap.dedent(
    """
    import os
    import stat
    import sys
    import tempfile

    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    tree = sys.argv[1]
    os.environ["AURORA_DATA_DIR"] = tempfile.mkdtemp(prefix="aurora_a071_perm_")
    sys.path.insert(0, tree)
    failed = []

    def bad(name, msg=""):
        failed.append("%s %s" % (name, msg))

    def ok(name):
        if name not in failed:
            print("ok", name)

    def check(name, cond, msg=""):
        if cond:
            ok(name)
        else:
            bad(name, msg)

    import crypt

    posix = os.name != "nt"
    data = crypt.DATA_DIR
    target = os.path.join(data, "perm-target.json")
    with open(target, "w", encoding="utf-8") as fh:
        fh.write("{}")
    crypt.restrict_file(target)
    mode = stat.S_IMODE(os.stat(target).st_mode)
    if posix:
        check("restrict_file_600", mode == 0o600, oct(mode))
    else:
        check("nt_restrict_file", crypt.restrict_file(target) is True)
        check("nt_writable", bool(mode & 0o200), oct(mode))

    subdir = os.path.join(data, "perm-dir")
    os.makedirs(subdir, exist_ok=True)
    crypt.restrict_dir(subdir)
    dmode = stat.S_IMODE(os.stat(subdir).st_mode)
    if posix:
        check("restrict_dir_700", dmode == 0o700, oct(dmode))
    else:
        check("nt_restrict_dir", crypt.restrict_dir(subdir) is True)

    tmp_path = crypt.secure_temp_path(data, "a071-", ".json")
    with open(tmp_path, "wb") as fh:
        fh.write(b"x")
    tmpmode = stat.S_IMODE(os.stat(tmp_path).st_mode)
    crypt.restrict_file(tmp_path)
    tmpmode2 = stat.S_IMODE(os.stat(tmp_path).st_mode)
    if posix:
        check("secure_temp_600", tmpmode == 0o600, oct(tmpmode))
        check("secure_temp_600_again", tmpmode2 == 0o600, oct(tmpmode2))
    else:
        check("nt_temp_writable", bool(tmpmode2 & 0o200), oct(tmpmode2))
    os.unlink(tmp_path)

    store = os.path.join(data, "store.json")
    crypt.save_json(store, {"a": 1})
    smode = stat.S_IMODE(os.stat(store).st_mode)
    if posix:
        check("save_json_600", smode == 0o600, oct(smode))
    check("save_json_roundtrip", crypt.load_json(store, {}) == {"a": 1})
    check("alias_restrict_file", crypt._restrict_file is crypt.restrict_file)
    check("returns_bool", crypt.restrict_file(target) is True)

    if failed:
        print("A071_CHILD_FAIL", "; ".join(failed))
        raise SystemExit(1)
    print("A071_CHILD_OK")
    """
)

CRYPT_TOKENS = (
    "def _dacl_owner_only(",
    "icacls",
    "/inheritance:r",
    "*S-1-5-18",
    "*S-1-5-32-544",
    "def restrict_file(",
    "def restrict_dir(",
    "_ICACLS_RUN",
    "_DACL_DONE",
    "_restrict_file = restrict_file",
    "from subprocess import SubprocessError",
)

RESTRICTED = ("core.py", "source.py", "security.py", "config.py")


def read(path):
    return path.read_text(encoding="utf-8-sig")


def static_contract(tree):
    crypt = read(tree / "crypt.py")
    for token in CRYPT_TOKENS:
        assert token in crypt, (tree.name, "crypt", token)
    assert crypt.count("os.chmod(str(path), 0o600)") == 1, tree.name
    assert crypt.count("os.chmod(str(path), 0o700)") == 1, tree.name
    assert "stat.S_IREAD | stat.S_IWRITE" in crypt, tree.name
    for name in RESTRICTED:
        text = read(tree / name)
        assert "os.chmod" not in text, (tree.name, name, "os.chmod")
        assert "crypt.restrict_file(" in text or "crypt.restrict_dir(" in text, (
            tree.name, name, "no restrict")
    core = read(tree / "core.py")
    source = read(tree / "source.py")
    assert "import crypt" in core and "import crypt" in source, tree.name
    security = read(tree / "security.py")
    assert "crypt.restrict_dir(" in security, tree.name
    cfg = read(tree / "config.py")
    assert "PLAINTEXT_FILE_MODE = 0o600" in cfg, tree.name
    assert "PLAINTEXT_DIR_MODE = 0o700" in cfg, tree.name
    assert "AURORA_TLS_CERT" not in cfg, tree.name


def parity():
    left = read(ROOT / "crypt.py")
    right = read(ROOT / "windows" / "crypt.py")
    for tree in (ROOT, ROOT / "windows"):
        text = read(tree / "crypt.py")
        start = text.index("def _dacl_owner_only(")
        end = text.index("def _atomic_write(")
        region = text[start:end]
        assert "icacls" in region, tree.name
        assert "_ICACLS_RUN" in region, tree.name
    assert left.count("def restrict_file(") == right.count("def restrict_file(") == 1
    assert left.count("def restrict_dir(") == right.count("def restrict_dir(") == 1


def main():
    for tree in TREES:
        proc = subprocess.run([sys.executable, "-c", WORKER, str(tree)],
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace")
        assert proc.returncode == 0, (tree.name, proc.stdout, proc.stderr)
        assert "A071_CHILD_OK" in proc.stdout, (tree.name, proc.stdout)
        static_contract(tree)
    parity()
    print("A071_PERM_OK")


if __name__ == "__main__":
    main()
