import ast
import pathlib
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = pathlib.Path(__file__).resolve().parent.parent
TREES = (ROOT / "windows", ROOT)
MODULES = ["api.py", "config.py", "core.py", "crypt.py", "mesh.py", "pool.py",
           "recovery.py", "run.py", "rusegment.py", "security.py", "source.py",
           "subs.py", "telemetry.py", "tgws.py", "ui.py", "updater.py",
           "release_sign.py"]
NEEDS_TOP_IMPORT = ("core.py", "source.py", "security.py")


def read(path):
    return path.read_text(encoding="utf-8-sig")


def func_nodes(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def has_top_import(tree):
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "crypt" and alias.asname is None:
                    return True
    return False


def first_crypt_use(node):
    best = None
    for sub in ast.walk(node):
        line = getattr(sub, "lineno", None)
        if line is None:
            continue
        if isinstance(sub, ast.Name) and sub.id == "crypt":
            best = line if best is None else min(best, line)
        elif isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name) \
                and sub.value.id == "crypt":
            best = line if best is None else min(best, line)
    return best


def local_import_line(node):
    for sub in ast.walk(node):
        if isinstance(sub, ast.Import):
            for alias in sub.names:
                if alias.name == "crypt" and alias.asname is None:
                    return sub.lineno
    return None


def contract(tree):
    for name in MODULES:
        path = tree / name
        assert path.is_file(), "missing %s" % path
        source = read(path)
        parsed = ast.parse(source)
        if name in NEEDS_TOP_IMPORT:
            assert has_top_import(parsed), "no module-level import crypt in %s" % path
        for node in func_nodes(parsed):
            imp = local_import_line(node)
            if imp is None:
                continue
            use = first_crypt_use(node)
            assert not (use is not None and use < imp), (
                "crypt shadow in %s:%s use@%s import@%s" % (path, node.name, use, imp))
        if name == "core.py":
            start = source.index("def _xray_config_valid(")
            end = source.index("def _restore_config_cas(")
            body = source[start:end]
            assert "crypt.restrict_file(tmp)" in body, body
            assert "crypt.unlink_quiet(tmp" in body, body
            assert "import crypt" not in body, body
    return True


def parity():
    linux = read(ROOT / "core.py")
    windows = read(ROOT / "windows" / "core.py")
    left = linux[linux.index("def _xray_config_valid("):linux.index("def _restore_config_cas(")]
    right = windows[windows.index("def _xray_config_valid("):windows.index("def _restore_config_cas(")]
    assert left == right, "core._xray_config_valid parity"
    return True


for tree in TREES:
    assert contract(tree), tree
assert parity()
print("A071_SHADOW_OK")
