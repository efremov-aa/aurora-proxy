import os
import stat
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path


WORKER = textwrap.dedent(
    r'''
    import json
    import os
    import stat
    import sys

    tree, case, data, *paths = sys.argv[1:]
    os.environ["AURORA_DATA_DIR"] = data
    sys.path.insert(0, tree)
    import crypt

    crypt.DATA_DIR = data
    crypt._KEY_FILE = os.path.join(data, ".aurora_key")
    crypt._KEY_LOCK_FILE = os.path.join(data, ".aurora_key.lock")
    crypt._key = None

    key_file = crypt._KEY_FILE
    state = os.path.join(data, "state.json")

    if case == "malformed":
        with open(key_file, "wb") as f:
            f.write(b"broken-key")
        with open(state, "wb") as f:
            f.write(b"AURORA1" + b"x" * 49)
        try:
            crypt.load_json(state, default=[])
        except crypt.KeyFileError:
            print("CRYPTO_CASE_OK")
        else:
            raise AssertionError("malformed key was accepted")
    elif case == "missing":
        with open(state, "wb") as f:
            f.write(b"AURORA1" + b"x" * 49)
        try:
            crypt.load_json(state, default=[])
        except crypt.KeyFileError:
            print("CRYPTO_CASE_OK")
        else:
            raise AssertionError("missing key with encrypted payload was accepted")
    elif case == "wrong":
        with open(key_file, "wb") as f:
            f.write(b"A" * 32)
        crypt.save_json(state, {"secret": "value"})
        with open(key_file, "wb") as f:
            f.write(b"B" * 32)
        crypt._key = None
        try:
            crypt.load_json(state, default=[])
        except crypt.StorageError:
            print("CRYPTO_CASE_OK")
        else:
            raise AssertionError("wrong key was accepted")
    elif case == "roundtrip":
        expected = {"items": [1, 2, 3], "text": "значение"}
        crypt.save_json(state, expected)
        assert crypt.load_json(state) == expected
        assert not any(name.endswith(".tmp") for name in os.listdir(data))
        if os.name != "nt":
            assert stat.S_IMODE(os.stat(key_file).st_mode) == 0o600
            assert stat.S_IMODE(os.stat(state).st_mode) == 0o600
        print("CRYPTO_CASE_OK")
    elif case == "legacy":
        with open(state, "w", encoding="utf-8") as f:
            json.dump({"legacy": True}, f)
        assert crypt.load_json(state) == {"legacy": True}
        assert not os.path.exists(key_file)
        print("CRYPTO_CASE_OK")
    elif case == "create":
        crypt.save_json(paths[0], {"worker": paths[0]})
        print("CRYPTO_CASE_OK")
    elif case == "read":
        for path in paths:
            crypt.load_json(path)
        print("CRYPTO_CASE_OK")
    else:
        raise AssertionError("unknown case: " + case)
    '''
).strip()


ROOT = Path(__file__).resolve().parent.parent
TREES = (ROOT / "windows", ROOT)


def run_case(tree, case, data, *paths, check=True):
    env = os.environ.copy()
    env["AURORA_DATA_DIR"] = str(data)
    command = [sys.executable, "-c", WORKER, str(tree), case, str(data), *map(str, paths)]
    result = subprocess.run(command, cwd=str(tree), env=env, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise AssertionError("%s/%s failed:\n%s\n%s" % (tree.name, case, result.stdout, result.stderr))
    if check and "CRYPTO_CASE_OK" not in result.stdout:
        raise AssertionError("%s/%s did not complete" % (tree.name, case))
    return result


def run_tree(tree):
    with tempfile.TemporaryDirectory(prefix="aurora-crypt-") as directory:
        data = Path(directory)
        run_case(tree, "malformed", data)
        key = data / ".aurora_key"
        quarantine = data / ".aurora_key.corrupt"
        assert key.read_bytes() == b"broken-key"
        assert quarantine.read_bytes() == b"broken-key"

    with tempfile.TemporaryDirectory(prefix="aurora-crypt-") as directory:
        data = Path(directory)
        run_case(tree, "missing", data)
        assert not (data / ".aurora_key").exists()
        assert (data / "state.json").read_bytes().startswith(b"AURORA1")

    with tempfile.TemporaryDirectory(prefix="aurora-crypt-") as directory:
        data = Path(directory)
        run_case(tree, "wrong", data)
        assert (data / "state.json").read_bytes().startswith(b"AURORA2")
        assert (data / ".aurora_key").read_bytes() == b"B" * 32

    with tempfile.TemporaryDirectory(prefix="aurora-crypt-") as directory:
        data = Path(directory)
        run_case(tree, "roundtrip", data)

    with tempfile.TemporaryDirectory(prefix="aurora-crypt-") as directory:
        data = Path(directory)
        run_case(tree, "legacy", data)

    with tempfile.TemporaryDirectory(prefix="aurora-crypt-") as directory:
        data = Path(directory)
        outputs = [data / ("out-%d.json" % index) for index in range(4)]
        processes = []
        for output in outputs:
            env = os.environ.copy()
            env["AURORA_DATA_DIR"] = str(data)
            command = [sys.executable, "-c", WORKER, str(tree), "create", str(data), str(output)]
            processes.append(subprocess.Popen(command, cwd=str(tree), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
        results = [process.communicate(timeout=30) for process in processes]
        for process, (stdout, stderr) in zip(processes, results):
            assert process.returncode == 0, "%s/%s concurrent create failed:\n%s\n%s" % (tree.name, process.returncode, stdout, stderr)
            assert "CRYPTO_CASE_OK" in stdout
        assert (data / ".aurora_key").stat().st_size == 32
        run_case(tree, "read", data, *outputs)
        assert not any(name.endswith(".tmp") for name in os.listdir(data))


def main():
    for tree in TREES:
        run_tree(tree)
    print("A030_CRYPT_STORAGE_OK")


if __name__ == "__main__":
    main()
