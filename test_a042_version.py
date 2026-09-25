import os
import re

ROOT = os.path.dirname(os.path.abspath(__file__))


def value(path, pattern):
    text = open(os.path.join(ROOT, path), encoding="utf-8-sig").read()
    match = re.search(pattern, text, re.M)
    assert match, path
    return match.group(1)


version = value("config.py", r'^VERSION\s*=\s*["\']([^"\']+)["\']')
name = value("config.py", r'^VERSION_NAME\s*=\s*["\']([^"\']+)["\']')
assert version == "1.9.2"
assert name == "Кот-починщик"
assert value("windows/config.py", r'^VERSION\s*=\s*["\']([^"\']+)["\']') == version
assert value("windows/config.py", r'^VERSION_NAME\s*=\s*["\']([^"\']+)["\']') == name
readme = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
assert "Release v%s" % version in readme
assert "Aurora-v%s-linux.zip" % version in readme
assert "Aurora-v%s-windows.zip" % version in readme
assert "VERSION=%s" % version in readme
assert "VERSION_NAME=%s" % name in readme
windows_readme = open(os.path.join(ROOT, "windows", "README-windows.md"), encoding="utf-8").read()
assert "v%s" % version in windows_readme
assert name in windows_readme
installer = open(os.path.join(ROOT, "windows", "installer", "install.iss"), encoding="utf-8-sig").read()
assert '#define AuroraVersion "%s"' % version in installer
assert '#define AuroraVersionName "%s"' % name in installer
assert "AppVersion={#AuroraVersion}" in installer
assert "VersionInfoVersion={#AuroraVersion}" in installer
assert "OutputBaseFilename=Aurora-Setup-{#AuroraVersion}" in installer
assert "AppVersion=1.6.0" not in installer
assert "OutputBaseFilename=Aurora-Setup-1.6.0" not in installer
print("A042_VERSION_CONTRACT_OK")
