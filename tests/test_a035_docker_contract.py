import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")
COMPOSE = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")
RUNNER = (ROOT / "run_tgws.sh").read_text(encoding="utf-8")
SERVICE = (ROOT / "tg-ws-proxy.service").read_text(encoding="utf-8")
CRYPT = (ROOT / "crypt.py").read_text(encoding="utf-8")

expose = next((line for line in DOCKERFILE.splitlines() if line.startswith("EXPOSE ")), "")
assert expose, "Dockerfile must declare EXPOSE"
assert "443" not in re.findall(r"\d+", expose), "Dockerfile must not expose TG-WS 443"
assert "443:443" not in COMPOSE, "Docker Compose must not publish TG-WS 443"

docker_section = README.split("### Вариант 1 — Docker", 1)[1].split("### Вариант 2", 1)[0]
assert "TG-WS в Docker-варианте не запускается" in docker_section
assert "порт `:443` не публикуется" in docker_section
assert "run_tgws.sh" in docker_section
assert "tg-ws-proxy.service" in docker_section
assert "AURORA_TGWS_PORT" in README
assert "Docker-порт не публикуется" in README

assert "cat " not in RUNNER
assert "echo " not in RUNNER
assert "--secret " not in RUNNER
assert "--secret-fd 3" in RUNNER
assert "mktemp" in RUNNER
assert "RUNTIME_SECRET" in RUNNER
assert "RuntimeDirectory=aurora-tgws" in SERVICE
assert "UMask=0077" in SERVICE
assert "AURORA1" in CRYPT
assert "load_bytes" in CRYPT
assert "save_bytes" in CRYPT

print("A035_DOCKER_PORT_REMOVED_OK")
