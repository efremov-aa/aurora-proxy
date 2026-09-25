# Aurora v1.0 — конфигурация ядра.
# Всё, что меняется между деплоями: пути, порты, источники ключей, режимы.

import base64
from contextlib import contextmanager
import binascii
import ipaddress
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid

# Windows: флаг CREATE_NO_WINDOW скрывает окна консоли дочерних процессов
# (xray run/keytest/statsquery/netstat/netsh/taskkill/tg-ws-proxy и т.п.).
HIDE_FLAG = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0

VERSION = "1.9.3"
VERSION_NAME = "Кот-глашатай"
APP_NAME = "Aurora"

# История версий для вкладки «Версии» (v, имя, дата).
VERSION_HISTORY = (
    ("1.9.3", "Кот-глашатай", "25.09.2026"),
    ("1.9.3", "Кот-глашатай", "25.09.2026"),
    ("1.9.3", "Кот-глашатай", "25.09.2026"),
    ("1.9.3", "Кот-глашатай", "25.09.2026"),
    ("1.9.2", "Кот-починщик", "25.09.2026"),
    ("1.9.1", "Кот-крепость", "25.09.2026"),
    ("1.9.0", "Кот-правозащитник", "24.09.2026"),
    ("1.8.0", "Кот-именитый", "24.09.2026"),
    ("1.7.0", "Кот-дипломат", "24.09.2026"),
    ("1.6.0", "Кот-банкир", "24.09.2026"),
    ("1.5.0", "Кот в мешке", "24.09.2026"),
    ("1.4.0", "Подписки", "22.09.2026"),
    ("1.3.1", "Мур-апдейт", "22.09.2026"),
    ("1.3.0", "Mesh", "22.09.2026"),
    ("1.2.0", "Windows-fix", "19.09.2026"),
    ("1.1.0", "Свежая рыба", "19.09.2026"),
)

# --- политика сервиса (GitHub-сборки: первая страница — правила) ---
# POLICY_REV меняется ТОЛЬКО при изменении POLICY_TEXT.
# REV > принятого => панель снова требует принять политику (после обновления).
POLICY_REV = 2
POLICY_TEXT = """ПОЛИТИКА И ПРАВИЛА ПРОЕКТА AURORA «Кот в законе»

1. НАЗНАЧЕНИЕ
Aurora — персональный VPN/прокси-сервер. Установка и использование подразумевают
полное согласие с настоящей политикой. Если вы не согласны — не устанавливайте.

2. РАЗРЕШЕНО
- подключать собственные устройства (телефоны, планшеты, ПК, телевизоры);
- использовать прокси в личных целях: приватность, доступ к заблокированным
  сайтам, безопасные подключения в общественных сетях;
- привлекать в свою сеть (меш) друзей с их согласия и на тех же правилах.

3. ЗАПРЕЩЕНО
- раздавать доступ посторонним без явного согласия владельца сервера;
- использовать канал для DDoS, массового сканирования, покупки запрещённого,
  кражи данных, мошенничества и любых нарушений закона;
- обходить лимиты тарифов, маскировать свой трафик против владельца сервера;
- продавать/перепродавать ключи и подписки без разрешения владельца;
- вмешиваться в работу серверного ПО или панели управления.

4. ОБЯЗАТЕЛЬСТВА ВЛАДЕЛЬЦА СЕРВЕРА
- шифровать хранимые данные (подписки, ключи) и ограничивать доступ к файлам;
- не передавать персональные данные клиентов третьим лицам без оснований;
- немедленно уведомлять клиентов об изменении правил.
При изменении текста политики ревизия увеличивается, и при следующем запуске
панель снова запросит принятие — это обязательное условие продолжения работы.

5. СОТРУДНИЧЕСТВО С ПРАВООХРАНИТЕЛЬНЫМИ ОРГАНАМИ
Владелец гарантирует анонимность и конфиденциальность ВСЕГДА — до момента
нарушения закона. По официальному письменному запросу правоохранительных
органов (в т.ч. по официальным каналам связи) владелец обязан предоставить
все имеющиеся данные об абоненте (адрес, логи, тайминг и т.п.).
При нарушении закона любой страны владелец обязан сотрудничать
с правоохранительными органами. Без официального запроса данные не передаются.

6. ОГРАНИЧЕНИЕ ОТВЕТСТВЕННОСТИ
Сервер предоставляется «как есть». Владелец не отвечает за доступность сторонних
ресурсов, за действия клиентов сети и за последствия нарушения настоящих правил.

7. СОГЛАСИЕ
Нажатие кнопки «Принять» на панели управления означает безоговорочное принятие
настоящей политики для всего оборудования, подключённого к серверу."""

_BOOT_TS = time.time()   # время старта процесса (для /api/settings.uptime)

# --- периметр plaintext-файлов Xray/keytest (A-072) ---
# Формат xray.json/keytest-конфигов менять нельзя (требование xray), поэтому
# секреты в них защищаются правами доступа: POSIX 0600 (файл) / 0700 (каталог),
# Windows DACL — владелец + SYSTEM + Administrators, наследование отключено.
PLAINTEXT_FILE_MODE = 0o600
PLAINTEXT_DIR_MODE = 0o700

# --- авто-обновление (GitHub Releases) ---
# Обязательное: публичная сборка всегда обновляется с этого репо.
# Локальное отключение/обход НЕ предусмотрен (управляется только политикой релизов).
UPDATE_REPO = "efremov-aa/aurora-proxy"
# Пиннированный Ed25519-ключ подписи релизов (fail-closed: без ключа обновление не ставится)
UPDATE_PUBKEY = "6159031f0fd9ab6c5074f9bef99f5ac125df75e05bdeaa772860236fb85e3371"
UPDATE_CHECK_INTERVAL = 15 * 60  # проверка признаков обновления каждые 15 минут

# --- пути (относительно корня проекта) ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("AURORA_DATA_DIR", os.path.join(BASE_DIR, "data"))
XRAY_CONFIG = os.path.join(BASE_DIR, "xray.json")
LOG_FILE = os.path.join(BASE_DIR, "aurora.log")

os.makedirs(DATA_DIR, exist_ok=True)

if getattr(sys, "frozen", False):
    # в frozen-бандле BASE_DIR указывает на _internal (read-only при Program Files) —
    # журнал и xray.json переносим в каталог данных пользователя (AURORA_DATA_DIR)
    XRAY_CONFIG = os.path.join(DATA_DIR, "xray.json")
    LOG_FILE = os.path.join(DATA_DIR, "aurora.log")

# --- подписки (продаваемые VLESS-ключи клиентам) ---
SUBS_FILE = os.path.join(DATA_DIR, "subs.json")
SUBS_PLANS_FILE = os.path.join(DATA_DIR, "plans.json")
AUTO_REFRESH_INTERVAL = 1800   # фоновый цикл обновления github-ключей (сек)

SUBS_PLANS = {
    "free": {"name": "Бесплатный", "price": 0, "bytes": 10 * 1024 ** 3, "days": 30,
             "devices": 1, "keys": 1,
             "features": ["1 устройство", "10 ГБ трафика", "Базовая локация 🇷🇺"],
             "features_no": ["Меш-сеть", "Внешний доступ извне", "Приоритетная поддержка"]},
    "basic": {"name": "Базовый", "price": 399, "bytes": 100 * 1024 ** 3, "days": 30,
              "devices": 3, "keys": 2,
              "features": ["3 устройства", "100 ГБ трафика", "Все локации + 🇩🇪 🇳🇱",
                           "Меш-сеть", "Внешний доступ извне"],
              "features_no": ["Приоритетная поддержка"]},
    "prem": {"name": "Премиум", "price": 799, "bytes": 0, "days": 30,
             "devices": 10, "keys": 5,
             "features": ["10 устройств", "Безлимит трафика", "Все локации + эксклюзив",
                          "Меш-сеть + приоритет", "Внешний доступ извне",
                          "Приоритетная поддержка 24/7"],
             "features_no": []},
}
SUBS_PLAN_DEFAULT = "free"
SUBS_MASK_UUID = True  # в UI показывать маскированные uuid подключений

# --- порты (конфигурируются через env AURORA_*_PORT; дефолты совместимы с сервером) ---
UI_PORT = int(os.environ.get("AURORA_UI_PORT", "8890"))            # панель Aurora
XRAY_PORT = int(os.environ.get("AURORA_XRAY_PORT", "8899"))        # mixed-вход xray (http+socks)
XRAY_API_PORT = int(os.environ.get("AURORA_XRAY_API_PORT", "8897"))  # докодемо-API xray (статистика)
TGWS_PORT = int(os.environ.get("AURORA_TGWS_PORT", "443"))        # Telegram WS-прокси (443; 1443 блокировался РКН снаружи)

# --- сеть (значения из env, дефолты безопасны) ---
# На Windows локальный адрес авто-определяется (для внешних ссылок/QR).
_DETECT_LOCK = threading.Lock()
_PUBLIC = {"ip": None, "ts": 0.0}
_PUBLIC_TTL_S = 3600.0


def _detect_local_ip():
    """Локальный IP машины (UDP-трюк без реального трафика)."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass
    return "127.0.0.1"


def _fetch_public_ip():
    """Публичный IP через ipify (без прокси)."""
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open("http://api.ipify.org?format=json", timeout=5) as r:
            value = json.loads(r.read().decode("utf-8")).get("ip", "")
        return str(ipaddress.ip_address(str(value)))
    except Exception:
        return ""


def get_public_ip():
    """Публичный IP с TTL-кэшем (для внешних ссылок/QR)."""
    import time as _t
    now = _t.time()
    if _PUBLIC["ip"] and (now - _PUBLIC["ts"]) < _PUBLIC_TTL_S:
        return _PUBLIC["ip"]
    with _DETECT_LOCK:
        if _PUBLIC["ip"] and (_t.time() - _PUBLIC["ts"]) < _PUBLIC_TTL_S:
            return _PUBLIC["ip"]
        ip = _fetch_public_ip()
        if ip:
            _PUBLIC["ip"] = ip
            _PUBLIC["ts"] = _t.time()
        return _PUBLIC["ip"] or ""


def refresh_public_ip_async():
    """Фоновое обновление публичного IP (на старте)."""
    def _bg():
        try:
            get_public_ip()
        except Exception:
            pass
    threading.Thread(target=_bg, daemon=True).start()


VM_HOST = os.environ.get("AURORA_HOST", "") or _detect_local_ip()  # адрес сервера для внешних ссылок/QR
WHITE_IP = os.environ.get("AURORA_WHITE_IP", "")      # белый IP провайдера — фильтр «не выход VPN»


def get_direct_ip(force=False):
    configured = str(WHITE_IP or "").strip()
    if configured:
        try:
            return str(ipaddress.ip_address(configured))
        except ValueError:
            return ""
    return get_public_ip()

# --- источники github-ключей ---
# Репо barry-far/V2ray-Config: файлы регенерируются workflow main.yml каждые 15 минут.
GITHUB_SOURCES = ["https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt"]

# --- ру-байпас: RU-домены уходят на direct (без VPN) ---
# Базовый список (актуально навсегда: обновления ПО, ключевые RU-сервисы).
# При недоступности github-источников используется ТОЛЬКО он.
RU_DOMAINS_STATIC = [
    "github.com", "githubusercontent.com", "raw.githubusercontent.com",
    "github.io", "huggingface.co", "hf-mirror.com",
    "pypi.org", "files.pythonhosted.org", "npmjs.org",
    "registry.npmjs.org", "crates.io", "static.crates.io",
    "nuget.org", "download.visualstudio.microsoft.com", "dotnet.microsoft.com",
    "pypi.python.org", "files.pythonhosted.org",
    "jetbrains.com", "download.jetbrains.com", "plugins.jetbrains.com",
    "opencode.ai",
    "yandex.ru", "ya.ru", "vk.com", "ok.ru", "mail.ru", "vk.ru",
    "rutube.ru", "gosuslugi.ru", "mos.ru", "kremlin.ru", "gov.ru",
]

# Списки с github для расширения базового набора (плейн-домены ИЛИ domain:...).
RU_DOMAINS_SOURCES = [
    "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/whitelist.txt",
    "https://raw.githubusercontent.com/UnRKN/ru-blocklist/refs/heads/main/ru-blocklist-domain.txt",
]

# Кэш загруженного списка (TTL 900с; при сбое = пустой, работает фолбэк).
RU_DOMAINS_TTL_S = 900
MAX_RU_SOURCE_BYTES = 4 * 1024 * 1024
MAX_RU_SOURCE_LINES = 200000
RU_DOMAINS_LOCK = threading.Lock()
RU_DOMAINS_CACHE = {"list": [], "ts": 0.0}

# --- лимиты ---
MAX_USER_KEYS = 120       # максимум ключей в пуле (60 -> 120: большая выборка из 2529 reality-ключей)
MAX_PING_MS = 700        # выше = ключ мёртв (правило юзера: >700мс мёртвый)
EGRESS_TTL_S = 60         # кэш egress
ROTATE_COOLDOWN_S = 180.0 # демпф ротации
VPN_KEYS_N = 4            # сколько ключей попадает в xray.json при VPN ON

# --- внешнее подключение (VLESS-Reality inbound :8443) ---
# На Windows/публичной сборке ключи генерируются автоматически при первом старте
# (см. ensure_vless()): uuid + пара x25519 через `xray x25519`, сохраняются в data/vless_public.json.
# Вручную можно переопределить через env AURORA_VLESS_* (см. README/.env.example).
def _parse_port(value):
    if type(value) is int:
        return value if 1 <= value <= 65535 else None
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value.isdigit():
        return None
    value = int(value)
    return value if 1 <= value <= 65535 else None


def canonical_uuid(value):
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = uuid.UUID(value.strip())
    except (ValueError, AttributeError):
        return None
    if parsed.int == 0:
        return None
    return str(parsed)


def _valid_x25519(value):
    if not isinstance(value, str) or len(value) != 43:
        return False
    if any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for ch in value):
        return False
    try:
        raw = base64.urlsafe_b64decode(value + "=")
    except (ValueError, binascii.Error):
        return False
    if len(raw) != 32:
        return False
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == value


def _valid_short_id(value):
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value:
        return ""
    if len(value) > 16 or len(value) % 2 or any(ch not in "0123456789abcdefABCDEF" for ch in value):
        return None
    return value.lower()


def _valid_sni(value):
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or any(ch in value for ch in "/?#@,; \t\r\n"):
        return None
    try:
        value = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if not value or len(value) > 253 or "*" in value:
        return None
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+", value):
        return None
    return value


METADATA_HOSTS = frozenset((
    "169.254.169.254", "100.100.100.200", "168.63.129.16", "fd00:ec2::254",
))


def _read_setup_token():
    value = os.environ.get("AURORA_SETUP_TOKEN", "").strip()
    if len(value) < 16 or len(value) > 256:
        return ""
    if any(ch.isspace() or ord(ch) < 33 or ord(ch) > 126 for ch in value):
        return ""
    return value


SETUP_TOKEN = _read_setup_token()


def _private_links_allowed():
    return os.environ.get("AURORA_ALLOW_PRIVATE_LINK", "").lower() in ("1", "true", "yes", "on")


def _valid_public_host(value):
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or any(ch in value for ch in "/?#@,; \t\r\n"):
        return None
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    elif "[" in value or "]" in value:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        try:
            value = value.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError:
            return None
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+", value):
            return None
        if value == "localhost" or value.endswith(".local") or value.endswith(".internal"):
            return None
        return value
    if str(address) in METADATA_HOSTS:
        return None
    if not address.is_global:
        private_ok = _private_links_allowed() and address.is_private and not address.is_loopback and not address.is_link_local and not address.is_unspecified and not address.is_multicast
        if not private_ok:
            return None
    return str(address)


def external_link_host(raw=None):
    for name in ("AURORA_VLESS_HOST", "AURORA_HOST"):
        if name in os.environ:
            return _valid_public_host(os.environ.get(name, "")) or ""
    if raw is None:
        raw = VLESS_PUBLIC
    if isinstance(raw, dict):
        host = _valid_public_host(raw.get("host", ""))
        if host:
            return host
    get_public_ip = globals().get("get_public_ip")
    if callable(get_public_ip):
        return _valid_public_host(get_public_ip() or "") or ""
    return ""


def _format_link_host(host):
    if not host:
        return ""
    try:
        if ipaddress.ip_address(host).version == 6:
            return "[%s]" % host
    except ValueError:
        pass
    return host


def vless_public(raw=None):
    if raw is None:
        raw = VLESS_PUBLIC
    if not isinstance(raw, dict):
        return {"enabled": False}
    enabled = raw.get("enabled") is True
    port = _parse_port(raw.get("port", 8443))
    out = {
        "enabled": enabled,
        "port": port if port is not None else 0,
        "host": external_link_host(raw),
        "uuid": canonical_uuid(raw.get("uuid")),
        "private_key": raw.get("private_key") if _valid_x25519(raw.get("private_key")) else "",
        "public_key": raw.get("public_key") if _valid_x25519(raw.get("public_key")) else "",
        "short_id": _valid_short_id(raw.get("short_id", "")),
        "sni": _valid_sni(raw.get("sni", "www.microsoft.com")),
        "flow": raw.get("flow") if raw.get("flow") == "xtls-rprx-vision" else None,
    }
    if not enabled or port is None or not out["uuid"] or not out["private_key"] or not out["public_key"] or out["short_id"] is None or not out["sni"] or not out["flow"]:
        out["enabled"] = False
    return out


VLESS_PUBLIC = {
    "enabled": os.environ.get("AURORA_VLESS_ENABLED", "true").lower() != "false",
    "port": _parse_port(os.environ.get("AURORA_VLESS_PORT", "8443")) or 0,
    "host": os.environ.get("AURORA_VLESS_HOST", "127.0.0.1"),
    "uuid": os.environ.get("AURORA_VLESS_UUID", ""),
    "private_key": os.environ.get("AURORA_VLESS_PRIVATE_KEY", ""),
    "public_key": os.environ.get("AURORA_VLESS_PUBLIC_KEY", ""),
    "short_id": os.environ.get("AURORA_VLESS_SHORT_ID", ""),
    "sni": os.environ.get("AURORA_VLESS_SNI", "www.microsoft.com"),
    "flow": os.environ.get("AURORA_VLESS_FLOW", "xtls-rprx-vision"),
}

_VLESS_FILE = os.path.join(DATA_DIR, "vless_public.json")

_VLESS_FILE_LOCK = threading.RLock()
_VLESS_FILE_STATE = {"handle": None, "depth": 0}


@contextmanager
def _vless_file_lock():
    with _VLESS_FILE_LOCK:
        if _VLESS_FILE_STATE["depth"] == 0:
            os.makedirs(DATA_DIR, exist_ok=True)
            path = os.path.join(DATA_DIR, ".vless-public.lock")
            handle = open(path, "a+", encoding="utf-8")
            try:
                if os.name == "nt":
                    import msvcrt
                    handle.seek(0, os.SEEK_END)
                    if handle.tell() == 0:
                        handle.write("0")
                        handle.flush()
                    deadline = time.monotonic() + 120.0
                    while True:
                        try:
                            handle.seek(0)
                            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                            break
                        except OSError:
                            if time.monotonic() >= deadline:
                                raise TimeoutError("vless public lock timeout")
                            time.sleep(0.05)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                    import crypt

                    crypt.restrict_file(path)
            except Exception:
                handle.close()
                raise
            _VLESS_FILE_STATE["handle"] = handle
            _VLESS_FILE_STATE["depth"] = 1
        else:
            _VLESS_FILE_STATE["depth"] += 1
        try:
            yield
        finally:
            _VLESS_FILE_STATE["depth"] -= 1
            if _VLESS_FILE_STATE["depth"] == 0:
                handle = _VLESS_FILE_STATE["handle"]
                try:
                    if os.name == "nt":
                        import msvcrt
                        handle.seek(0)
                        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                finally:
                    handle.close()
                    _VLESS_FILE_STATE["handle"] = None


def _gen_vless_material():
    """uuid + пара x25519 через `xray x25519`. Возвращает (uuid, priv, pub) или None."""
    import subprocess
    import uuid as _uuid
    xbin = os.path.join(BASE_DIR, "bin", "xray.exe")
    if not os.path.exists(xbin):
        xbin = os.path.join(BASE_DIR, "xray")
    if not os.path.exists(xbin):
        return None
    try:
        out = subprocess.run([xbin, "x25519"], capture_output=True, text=True,
                             timeout=10, creationflags=HIDE_FLAG).stdout
    except Exception:
        return None
    priv = pub = ""
    for ln in out.splitlines():
        if ln.startswith("PrivateKey:"):
            priv = ln.split(":", 1)[1].strip()
        elif ln.startswith("PublicKey:"):
            pub = ln.split(":", 1)[1].strip()
    if not priv or not pub:
        return None
    return str(_uuid.uuid4()), priv, pub


def _vless_storage_failure(reason):
    quarantine_file(_VLESS_FILE)
    raise StorageDataError("vless_public.json: %s" % reason)


def ensure_vless():
    """Авто-включение внешнего VLESS: env -> сохранённый -> автогенерация. Возвращает VLESS_PUBLIC."""
    global VLESS_PUBLIC
    import crypt
    missing = object()
    env_names = (
        "AURORA_VLESS_ENABLED", "AURORA_VLESS_PORT", "AURORA_VLESS_HOST",
        "AURORA_VLESS_UUID", "AURORA_VLESS_PRIVATE_KEY", "AURORA_VLESS_PUBLIC_KEY",
        "AURORA_VLESS_SHORT_ID", "AURORA_VLESS_SNI", "AURORA_VLESS_FLOW",
    )
    if any(name in os.environ for name in env_names):
        normalized = vless_public(dict(VLESS_PUBLIC))
        VLESS_PUBLIC = normalized
        return VLESS_PUBLIC
    with _vless_file_lock():
        try:
            saved = crypt.load_json(_VLESS_FILE, default=missing)
        except crypt.StorageError as e:
            _vless_storage_failure(str(e))
        if saved is not missing:
            if not isinstance(saved, dict):
                _vless_storage_failure("root is not an object")
            enabled = saved.get("enabled", True)
            if type(enabled) is not bool:
                _vless_storage_failure("enabled is invalid")
            candidate = dict(saved)
            candidate["enabled"] = True
            normalized = vless_public(candidate)
            if (not normalized["uuid"] or not normalized["private_key"]
                    or not normalized["public_key"] or normalized["port"] == 0
                    or normalized["short_id"] is None or not normalized["sni"]
                    or normalized["flow"] != "xtls-rprx-vision"):
                _vless_storage_failure("secret fields are invalid")
            try:
                crypt.save_json(_VLESS_FILE, dict(normalized, enabled=enabled))
            except (crypt.StorageError, OSError) as e:
                _vless_storage_failure(str(e))
            VLESS_PUBLIC = dict(normalized, enabled=enabled)
            return VLESS_PUBLIC
        made = _gen_vless_material()
        if not made:
            VLESS_PUBLIC = vless_public(dict(VLESS_PUBLIC))
            log("vless: xray недоступен, внешний VLESS не сгенерирован")
            return VLESS_PUBLIC
        _uuid, priv, pub = made
        candidate = dict(VLESS_PUBLIC)
        candidate.update({
            "enabled": True,
            "uuid": _uuid,
            "private_key": priv,
            "public_key": pub,
            "short_id": "",
        })
        normalized = vless_public(candidate)
        if not normalized["enabled"]:
            log("vless: xray вернул некорректные ключи")
            return normalized
        try:
            crypt.save_json(_VLESS_FILE, normalized)
        except (crypt.StorageError, OSError) as e:
            _vless_storage_failure(str(e))
        VLESS_PUBLIC = normalized
        log("vless: внешний VLESS сгенерирован (%s:%d)" % (VLESS_PUBLIC["host"], VLESS_PUBLIC["port"]))
        return VLESS_PUBLIC
def open_firewall(ports=None):
    """Windows: netsh правила для наших портов (best-effort, ошибки игнорируются).

    ports: явный список портов; по умолчанию UI/XRAY/XRAY_API/TGWS/VLESS(8443).
    """
    if os.name != "nt":
        return
    import subprocess
    _ports = list(ports) if ports else [
        UI_PORT, XRAY_PORT, XRAY_API_PORT, TGWS_PORT,
    ]
    if not ports:
        vless_port = _parse_port(VLESS_PUBLIC.get("port", 8443))
        if vless_port:
            _ports.append(vless_port)
    seen = {}
    ordered = []
    for p in _ports:
        if p in seen:
            continue
        seen[p] = 1
        ordered.append(p)
    for p in ordered:
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 "name=Aurora_%d" % p, "dir=in", "action=allow",
                 "protocol=TCP", "localport=%d" % p],
                capture_output=True, timeout=10, creationflags=HIDE_FLAG)
        except Exception:
            pass
    log("firewall: правила добавлены для портов %s" % ",".join(str(p) for p in ordered))

# --- агент ПК (recovery, команды) ---
AGENT_TOKEN = ""
AGENT_UPDATE_URL = ""
AGENT_UPDATE_VERSION = ""

# --- настройки (сохранение в data/settings.json) ---
_LOCK = threading.RLock()   # RLock: set() берёт лок, save_settings берёт вложенно
_SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")

_SETTINGS_DEFAULTS = {
    "vpn_mode": True,        # True = VPN активен (final = лучший ключ), False = прямой
    "auto_recovery": True,   # авто-восстановление канала через агента
    "continue_text": "",     # текст при отправке continue
    "ui_token": "",          # X-Auth-токен панели (пусто = как раньше, секреты видны в LAN)
    # --- v1.4.0: сервер / меш / безопасность ---
    "server_name": "Home",       # имя сервера (хаб меша)
    "auto_refresh": True,        # автообновление github-ключей фоновым циклом
    "lan_only": False,           # панель: loopback + LAN (дефолт выключен для публичного деплоя)
    "block_scanners": False,     # 403 на шаблонные пути сканеров/ботов
    "rate_limit": True,          # демпфер 600 req/min на не-loopback IP
    "mesh_id": "mesh-aurora-home",  # идентификатор меша (invite-ссылка)
    "mesh_token": "",            # токен invite (генерируется при первом запросе)
    "twofa": False,              # требовать X-2FA на POST /api/*
    "ui_pin": "",                # пин 2FA (заголовок X-2FA)
    "show_mesh": False,          # показывать вкладку «Меш-сеть» в панели (ТОЛЬКО по команде мастера)
    "show_subs": False,          # показывать вкладку «Магазин» в панели (ТОЛЬКО по команде мастера)
    "mesh_master": False,        # головной сервер: раздаёт политику видимости клиентам меша
    "policy_rev_accepted": 0,    # принятая ревизия политики (0 = не принимал)
    "segment_title": "",         # своё название сегмента монитора (пусто = авто)
    "segment_regions": [],       # выбранные регионы (ru/global/eu/asia)
    "segment_custom": "",        # пользовательские домены (по одному на строку)
    # --- v1.8.0: гологоловной сервер (master) / авто-джойн / замок тестового сервера ---
    "master_addr": "",           # URL головного сервера (напр. http://10.1.136.56:5053)
    "master_token": "",          # секрет регистрации у головного (выдаёт головной)
    "mesh_own_secret": "",       # секрет собственного mesh-узла
    "auto_join": False,          # при старте регистрироваться в меше головного (авто-джуin)
    "master_only": False,        # замок: подключиться/использовать может только головной
    "setup_complete": False,    # первый запуск public-сервера завершён
    "ui_port": UI_PORT,
    "xray_port": XRAY_PORT,
    "xray_api_port": XRAY_API_PORT,
    "tgws_port": TGWS_PORT,
    # --- windows: белый список (белый IP + кастомные домены на direct) ---
    "white_ip": "",          # белый IP провайдера (переопределяет env AURORA_WHITE_IP)
    "bypass_domains": [],    # кастомный белый список доменов, идущих на direct (в дополнение к RU-байпасу)
}

_settings = dict(_SETTINGS_DEFAULTS)

# --- разделяемые runtime-состояния (фоновые треды пишут, web читает) ---
STATE = {
    "conns": 0,
    "devices": {},          # {ip: {name, conns, upload, download}}
    "up": 0,
    "down": 0,
    "tgws": {"running": False, "port_open": False, "secret_ok": False},
    "comm": {"state": "idle", "msg": ""},
    "vless_now": "-",
    "egress_ip": "-",
    "final_mode": "direct",
    "rusegment": {"running": False, "results": [], "ts": 0},
}
STATE_LOCK = threading.Lock()


class StorageDataError(ValueError):
    pass


def quarantine_file(path):
    source = os.path.abspath(path)
    if not os.path.isfile(source):
        return False
    index = 0
    while True:
        candidate = source + ".corrupt" if index == 0 else "%s.corrupt.%d" % (source, index)
        try:
            with open(source, "rb") as src:
                data = src.read()
            with open(candidate, "xb") as dst:
                dst.write(data)
                dst.flush()
                os.fsync(dst.fileno())
            try:
                import crypt

                crypt.restrict_file(candidate)
            except OSError:
                pass
            return True
        except FileExistsError:
            index += 1
        except OSError:
            return False


LOG_LOCK = threading.Lock()


def log(msg):
    """Единая запись в лог (время + сообщение), потокобезопасно."""
    ts = _ts()
    with LOG_LOCK:
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write("[%s] %s\n" % (ts, msg))
        except OSError:
            pass


def log_tail(n=40):
    """Последние n строк LOG_FILE (для /api/log). Возвращает список строк."""
    try:
        with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
        return lines[-n:]
    except OSError:
        return []


# --- RU-байпас: загрузка списка доменов (фолбэк на статический) ---
def _normalize_ru_line(line):
    """Из сырой строки github-списка -> домен без префикса domain: (или None)."""
    line = line.strip().lower()
    if not line or line.startswith(("#", "!", "//")):
        return None
    if line.startswith("domain:"):
        d = line[len("domain:"):].strip()
        return d or None
    if line.startswith("*.") or line.startswith("."):
        d = line.lstrip("*.")
        return d or None
    if " " in line or "/" in line:
        return None
    return line


def _fetch_ru_sources():
    """Скачивает RU_DOMAINS_SOURCES с github, возвращает список доменов."""
    import urllib.request
    domains = []
    seen = {}
    for url in RU_DOMAINS_SOURCES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Aurora/1.0"})
            with urllib.request.urlopen(req, timeout=20) as r:
                raw_length = r.headers.get("Content-Length")
                if raw_length is not None:
                    if not str(raw_length).isdigit():
                        raise ValueError("invalid content length")
                    if int(raw_length) > MAX_RU_SOURCE_BYTES:
                        raise ValueError("ru source too large")
                data = r.read(MAX_RU_SOURCE_BYTES + 1)
                if len(data) > MAX_RU_SOURCE_BYTES:
                    raise ValueError("ru source too large")
                body = data.decode("utf-8")
                if len(body.splitlines()) > MAX_RU_SOURCE_LINES:
                    raise ValueError("too many ru source lines")
            for ln in body.splitlines():
                d = _normalize_ru_line(ln)
                if d and d not in seen:
                    seen[d] = 1
                    domains.append(d)
        except Exception as e:
            log("ru-bypass: источник %s недоступен: %s" % (url, e))
    return domains


def ru_domains():
    """Актуальный список RU-доменов для байпаса (кэш TTL + фолбэк на статику)."""
    now = time.time()
    with RU_DOMAINS_LOCK:
        cached = RU_DOMAINS_CACHE["list"]
        if cached and now - RU_DOMAINS_CACHE["ts"] < RU_DOMAINS_TTL_S:
            return cached
    fetched = _fetch_ru_sources()
    with RU_DOMAINS_LOCK:
        # фолбэк: при пустой загрузке — статический минимум
        merged = fetched if fetched else list(RU_DOMAINS_STATIC)
        # дедуп цельном (static мог прийти первым)
        seen = {}
        final = []
        for d in merged + RU_DOMAINS_STATIC:
            if d and d not in seen:
                seen[d] = 1
                final.append(d)
        RU_DOMAINS_CACHE["list"] = final
        RU_DOMAINS_CACHE["ts"] = now
        log("ru-bypass: доменов %d (%s)" % (
            len(final), "github" if fetched else "static fallback"))
    return RU_DOMAINS_CACHE["list"]


# --- сегменты монитора (t-rusegment): регионы + свои домены ---
REGIONS = {
    "ru": {"title": "Ру-сегмент", "flag": "🇷🇺", "domains": [
        "yandex.ru", "ya.ru", "vk.com", "ok.ru", "mail.ru", "rambler.ru",
        "lenta.ru", "rbc.ru", "gazeta.ru", "kommersant.ru", "rg.ru",
        "kremlin.ru", "gosuslugi.ru", "gov.ru", "sberbank.ru", "tinkoff.ru",
        "avito.ru", "ozon.ru", "wildberries.ru", "kinopoisk.ru", "rutube.ru",
        "matchtv.ru", "kp.ru", "mos.ru",
    ]},
    "global": {"title": "Международный сегмент", "flag": "🌐", "domains": [
        "google.com", "youtube.com", "wikipedia.org", "github.com",
        "cloudflare.com", "mozilla.org", "openai.com", "netflix.com",
        "amazon.com", "reddit.com", "x.com", "instagram.com",
        "microsoft.com", "apple.com", "stackoverflow.com", "medium.com",
    ]},
    "eu": {"title": "ЕС-сегмент", "flag": "🇪🇺", "domains": [
        "bbc.com", "dw.com", "lemonde.fr", "elpais.com", "ilpost.it",
        "france24.com", "rtve.es", "europarl.europa.eu", "rtl.be", "oe24.at",
    ]},
    "asia": {"title": "Азия", "flag": "🌏", "domains": [
        "baidu.com", "alibaba.com", "taobao.com", "tmall.com",
        "naver.com", "yahoo.co.jp", "rakuten.co.jp", "kakaku.com",
        "sina.com.cn", "line.me",
    ]},
}


def _seg_line_to_domain(line):
    """Нормализация строки списка доменов (переиспользует _normalize_ru_line)."""
    d = _normalize_ru_line(line)
    if not d or "." not in d:
        return None
    return d


def segment_regions():
    """Выбранные регионы списком (только существующие в REGIONS)."""
    raw = get("segment_regions") or ["ru"]
    if isinstance(raw, str):
        raw = [raw]
    out = []
    for r in raw:
        if r in REGIONS and r not in out:
            out.append(r)
    return out or ["ru"]


def segment_title():
    """Название вкладки монитора: своё или авто (один регион — его имя, иначе флаги)."""
    own = (get("segment_title") or "").strip()
    if own:
        return own
    sel = segment_regions()
    if len(sel) == 1 and REGIONS.get(sel[0], {}).get("title"):
        return REGIONS[sel[0]]["title"]
    flags = [REGIONS[r]["flag"] for r in sel]
    return "Сегмент" if not flags else " ".join(flags) + " сегмент"


def segment_flag():
    """Флаг/эмодзи вкладки монитора (регионы, иначе глобус)."""
    sel = segment_regions()
    if len(sel) == 1:
        return REGIONS[sel[0]].get("flag", "🌐")
    return "🌐"


# --- v1.8.0: рандомное уникальное имя сервера ---
_NAME_ADJ = ["Мур", "Барс", "Снеж", "Рыж", "Полос", "Тих", "Быстр", "Хит", "Добр", "Гром"]
_NAME_NOUN = ["кот", "барсик", "мурзик", "лео", "тишка", "снежок", "рыжик", "марс", "симба", "том"]


def random_server_name(taken=None, tries=20):
    """Случайное имя сервера, не пересекающееся с уже существующими (taken)."""
    import secrets
    seen = {str(x or "").strip().lower() for x in (taken or [])}
    for _ in range(tries):
        name = "%s-%s-%s" % (
            _NAME_ADJ[secrets.randbelow(len(_NAME_ADJ))],
            _NAME_NOUN[secrets.randbelow(len(_NAME_NOUN))],
            secrets.token_hex(2),
        )
        if name.lower() not in seen:
            return name
    return "Aurora-%s" % secrets.token_hex(3)


def segment_domains():
    """Домены монитора: выбранные регионы + пользовательские домены (custom)."""
    domains = []
    for r in segment_regions():
        for d in REGIONS[r]["domains"]:
            if d not in domains:
                domains.append(d)
    custom = (get("segment_custom") or "").strip()
    if custom:
        for ln in custom.splitlines():
            d = _seg_line_to_domain(ln)
            if d and d not in domains:
                domains.append(d)
    return domains


def policy_required():
    """True, пока не принята актуальная ревизия политики (после обновления — снова True)."""
    try:
        acc = int(get("policy_rev_accepted", 0) or 0)
    except (TypeError, ValueError):
        acc = 0
    return POLICY_REV > acc


def _ts():
    import datetime
    return datetime.datetime.now().strftime("%H:%M:%S")


def _is_nonnegative_int(value):
    return type(value) is int and value >= 0


def _validate_ports(data):
    ports = {}
    for key in ("ui_port", "xray_port", "xray_api_port", "tgws_port"):
        value = data.get(key, _SETTINGS_DEFAULTS[key])
        if type(value) is not int or value < 1 or value > 65535:
            return None
        ports[key] = value
    values = list(ports.values())
    if any(values.count(value) > 1 for value in values):
        return None
    return ports


def _validate_settings(raw):
    if not isinstance(raw, dict):
        raise ValueError("root is not an object")
    bool_keys = (
        "vpn_mode", "auto_recovery", "auto_refresh", "lan_only",
        "block_scanners", "rate_limit", "twofa", "show_mesh", "show_subs",
        "mesh_master", "auto_join", "master_only", "setup_complete",
    )
    string_keys = (
        "continue_text", "ui_token", "server_name", "mesh_id", "mesh_token",
        "ui_pin", "segment_title", "segment_custom", "master_addr",
        "master_token", "mesh_own_secret", "white_ip",
    )
    list_keys = ("segment_regions", "bypass_domains")
    for key in bool_keys:
        if key in raw and type(raw[key]) is not bool:
            raise ValueError("%s is not a boolean" % key)
    for key in string_keys:
        if key in raw and not isinstance(raw[key], str):
            raise ValueError("%s is not a string" % key)
    for key in list_keys:
        if key in raw and (not isinstance(raw[key], list)
                           or any(not isinstance(x, str) for x in raw[key])):
            raise ValueError("%s is not a string list" % key)
    if "policy_rev_accepted" in raw and not _is_nonnegative_int(raw["policy_rev_accepted"]):
        raise ValueError("policy_rev_accepted is not a nonnegative integer")
    if raw.get("ui_pin") and not re.fullmatch(r"[0-9]{6}", raw["ui_pin"]):
        raise ValueError("ui_pin must be six ASCII digits")
    if raw.get("ui_token") and not 12 <= len(raw["ui_token"]) <= 256:
        raise ValueError("ui_token length is invalid")
    merged = dict(_SETTINGS_DEFAULTS)
    merged.update({k: raw[k] for k in raw if k in _SETTINGS_DEFAULTS})
    if _validate_ports(merged) is None:
        raise ValueError("ports are invalid")
    return merged


def _storage_failure(path, reason):
    quarantine_file(path)
    raise StorageDataError("%s: %s" % (os.path.basename(path), reason))


# --- настройки ---
def _apply_port_overrides(settings):
    global UI_PORT, XRAY_PORT, XRAY_API_PORT, TGWS_PORT
    ports = _validate_ports(settings)
    if ports is None:
        return False
    UI_PORT = ports["ui_port"]
    XRAY_PORT = ports["xray_port"]
    XRAY_API_PORT = ports["xray_api_port"]
    TGWS_PORT = ports["tgws_port"]
    return True


def load_settings():
    """Читает data/settings.json (выживают только известные ключи)."""
    global _settings, WHITE_IP
    with _LOCK:
        import crypt
        missing = object()
        try:
            raw = crypt.load_json(_SETTINGS_FILE, default=missing)
        except crypt.StorageError as e:
            _storage_failure(_SETTINGS_FILE, str(e))
        if raw is missing:
            _settings = dict(_SETTINGS_DEFAULTS)
            if not _apply_port_overrides(_settings):
                raise ValueError("ports are invalid")
            WHITE_IP = _SETTINGS_DEFAULTS.get("white_ip", "")
            return
        try:
            merged = _validate_settings(raw)
        except (TypeError, ValueError) as e:
            _storage_failure(_SETTINGS_FILE, str(e))
        try:
            crypt.save_json(_SETTINGS_FILE, merged)
        except (crypt.StorageError, OSError) as e:
            _storage_failure(_SETTINGS_FILE, str(e))
        if not _apply_port_overrides(merged):
            raise ValueError("ports are invalid")
        _settings = merged
        WHITE_IP = str(merged.get("white_ip") or "").strip()


def _persist_settings(value):
    import crypt
    crypt.save_json(_SETTINGS_FILE, value)


def save_settings():
    """Атомарно пишет настройки в data/settings.json."""
    with _LOCK:
        try:
            _persist_settings(_settings)
        except (crypt.StorageError, OSError) as e:
            log("settings: не удалось сохранить: %s" % e)
            return False
    return True


def reset_settings():
    """Сброс настроек к значениям по умолчанию (кнопка «Сбросить всё»)."""
    global _settings
    with _LOCK:
        candidate = dict(_SETTINGS_DEFAULTS)
        try:
            _persist_settings(candidate)
        except (crypt.StorageError, OSError) as e:
            log("settings: не удалось сохранить: %s" % e)
            return False
        _settings.clear()
        _settings.update(candidate)
        WHITE_IP = str(candidate.get("white_ip", "") or "").strip()
    log("settings: сброшены к значениям по умолчанию")
    return True


# --- тарифы: переопределение из data/plans.json (редактор тарифов в UI) ---
_SUBS_PLANS_LOCK = threading.RLock()


def save_plans():
    """Сохраняет текущие SUBS_PLANS в data/plans.json (атомарно)."""
    with _SUBS_PLANS_LOCK:
        try:
            import crypt
            data = json.dumps(SUBS_PLANS, indent=2, ensure_ascii=False).encode("utf-8")
            crypt._atomic_write(SUBS_PLANS_FILE, data)
        except Exception as e:
            log("plans: не удалось сохранить: %s" % e)


def _valid_plan_id(value):
    return (isinstance(value, str) and 1 <= len(value) <= 40
            and all(ch.isascii() and (ch.isalnum() or ch in "_-") for ch in value))


def _validate_plans(raw):
    if not isinstance(raw, dict):
        raise ValueError("root is not an object")
    valid = {}
    need = ("name", "price", "bytes", "days", "devices", "keys")
    for key, value in raw.items():
        if not _valid_plan_id(key):
            raise ValueError("invalid plan id")
        if not isinstance(value, dict) or any(name not in value for name in need):
            raise ValueError("invalid plan record")
        if not isinstance(value["name"], str) or not value["name"].strip():
            raise ValueError("invalid plan name")
        for name in ("price", "bytes", "days", "devices", "keys"):
            if not _is_nonnegative_int(value[name]):
                raise ValueError("invalid plan field %s" % name)
        if value["devices"] < 1 or value["keys"] < 1:
            raise ValueError("invalid plan limits")
        for name in ("features", "features_no"):
            if name in value and (not isinstance(value[name], list)
                                  or any(not isinstance(x, str) for x in value[name])):
                raise ValueError("invalid plan features")
        base = dict(SUBS_PLANS.get(key, {}))
        base.update(value)
        valid[key] = base
    return valid


def _load_plans_override():
    """Переопределение тарифов из data/plans.json (валидные планы перезаписывают)."""
    try:
        with open(SUBS_PLANS_FILE, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        return
    except (OSError, ValueError) as e:
        _storage_failure(SUBS_PLANS_FILE, str(e))
    try:
        valid = _validate_plans(raw)
    except (TypeError, ValueError) as e:
        _storage_failure(SUBS_PLANS_FILE, str(e))
    with _SUBS_PLANS_LOCK:
        if valid:
            SUBS_PLANS.update(valid)
            log("plans: тарифы переопределены из data/plans.json (%d)" % len(valid))


# --- меш: общий ключ подписи приглашений/политики с головным сервером ---
MESH_POLICY_TTL_S = 120


def _read_mesh_policy_key():
    value = (os.environ.get("AURORA_MESH_POLICY_KEY") or "").strip()
    return value if len(value.encode("utf-8")) >= 32 else ""


def _read_mesh_master_id():
    value = (os.environ.get("AURORA_MESH_MASTER_ID") or "").strip()
    if not value or len(value) > 64:
        return ""
    for ch in value:
        if not (ch.isalnum() or ch in "._-"):
            return ""
    return value


MESH_POLICY_KEY = _read_mesh_policy_key()
MESH_MASTER_ID = _read_mesh_master_id()


def mesh_policy_key():
    return MESH_POLICY_KEY


def mesh_master_id():
    return MESH_MASTER_ID


def get(key, default=None):
    return _settings.get(key, default)


def set_many(values, strict=True):
    global WHITE_IP
    import crypt
    if not isinstance(values, dict):
        return False
    with _LOCK:
        candidate = dict(_settings)
        candidate.update(values)
        if strict:
            try:
                candidate = _validate_settings(candidate)
            except (TypeError, ValueError) as e:
                log("settings: невалидное значение: %s" % e)
                return False
        try:
            _persist_settings(candidate)
        except (crypt.StorageError, OSError) as e:
            log("settings: не удалось сохранить: %s" % e)
            return False
        _settings.clear()
        _settings.update(candidate)
        if "white_ip" in values:
            WHITE_IP = str(candidate.get("white_ip", "") or "").strip()
    return True


def set(key, value):
    return set_many({key: value}, strict=key in _SETTINGS_DEFAULTS)


def update_state_sub(key, **kw):
    """Атомарный апдейт вложенного словаря STATE (напр. tgws) под локом."""
    with STATE_LOCK:
        STATE.setdefault(key, {}).update(kw)


def update_state(**kw):
    """Безопасное обновление /api/state-словаря."""
    with STATE_LOCK:
        STATE.update(kw)


def get_state():
    with STATE_LOCK:
        return dict(STATE)


def state_fields():
    """Плоская копия STATE для JSON-ответа."""
    return get_state()


# Переопределение тарифов из data/plans.json — в конце модуля (после log()).
_load_plans_override()


# --- белый список (белый IP + кастомные домены на direct) ---
def get_white_ip():
    """Белый IP провайдера: settings override -> env -> ''."""
    v = (_settings.get("white_ip") or "").strip()
    return v or (os.environ.get("AURORA_WHITE_IP", "") or "").strip()


def set_white_ip(ip):
    """Сохраняет белый IP в настройки (и обновляет WHITE_IP). Возвращает новый IP."""
    global WHITE_IP
    WHITE_IP = (ip or "").strip()
    _settings["white_ip"] = WHITE_IP
    save_settings()
    return WHITE_IP


def get_bypass_domains():
    """Кастомный белый список доменов (direct-байпас)."""
    return list(_settings.get("bypass_domains") or [])


def set_bypass_domains(domains):
    """Сохраняет список кастомных доменов (direct-байпас). Возвращает сохранённый список."""
    clean = []
    seen = {}
    for d in domains or []:
        d = str(d).strip().lower()
        if d and d not in seen and not d.startswith(("http://", "https://", "www.")):
            seen[d] = 1
            clean.append(d)
    _settings["bypass_domains"] = clean
    save_settings()
    return clean